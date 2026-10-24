"""Version-pinned Premium gateway adapter; only root-private state contains secrets.

Protocol reference: AmneziaVPN 5.0.3.0 SubscriptionController/GatewayController.
This is not a public SDK. Unsupported server changes stop protected work safely.
"""
from __future__ import annotations
import base64
import hashlib
import http.client
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import socket
import ssl
import stat
import time
import uuid
import zlib
from urllib.parse import urlsplit

from .vpn_config import parse_profile

CLIENT_VERSION = '5.0.3.0'
PUBLIC_KEY_SHA256 = '8c470f207d071799be894e5562a171da73400268a195a32106e7fd56fe30bc36'
MAX_BYTES = 1024 * 1024
LOCATION = re.compile(r'[a-z0-9][a-z0-9_-]{0,31}')
ERRORS = {
    'LIMIT': 'بلغ اشتراك Premium حد الأجهزة والملفات. حرّر خانة من حسابك ثم أعد المحاولة.',
    'AUTH': 'تعذرت مصادقة اشتراك Premium. راجع المفتاح وصلاحية الاشتراك.',
    'EXPIRED': 'اشتراك Premium غير نشط أو منتهي؛ لم يُبدّل اتصال الخادم.',
    'CAPTCHA': 'تطلب Amnezia تحقق CAPTCHA تفاعليًا؛ أُوقفت المحاولة دون تجاوزه.',
    'RATE_LIMIT': 'طلبت Amnezia الانتظار قبل محاولة أخرى.',
    'UPDATE': 'تغير بروتوكول Premium أو يتطلب إصدارًا أحدث؛ يلزم تحديث المزوّد.',
    'NETWORK': 'تعذر الاتصال الآمن ببوابة Premium ضمن المهلة المحددة.',
    'RESPONSE': 'استجابة Premium غير متوافقة؛ لم يُستخدم إعداد غير متحقق.',
}


def fail(code):
    raise RuntimeError('[PREMIUM_' + code + '] ' + ERRORS[code]) from None


def private_json(path, data):
    """Exclusive private temp file, atomic replace and directory fsync."""
    path = Path(path)
    tmp = path.with_name(path.name + '.' + secrets.token_hex(8) + '.tmp')
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, 'w') as stream:
            json.dump(data, stream)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, path)
        folder = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try: os.fsync(folder)
        finally: os.close(folder)
    finally:
        tmp.unlink(missing_ok=True)


def read_private(path, owner=0):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd) as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != owner or info.st_mode & 0o077:
                raise ValueError()
            raw = stream.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES: raise ValueError()
        value = json.loads(raw)
        if not isinstance(value, dict): raise ValueError()
        return value
    except FileNotFoundError:
        return {}
    except (OSError, ValueError):
        raise RuntimeError('Premium state must be a private root-owned JSON file.') from None


def decode_key(value):
    """Bounded Qt qCompress / vpn:// decoder, without echoing input on failure."""
    try:
        if not isinstance(value, str) or len(value) > 150000:
            raise ValueError()
        value = value.strip()
        if not value.startswith('vpn://'): raise ValueError()
        encoded = value[6:]
        raw = base64.b64decode(encoded + '=' * (-len(encoded) % 4), altchars=b'-_', validate=True)
        if not raw.startswith(b'{'):
            inflater = zlib.decompressobj()
            raw = inflater.decompress(raw[4:], MAX_BYTES + 1)
            if not inflater.eof or inflater.unused_data or len(raw) > MAX_BYTES: raise ValueError()
        result = json.loads(raw)
        if not isinstance(result, dict): raise ValueError()
        return result
    except (ValueError, zlib.error, UnicodeError, RecursionError):
        fail('RESPONSE')


def subscription(value):
    obj = decode_key(value)
    try:
        api, auth = obj['api_config'], obj['auth_data']
        token, country = auth['api_key'], api['user_country_code']
        if obj.get('config_version') != 2 or api['service_type'] != 'amnezia-premium': raise ValueError()
        if not isinstance(token, str) or not 8 <= len(token) <= 4096 or any(ord(c) < 33 for c in token): raise ValueError()
        if not isinstance(country, str) or not re.fullmatch('[a-zA-Z]{2}', country): raise ValueError()
        return {'api_key': token, 'user_country_code': country.lower()}
    except (KeyError, TypeError, ValueError): fail('RESPONSE')


def countries(raw):
    try:
        if not isinstance(raw, list) or not 1 <= len(raw) <= 250: raise ValueError()
        result, seen = [], set()
        for row in raw:
            code, name = row['server_country_code'], row['server_country_name']
            protocols = row['available_protocols']
            flag = row.get('server_country_code_l10n') or code.split('-')[0]
            if not isinstance(code, str) or not LOCATION.fullmatch(code) or code in seen: raise ValueError()
            if not isinstance(name, str) or not 1 <= len(name) <= 80 or any(ord(c) < 32 for c in name): raise ValueError()
            if not isinstance(flag, str) or not re.fullmatch('[a-zA-Z]{2}', flag): raise ValueError()
            if not isinstance(protocols, list) or not all(isinstance(p, str) for p in protocols): raise ValueError()
            result.append(dict(location=code, name=name, country=flag.upper(), supported='awg' in protocols))
            seen.add(code)
        return result
    except (KeyError, TypeError, ValueError): fail('RESPONSE')


def check_error(body, status=200):
    code = body.get('http_status', status)
    if not isinstance(code, int): fail('RESPONSE')
    if 'captcha_id' in body or 'captcha_image' in body: fail('CAPTCHA')
    if code == 409: fail('LIMIT')
    if code in (401, 403, 404): fail('AUTH')
    if code in (402, 422): fail('EXPIRED')
    if code == 429: fail('RATE_LIMIT')
    if code == 501: fail('UPDATE')
    if code >= 300: fail('RESPONSE')


def crypto():
    try:
        from cryptography.hazmat.primitives import padding, serialization
        from cryptography.hazmat.primitives.asymmetric import padding as rsa_padding, x25519
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        return padding, serialization, rsa_padding, x25519, Cipher, algorithms, modes
    except ImportError:
        raise RuntimeError('Premium requires the Debian python3-cryptography package.') from None


def encrypt_payload(payload, pem):
    padding, serialization, rsa_padding, _, Cipher, algorithms, modes = crypto()
    key, iv, salt = os.urandom(32), os.urandom(32), os.urandom(8)
    b64 = lambda data: base64.b64encode(data).decode('ascii')
    keys = json.dumps(dict(aes_key=b64(key), aes_iv=b64(iv), aes_salt=b64(salt))).encode()
    encrypted_key = serialization.load_pem_public_key(pem).encrypt(keys, rsa_padding.PKCS1v15())
    pad = padding.PKCS7(128).padder()
    data = json.dumps(payload).encode()
    data = pad.update(data) + pad.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv[:16])).encryptor()
    body = json.dumps(dict(key_payload=b64(encrypted_key), api_payload=b64(cipher.update(data) + cipher.finalize()))).encode()
    return body, key, iv


def decrypt_payload(raw, key, iv):
    padding, _, _, _, Cipher, algorithms, modes = crypto()
    dec = Cipher(algorithms.AES(key), modes.CBC(iv[:16])).decryptor()
    padded = dec.update(raw) + dec.finalize()
    unpad = padding.PKCS7(128).unpadder()
    obj = json.loads(unpad.update(padded) + unpad.finalize())
    if not isinstance(obj, dict): raise ValueError()
    return obj


def validate_transport(config):
    try:
        pem = config['public_key'].encode('ascii')
        if hashlib.sha256(pem).hexdigest() != PUBLIC_KEY_SHA256: raise ValueError()
        endpoints = config['endpoints']
        if not isinstance(endpoints, list) or not 1 <= len(endpoints) <= 8: raise ValueError()
        for endpoint in endpoints:
            url = urlsplit(endpoint)
            if (url.scheme != 'https' or not url.hostname or url.username or url.password
                    or url.port not in (None, 443) or url.query or url.fragment or url.path not in ('', '/')):
                raise ValueError()
        return pem, endpoints
    except (KeyError, TypeError, ValueError, UnicodeError):
        raise RuntimeError('Premium gateway trust configuration is missing or incompatible.') from None


class Gateway:
    def __init__(self, config):
        self.pem, self.endpoints = validate_transport(config)

    def __call__(self, operation, payload):
        if operation not in {'account_info', 'config'}:
            raise ValueError('Premium operation is not allowed.')
        body, key, iv = encrypt_payload(payload, self.pem)
        deadline = time.monotonic() + 24
        request_id = str(uuid.uuid4())
        # No redirects, proxies from environment, arbitrary paths, or export calls.
        for endpoint in self.endpoints[:6]:
            connection = None
            try:
                host = urlsplit(endpoint).hostname
                # These are root-provisioned origins; additionally reject private DNS answers.
                answers = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
                if not answers or any(not ipaddress.ip_address(a[4][0]).is_global for a in answers):
                    fail('NETWORK')
                if time.monotonic() >= deadline: break
                connection = http.client.HTTPSConnection(host, timeout=min(4, deadline-time.monotonic()), context=ssl.create_default_context())
                connection.request('POST', '/v1/' + operation, body, {
                    'Content-Type': 'application/json', 'X-Client-Request-ID': request_id,
                    'User-Agent': 'ShodanStudio-PremiumAdapter/1.0 (AmneziaVPN-5.0.3.0-protocol)'})
                reply = connection.getresponse()
                chunks, total = [], 0
                while True:
                    if time.monotonic() >= deadline: fail('NETWORK')
                    chunk = reply.read1(min(65536, MAX_BYTES + 1 - total))
                    if not chunk: break
                    total += len(chunk)
                    if total > MAX_BYTES: fail('RESPONSE')
                    chunks.append(chunk)
                raw = b''.join(chunks)
                try: result = decrypt_payload(raw, key, iv)
                except (ValueError, UnicodeError):
                    # Cleartext error envelopes are used by upstream, never accept cleartext success.
                    try: error = json.loads(raw)
                    except (ValueError, UnicodeError): continue
                    if isinstance(error, dict): check_error(error, reply.status)
                    fail('RESPONSE')
                check_error(result, reply.status)
                return result
            except (OSError, http.client.HTTPException):
                continue
            finally:
                if connection: connection.close()
        fail('NETWORK')


def keypair():
    _, serialization, _, x25519, *_ = crypto()
    private = x25519.X25519PrivateKey.generate()
    raw = private.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    public = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return base64.b64encode(raw).decode(), base64.b64encode(public).decode()


def tunnel_config(obj, private, location):
    """Select only the AWG native text from the gateway's nested VPN document."""
    try:
        if obj['api_config']['server_country_code'] != location: raise ValueError()
        containers = obj['containers']
        if not isinstance(containers, list) or len(containers) != 1: raise ValueError()
        container = containers[0]
        # The protocol object is named 'awg'; container's type is 'amnezia-awg'.
        awg = container['awg']
        last = awg['last_config']
        if isinstance(last, str): last = json.loads(last)
        raw = last['config']
        if not isinstance(raw, str) or '$WIREGUARD_CLIENT_PRIVATE_KEY' not in raw: raise ValueError()
        raw = raw.replace('$WIREGUARD_CLIENT_PRIVATE_KEY', private)
        parsed = parse_profile(raw)
        if parsed['protocol'] != 'amneziawg': raise ValueError()
        actual = next(line.split('=', 1)[1].strip() for line in parsed['config'].splitlines() if line.startswith('PrivateKey'))
        if not secrets.compare_digest(actual, private): raise ValueError()
        return raw
    except (ValueError, TypeError, KeyError, StopIteration): fail('RESPONSE')


class Premium:
    def __init__(self, root, *, transport=None, clock=time.time, owner=0):
        self.path = Path(root) / 'premium.json'
        self.state = read_private(self.path, owner)
        self.transport = transport
        self.clock = clock
        self.last_attempt = 0

    def save(self): private_json(self.path, self.state)

    def status(self):
        state = self.state
        return dict(configured=bool(state.get('api_key')), device_tag=state.get('installation_uuid', '')[:8],
                    registered=bool(state.get('registered')), location_count=len(state.get('countries', [])),
                    catalog_source=state.get('catalog_source'), last_refresh=state.get('last_refresh'),
                    account=state.get('account', {}), adapter_version=CLIENT_VERSION,
                    last_error=state.get('last_error'), cooldown_until=state.get('cooldown_until', 0))

    def enroll(self, key):
        clean = subscription(key)
        if self.state.get('api_key') and not secrets.compare_digest(self.state['api_key'], clean['api_key']):
            raise ValueError('Premium is already enrolled; account replacement requires explicit root reprovisioning.')
        if not self.transport: validate_transport(self.state.get('transport', {}))
        self.state.update(clean)
        self.state.setdefault('installation_uuid', str(uuid.uuid4()))
        self.save()  # Persist before any request so failures/restarts never allocate new identities.
        return self.refresh()

    def _request(self, operation, **fields):
        if not self.state.get('api_key'):
            raise RuntimeError('اربط اشتراك Premium أولًا.')
        if self.clock() < self.state.get('cooldown_until', 0):
            fail(self.state.get('last_error') if self.state.get('last_error') in ERRORS else 'RATE_LIMIT')
        payload = dict(os_version='debian', app_version=CLIENT_VERSION, cli_name='AmneziaVPN',
                       distribution='github', app_language='en', installation_uuid=self.state['installation_uuid'],
                       service_type='amnezia-premium', user_country_code=self.state['user_country_code'],
                       auth_data={'api_key': self.state['api_key']}, **fields)
        transport = self.transport or Gateway(self.state.get('transport', {}))
        try:
            result = transport(operation, payload)
            if not isinstance(result, dict): fail('RESPONSE')
            check_error(result)
        except RuntimeError as exc:
            # Only our fixed error codes are persisted, never remote exception/body strings.
            code = next((k for k in ERRORS if str(exc).startswith('[PREMIUM_' + k + ']')), 'NETWORK')
            self.state.update(last_error=code, cooldown_until=self.clock() + (300 if code in {'LIMIT','AUTH','EXPIRED','CAPTCHA','RATE_LIMIT','UPDATE'} else 30))
            self.save()
            fail(code)
        self.state.update(last_error=None, cooldown_until=0)
        return result

    def _catalog(self, data, source):
        if 'available_countries' in data:
            self.state['countries'] = countries(data['available_countries'])
            self.state['catalog_source'] = source

    def refresh(self):
        if self.clock() - self.last_attempt < 5:
            raise RuntimeError('انتظر خمس ثوانٍ قبل تحديث Premium.')
        self.last_attempt = self.clock()
        data = self._request('account_info', cli_version=CLIENT_VERSION, subscription_status='active')
        self._catalog(data, 'gateway')
        account = {}
        for key in ('active_device_count', 'max_device_count'):
            if type(data.get(key)) is int and 0 <= data[key] <= 10000: account[key] = data[key]
        issued = data.get('issued_configs')
        if isinstance(issued, list):
            account['issued_config_count'] = sum(isinstance(x, dict) and x.get('source_type') == 'country_config' for x in issued)
            self.state['registered'] = any(isinstance(x, dict) and x.get('installation_uuid') == self.state['installation_uuid']
                                           and x.get('source_type') != 'country_config' for x in issued)
        elif type(issued) is int and 0 <= issued <= 10000: account['issued_config_count'] = issued
        self.state.update(account=account, last_refresh=self.clock())
        self.save()
        return self.status()

    def profiles(self):
        if not self.state.get('api_key'): return []
        namespace = uuid.UUID(self.state['installation_uuid'])
        return [dict(id=uuid.uuid5(namespace, c['location']).hex, provider='amnezia-premium',
                     location=c['location'], name='Premium · ' + c['name'], country=c['country'],
                     protocol='amneziawg', enabled=c['supported'], available=c['supported'])
                for c in self.state.get('countries', [])]

    def configuration(self, location):
        if not any(c['location'] == location and c['supported'] for c in self.state.get('countries', [])):
            raise ValueError('Premium location is not in the supported account catalog.')
        private, public = keypair()
        # Config requests can have succeeded remotely even if the response is lost.
        # Persist the identity beforehand; never retry with another device UUID.
        self.state['last_requested_location'] = location
        self.save()
        data = self._request('config', service_protocol='awg', server_country_code=location,
                             public_key=public, is_connect_event=True)
        try:
            encoded = data.get('config')
            if not isinstance(encoded, str): fail('RESPONSE')
            obj = decode_key(encoded if encoded.startswith('vpn://') else 'vpn://' + encoded)
            raw = tunnel_config(obj, private, location)
            # Embedded tunnel templates can contain an older country list than
            # account_info (observed 54 vs 55). Only explicit account refresh
            # replaces the catalog; connecting must not hide valid locations.
        except RuntimeError:
            self.state.update(last_error='RESPONSE', cooldown_until=self.clock()+300)
            self.save()
            raise
        self.state.update(registered=True, last_location=location, last_connection=self.clock())
        self.save()
        return raw


def gateway_main():
    """Fixed unprivileged gateway subprocess; stdout is a private broker pipe."""
    import sys
    try:
        raw = sys.stdin.buffer.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES: fail('RESPONSE')
        request = json.loads(raw)
        result = Gateway(request['transport'])(request['operation'], request['payload'])
        print(json.dumps({'ok': True, 'result': result}))
    except Exception as exc:
        code = next((k for k in ERRORS if str(exc).startswith('[PREMIUM_' + k + ']')), 'NETWORK')
        print(json.dumps({'ok': False, 'code': code}))


if __name__ == '__main__': gateway_main()
