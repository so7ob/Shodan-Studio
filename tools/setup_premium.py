#!/usr/bin/env python3
"""Root-only, read-only import from the verified installed Linux client.

Never writes the host client's settings or reuses its installation/tunnel keys.
--check reports metadata only; --apply provisions the helper's independent identity.
No HTTP requests or tunnel changes are performed by this tool.
"""
import argparse
import base64
import configparser
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from studio.premium import (CLIENT_VERSION, PUBLIC_KEY_SHA256, countries, crypto,
                            private_json, read_private, subscription, validate_transport)

SETTINGS = Path('/root/.config/AmneziaVPN.ORG/AmneziaVPN.conf')
BINARY = Path('/opt/AmneziaVPN/bin/AmneziaVPN')
ROOT = Path('/etc/shodan-studio/vpn')


def qt_bytes(text):
    if text.startswith('"') and text.endswith('"'): text = text[1:-1]
    if not text.startswith('@ByteArray(') or not text.endswith(')'):
        raise ValueError('Unsupported Qt settings format.')
    def escape(match):
        token = match[1]
        if token.startswith('x'): return chr(int(token[1:], 16))
        return {'n':'\n', 'r':'\r', 't':'\t', '0':'\0', '"':'"', '\\':'\\'}.get(token, token)
    return re.sub(r'\\(x[0-9a-fA-F]{1,4}|.)', escape, text[11:-1])


def installed():
    info = SETTINGS.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077:
        raise ValueError('Installed client settings must be root-private.')
    if SETTINGS.stat().st_size > 2*1024*1024: raise ValueError('Settings exceed size limit.')
    cfg = configparser.ConfigParser(interpolation=None)
    cfg.optionxform = str
    cfg.read(SETTINGS)
    servers = json.loads(qt_bytes(cfg['Servers']['serversList']))
    premium = [x for x in servers if x.get('api_config', {}).get('service_type') == 'amnezia-premium']
    if len(premium) != 1: raise ValueError('Expected exactly one Premium subscription in the installed client.')
    server = premium[0]
    # The GUI caches vpn_key without a URI prefix in some builds. Validate the
    # canonical subscription fields directly, ignoring cached tunnel material.
    envelope = {k:server[k] for k in ('config_version', 'api_config', 'auth_data')}
    key = 'vpn://' + base64.urlsafe_b64encode(json.dumps(envelope).encode()).decode()
    auth = subscription(key)
    if server.get('config_version') != 2: raise ValueError('Unsupported subscription format.')
    pem = next((p.replace(b'\\n', b'\n') for p in re.findall(
        rb'-----BEGIN PUBLIC KEY-----.*?-----END PUBLIC KEY-----', BINARY.read_bytes(), re.S)
        if hashlib.sha256(p.replace(b'\\n', b'\n')).hexdigest() == PUBLIC_KEY_SHA256), None)
    if not pem: raise ValueError('Installed client production public-key fingerprint does not match.')
    # Same cached gateway-proxy envelope as upstream; prioritize Premium's cache.
    country = auth['user_country_code']
    values = [v for k,v in cfg['Conf'].items() if k == 'proxyUrls\\service_amnezia-premium_country_' + country]
    if not values: raise ValueError('No trusted Premium HTTPS gateway cache is available; open the client first.')
    padding, _, _, _, Cipher, algorithms, modes = crypto()
    digest = hashlib.sha512(pem).digest()
    value = values[0].strip('"')
    if value.startswith('@ByteArray('): value = qt_bytes(values[0])
    dec = Cipher(algorithms.AES(digest[:32]), modes.CBC(digest[32:48])).decryptor()
    data = dec.update(base64.b64decode(value, validate=True)) + dec.finalize()
    unpad = padding.PKCS7(128).unpadder()
    endpoints = json.loads(unpad.update(data) + unpad.finalize())
    transport = dict(public_key=pem.decode('ascii'), endpoints=endpoints)
    validate_transport(transport)
    return dict(**auth, transport=transport, countries=countries(server['api_config']['available_countries']),
                catalog_source='installed_client', adapter_version=CLIENT_VERSION)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--apply', action='store_true')
    parser.add_argument('--transport-only', action='store_true', help='Provision gateway trust only; enroll the subscription from the browser.')
    args = parser.parse_args()
    if os.geteuid() != 0 or args.check == args.apply:
        parser.error('Use root with exactly one of --check or --apply.')
    try:
        data = installed()
        if args.apply:
            if ROOT.is_symlink(): raise ValueError('Unsafe helper root.')
            ROOT.mkdir(parents=True, exist_ok=True, mode=0o700)
            state = read_private(ROOT / 'premium.json')
            if state.get('api_key') and state['api_key'] != data['api_key']:
                raise ValueError('An independent subscription is already enrolled; replacement refused.')
            state['transport'] = data['transport']
            state.setdefault('installation_uuid', str(uuid.uuid4()))
            if not args.transport_only:
                state.update(api_key=data['api_key'], user_country_code=data['user_country_code'])
                for name in ('countries', 'catalog_source', 'adapter_version'): state.setdefault(name, data[name])
            private_json(ROOT / 'premium.json', state)
        print(json.dumps(dict(applied=args.apply, location_count=len(data['countries']),
                              supported_awg_count=sum(c['supported'] for c in data['countries']),
                              new_device_identity=True, host_client_modified=False,
                              gateway_request_sent=False, transport_only=args.transport_only)))
        return 0
    except Exception:
        # JSON/Qt/crypto parsers can include credential fragments in their errors.
        print('Premium setup could not validate the installed client. No credentials displayed.', file=sys.stderr)
        return 1


if __name__ == '__main__': raise SystemExit(main())
