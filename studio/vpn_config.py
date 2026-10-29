"""Strict public policy and secret profile parsing; exceptions never echo input."""
import base64
import ipaddress
import re

PROFILE_ID = re.compile(r'[a-f0-9]{32}')
MODES = {'direct', 'preferred', 'failover', 'manual'}
DEFAULT_FAILOVERS = 20
MAX_FAILOVERS = 100
NETWORK_DEFAULTS = dict(network_mode='direct', preferred_vpn_profile=None,
                        allowed_vpn_profiles=[], vpn_failover_enabled=False, max_failovers=DEFAULT_FAILOVERS)


def can_failover(job):
    return (job.get('network_mode') == 'failover' and job.get('vpn_failover_enabled', False)
            and job.get('failover_count', 0) < job.get('max_failovers', DEFAULT_FAILOVERS))


def profile_id(value):
    if not isinstance(value, str) or not PROFILE_ID.fullmatch(value):
        raise ValueError('معرّف ملف VPN غير صالح.')
    return value


def policy(payload=None):
    payload = {} if payload is None else payload
    if not isinstance(payload, dict) or set(payload) - NETWORK_DEFAULTS.keys():
        raise ValueError('إعدادات اتصال المهمة غير صالحة.')
    result = {**NETWORK_DEFAULTS, **payload}
    if result['network_mode'] not in MODES:
        raise ValueError('سياسة اتصال غير مدعومة.')
    if type(result['max_failovers']) is not int or not 0 <= result['max_failovers'] <= MAX_FAILOVERS:
        raise ValueError(f'حد التبديل يجب أن يكون بين صفر و{MAX_FAILOVERS}.')
    if type(result['vpn_failover_enabled']) is not bool:
        raise ValueError('خيار التبديل غير صالح.')
    allowed = result['allowed_vpn_profiles']
    if not isinstance(allowed, list) or len(allowed) > 20:
        raise ValueError('قائمة VPN المسموحة غير صالحة.')
    result['allowed_vpn_profiles'] = list(dict.fromkeys(profile_id(x) for x in allowed))
    preferred = result['preferred_vpn_profile']
    if preferred is not None:
        profile_id(preferred)
    if result['network_mode'] != 'direct' and not preferred:
        raise ValueError('اختر ملف VPN لهذه المهمة.')
    if result['network_mode'] == 'failover' and preferred not in allowed:
        raise ValueError('يجب إدراج الملف المفضل ضمن قائمة التبديل.')
    if result['vpn_failover_enabled'] and result['network_mode'] != 'failover':
        raise ValueError('التبديل التلقائي متاح في سياسة VPN Failover فقط.')
    return result


def metadata(data):
    if not isinstance(data, dict) or set(data) - {'name', 'country', 'enabled'}:
        raise ValueError('بيانات الملف غير صالحة.')
    name = data.get('name', '').strip() if isinstance(data.get('name'), str) else ''
    country = data.get('country', '')
    if not 1 <= len(name) <= 100 or any(ord(c) < 32 for c in name):
        raise ValueError('اسم ملف VPN غير صالح.')
    if not isinstance(country, str) or (country and not re.fullmatch('[A-Z]{2}', country)):
        raise ValueError('الدولة رمز من حرفين مثل DE، أو فارغ إن لم تُعرف.')
    enabled = data.get('enabled', True)
    if type(enabled) is not bool:
        raise ValueError('حالة التفعيل غير صالحة.')
    return dict(name=name, country=country or None, enabled=enabled)


INTERFACE_KEYS = {'PrivateKey', 'Address', 'DNS', 'MTU', 'ListenPort',
                  'Jc', 'Jmin', 'Jmax', 'S1', 'S2', 'S3', 'S4', 'H1', 'H2', 'H3', 'H4',
                  'I1', 'I2', 'I3', 'I4', 'I5', 'HeaderProtectionKey', 'ContentPaddingAddition',
                  'RekeyAfterTime', 'RejectAfterTime', 'RekeyTimeout', 'KeepaliveTimeout', 'MaxHandshakeAttempts'}
PEER_KEYS = {'PublicKey', 'PresharedKey', 'Endpoint', 'AllowedIPs', 'PersistentKeepalive'}


def parse_profile(raw):
    """One-peer .conf only. Never execute quick hooks, accept paths, or expand variables."""
    try:
        if not isinstance(raw, str) or len(raw.encode()) > 16384 or '\x00' in raw:
            raise ValueError()
        sections = {}
        current = None
        for line in raw.splitlines():
            line = line.split('#', 1)[0].strip()
            if not line:
                continue
            if line.startswith('['):
                if line not in ('[Interface]', '[Peer]') or line in sections:
                    raise ValueError()
                current = sections[line] = {}
                continue
            if current is None or '=' not in line:
                raise ValueError()
            key, value = (x.strip() for x in line.split('=', 1))
            # AWG 2/3 Premium signatures include hex packet templates (I1-I5).
            # They are passed as data to the native parser, never a shell.
            limit = 4096 if key in {'I1', 'I2', 'I3', 'I4', 'I5'} else 1024
            if key in current or not value or len(value) > limit:
                raise ValueError()
            current[key] = value
        interface, peer = sections['[Interface]'], sections['[Peer]']
        if set(interface) - INTERFACE_KEYS or set(peer) - PEER_KEYS:
            raise ValueError()
        if sum(len(v) for k,v in interface.items() if k in {'I1', 'I2', 'I3', 'I4', 'I5'}) > 8192:
            raise ValueError()
        for obj, keys in ((interface, ('PrivateKey', 'HeaderProtectionKey')), (peer, ('PublicKey', 'PresharedKey'))):
            for key in keys:
                if key in obj and len(base64.b64decode(obj[key], validate=True)) != 32:
                    raise ValueError()
        if 'PrivateKey' not in interface or 'PublicKey' not in peer:
            raise ValueError()
        addresses = [str(ipaddress.ip_interface(x.strip())) for x in interface['Address'].split(',')]
        dns = [str(ipaddress.ip_address(x.strip())) for x in interface['DNS'].split(',')]
        if not 1 <= len(addresses) <= 2 or not 1 <= len(dns) <= 3:
            raise ValueError()
        if any(ipaddress.ip_address(x).is_loopback or ipaddress.ip_address(x).is_unspecified for x in dns):
            raise ValueError()
        endpoint, port = peer['Endpoint'].rsplit(':', 1)
        # Literal endpoints avoid bootstrap DNS outside the selected tunnel.
        ipaddress.ip_address(endpoint.strip('[]'))
        if not 1 <= int(port) <= 65535:
            raise ValueError()
        networks = [ipaddress.ip_network(x.strip(), strict=False) for x in peer['AllowedIPs'].split(',')]
        for version in {ipaddress.ip_interface(x).version for x in addresses}:
            if ipaddress.ip_network('0.0.0.0/0' if version == 4 else '::/0') not in networks:
                raise ValueError()
        mtu = int(interface.get('MTU', '1280'))
        if not 1280 <= mtu <= 1500:
            raise ValueError()
        awg = bool(set(interface) - {'PrivateKey', 'Address', 'DNS', 'MTU', 'ListenPort'})
        # Hand the protocol-only config to the official tool via stdin. Never disk/argv.
        config = '[Interface]\n' + ''.join(f'{k} = {v}\n' for k, v in interface.items() if k not in {'Address', 'DNS', 'MTU'})
        config += '[Peer]\n' + ''.join(f'{k} = {v}\n' for k, v in peer.items())
        return dict(protocol='amneziawg' if awg else 'wireguard', addresses=addresses, dns=dns, mtu=mtu, config=config)
    except (ValueError, KeyError, TypeError, OverflowError):
        raise ValueError('ملف غير مدعوم: يلزم WG/AWG .conf بقرين واحد وDNS وEndpoint رقمي ومسار كامل، دون hooks أو مفاتيح مجهولة.') from None


def network_error(exc):
    """HTTP responses/certificate trust errors do not justify changing egress."""
    if getattr(exc, 'http_status', None) is not None:
        return None
    import errno
    import socket
    import ssl
    if isinstance(exc, ssl.SSLCertVerificationError):
        return None
    if isinstance(exc, socket.gaierror):
        return 'DNS'
    if isinstance(exc, TimeoutError):
        return 'TIMEOUT'
    if isinstance(exc, ConnectionResetError):
        return 'CONNECTION_RESET'
    if isinstance(exc, ssl.SSLError):
        return 'TLS'
    if isinstance(exc, OSError) and exc.errno in (errno.ENETUNREACH, errno.EHOSTUNREACH):
        return 'NETWORK_UNREACHABLE'
    match = re.match(r'^\[(?:API_)?(DNS|DNS_PROXY|TIMEOUT|TLS|CONNECTION_RESET|NETWORK_UNREACHABLE|CONNECTION|CONNECT|RESPONSE_READ|BROWSER_NETWORK)\]', str(exc))
    return match[1] if match else None
