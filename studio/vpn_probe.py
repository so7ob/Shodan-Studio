"""Fixed, bounded diagnostic targets. Runs as the web UID inside chosen namespace."""
import ipaddress
import json
import socket
import ssl
import time
import urllib.request

TARGET = 'www.shodan.io'
EGRESS = 'https://api.ipify.org'


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args):
        return None


def probe():
    result = {'dns': False, 'tcp': False, 'tls': False, 'http': False,
              'egress_ip': None, 'geolocation': None, 'target': TARGET}
    start = time.monotonic()
    try:
        # Process deadline in helper bounds libc resolution as well.
        socket.getaddrinfo(TARGET, 443, type=socket.SOCK_STREAM)
        result['dns'] = True
        with socket.create_connection((TARGET, 443), timeout=4) as sock:
            result['tcp'] = True
            with ssl.create_default_context().wrap_socket(sock, server_hostname=TARGET):
                result['tls'] = True
    except Exception as exc:
        result['error'] = type(exc).__name__
    # Independent egress probe distinguishes destination-only faults from a
    # broken tunnel. A Shodan TLS outage alone must not rotate VPN profiles.
    try:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        with opener.open(EGRESS, timeout=5) as response:
            result['http'] = response.status == 200
            value = str(ipaddress.ip_address(response.read(65).decode().strip()))
            if not ipaddress.ip_address(value).is_global:
                raise ValueError()
            result['egress_ip'] = value
    except Exception as exc:
        # Error type only; no remote content, paths, URLs, or credentials.
        result['egress_error'] = type(exc).__name__
        result.setdefault('error', type(exc).__name__)
    result['latency_ms'] = round((time.monotonic() - start) * 1000)
    result['healthy'] = all(result[x] for x in ('dns', 'tcp', 'tls', 'http', 'egress_ip'))
    return result


if __name__ == '__main__':
    print(json.dumps(probe()))
