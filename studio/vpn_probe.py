"""Fixed, bounded diagnostic targets. Runs as the web UID inside chosen namespace."""
import concurrent.futures
import http.client
import ipaddress
import json
import socket
import ssl
import sys
import time
import urllib.request

TARGET = 'www.shodan.io'
EGRESS = 'https://api.ipify.org'


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args):
        return None


def destination_probe(source_check=False):
    result = {'dns': False, 'tcp': False, 'tls': False, 'source_access': 'not_tested'}
    start = time.monotonic()
    try:
        # Process deadline in helper bounds libc resolution as well.
        addresses = socket.getaddrinfo(TARGET, 443, type=socket.SOCK_STREAM)
        result['dns_ms'] = round((time.monotonic() - start) * 1000)
        if not addresses: raise OSError('No resolved addresses')
        result['dns'] = True
        # Connect to the resolved address directly. create_connection(TARGET)
        # would repeat DNS and its retries on every check of a slow resolver.
        deadline = time.monotonic() + 4
        sock = None
        for family, kind, protocol, _, address in addresses[:4]:
            remaining = deadline - time.monotonic()
            if remaining <= 0: break
            candidate = socket.socket(family, kind, protocol)
            try:
                candidate.settimeout(remaining)
                candidate.connect(address)
                sock = candidate
                break
            except OSError:
                candidate.close()
        if sock is None: raise OSError('TCP connection failed')
        with sock:
            result['tcp'] = True
            sock.settimeout(4)
            with ssl.create_default_context().wrap_socket(sock, server_hostname=TARGET) as secure:
                result['tls'] = True
                if source_check:
                    # Explicit diagnostics only. No query, credentials, cookies,
                    # redirects or challenge handling. Inspect headers only.
                    secure.sendall(('GET / HTTP/1.1\r\nHost: ' + TARGET +
                                    '\r\nUser-Agent: ShodanStudio-NetworkDiagnostics/1.0\r\nConnection: close\r\n\r\n').encode('ascii'))
                    with http.client.HTTPResponse(secure) as response:
                        response.begin()
                        result['source_http_status'] = response.status
                        result['source_access'] = ('browser_challenge' if response.getheader('cf-mitigated') == 'challenge'
                            else 'access_denied' if response.status in (401, 403)
                            else 'rate_limited' if response.status == 429
                            else 'website_reachable' if response.status == 200 else 'other_http_status')
    except Exception as exc:
        result['error'] = type(exc).__name__
        if source_check and result['tls']: result['source_access'] = 'check_failed'
    result['destination_ms'] = round((time.monotonic() - start) * 1000)
    return result


def egress_probe():
    result = {'http': False, 'egress_ip': None, 'geolocation': None}
    start = time.monotonic()
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
    result['egress_ms'] = round((time.monotonic() - start) * 1000)
    return result


def probe(source_check=False):
    start = time.monotonic()
    # Independent fixed targets can run together. The helper's process deadline
    # bounds both threads, including DNS. Both use the selected namespace's DNS.
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        destination = pool.submit(destination_probe, source_check)
        egress = pool.submit(egress_probe)
        result = {**destination.result(), **egress.result(), 'target': TARGET}
    if result.get('egress_error'): result.setdefault('error', result['egress_error'])
    result['latency_ms'] = round((time.monotonic() - start) * 1000)
    result['healthy'] = all(result[x] for x in ('dns', 'tcp', 'tls', 'http', 'egress_ip'))
    return result


if __name__ == '__main__':
    print(json.dumps(probe(source_check=sys.argv[1:] == ['--source'])))
