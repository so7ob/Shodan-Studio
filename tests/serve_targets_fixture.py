"""Disposable inventory UI fixture. No scheduler or external requests."""
import argparse
from pathlib import Path
import sys
import tempfile
from wsgiref.simple_server import make_server
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from studio.server import create_app
from test_vpn import FakeProvider


def main():
    parser = argparse.ArgumentParser(); parser.add_argument('--port', type=int, default=8813); args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='studio-targets-fixture-') as folder:
        app = create_app(folder, allowed_hosts=[f'127.0.0.1:{args.port}'], demo=True, autostart=False)
        m = app.manager; m.vpn.provider = FakeProvider()
        m.store.setup(m.store.setup_token(), 'acceptance', 'local-browser-fixture-123!')
        a = m.create_job({'title': 'Inventory fixture A', 'query': 'fixture product:nginx'})
        b = m.create_job({'title': 'Inventory fixture B', 'query': 'fixture port:53'})
        for j in (a, b): m.store.update_job(j['id'], status='paused')
        ips = [f'203.0.113.{n}' for n in range(1, 121)]
        m.store.record_ip_progress(a['id'], ips)
        m.store.record_ip_progress(b['id'], [ips[0]])
        for n, ip in enumerate(ips):
            country, city = ('US', 'Mountain View') if n < 80 else ('DE', 'Berlin')
            entry = {'request_id': f'{n+1:032x}', 'query': a['query']+f' country:{country}', 'source': 'html',
                     'finished_at': f'2026-10-{20+n%10:02d}T12:00:00Z'}
            if n != 119: m.store.targets.discover(a, entry, [ip])
            ident = m.store.targets.select_ids({'q': ip})
            # Exact address lookup avoids substring matches such as .1/.10.
            with m.store.connection() as c: ident = c.execute('SELECT id FROM targets WHERE ip=?', (ip,)).fetchone()[0]
            if n % 7 == 0: continue
            m.store.targets.snapshot(a['id'], ident, f'{n+1:032x}', 'api', {'ip_str': ip, 'country_code': country,
                'city': city, 'org': '<img src=x onerror=alert(1)> Fixture' if n == 1 else 'Fixture Organization', 'asn': 'AS64500',
                'data': [{'port': 443, 'transport': 'tcp', 'product': 'nginx', 'version': 'fixture', 'timestamp': '2026-10-19T12:00:00Z'},
                         {'port': 53, 'transport': 'udp', 'product': 'DNS'}]})
        try:
            print(f'Fixture ready: http://127.0.0.1:{args.port}', flush=True)
            make_server('127.0.0.1', args.port, app).serve_forever()
        finally: app.close()

if __name__ == '__main__': main()
