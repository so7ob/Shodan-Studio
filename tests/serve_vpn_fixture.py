"""Loopback-only browser fixture. Never uses a real subscription or VPN helper."""
import argparse
from pathlib import Path
import sys
import tempfile
from wsgiref.simple_server import make_server

sys.path[:0] = [str(Path(__file__).resolve().parents[1]), str(Path(__file__).resolve().parent)]
from studio.server import create_app, ThreadingWSGIServer, QuietRequestHandler
from studio.jobs import JobManager
from studio.store import Store
from studio.vpn import VPNManager
from test_vpn import FakeProvider
from test_premium import BrowserPremiumProvider


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--premium', action='store_true')
    parser.add_argument('--source-denial', action='store_true')
    parser.add_argument('--port', type=int, default=8792)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='studio-browser-fixture-') as folder:
        store = Store(folder)
        store.setup(store.setup_token(), 'acceptance', 'local-browser-fixture-123!')
        manager = JobManager(folder, store=store, autostart=False, demo=True)
        manager.vpn = VPNManager(store, BrowserPremiumProvider() if args.premium else FakeProvider())
        if args.source_denial:
            from test_vpn import GOOD
            manager.vpn.provider.diagnostics = lambda scope: dict(GOOD, scope=scope,
                source_access='browser_challenge', source_http_status=403)
            job = manager.create_job(dict(title='HTML denial fixture',query='fixture',mode='html',settings={'demo':True}))
            store.update_job(job['id'],status='waiting_input',input_reason='source_error',
                error='[HTTP_403] [BROWSER_CHALLENGE] Interactive verification required.',network_health='healthy')
        app = create_app(folder, manager=manager, autostart=False, demo=True,
                         allowed_hosts=(f'127.0.0.1:{args.port}',))
        try:
            with make_server('127.0.0.1', args.port, app, server_class=ThreadingWSGIServer,
                             handler_class=QuietRequestHandler) as server:
                print(f'Synthetic fixture at http://127.0.0.1:{args.port}; restart before each browser run.', flush=True)
                server.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            manager.shutdown()


if __name__ == '__main__': main()
