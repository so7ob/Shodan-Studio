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
    parser.add_argument('--port', type=int, default=8792)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='studio-browser-fixture-') as folder:
        store = Store(folder)
        store.setup(store.setup_token(), 'acceptance', 'local-browser-fixture-123!')
        manager = JobManager(folder, store=store, autostart=False, demo=True)
        manager.vpn = VPNManager(store, BrowserPremiumProvider() if args.premium else FakeProvider())
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
