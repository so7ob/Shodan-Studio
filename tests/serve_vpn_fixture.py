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
    parser.add_argument('--interactive', action='store_true')
    parser.add_argument('--port', type=int, default=8792)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='studio-browser-fixture-') as folder:
        store = Store(folder)
        store.setup(store.setup_token(), 'acceptance', 'local-browser-fixture-123!')
        manager = JobManager(folder, store=store, autostart=False, demo=True)
        manager.vpn = VPNManager(store, BrowserPremiumProvider() if args.premium else FakeProvider())
        if args.interactive:
            state={'running':True,'state':'awaiting_verification','http_status':403,'width':1100,'height':760}
            image='data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+jRZkAAAAASUVORK5CYII='
            def browser_rpc(job_id,data):
                if data['action']=='verify':state.update(state='ready',http_status=200)
                if data['action']=='stop':return {'running':False,'state':'closed'}
                return {**state,**({'image':image} if data['action']=='frame' else {})}
            manager._browser_rpc=browser_rpc
            job=manager.create_job({'title':'Interactive browser fixture','query':'fixture','mode':'html','settings':{'demo':True},'network':{'network_mode':'preferred','preferred_vpn_profile':'1'*32}})
            store.update_job(job['id'],status='waiting_input',input_reason='source_error',error='[HTTP_403] [BROWSER_CHALLENGE] fixture')
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
