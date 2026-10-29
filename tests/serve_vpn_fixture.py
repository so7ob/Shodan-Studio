"""Loopback-only browser fixture. Never uses a real subscription or VPN helper."""
import argparse
from pathlib import Path
import sys
import tempfile
import time
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
    parser.add_argument('--accounts', action='store_true')
    parser.add_argument('--empty-facet', action='store_true')
    parser.add_argument('--automatic-browser', action='store_true')
    parser.add_argument('--adaptive', action='store_true')
    parser.add_argument('--pacing', action='store_true')
    parser.add_argument('--pacing-progress', action='store_true')
    parser.add_argument('--request-history', action='store_true')
    parser.add_argument('--port', type=int, default=8792)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='studio-browser-fixture-') as folder:
        store = Store(folder)
        store.setup(store.setup_token(), 'acceptance', 'local-browser-fixture-123!')
        manager = JobManager(folder, store=store, autostart=False, demo=True)
        manager.vpn = VPNManager(store, BrowserPremiumProvider() if args.premium else FakeProvider())
        if args.request_history:
            job=manager.create_job({'title':'سجل الاستعلامات التجريبي','query':'fixture','mode':'html','settings':{'demo':True,'delay':18}})
            store.update_job(job['id'],status='running')
            for n in range(1,71):
                entry={'request_id':f'{n:032x}','query':'http.component:"php" country:"EG" port:"443"',
                       'facet':'port','source':'html','number':n,'session_number':1,
                       'status':'success' if n<70 else 'requesting','origin':'live',
                       'started_at':'2026-10-29T20:00:00+00:00','total_records':579 if n<70 else None,
                       'row_count':250 if n<70 else None}
                store.requests.save(job['id'],entry)
            latest=entry
            raw_get=manager.get_job
            ready=[None]
            def history_job(job_id):
                if ready[0] is None: ready[0]=time.monotonic()+4
                if latest['status']=='requesting' and time.monotonic()>=ready[0]:
                    latest.update(status='success',total_records=579,row_count=250,duration_ms=1500)
                    store.requests.save(job_id,latest)
                    from studio.request_history import batches
                    for offset,values in batches([{'value':str(i),'label':'<img src=x onerror=alert(1)>' if i==1 else str(i),'count':i+1} for i in range(250)]):
                        store.requests.values(job_id,latest['request_id'],offset,values)
                    store.append_event(job_id,{'kind':'request','request':latest})
                return raw_get(job_id)
            manager.get_job=history_job
        if args.adaptive:
            job=manager.create_job({'title':'Adaptive 160 fixture','query':'fixture','mode':'html','settings':{'demo':True}})
            store.record_ip_progress(job['id'],[f'192.0.2.{i+1}' for i in range(160)],
                {'branches':[{'expected_records':80,'completed':True},{'expected_records':80,'completed':True}], 'planning_complete':True,'traversal_completed':True},
                stats={'phase':'completed','requests':4,'requests_this_run':4,'ready_branches':2,'completed_branches':2,
                       'remaining_branches':0,'plan_known':True,'facet_probes':1,
                       'source_total_records':160,
                       'last_partition':{'facet':'port','children':2,'raw_children':52,'estimated_requests':2}})
            store.update_job(job['id'],status='completed')
            if args.pacing:
                store.update_job(job['id'],settings={**job['settings'],'delay':180})
                store.record_ip_progress(job['id'],[],
                    {'branches':[{'expected_records':80,'completed':False},{'expected_records':80,'completed':False}],
                     'planning_complete':False,'traversal_completed':False},
                    stats={'phase':'partitioning','ready_branches':2,'completed_branches':0,'remaining_branches':2,
                           'plan_known':True,'source_total_records':160,'facet_probes':1,
                           'last_partition':{'facet':'port','children':2,'raw_children':52,'estimated_requests':2},
                           'request_wait':{'reason':'request_delay','until':time.time()+180}})
                store.update_job(job['id'],status='running')
        if args.pacing_progress:
            job=manager.create_job({'title':'Pacing and progress fixture','query':'synthetic progress fixture',
                                    'mode':'html','settings':{'demo':True,'delay':18}})
            store.record_ip_progress(job['id'],[f'192.0.2.{i+1}' for i in range(100)],
                {'branches':[{'expected_records':None,'completed':False}],
                 'planning_complete':False,'traversal_completed':False},
                stats={'phase':'partitioning','ready_branches':1,'completed_branches':0,'remaining_branches':1,
                       'plan_known':True,'source_total_records':579,'requests':4,'requests_this_run':4})
            store.update_job(job['id'],status='running')
            original_get_job=manager.get_job
            deadline=[None]
            def pacing_job(job_id):
                if deadline[0] is None: deadline[0]=time.time()+18
                current=store.get_job(job_id)
                wait={'reason':'request_delay','until':deadline[0],'duration':18,'configured_delay':18}
                if time.time()>deadline[0]+1: wait=None
                store.update_job(job_id,stats={**current['stats'],'request_wait':wait})
                return original_get_job(job_id)
            manager.get_job=pacing_job
        if args.interactive or args.accounts or args.empty_facet:
            state={'running':True,'backend':'patchright' if args.automatic_browser else 'chromium',
                   'state':'off_task_page','can_return_to_results':True,'http_status':200,'width':1100,'height':760}
            image='data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+jRZkAAAAASUVORK5CYII='
            def browser_rpc(job_id,data):
                if data['action']=='login':
                    assert data['username']=='fixture-user' and data['password']=='fixture-account-password'
                    state.update(login_status='submitted',state='off_task_page',can_return_to_results=True)
                if data['action']=='forget_account':return {'removed':True}
                if data['action']=='verify':
                    if data.get('return_to_results') is True:state.update(state='awaiting_verification',can_return_to_results=False,http_status=200)
                    elif not state['can_return_to_results']:state.update(state='ready',http_status=200)
                if args.empty_facet and data['action']=='frame' and not state['can_return_to_results']:
                    state.update(state='ready',login_status='submitted')
                if data['action']=='stop':return {'running':False,'state':'closed'}
                return {**state,**({'image':image} if data['action']=='frame' else {})}
            manager._browser_rpc=browser_rpc
            if args.accounts:manager.vpn.prepare=lambda job: {'active_vpn_profile':'1'*32,'network_health':'healthy'}
            job=manager.create_job({'title':'Interactive browser fixture','query':'fixture','mode':'html','settings':{'demo':True},'network':{'network_mode':'preferred','preferred_vpn_profile':'1'*32}})
            store.update_job(job['id'],status='waiting_input',input_reason='source_error',error='[HTTP_403] [BROWSER_CHALLENGE] fixture')
            if args.automatic_browser:
                manager._browser_job=job['id']
                store.update_job(job['id'],browser_session_enabled=True,browser_backend='patchright',
                    browser_recovery_attempt={'state':'awaiting_verification'})
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
