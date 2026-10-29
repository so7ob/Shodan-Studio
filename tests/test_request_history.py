"""Request visibility contracts: actual attempts, durable results and offline recovery."""
import contextlib
import copy
import io
import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

from studio import engine
from studio.request_history import batches, summary
from studio.store import Store
from studio.worker import DemoData
from studio.server import create_app
from studio.jobs import JobManager
from test_server import Client, FakeManager, PASSWORD


class HistoryStoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.store=Store(self.tmp.name)
        self.job=self.store.create_job({'query':'fixture','status':'paused'})
        self.h=self.store.requests

    def tearDown(self): self.tmp.cleanup()

    def entry(self,n=1,**kw):
        return dict(request_id=f'{n:032x}',query='fixture',facet='port',source='html',
                    status='success',origin='live',**kw)

    def test_pagination_updates_and_job_scoping(self):
        for i in range(1,72): self.h.save(self.job['id'],self.entry(i))
        first=self.h.list(self.job['id']);second=self.h.list(self.job['id'],first['next_cursor'])
        self.assertEqual((len(first['items']),len(second['items'])),(50,21))
        self.assertFalse(set(x['request_id'] for x in first['items'])&set(x['request_id'] for x in second['items']))
        e=self.entry(71);e.update(status='failed',error='[HTTP_403] permission denied');self.h.save(self.job['id'],e)
        self.assertEqual(self.h.latest(self.job['id'])['seq'],first['items'][0]['seq'])
        self.assertEqual(self.h.latest(self.job['id'])['status'],'failed')
        other=self.store.create_job({'query':'other','status':'paused'})
        self.assertEqual(self.h.list(other['id'])['items'],[])
        with self.assertRaises(KeyError):self.h.detail(other['id'],e['request_id'])

    def test_large_values_are_chunked_replay_safe_and_cascade_deleted(self):
        e=self.entry();self.h.save(self.job['id'],e)
        values=[{'value':f'{i}-'+('ق'*500),'count':i} for i in range(10000)]
        chunks=list(batches(values))
        self.assertGreater(len(chunks),100)
        huge=list(batches([{'value':'ق'*2000000,'count':1}]))
        self.assertLess(len(json.dumps(huge,ensure_ascii=False).encode()),64000)
        self.assertTrue(huge[0][1][0]['truncated'])
        for offset,rows in chunks:
            self.assertLess(len(json.dumps(rows,ensure_ascii=False).encode()),66000)
            self.h.values(self.job['id'],e['request_id'],offset,rows)
        self.h.values(self.job['id'],e['request_id'],*chunks[0])
        result=self.h.detail(self.job['id'],e['request_id'],offset=9900)
        self.assertEqual((result['total'],len(result['items']),result['has_more']),(10000,100,False))
        self.assertEqual(self.h.list(self.job['id'])['items'][0]['details_count'],10000)
        self.store.delete_job(self.job['id'])
        with self.store.connection() as c:
            self.assertEqual(c.execute('SELECT COUNT(*) FROM request_values').fetchone()[0],0)

    def test_unknown_counts_and_interrupted_results_are_not_success(self):
        e=self.entry();e.update(status='processing');self.h.save(self.job['id'],e)
        self.h.interrupt(self.job['id']);r=self.h.latest(self.job['id'])
        self.assertEqual(r['status'],'uncertain')
        self.assertIsNone(r['total_records']);self.assertIsNone(r['duration_ms']);self.assertIsNone(r['finished_at'])
        e['status']='success';e['total_records']=0;self.h.save(self.job['id'],e)
        self.h.interrupt();self.assertEqual(self.h.latest(self.job['id'])['status'],'success')

    def test_legacy_sessions_match_only_proven_attempts_and_reimport_is_idempotent(self):
        job_id=self.job['id'];folder=Path(self.tmp.name)/'legacy';folder.mkdir()
        for session in (1,2):
            self.store.append_event(job_id,{'kind':'progress','stats':{'session_number':session}})
            self.store.append_event(job_id,{'kind':'log','at':f'2026-10-29T12:00:0{session}+00:00',
                'message':'[1/500] PORT | fixture'})
        report={'started_at_utc':'2026-10-29T12:00:02+00:00','finished_at_utc':'2026-10-29T12:00:03+00:00',
                'resume':{'session_number':2},'pages':[{'number':1,'query':'fixture','facet':'port','source':'html',
                'status':'parsed','displayed_total':20,'row_count':1,'rows':[{'value':'443','count':20}]}]}
        (folder/'result.txt.report.json').write_text(json.dumps(report))
        before=self.store.get_job(job_id)
        self.h.backfill(job_id,folder);self.h.backfill(job_id,folder)
        items=self.h.list(job_id)['items'];self.assertEqual(len(items),2)
        success=next(x for x in items if x['status']=='success')
        self.assertEqual(success['session_number'],2);self.assertEqual(success['total_records'],20)
        self.assertEqual(self.h.latest(job_id)['request_id'],success['request_id'])
        self.assertIsNone(success['duration_ms']);self.assertIsNone(success['new_unique_ips'])
        self.assertEqual(self.h.detail(job_id,success['request_id'])['items'][0]['value'],'443')
        self.assertEqual(self.store.get_job(job_id),before)

    def test_snapshot_never_relabels_a_failed_attempt_and_modern_logs_do_not_duplicate(self):
        folder=Path(self.tmp.name)/'legacy';folder.mkdir();job_id=self.job['id']
        e=self.entry(number=1,session_number=1);e.update(status='failed',error='[HTTP_429] rate limited',http_status=429)
        self.h.save(job_id,e)
        self.store.append_event(job_id,{'kind':'progress','stats':{'session_number':1}})
        self.store.append_event(job_id,{'kind':'log','message':'[1/500] PORT | fixture'})
        (folder/'checkpoint.json').write_text(json.dumps({'state':{'cache':[{'query':'fixture','facet':'port','total':20,'rows':[{'value':'80','count':20}]}]}}))
        self.h.backfill(job_id,folder)
        self.assertEqual(len(self.h.list(job_id)['items']),2)
        self.assertEqual(self.h.latest(job_id)['status'],'rate_limited')
        snap=next(x for x in self.h.list(job_id)['items'] if x['origin']=='snapshot')
        self.assertIsNone(snap['started_at']);self.assertIsNone(snap['new_unique_ips'])

    def test_whitelist_excludes_response_bodies_headers_and_credential_urls(self):
        e=self.entry();e.update(url='https://api.shodan.io/x?key=secret',headers={'Cookie':'secret'},password='secret',
                               body='secret',error='Error at https://api.shodan.io/x?key=secret')
        self.h.save(self.job['id'],e)
        stored=json.dumps(self.h.latest(self.job['id']))
        self.assertNotIn('secret',stored);self.assertNotIn('Cookie',stored);self.assertNotIn('password',stored)

    def test_final_report_recovers_a_result_lost_between_worker_and_manager(self):
        folder=Path(self.tmp.name)/'crash';folder.mkdir();e=self.entry(number=1,session_number=1)
        pending={**e,'status':'processing'};self.h.save(self.job['id'],pending);self.h.interrupt()
        e.update(status='parsed',new_unique_ips=4,row_count=4,total_records=4,duration_ms=250,
                 rows=[{'value':'192.0.2.1','count':1}])
        (folder/'result.txt.report.json').write_text(json.dumps({'pages':[e]}))
        self.store.append_event(self.job['id'],{'kind':'log','request_id':e['request_id'],'message':'[1/500] PORT | fixture'})
        self.h.backfill(self.job['id'],folder)
        items=self.h.list(self.job['id'])['items'];self.assertEqual(len(items),1)
        self.assertEqual(items[0]['status'],'success')
        self.assertIsNone(items[0]['new_unique_ips'])  # Old reports cannot prove per-attempt SQLite additions.

    def test_new_ips_use_atomic_sqlite_additions_even_after_replay_or_stale_checkpoint(self):
        job_id=self.job['id'];self.store.record_ip_progress(job_id,['192.0.2.1'])
        e=self.entry();e.update(status='requesting',facet='ip');self.h.save(job_id,e)
        for _ in range(2):self.store.record_ip_progress(job_id,['192.0.2.1','192.0.2.2'],request_id=e['request_id'])
        e.update(status='success',new_unique_ips=2);self.h.save(job_id,e)
        self.assertEqual(self.h.latest(job_id)['new_unique_ips'],1)
        self.assertEqual(self.store.get_job(job_id)['stats']['unique_ips'],2)


class ObservedCrawler(engine.Crawler):
    def __init__(self,*args,**kwargs):
        self.observations=[]
        super().__init__(*args,**kwargs)
    def on_request(self,entry,rows=None):
        self.observations.append((copy.deepcopy(summary(entry,entry.get('origin','live'))),copy.deepcopy(rows)))


class AttemptTests(unittest.TestCase):
    def setUp(self): self.tmp=tempfile.TemporaryDirectory()
    def tearDown(self): self.tmp.cleanup()
    def crawler(self,mode='html',fetcher=None,**kw):
        args=engine.parse_args(['--query','fixture','--mode',mode,'--strategy','adaptive','--delay','0',
            '--include-non-global','--output',str(Path(self.tmp.name)/'ips.txt')]+(['--api-key','fixture-api-key'] if mode=='api' else []))
        c=ObservedCrawler(args,fetcher=fetcher or DemoData('fixture').fetch,**kw)
        if mode=='api':c.configure_source('api',DemoData('fixture'))
        return c

    def test_html_result_counts_cache_and_new_ip_delta_do_not_add_requests(self):
        c=self.crawler()
        with contextlib.redirect_stdout(io.StringIO()),contextlib.redirect_stderr(io.StringIO()):
            p=c.read_page('fixture','ip');c.collect_ips(p)
            cached=c.read_page('fixture','ip');c.collect_ips(cached)
        latest={e['request_id']:e for e,_ in c.observations}
        self.assertEqual(c.report['requests_attempted'],1)
        self.assertEqual(len(latest),2)
        live=next(e for e in latest.values() if e['origin']=='live')
        hit=next(e for e in latest.values() if e['origin']=='cache')
        self.assertEqual((live['row_count'],live['total_records'],live['new_unique_ips']),(100,292,100))
        self.assertEqual((hit['status'],hit['new_unique_ips']),('cached',0))
        self.assertTrue(any(rows and len(rows)==100 for _,rows in c.observations))

    def test_api_pagination_tracks_each_page_and_ip_delta(self):
        c=self.crawler('api')
        with contextlib.redirect_stdout(io.StringIO()),contextlib.redirect_stderr(io.StringIO()):c.read_page('fixture','ip')
        latest={e['request_id']:e for e,_ in c.observations}
        self.assertEqual(c.report['requests_attempted'],3)
        self.assertEqual([e['api_page'] for e in latest.values()],[1,2,3])
        self.assertEqual([e['new_unique_ips'] for e in latest.values()],[100,100,92])
        self.assertTrue(all(e['status']=='success' for e in latest.values()))
        details=[rows for _,rows in c.observations if rows is not None]
        self.assertEqual([sum(row['count'] for row in rows) for rows in details],[100,100,92])

    def test_attempt_begins_after_wait_and_retry_has_its_own_identity(self):
        clock=[0];calls=[]
        def fetch(url):
            calls.append(clock[0]);clock[0]+=0.25
            if len(calls)==1:raise engine.SpiderError('[HTTP_429] limited',http_status=429,retry_after=5)
            return DemoData('fixture').fetch(url)
        c=self.crawler(fetcher=fetch,clock=lambda:clock[0],sleeper=lambda n:clock.__setitem__(0,clock[0]+n))
        c.args.delay=2;c.args.retry_base_delay=1;c.last_finished=0
        with contextlib.redirect_stdout(io.StringIO()),contextlib.redirect_stderr(io.StringIO()):c.read_page('fixture','port')
        last={e['request_id']:e for e,_ in c.observations}
        self.assertEqual(calls,[2,7.25]);self.assertEqual(len(last),2)
        self.assertEqual([e['status'] for e in last.values()],['rate_limited','success'])
        self.assertEqual([e['duration_ms'] for e in last.values()],[250,250])

    def test_empty_unavailable_and_errors_have_distinct_results(self):
        from test_empty_facets import empty_html
        cases=[(lambda u:DemoData('fixture').fetch(u.replace('query=fixture','query=fixture%20port%3A1')),'ip','empty'),
               (lambda u:empty_html('fixture','version'),'version','unavailable'),
               (lambda u:'<html><title>Login</title><input type="password"></html>','port','login_required'),
               (lambda u:'<html><title>Just a moment...</title><form id="challenge-form"></form></html>','port','challenge'),
               (lambda u:'<html>unknown layout</html>','port','failed')]
        for fetch,facet,status in cases:
            with self.subTest(status=status):
                c=self.crawler(fetcher=fetch)
                with contextlib.redirect_stdout(io.StringIO()),contextlib.redirect_stderr(io.StringIO()):
                    try:c.read_page('fixture',facet)
                    except engine.SpiderError:pass
                self.assertEqual(c.observations[-1][0]['status'],status)
        for message,status in [('[BROWSER_CHALLENGE] required','challenge'),('[BROWSER_LOGIN] required','login_required'),('[CONNECTION] refused','connection_failed')]:
            def blocked(url):raise engine.SpiderError(message,http_status=403 if 'BROWSER' in message else None)
            c=self.crawler(fetcher=blocked)
            with contextlib.redirect_stdout(io.StringIO()),self.assertRaises(engine.SpiderError):c.read_page('fixture','port')
            self.assertEqual(c.observations[-1][0]['status'],status)


class RequestAPITests(unittest.TestCase):
    def test_authenticated_job_scoped_routes_and_validation(self):
        with tempfile.TemporaryDirectory() as folder:
            store=Store(folder);manager=FakeManager(store);app=create_app(folder,manager=manager)
            client=Client(app);client.request('GET','/api/session')
            job=manager.create_job({'query':'fixture'});other=manager.create_job({'query':'other'})
            ident='a'*32;store.requests.save(job['id'],dict(request_id=ident,query='fixture',status='success'))
            base=f"/api/jobs/{job['id']}/requests"
            self.assertEqual(client.request('GET',base)[0],401)
            self.assertEqual(client.request('GET',base+'/'+ident)[0],401)
            client.request('POST','/api/setup',{'username':'admin','password':PASSWORD,'setup_token':store.setup_token()})
            self.assertEqual(client.request('GET',base)[1]['items'][0]['request_id'],ident)
            self.assertEqual(client.request('GET',base+'/'+ident)[1]['total'],0)
            self.assertEqual(client.request('GET',f"/api/jobs/{other['id']}/requests/{ident}")[0],404)
            for suffix in ('?before=-1','?limit=0','?limit=201','/'+ident+'?offset=-1'):
                self.assertEqual(client.request('GET',base+suffix)[0],400)
            self.assertEqual(client.request('POST',base)[0],405)
            app.close()

    def test_worker_history_survives_restart_without_duplicate_attempts_or_replayed_queries(self):
        with tempfile.TemporaryDirectory() as folder:
            manager=JobManager(folder,demo=True,autostart=False)
            try:
                job=manager.create_job({'query':'fixture','mode':'html',
                    'settings':{'demo':True,'delay':0,'strategy':'tree','max_requests':25}})
                manager.start()
                deadline=time.monotonic()+15
                while time.monotonic()<deadline:
                    finished=manager.get_job(job['id'])
                    if finished['status'] in ('completed','completed_warnings','failed') and not manager._active_id: break
                    time.sleep(.02)
                self.assertIn(finished['status'],('completed','completed_warnings'))
                before=manager.store.requests.list(job['id'],limit=200)['items']
                actual=[e for e in before if e['origin']=='live']
                self.assertEqual(len(actual),finished['stats']['requests'])
                self.assertTrue(all(e['status'] in ('success','empty','unavailable') for e in actual))
                self.assertEqual(sum(e['new_unique_ips'] or 0 for e in actual),finished['stats']['unique_ips'])
                self.assertIsNotNone(finished['latest_request'])
            finally: manager.shutdown()
            with patch.object(engine,'fetch_html',side_effect=AssertionError('network')):
                restored=JobManager(folder,demo=True)
                try:
                    after=restored.store.requests.list(job['id'],limit=200)['items']
                    self.assertEqual([e for e in after if e['origin']=='live'],actual)
                    self.assertFalse(any(e['origin']=='legacy' for e in after))
                    self.assertEqual(restored.get_job(job['id'])['stats']['requests'],finished['stats']['requests'])
                finally:restored.shutdown()


if __name__=='__main__':unittest.main()
