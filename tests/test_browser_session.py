"""Offline browser boundary, queue lease and same-session HTML recovery."""
import json
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import MagicMock,patch
from studio.browser_session import Session,allowed_url,facet_url,same_facet
from studio.browser_broker import BrowserBroker,BrowserPipeError
from studio.vpn_helper import Broker
from studio.engine import build_url
from studio.jobs import JobManager
from studio.store import Store
from studio.server import create_app
from test_server import Client,PASSWORD
from test_vpn import FakeProvider,P1,P2,GOOD
import test_worker
from studio.worker import DemoData
from studio import engine

URL=build_url('fixture','ip')

class BoundaryTests(unittest.TestCase):
    def test_only_approved_https_hosts_and_exact_facet_urls(self):
        self.assertTrue(allowed_url('https://challenges.cloudflare.com/path'))
        self.assertEqual(facet_url(URL),('fixture','ip'))
        for url in ['file:///etc/passwd','http://www.shodan.io/','https://www.shodan.io.evil.test/','https://user:secret@www.shodan.io/','https://127.0.0.1/','https://www.shodan.io:444/']:
            self.assertFalse(allowed_url(url))
        for url in ['https://www.shodan.io/search','https://account.shodan.io/search/facet?query=x&facet=ip',URL+'&key=secret',URL+'#fragment']:
            with self.assertRaises(ValueError):facet_url(url)
    def session(self):
        s=object.__new__(Session);s.call=MagicMock(return_value={});s.document={};s.expected=URL;s.ready=False;s.cdp=MagicMock();s.target='page';s.session='session';s.main_frame='main'
        return s
    def test_reject_shell_arbitrary_eval_urls_keys_and_coordinates(self):
        s=self.session()
        for data in [{'action':'evaluate','code':'secret'},{'action':'navigate','url':'file:///etc/passwd'},{'action':'click','x':1100,'y':0},{'action':'click','x':True,'y':0},{'action':'key','key':'F12'},{'action':'text','text':'a\nb'},{'action':'stop'},{'action':'scroll','delta':10000}]:
            with self.assertRaises(ValueError):s.action(data)
        s.call.assert_not_called()
    def test_manual_input_only_fixed_cdp_methods(self):
        s=self.session();s.action({'action':'text','text':'private-password'});s.action({'action':'click','x':20,'y':40});s.action({'action':'key','key':'Enter'})
        self.assertEqual([c.args[0] for c in s.call.call_args_list],['Input.insertText','Input.dispatchMouseEvent','Input.dispatchMouseEvent','Input.dispatchKeyEvent','Input.dispatchKeyEvent'])
        self.assertNotIn('private-password',json.dumps(s.status()))
    def test_headers_must_belong_to_main_frame_and_manual_verification_is_parsed(self):
        s=self.session();s.html=lambda:{'url':URL,'html':DemoData('fixture').fetch(URL)}
        s.event({'method':'Network.responseReceived','sessionId':'session','params':{'type':'Document','frameId':'main','response':{'url':URL,'status':200,'headers':{}}}})
        s.event({'method':'Network.responseReceived','sessionId':'session','params':{'type':'Document','frameId':'child','response':{'url':'https://challenges.cloudflare.com/','status':403,'headers':{'cf-mitigated':'challenge'}}}})
        self.assertEqual(s.verify()['state'],'ready');self.assertEqual(s.status()['state'],'ready')
        s.document['challenge']=True;self.assertEqual(s.verify()['state'],'browser_challenge')
        s.document['challenge']=False;s.html=lambda:{'url':URL,'html':'<html>log in</html>'}
        self.assertNotEqual(s.verify()['state'],'ready')
    def test_challenge_is_not_solved_or_rotated(self):
        s=self.session();s.document={'url':URL,'status':403,'challenge':True};s.html=lambda:{'url':URL,'html':'<html>challenge</html>'}
        s.navigate=MagicMock()
        for _ in range(3):
            with self.assertRaisesRegex(RuntimeError,'BROWSER_CHALLENGE'):s.fetch(URL)
        s.navigate.assert_not_called()
        s.call.assert_not_called()
    def test_rate_limit_preserves_numeric_or_unbounded_wait_without_raw_headers(self):
        for header,expected in [('3600',3600),('9'*400,'unbounded')]:
            s=self.session();s.html=lambda:{'url':URL,'html':'rate limited'};s.navigate=MagicMock()
            s.event({'method':'Network.responseReceived','sessionId':'session','params':{'type':'Document','frameId':'main','response':{'url':URL,'status':429,'headers':{'Retry-After':header,'Set-Cookie':'private-cookie'}}}})
            for _ in range(3):
                result=s.fetch(URL)
                self.assertEqual(result,{'http_status':429,'retry_after':expected})
            s.navigate.assert_not_called()
            self.assertEqual(s.status()['state'],'rate_limited')
            self.assertNotIn('private-cookie',json.dumps(result))
    def test_fetch_never_navigates_away_from_a_denied_document(self):
        for current in (URL, build_url('fixture','org'), 'https://account.shodan.io/'):
            for status in (401,403,429):
                with self.subTest(current=current,status=status):
                    s=self.session()
                    saved={'url':current,'status':status,'retry_after':3600}
                    s.document=dict(saved)
                    s.html=MagicMock(return_value={'url':current,'html':'denied'})
                    for _ in range(3):
                        if status==429:
                            self.assertEqual(s.fetch(URL),{'http_status':429,'retry_after':3600})
                        else:
                            with self.assertRaisesRegex(RuntimeError,'HTTP_'+str(status)):s.fetch(URL)
                        self.assertEqual(s.document,saved)
                    s.call.assert_not_called()  # Includes the real Page.navigate boundary.
                    s.html.assert_not_called()
    def test_denial_arriving_during_verification_blocks_navigation(self):
        s=self.session();s.document={'url':URL,'status':200}
        def verify():
            s.document={'url':URL,'status':429,'retry_after':60}
            return {'state':'rate_limited'}
        s.verify=verify
        self.assertEqual(s.fetch(URL),{'http_status':429,'retry_after':60})
        s.call.assert_not_called()
    def test_new_successful_document_can_clear_prior_denial(self):
        s=self.session();s.document={'url':URL,'status':403,'challenge':True}
        with self.assertRaisesRegex(RuntimeError,'BROWSER_CHALLENGE'):s.fetch(URL)
        s.event({'method':'Network.responseReceived','sessionId':'session','params':{'type':'Document','frameId':'main','response':{'url':URL,'status':200,'headers':{}}}})
        body=DemoData('fixture').fetch(URL);s.html=lambda:{'url':URL,'html':body}
        self.assertEqual(s.fetch(URL),{'html':body})
        s.call.assert_not_called()
    def test_successful_document_allows_next_facet_navigation(self):
        s=self.session();s.document={'url':URL,'status':200}
        target=build_url('fixture','org');body=DemoData('fixture').fetch(target)
        def navigate(method,params):
            self.assertEqual(method,'Page.navigate');self.assertEqual(params,{'url':target})
            s.document={'url':target,'status':200}
            return {}
        s.call.side_effect=navigate;s.html=lambda:{'url':target,'html':body}
        self.assertEqual(s.fetch(target),{'html':body})
        s.call.assert_called_once_with('Page.navigate',{'url':target})
    def test_repeated_verification_only_reads_page_without_reloading_challenge(self):
        s=self.session();s.document={'url':URL,'status':403,'challenge':True}
        s.call.return_value={'result':{'value':json.dumps({'url':URL,'html':'<html>Challenge</html>'})}}
        for _ in range(6):self.assertEqual(s.verify()['state'],'browser_challenge')
        self.assertEqual([c.args[0] for c in s.call.call_args_list],['Runtime.evaluate']*6)
    def test_login_landing_page_requires_explicit_return_to_pending_facet(self):
        s=self.session();pending=build_url('fixture country:DE','org');s.expected=pending
        landing='https://account.shodan.io/?private=not-for-api'
        s.document={'url':landing,'status':200};s.html=lambda:{'url':landing,'html':'<html>Account private fixture</html>'}
        for _ in range(6):
            result=s.action({'action':'verify'})
            self.assertEqual(result['state'],'off_task_page');self.assertTrue(result['can_return_to_results'])
            self.assertNotIn('private',json.dumps(result))
        s.call.assert_not_called()
        result=s.action({'action':'verify','return_to_results':True})
        s.call.assert_called_once_with('Page.navigate',{'url':pending})
        self.assertEqual(s.expected,pending);self.assertNotEqual(result['state'],'ready')
        self.assertFalse(result['can_return_to_results']);s.cdp.send.assert_not_called()
        s.document={'url':pending,'status':200};s.html=lambda:{'url':pending,'html':DemoData('fixture').fetch(pending)}
        self.assertEqual(s.verify()['state'],'ready')
    def test_return_cannot_accept_external_url_or_truthy_input(self):
        s=self.session()
        for extra in ({'return_to_results':'true'},{'return_to_results':1},{'return_to_results':False},{'return_to_results':True,'url':URL}):
            with self.assertRaises(ValueError):s.action({'action':'verify',**extra})
        s.call.assert_not_called()
    def test_return_on_existing_results_only_verifies_without_reload(self):
        s=self.session();s.document={'url':URL,'status':200};s.html=lambda:{'url':URL,'html':DemoData('fixture').fetch(URL)}
        self.assertEqual(s.action({'action':'verify','return_to_results':True})['state'],'ready')
        s.call.assert_not_called()
    def test_equivalent_query_encoding_is_accepted_but_different_facet_is_not(self):
        s=self.session();s.expected=build_url('fixture country:DE','ip')
        equivalent='https://www.shodan.io/search/facet?facet=ip&query=fixture%20country%3ADE'
        self.assertTrue(same_facet(equivalent,s.expected))
        s.document={'url':equivalent,'status':200};s.html=lambda:{'url':equivalent,'html':DemoData('fixture').fetch(equivalent)}
        self.assertEqual(s.verify()['state'],'ready')
        for url in [build_url('fixture country:US','ip'),build_url('fixture country:DE','org'),equivalent+'&query=extra',equivalent.replace('www.shodan.io','account.shodan.io')]:
            self.assertFalse(same_facet(url,s.expected))
    def test_new_navigation_and_same_document_redirect_invalidate_ready(self):
        s=self.session();s.ready=True;s.document={'url':URL,'status':200}
        s.event({'method':'Page.navigatedWithinDocument','sessionId':'session','params':{'frameId':'main','url':'https://www.shodan.io/'}})
        self.assertEqual(s.status()['state'],'off_task_page');self.assertFalse(s.ready)
        s.event({'method':'Network.requestWillBeSent','sessionId':'session','params':{'type':'Document','frameId':'main','request':{'url':URL}}})
        self.assertFalse(s.document);self.assertEqual(s.status()['state'],'awaiting_verification')
        # A prior account HTTP 200 must not authorize a newly loading task page.
        s.document={'url':'https://account.shodan.io/','status':200};s.html=lambda:{'url':URL,'html':DemoData('fixture').fetch(URL)}
        self.assertNotEqual(s.verify()['state'],'ready')
    def test_return_then_source_denial_never_enables_resume(self):
        for status,challenge,state in [(403,True,'browser_challenge'),(429,False,'rate_limited'),(403,False,'access_denied')]:
            s=self.session();s.document={'url':'https://www.shodan.io/','status':200}
            s.html=lambda:{'url':'https://www.shodan.io/','html':'home'}
            s.action({'action':'verify','return_to_results':True})
            s.document={'url':URL,'status':status,'challenge':challenge};s.html=lambda:{'url':URL,'html':'denied'}
            self.assertEqual(s.verify()['state'],state);self.assertFalse(s.ready)
    def test_request_filter_and_popups_are_closed(self):
        s=self.session()
        s.event({'method':'Fetch.requestPaused','sessionId':'session','params':{'requestId':'1','request':{'url':'http://169.254.169.254/'}}})
        self.assertEqual(s.cdp.send.call_args.args[0],'Fetch.failRequest')
        s.event({'method':'Target.targetCreated','params':{'targetInfo':{'type':'page','targetId':'popup'}}})
        self.assertEqual(s.cdp.send.call_args.args[0],'Target.closeTarget')
    def test_first_frame_not_painted_retries_without_navigation_or_losing_session(self):
        s=self.session();s.call.side_effect=[RuntimeError('Frame not ready'),{'data':'fixture'}]
        with patch('studio.browser_session.time.sleep'):
            frame=s.action({'action':'frame'})
        self.assertTrue(frame['running'])
        self.assertEqual(frame['image'],'data:image/jpeg;base64,fixture')
        self.assertEqual([c.args[0] for c in s.call.call_args_list],['Page.captureScreenshot']*2)
    def test_browser_fetch_requires_actual_worker_lease(self):
        root=MagicMock();root.active=P1;root.running_job='1'*32
        b=BrowserBroker(root);b.profile=P1;b.job='1'*32;b.request=MagicMock(return_value={'html':'fixture'})
        self.assertEqual(b.fetch('1'*32,URL),{'html':'fixture'})
        root.running_job=None
        with self.assertRaises(RuntimeError):b.fetch('1'*32,URL)
        b.request.assert_called_once()
    def test_broken_pipe_closes_session_but_http_denial_preserves_it(self):
        b=BrowserBroker(MagicMock());b.process=MagicMock();b.process.poll.return_value=None;b.close=MagicMock()
        b.reply=MagicMock(side_effect=BrowserPipeError())
        with self.assertRaisesRegex(RuntimeError,'BROWSER_SESSION'):b.request({'action':'frame'})
        b.close.assert_called_once();b.close.reset_mock();b.reply.side_effect=RuntimeError('[HTTP_403] challenge')
        with self.assertRaisesRegex(RuntimeError,'HTTP_403'):b.request({'action':'fetch','url':URL})
        b.close.assert_not_called()
    def test_root_broker_blocks_switch_and_manual_input_during_worker_lease(self):
        root=object.__new__(Broker);root.lock=threading.RLock();root.active=P1;root.running_job=None
        root.browser=BrowserBroker(root);root.browser.process=MagicMock();root.browser.process.poll.return_value=None
        root.browser.job='a'*32;root.browser.profile=P1
        for request in ({'op':'connect','profile_id':P2},{'op':'disconnect'},{'op':'restore'}):
            with self.assertRaises(RuntimeError):root.dispatch(request)
        root.running_job='a'*32
        with self.assertRaises(RuntimeError):root.browser.action({'job_id':'a'*32,'input':{'action':'text','text':'private'}})
    def test_lost_isolation_closes_browser_before_manual_input(self):
        root=MagicMock();root.running_job=None;root.active=P1;root._isolation.return_value={'route_verified':False,'leak_protection':True}
        b=BrowserBroker(root);b.job='a'*32;b.profile=P1;b.close=MagicMock();b.request=MagicMock()
        with self.assertRaisesRegex(RuntimeError,'BROWSER_SESSION'):b.action({'job_id':'a'*32,'input':{'action':'frame'}})
        b.close.assert_called_once();b.request.assert_not_called()

class ManagerTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.manager=JobManager(self.tmp.name,autostart=False,demo=True)
        self.manager.vpn.provider=FakeProvider()
        self.job=self.manager.create_job({'query':'fixture','mode':'html','settings':{'demo':True},'network':{'network_mode':'preferred','preferred_vpn_profile':P1}})
        self.manager.store.update_job(self.job['id'],status='paused')
    def tearDown(self):self.manager.shutdown();self.tmp.cleanup()
    def test_session_reserves_queue_and_resume_requires_valid_page(self):
        manager=self.manager
        with patch.object(manager,'_browser_rpc',return_value={'state':'awaiting_verification','running':True}):
            manager.browser_action(self.job['id'],{'action':'start'})
            self.assertEqual(manager._browser_job,self.job['id'])
            with self.assertRaisesRegex(ValueError,'Shodan'):manager.action(self.job['id'],{'action':'resume'})
            with self.assertRaises(RuntimeError):manager.network_settings(self.job['id'],{'network_mode':'direct'})
        other=manager.create_job({'query':'other','mode':'html','settings':{'demo':True}})
        self.assertIsNone(manager.store.claim_next(manager._browser_job))
        with patch.object(manager,'_browser_rpc',return_value={'state':'ready'}):manager.action(self.job['id'],{'action':'resume'})
        self.assertEqual(manager.store.claim_next(manager._browser_job)['id'],self.job['id'])
        self.assertEqual(manager.store.get_job(other['id'])['status'],'queued')
    def test_no_direct_browser_start_and_no_input_auditing(self):
        manager=self.manager
        manager.store.update_job(self.job['id'],network_mode='direct')
        with patch.object(manager,'_browser_rpc') as rpc:
            with self.assertRaises(RuntimeError):manager.browser_action(self.job['id'],{'action':'start'})
            rpc.assert_not_called()
        manager.store.update_job(self.job['id'],network_mode='preferred')
        with patch.object(manager,'_browser_rpc',return_value={'state':'awaiting_verification'}):
            manager.browser_action(self.job['id'],{'action':'start'})
            manager.browser_action(self.job['id'],{'action':'text','text':'private-password'})
        self.assertNotIn('private-password',json.dumps(manager.vpn.events()))
    def test_return_is_audited_and_does_not_resume_or_change_lease(self):
        self.manager._browser_job=self.job['id']
        payload={'action':'verify','return_to_results':True}
        with patch.object(self.manager,'_browser_rpc',return_value={'state':'awaiting_verification'}) as rpc:
            self.manager.browser_action(self.job['id'],payload)
            rpc.assert_called_once_with(self.job['id'],payload)
        self.assertEqual(self.manager._browser_job,self.job['id'])
        self.assertEqual(self.manager.store.get_job(self.job['id'])['status'],'paused')
        self.assertIn('browser_return_to_results',json.dumps(self.manager.vpn.events()))
    def test_browser_actions_require_auth_and_csrf(self):
        app=create_app(self.tmp.name,manager=self.manager,autostart=False,demo=True);client=Client(app)
        url='/api/jobs/'+self.job['id']+'/browser'
        self.assertEqual(client.request('POST',url,{'action':'frame'})[0],403)
        client.request('GET','/api/session');client.request('POST','/api/setup',{'setup_token':app.store.setup_token(),'username':'admin','password':PASSWORD})
        self.assertEqual(client.request('POST',url,{'action':'frame'},headers={'HTTP_X_CSRF_TOKEN':'bad'})[0],403)
        with patch.object(self.manager,'browser_action',return_value={'state':'ready'}):
            self.assertEqual(client.request('POST',url,{'action':'frame'})[0],200)
    def test_stop_retains_browser_transport_and_releases_reservation(self):
        self.manager._browser_job=self.job['id'];self.manager.store.update_job(self.job['id'],browser_session_enabled=True,status='cancelled')
        with patch.object(self.manager,'_browser_rpc',return_value={'running':False}):self.manager.browser_action(self.job['id'],{'action':'stop'})
        self.assertIsNone(self.manager._browser_job)
        self.assertTrue(self.manager.store.get_job(self.job['id'])['browser_session_enabled'])
    def test_restart_restores_live_reservation_and_requires_verification(self):
        self.manager.store.update_job(self.job['id'],browser_session_enabled=True)
        self.manager.shutdown()
        fresh=JobManager(self.tmp.name,autostart=False,demo=True)
        fresh.vpn.provider=FakeProvider()
        fresh.vpn.provider.get_status=lambda:{'browser':{'running':True,'job_id':self.job['id']}}
        with patch.object(fresh,'_loop'):
            fresh.start()
        try:
            self.assertEqual(fresh._browser_job,self.job['id'])
            with patch.object(fresh,'_browser_rpc',side_effect=RuntimeError('[BROWSER_SESSION] absent')):
                with self.assertRaises(RuntimeError):fresh.action(self.job['id'],{'action':'resume'})
            self.assertEqual(fresh.store.get_job(self.job['id'])['status'],'paused')
        finally:fresh.shutdown()

class BrowserWorkerTests(unittest.TestCase):
    setUp = test_worker.WorkerRecoveryTests.setUp
    tearDown = test_worker.WorkerRecoveryTests.tearDown
    run_capture = test_worker.WorkerRecoveryTests.run_capture
    checkpoint = test_worker.WorkerRecoveryTests.checkpoint
    def test_browser_rate_limit_checkpoint_prevents_early_resume(self):
        self.job.update(id='1'*32,mode='html',network_mode='manual',browser_session_enabled=True)
        self.job['settings']['demo']=False
        with patch('studio.vpn_client.rpc',return_value={'http_status':429,'retry_after':3600}) as fetch:
            code,events=self.run_capture()
        self.assertEqual(code,75);fetch.assert_called_once()
        self.assertEqual(events[-1]['input_reason'],'rate_limit')
        self.assertGreater(self.checkpoint()['state']['not_before_utc'],time.time()+3590)
        with patch('studio.vpn_client.rpc',side_effect=AssertionError('Must honor Retry-After')) as fetch:
            code,events=self.run_capture()
        self.assertEqual(code,75);fetch.assert_not_called()
    def test_browser_transport_pauses_and_resumes_checkpoint_without_http_fallback(self):
        self.job.update(id='1'*32,mode='html',network_mode='manual',browser_session_enabled=True)
        self.job['settings']['demo']=False;self.job['settings']['max_requests']=25;self.job['settings']['include_non_global']=True
        data=DemoData(self.job['query']);calls=[]
        def fetch(op,**fields):
            self.assertEqual(op,'browser_fetch');calls.append(fields['url'])
            if len(calls)==3:raise RuntimeError('[HTTP_403] [BROWSER_CHALLENGE] fixture')
            return {'html':data.fetch(fields['url'])}
        with patch('studio.vpn_client.rpc',side_effect=fetch):code,events=self.run_capture()
        self.assertEqual(code,75);saved=self.checkpoint();self.assertEqual(events[-1]['input_reason'],'browser_challenge')
        first_calls=list(calls);resumed=[]
        def resume(op,**fields):resumed.append(fields['url']);return {'html':data.fetch(fields['url'])}
        with patch('studio.vpn_client.rpc',side_effect=resume):code,events=self.run_capture()
        self.assertEqual(code,0);self.assertEqual(events[-1]['stats']['unique_ips'],292)
        self.assertFalse(set(first_calls[:2]) & set(resumed))
        self.assertGreaterEqual(self.checkpoint()['state']['requests_total'],len(first_calls))
