"""Offline Shodan failover: real worker checkpoints with simulated VPN/browser RPC."""
import asyncio
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import types
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from studio import engine
from studio.browser_broker import BrowserBroker
from studio.browser_session import Session
from studio.patchright_session import PatchrightSession
from studio.vpn_config import DEFAULT_FAILOVERS, MAX_FAILOVERS, network_error, policy
from studio.vpn_helper import Broker
from studio.worker import DemoData, StudioCrawler
import test_vpn
import test_worker


class WorkerTests(unittest.TestCase):
    setUp = test_worker.WorkerRecoveryTests.setUp
    tearDown = test_worker.WorkerRecoveryTests.tearDown
    run_capture = test_worker.WorkerRecoveryTests.run_capture
    checkpoint = test_worker.WorkerRecoveryTests.checkpoint

    def enable(self):
        self.job.update(id='f' * 32, network_mode='failover', vpn_failover_enabled=True,
                        max_failovers=20, failover_count=0)

    def test_fresh_429_requests_one_switch_and_preserves_wait_on_resume(self):
        self.enable()
        failure = engine.ShodanAPIError('[API_HTTP_429] fixture', http_status=429, retry_after=3600)
        with patch.object(DemoData, 'request', side_effect=failure) as request:
            code, events = self.run_capture()
            self.assertEqual(code, 75)
            self.assertTrue(events[-1]['vpn_failover_requested'])
            self.assertEqual(events[-1]['input_reason'], 'rate_limit')
            saved = self.checkpoint()
            self.assertTrue(saved['state']['pending_request'])
            deadline = saved['state']['not_before_utc']
            self.assertGreater(deadline, time.time() + 3590)
            self.job['failover_count'] = 1
            code, resumed = self.run_capture()
            self.assertEqual(code, 75)
            self.assertFalse(resumed[-1]['vpn_failover_requested'])
            self.assertEqual(resumed[-1]['input_reason'], 'rate_limit')
            self.assertEqual(resumed[-1]['stats']['requests_this_run'], 0)
            self.assertEqual(self.checkpoint()['state']['not_before_utc'], deadline)
            request.assert_called_once()

    def test_exhausted_switch_limit_uses_existing_rate_policy(self):
        self.enable(); self.job['failover_count'] = 20
        with patch.object(DemoData, 'request', side_effect=engine.ShodanAPIError('[API_HTTP_429] fixture', http_status=429)):
            _, events = self.run_capture()
        self.assertFalse(events[-1]['vpn_failover_requested'])
        self.assertEqual(events[-1]['input_reason'], 'rate_limit')

    def test_unbounded_wait_and_request_budget_do_not_trigger_switches(self):
        self.enable()
        with patch.object(DemoData, 'request', side_effect=engine.ShodanAPIError('[API_HTTP_429] fixture', http_status=429, retry_after=float('inf'))):
            _, events = self.run_capture()
        self.assertFalse(events[-1]['vpn_failover_requested'])
        self.assertTrue(events[-1]['stats']['wait_unbounded'])
        # A separate job exercises the request cap without a persisted wait.
        for file in self.job_dir.iterdir(): file.unlink()
        self.job['settings']['max_requests'] = 1
        with patch.object(DemoData, 'request', side_effect=engine.ShodanAPIError('[API_HTTP_429] fixture', http_status=429)):
            _, events = self.run_capture()
        self.assertFalse(events[-1]['vpn_failover_requested'])
        self.assertEqual(events[-1]['input_reason'], 'request_budget')

    def test_cancellation_at_429_boundary_wins(self):
        self.enable()
        def limited(*args):
            (self.job_dir / 'control.json').write_text('{"action":"cancel"}')
            raise engine.ShodanAPIError('[API_HTTP_429] fixture', http_status=429)
        with patch.object(DemoData, 'request', side_effect=limited):
            _, events = self.run_capture()
        self.assertEqual(events[-1]['status'], 'cancelled')
        self.assertFalse(events[-1]['vpn_failover_requested'])

    def test_browser_connection_failure_uses_network_recovery(self):
        self.enable(); self.job.update(mode='html', browser_session_enabled=True)
        self.job['settings']['demo'] = False
        with patch('studio.vpn_client.rpc', side_effect=RuntimeError('[BROWSER_NETWORK] fixture')) as fetch, \
             patch.object(StudioCrawler, 'interruptible_sleep'):
            code, events = self.run_capture()
        self.assertEqual(code, 75)
        self.assertEqual(events[-1]['input_reason'], 'network_error')
        self.assertEqual(fetch.call_count, 3)


# Each subprocess is a real worker with its normal stdin/event/checkpoint path.
# Only Shodan transport is replaced; an accidental real network call fails.
WORKER = '''
import json, sys
from pathlib import Path
from unittest.mock import patch
from studio import engine
from studio.worker import DemoData, run_worker
payload = json.load(sys.stdin)
job = payload['job']
original = DemoData.fetch
calls = 0
def fetch(self, url):
    global calls
    calls += 1
    if job['active_vpn_profile'] == '1' * 32 and calls > 8:
        raise engine.SpiderError('[HTTP_429] fixture', http_status=429, retry_after=1)
    return original(self, url)
def browser(op, **args):
    assert op == 'browser_fetch'
    try: return {'html': fetch(DemoData(job['query']), args['url'])}
    except engine.SpiderError: return {'http_status':429, 'retry_after':1}
def forbidden(*args, **kwargs): raise AssertionError('Real network forbidden')
with patch.object(DemoData, 'fetch', fetch), patch('studio.vpn_client.rpc', browser), \
     patch.object(engine, 'fetch_html', forbidden), patch.object(engine, 'fetch_html_curl', forbidden), \
     patch.object(engine.ShodanAPIClient, 'request', forbidden):
    sys.exit(run_worker(Path(sys.argv[1]), payload))
'''


class ManagerTests(unittest.TestCase):
    setUp = test_vpn.ManagerTests.setUp
    tearDown = test_vpn.ManagerTests.tearDown
    job = test_vpn.ManagerTests.job

    def test_default_and_configurable_limit_preserve_explicit_limits(self):
        self.assertEqual(policy()['max_failovers'], 20)
        self.assertEqual(DEFAULT_FAILOVERS, 20)
        self.assertEqual(MAX_FAILOVERS, 100)
        for value in (0, 5, 20, 100): self.assertEqual(policy({'max_failovers': value})['max_failovers'], value)
        for value in (-1, 101, True, 20.5):
            with self.assertRaises(ValueError): policy({'max_failovers': value})

    def test_destination_failure_during_connect_tries_next_profile(self):
        job = self.job()
        original = self.provider.switch_profile
        def connect(ident):
            if ident in (test_vpn.P1, test_vpn.P2):
                self.provider.calls.append(ident)
                raise RuntimeError('[VPN_DESTINATION] Shodan TLS failed')
            return original(ident)
        self.provider.switch_profile = connect
        with patch.object(self.manager, '_execute_worker') as worker:
            self.manager._execute(job)
        self.assertEqual(self.provider.calls, [test_vpn.P1, test_vpn.P2, test_vpn.P3])
        worker.assert_called_once()
        self.assertEqual(self.store.get_job(job['id'])['failover_count'], 2)

    def test_healthy_tunnel_cycles_allowlist_instead_of_repeating_first_pair(self):
        job = self.job(max_failovers=100)
        self.vpn.prepare(job)
        first = self.vpn.recover(job)
        self.store.update_job(job['id'], **first)
        self.vpn.clock = lambda: 1100
        second = self.vpn.recover(self.store.get_job(job['id']))
        self.assertEqual(second['active_vpn_profile'], test_vpn.P3)
        self.assertEqual(self.provider.calls, [test_vpn.P1, test_vpn.P2, test_vpn.P3])

    def test_more_than_five_switches_remain_bounded(self):
        job = self.job(max_failovers=7)
        self.vpn.prepare(job)
        for count in range(1, 8):
            self.vpn.clock = lambda count=count: 1000 + count * 100
            result = self.vpn.recover(self.store.get_job(job['id']))
            self.assertEqual(result['failover_count'], count)
            self.store.update_job(job['id'], **result)
        self.assertIsNone(self.vpn.recover(self.store.get_job(job['id'])))
        self.assertEqual(len(self.provider.calls), 8)

    def test_saved_rate_wait_without_fresh_response_never_switches(self):
        job = self.job()
        def worker(job):
            self.store.update_job(job['id'], status='waiting_input', input_reason='rate_limit', vpn_failover_requested=False)
        with patch.object(self.manager, '_execute_worker', side_effect=worker): self.manager._execute(job)
        self.assertEqual(self.provider.calls, [test_vpn.P1])

    def test_real_worker_switches_and_resumes_cached_pages_with_and_without_browser(self):
        original_popen = subprocess.Popen
        for browser in (False, True):
            with self.subTest(browser=browser):
                job = self.job()
                cfg = {**job['settings'], 'strategy': 'priority', 'demo': not browser,
                       'split_facets': ['asn', 'port', 'org'], 'include_non_global': True,
                       'max_requests': 100, 'retry_base_delay': 1, 'max_retry_wait': 10}
                self.store.update_job(job['id'], settings=cfg, browser_session_enabled=browser)
                account_scope = None
                if browser:
                    account = self.manager.shodan_account_save({'username':'failover-fixture','password':'fixture-account-secret'})
                    self.store.update_job(job['id'], shodan_account_id=account['id'])
                    account_scope = self.manager.shodan_accounts.secret(account['id'])['scope']
                self.provider.calls.clear()
                # Each independent job starts with fresh candidate cooldowns.
                self.vpn.clock = lambda: time.time()
                with self.store.connection() as con: con.execute('DELETE FROM vpn_profiles')
                starts = []; budgets = []
                def popen(command, **kwargs):
                    self.assertEqual(command[1:3], ['-m', 'studio.vpn_client'])
                    return original_popen([sys.executable, '-c', WORKER, str(self.manager._path(job['id']))], **kwargs)
                def rpc(ident, payload):
                    self.assertIsNone(self.manager._process)
                    starts.append(payload['action'])
                    if payload['action'] == 'start':
                        self.assertEqual(payload.get('account_scope'),account_scope)
                        self.assertTrue(payload['defer_navigation'])
                        self.assertEqual(self.provider.active, test_vpn.P2)
                        self.assertTrue((self.manager._path(ident) / 'checkpoint.json').exists())
                    return {'state': 'awaiting_verification', 'backend': 'patchright'}
                execute = self.manager._execute_worker
                def worker(value):
                    budgets.append(value['settings']['max_requests'])
                    return execute(value)
                with patch('studio.jobs.subprocess.Popen', side_effect=popen), \
                     patch.object(self.manager, '_browser_rpc', side_effect=rpc), \
                     patch.object(self.manager, '_execute_worker', side_effect=worker):
                    self.manager._execute(self.store.get_job(job['id']))
                saved = self.store.get_job(job['id'])
                self.assertIn(saved['status'], ('completed', 'completed_warnings'))
                self.assertEqual(saved['stats']['unique_ips'], 292)
                self.assertEqual(saved['failover_count'], 1)
                self.assertEqual(budgets, [100, 91])
                self.assertEqual(self.provider.calls, [test_vpn.P1, test_vpn.P2])
                self.assertEqual(starts, ['stop', 'start'] if browser else [])
                report = json.loads((self.manager._path(job['id']) / 'result.txt.report.json').read_text())
                self.assertGreaterEqual(report['resume']['cached_pages'], 8)
                self.assertNotIn('fixture-account-secret',json.dumps(report))
                self.assertNotIn('fixture-account-secret',(self.manager._path(job['id'])/'checkpoint.json').read_text())
                self.assertEqual(saved['settings']['max_requests'], 100)
                self.manager._browser_job = None

    def test_cancel_during_switch_prevents_browser_reopening_and_worker_resume(self):
        job = self.job(); self.store.update_job(job['id'], status='waiting_input', browser_session_enabled=True)
        def recover(*args, **kwargs):
            self.store.update_job(job['id'], status='cancelled')
            return {'active_vpn_profile': test_vpn.P2}
        with patch.object(self.vpn, 'recover', side_effect=recover), patch.object(self.manager, '_browser_rpc') as rpc:
            self.assertIsNone(self.manager._recover_vpn(self.store.get_job(job['id'])))
        rpc.assert_called_once_with(job['id'], {'action': 'stop'})
        self.assertEqual(self.store.get_job(job['id'])['status'], 'cancelled')

    def test_browser_close_failure_prevents_switch(self):
        job = self.job(); self.store.update_job(job['id'], status='waiting_input', browser_session_enabled=True)
        with patch.object(self.manager, '_browser_rpc', side_effect=RuntimeError('worker still owns lease')), patch.object(self.vpn, 'recover') as recover:
            self.assertIsNone(self.manager._recover_vpn(self.store.get_job(job['id'])))
        recover.assert_not_called()

    def test_browser_recovers_when_initial_tunnel_preparation_fails(self):
        job = self.job(); self.store.update_job(job['id'], browser_session_enabled=True)
        self.provider.broken.add(test_vpn.P1)
        with patch.object(self.manager, '_browser_rpc', return_value={'state': 'awaiting_verification'}) as rpc, \
             patch.object(self.manager, '_execute_worker') as worker:
            self.manager._execute(self.store.get_job(job['id']))
        self.assertEqual(self.provider.calls, [test_vpn.P1, test_vpn.P2])
        self.assertEqual([c.args[1]['action'] for c in rpc.call_args_list], ['stop', 'start'])
        self.assertTrue(rpc.call_args_list[1].args[1]['defer_navigation'])
        worker.assert_called_once()

    def test_final_429_cannot_override_pause_requested(self):
        job = self.job(); self.store.update_job(job['id'], status='pause_requested')
        process = MagicMock(stdin=io.StringIO(), stdout=io.StringIO(json.dumps({
            'kind': 'final', 'status': 'waiting_input', 'input_reason': 'rate_limit',
            'vpn_failover_requested': True}) + '\n'))
        process.poll.return_value = 0
        with patch('studio.jobs.subprocess.Popen', return_value=process):
            self.manager._execute_worker(self.store.get_job(job['id']))
        self.assertEqual(self.store.get_job(job['id'])['status'], 'paused')

    def test_pause_during_switch_prevents_browser_restart(self):
        job = self.job(); self.manager._active_id = job['id']
        self.store.update_job(job['id'], status='waiting_input', browser_session_enabled=True)
        def recover(*args, **kwargs):
            self.manager.action(job['id'], {'action': 'pause'})
            return {'active_vpn_profile': test_vpn.P2}
        with patch.object(self.vpn, 'recover', side_effect=recover), patch.object(self.manager, '_browser_rpc') as rpc:
            self.assertIsNone(self.manager._recover_vpn(self.store.get_job(job['id'])))
        rpc.assert_called_once_with(job['id'], {'action': 'stop'})
        self.assertEqual(self.store.get_job(job['id'])['status'], 'paused')
        self.manager._active_id = None

    def test_certificate_and_premium_errors_never_close_browser_or_switch(self):
        job = self.job()
        for error in ('[TLS_CERTIFICATE] fixture', '[PREMIUM_RATE_LIMIT] fixture'):
            self.store.update_job(job['id'], status='waiting_input', browser_session_enabled=True, last_network_error=error)
            with patch.object(self.manager, '_browser_rpc') as rpc:
                self.assertIsNone(self.manager._recover_vpn(self.store.get_job(job['id'])))
                rpc.assert_not_called()
        self.assertEqual(self.provider.calls, [])


class BrowserTests(unittest.TestCase):
    def test_native_navigation_errors_are_typed_without_disclosing_url(self):
        for error, kind in [('net::ERR_CONNECTION_RESET', 'BROWSER_NETWORK'), ('net::ERR_CERT_AUTHORITY_INVALID', 'TLS_CERTIFICATE')]:
            session = object.__new__(Session)
            session.call = MagicMock(return_value={'errorText': error + ' secret'})
            with self.assertRaisesRegex(RuntimeError, '^\\[' + kind + '\\]') as caught:
                session.navigate(engine.build_url('fixture', 'ip'))
            self.assertNotIn('secret', str(caught.exception))
            self.assertEqual(bool(network_error(caught.exception)), kind == 'BROWSER_NETWORK')

    def test_patchright_navigation_errors_are_typed(self):
        api = types.ModuleType('patchright.async_api'); api.Error = type('Error', (Exception,), {})
        for error, kind in [('net::ERR_TIMED_OUT', 'BROWSER_NETWORK'), ('net::ERR_CERT_DATE_INVALID', 'TLS_CERTIFICATE')]:
            session = PatchrightSession('/unused')
            session.page = MagicMock(goto=AsyncMock(side_effect=api.Error(error + ' secret')))
            with patch.dict(sys.modules, {'patchright.async_api': api}):
                with self.assertRaisesRegex(RuntimeError, '^\\[' + kind + '\\]') as caught:
                    asyncio.run(session.navigate(engine.build_url('fixture', 'ip')))
            self.assertNotIn('secret', str(caught.exception))

    def test_deferred_browser_start_retains_worker_lease_guard(self):
        broker = MagicMock(running_job=None)
        browser = BrowserBroker(broker); browser.start = MagicMock()
        payload = {'job_id': 'f' * 32, 'input': {'action': 'start', 'url': engine.build_url('fixture', 'ip'), 'defer_navigation': True}}
        browser.action(payload)
        browser.start.assert_called_once_with('f' * 32, payload['input']['url'], defer_navigation=True)
        browser.start.reset_mock(); broker.running_job = 'f' * 32
        with self.assertRaises(RuntimeError): browser.action(payload)
        browser.start.assert_not_called()

    def test_deferred_start_uses_new_profile_without_sending_navigation(self):
        broker = MagicMock(uid=995, active=test_vpn.P2, code='/unused')
        broker.launch_check.return_value = {'healthy': True}
        browser = BrowserBroker(broker); browser.backend = 'chromium'
        with tempfile.TemporaryDirectory() as folder, \
             patch('studio.browser_broker.ROOT', Path(folder)), \
             patch('studio.browser_broker.pwd.getpwnam', return_value=types.SimpleNamespace(pw_uid=996, pw_gid=996)), \
             patch('studio.browser_broker.os.chown'), patch('studio.browser_broker.Path.is_file', return_value=True), \
             patch('studio.browser_broker.shutil.disk_usage', return_value=types.SimpleNamespace(free=1024**3)), \
             patch('studio.vpn_helper.command'), patch('studio.browser_broker.subprocess.Popen') as launch, \
             patch.object(browser, 'reply', return_value={'state': 'awaiting_verification'}), \
             patch.object(browser, 'request') as request:
            result = browser.start('f' * 32, engine.build_url('fixture', 'ip'), defer_navigation=True)
            self.assertEqual(result['state'], 'awaiting_verification')
            self.assertEqual(launch.call_args.args[0][-1], str(Path(folder) / test_vpn.P2))
            request.assert_not_called()

    def test_certificate_failure_at_tunnel_verification_is_not_destination_failover(self):
        broker = object.__new__(Broker)
        broker.health_check = MagicMock(return_value={'healthy': False, 'tunnel_healthy': True,
                                                      'error': 'SSLCertVerificationError'})
        with patch('studio.vpn_helper.time.sleep'):
            with self.assertRaisesRegex(RuntimeError, '^\\[TLS_CERTIFICATE\\]'):
                broker._verify_connection()
