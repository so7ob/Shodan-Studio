"""Offline policy, persistence and checkpoint-to-browser handoff regressions."""
import json
from email.message import Message
import tempfile
import time
import unittest
from unittest.mock import MagicMock, patch

from studio import engine
from studio.browser_recovery import MIGRATION, migrate, pending_url, reserve
from studio.config import validate_job, JobValidationError
from studio.jobs import JobManager
from studio.patchright_session import PatchrightSession
from studio.server import create_app
from test_server import Client, PASSWORD
from test_vpn import FakeProvider, P1


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.manager = JobManager(self.tmp.name, autostart=False)
        self.manager.vpn.provider = FakeProvider()
        self.job = self.manager.create_job({'query': 'fixture country:DE', 'mode': 'html',
            'settings': {'delay': 0}, 'network': {'network_mode': 'preferred', 'preferred_vpn_profile': P1}})
        self.path = self.manager._path(self.job['id'])
        from studio.worker import build_args
        crawler = engine.Crawler(build_args(self.path, self.job, None))
        crawler.pending_request = {'query': self.job['query'] + ' port:443', 'facet': 'org', 'url': 'file:///ignored'}
        crawler.report['requests_attempted'] = 1
        crawler.checkpoint('paused')
        self.manager.store.update_job(self.job['id'], status='waiting_input', input_reason='browser_challenge',
            browser_challenge_id='first', stats={**self.job['stats'], 'requests': 1, 'requests_this_run': 1})

    def tearDown(self):
        self.manager.shutdown(); self.tmp.cleanup()

    def job_now(self): return self.manager._get(self.job['id'])

    def test_exact_pending_request_ignores_saved_url(self):
        self.assertEqual(pending_url(self.job_now(), self.path), engine.build_url(self.job['query'] + ' port:443', 'org'))

    def test_launch_once_after_worker_exit_charges_navigation_and_never_resumes(self):
        def start(ident, payload):
            self.assertIsNone(self.manager._active_id)
            self.assertEqual(self.job_now()['status'], 'waiting_input')
            self.assertEqual(payload['url'], pending_url(self.job_now(), self.path))
            return {'state': 'awaiting_verification', 'backend': 'patchright', 'running': True}
        with patch.object(self.manager, '_browser_rpc', side_effect=start) as rpc:
            self.manager._auto_browser_recovery(self.job['id'])
            self.manager._auto_browser_recovery(self.job['id'])
            rpc.assert_called_once()
        saved = engine.load_checkpoint(self.path / 'checkpoint.json')
        self.assertEqual(saved['state']['requests_total'], 2)
        self.assertEqual(self.job_now()['stats']['requests_this_run'], 2)
        self.assertEqual(self.job_now()['status'], 'waiting_input')
        self.assertEqual(self.job_now()['browser_backend'], 'patchright')

    def test_failed_or_crashed_attempt_is_not_replayed_after_restart(self):
        with patch.object(self.manager, '_browser_rpc', side_effect=RuntimeError('[BROWSER_DEPENDENCY] missing')) as rpc:
            self.manager._auto_browser_recovery(self.job['id'])
            self.manager._auto_browser_recovery(self.job['id'])
            rpc.assert_called_once()
        self.assertEqual(self.job_now()['browser_recovery_attempt']['state'], 'failed')
        self.assertEqual(self.job_now()['status'], 'waiting_input')
        self.manager.shutdown()
        fresh = JobManager(self.tmp.name, autostart=False)
        try:
            fresh.vpn.provider = FakeProvider()
            with patch.object(fresh, '_browser_rpc') as rpc:
                fresh._auto_browser_recovery(self.job['id']); rpc.assert_not_called()
        finally: fresh.shutdown()

    def test_scheduler_handoff_occurs_after_active_worker_is_released(self):
        ident = self.job['id']
        self.manager.store.update_job(ident, status='queued')
        def execute(job):
            self.assertEqual(self.manager._active_id, ident)
            self.manager.store.update_job(ident, status='waiting_input')
        def start(*args):
            self.assertIsNone(self.manager._active_id)
            self.manager._stop.set()
            return {'state': 'awaiting_verification', 'backend': 'patchright'}
        with patch.object(self.manager, '_execute', side_effect=execute), patch.object(self.manager, '_browser_rpc', side_effect=start) as rpc:
            self.manager._loop()
            rpc.assert_called_once()

    def test_cancellation_during_preparation_prevents_browser_navigation(self):
        def prepare(job):
            self.manager.store.update_job(job['id'], status='cancelled')
            return {}
        with patch.object(self.manager.vpn, 'prepare', side_effect=prepare), patch.object(self.manager, '_browser_rpc') as rpc:
            self.manager._auto_browser_recovery(self.job['id'])
            rpc.assert_not_called()
        self.assertEqual(self.job_now()['status'], 'cancelled')

    def test_budget_wait_manual_cancel_and_active_worker_prevent_launch(self):
        for change in [dict(settings={**self.job['settings'], 'max_requests': 1}),
                       dict(settings={**self.job['settings'], 'browser_recovery': 'manual'}),
                       dict(status='cancelled')]:
            self.manager.store.update_job(self.job['id'], **change)
            with patch.object(self.manager, '_browser_rpc') as rpc:
                self.manager._auto_browser_recovery(self.job['id']); rpc.assert_not_called()
            self.manager.store.update_job(self.job['id'], status='waiting_input', settings=self.job['settings'], browser_recovery_attempt={})
        checkpoint = engine.load_checkpoint(self.path / 'checkpoint.json')
        checkpoint['state']['not_before_utc'] = time.time() + 3600
        engine.save_checkpoint(self.path / 'checkpoint.json', checkpoint, allow_replace=True)
        with patch.object(self.manager, '_browser_rpc') as rpc:
            self.manager._auto_browser_recovery(self.job['id']); rpc.assert_not_called()
        self.manager._active_id = self.job['id']
        with patch.object(self.manager, '_browser_rpc') as rpc:
            self.manager._auto_browser_recovery(self.job['id']); rpc.assert_not_called()
        self.manager._active_id = None

    def test_migration_idempotent_preserves_history_and_explicit_opt_out(self):
        with self.manager.store.connection() as con:
            con.execute('DELETE FROM settings WHERE name=?', (MIGRATION,))
        job = self.job_now(); job['settings'].pop('browser_recovery')
        self.manager.store.update_job(job['id'], settings=job['settings'])
        before = (self.path / 'checkpoint.json').read_bytes()
        migrate(self.manager.store)
        self.assertEqual(self.job_now()['settings']['browser_recovery'], 'on_challenge')
        self.manager.browser_policy(job['id'], {'browser_recovery': 'manual'})
        migrate(self.manager.store)
        self.assertEqual(self.job_now()['settings']['browser_recovery'], 'manual')
        self.assertEqual(before, (self.path / 'checkpoint.json').read_bytes())
        self.assertEqual(self.job_now()['status'], 'waiting_input')

    def test_policy_endpoint_requires_auth_csrf_and_stopped_session(self):
        app = create_app(self.tmp.name, manager=self.manager, autostart=False)
        client = Client(app); url = '/api/jobs/' + self.job['id'] + '/browser-policy'
        payload = {'browser_recovery': 'manual'}
        self.assertEqual(client.request('POST', url, payload)[0], 403)
        client.request('GET', '/api/session')
        client.request('POST', '/api/setup', {'setup_token': app.store.setup_token(), 'username': 'admin', 'password': PASSWORD})
        self.assertEqual(client.request('POST', url, payload, headers={'HTTP_X_CSRF_TOKEN': 'bad'})[0], 403)
        self.assertEqual(client.request('POST', url, payload)[0], 200)
        self.manager._browser_job = self.job['id']
        with self.assertRaises(JobValidationError): self.manager.browser_policy(self.job['id'], payload)

    def test_migration_excludes_completed_jobs_and_rolls_back_partial_failure(self):
        other = self.manager.create_job({'query': 'history', 'mode': 'html',
            'network': {'network_mode': 'preferred', 'preferred_vpn_profile': P1}})
        for ident, status in [(self.job['id'], 'waiting_input'), (other['id'], 'completed')]:
            job = self.manager._get(ident); cfg = dict(job['settings']); cfg.pop('browser_recovery')
            self.manager.store.update_job(ident, status=status, settings=cfg)
        with self.manager.store.connection() as con:
            con.execute('DELETE FROM settings WHERE name=?', (MIGRATION,))
        with patch('studio.browser_recovery._json', side_effect=ValueError('fixture write failure')):
            with self.assertRaises(ValueError): migrate(self.manager.store)
        self.assertNotIn('browser_recovery', self.job_now()['settings'])
        migrate(self.manager.store)
        self.assertEqual(self.job_now()['settings']['browser_recovery'], 'on_challenge')
        self.assertNotIn('browser_recovery', self.manager._get(other['id'])['settings'])


class ChallengeTests(unittest.TestCase):
    def test_header_is_typed_for_any_status_except_rate_limit(self):
        headers = Message(); headers['Cf-Mitigated'] = 'challenge'
        for code in (200, 302, 401, 403, 503):
            self.assertEqual(engine.http_failure(code, headers).failure_kind, 'browser_challenge')
        self.assertIsNone(engine.http_failure(429, headers).failure_kind)
        self.assertIsNone(engine.http_failure(403).failure_kind)

    def test_new_task_defaults_and_invalid_policy(self):
        for network, expected in [({}, 'manual'), ({'network_mode': 'preferred', 'preferred_vpn_profile': P1}, 'on_challenge')]:
            job, _ = validate_job({'query': 'fixture', 'mode': 'html', 'network': network})
            self.assertEqual(job['settings']['browser_recovery'], expected)
        with self.assertRaises(JobValidationError): validate_job({'query': 'fixture', 'settings': {'browser_recovery': 'always'}})

    def test_patchright_denial_never_navigates_and_status_matches_legacy(self):
        session = PatchrightSession('/unused')
        session.expected = engine.build_url('fixture', 'ip')
        session.document = {'url': session.expected, 'status': 403, 'challenge': True}
        self.assertEqual(session.status()['state'], 'browser_challenge')
        for _ in range(3):
            with self.assertRaisesRegex(RuntimeError, 'BROWSER_CHALLENGE'): session.source_failure()
        session.document['status'] = 429
        self.assertEqual(session.status()['state'], 'rate_limited')
        self.assertEqual(session.source_failure(), {'http_status': 429, 'retry_after': None})
