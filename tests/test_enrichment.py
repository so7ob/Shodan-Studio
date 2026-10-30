"""Enrichment uses real queue/lifecycle code with offline host fixtures."""
import json
import contextlib
import io
import tempfile
import unittest
from unittest.mock import patch, MagicMock

from studio.enrichment import host_page_url, parse_host_html
from studio.jobs import JobManager
from studio import engine
from studio.worker import run_worker


HOST_HTML = '''<html><title>8.8.8.8</title><h2>8.8.8.8</h2><table>
<tr><th>Country</th><td><a href='/search?query=country:US'>United States</a></td></tr>
<tr><th>City</th><td>Mountain View</td></tr><tr><th>ASN</th><td>AS15169</td></tr>
</table><section><h3>53 / udp</h3><time datetime='2026-10-29T12:00:00Z'></time></section></html>'''


class EnrichmentTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.m = JobManager(self.tmp.name, autostart=False, demo=True)
        self.source = self.m.create_job({'query': 'fixture', 'settings': {'demo': True, 'delay': 0, 'transport': 'python'}})
        self.m.store.update_job(self.source['id'], status='paused')
        self.m.store.record_ip_progress(self.source['id'], ['8.8.8.8', '1.1.1.1'])
        self.ids = self.m.store.targets.select_ids({'demo': '1'})
    def tearDown(self): self.m.shutdown(); self.tmp.cleanup()
    def create(self): return self.m.create_job({'kind': 'enrichment', 'target_ids': self.ids, 'mode': 'html', 'settings': {'demo': True, 'delay': 0}})
    def test_host_html_and_url_identity(self):
        data = parse_host_html(HOST_HTML, '8.8.8.8')
        self.assertEqual((data['country_code'], data['city'], data['services'][0]['transport']), ('US', 'Mountain View', 'udp'))
        for url in ('http://www.shodan.io/host/8.8.8.8', 'https://www.shodan.io/host/8.8.8.8?x=1', 'https://example.com/host/8.8.8.8'):
            with self.assertRaises(ValueError): host_page_url(url)
        for html in ('<title>Just a moment</title>', '<title>Log in</title>', HOST_HTML.replace('<h2>8.8.8.8</h2>', '<h2>1.1.1.1</h2>')):
            with self.assertRaises(ValueError): parse_host_html(html, '8.8.8.8')
    def test_queue_worker_results_duplicate_and_checkpoint_import(self):
        job = self.create(); claimed = self.m.store.claim_next(job['id'])
        self.m._execute_worker(claimed)
        result = self.m.get_job(job['id'])
        self.assertEqual(result['status'], 'completed')
        self.assertEqual(result['enrichment_progress']['success'], 2)
        self.assertEqual(len(self.m.results(job['id'])['items']), 2)
        data, _, _ = self.m.download(job['id'], 'checkpoint'); checkpoint = json.loads(data)
        self.assertEqual(checkpoint['kind'], 'enrichment')
        imported = self.m.import_checkpoint({'checkpoint': checkpoint})
        self.assertEqual(imported['status'], 'paused'); self.assertEqual(imported['enrichment_progress']['processed'], 2)
        duplicate = self.m.action(job['id'], {'action': 'duplicate'})
        self.assertEqual(duplicate['kind'], 'enrichment'); self.assertEqual(duplicate['enrichment_progress']['processed'], 0)
    def test_pause_cancel_and_demo_never_use_network(self):
        job = self.create(); self.m.action(job['id'], {'action': 'pause'})
        self.assertEqual(self.m.get_job(job['id'])['status'], 'paused')
        self.m.action(job['id'], {'action': 'resume'}); self.m.action(job['id'], {'action': 'cancel'})
        self.assertEqual(self.m.get_job(job['id'])['status'], 'cancelled')
        self.assertEqual(self.m.store.targets.progress(job['id'])['pending'], 2)
    def test_encrypted_optional_key_is_not_public(self):
        key = 'ENRICHMENT_FIXTURE_KEY_ONLY'
        public = self.m.enrichment_settings.save({'api_key': key})
        self.assertTrue(public['has_key']); self.assertNotIn(key, json.dumps(public))
        self.assertEqual(self.m.enrichment_settings.key(), key)
        self.assertNotIn(key.encode(), self.m.store.path.read_bytes())
        self.m.enrichment_settings.save({'clear_key': True}); self.assertIsNone(self.m.enrichment_settings.key())

    def test_priority_schedule_and_runtime_configuration(self):
        job = self.create()
        updated = self.m.action(job['id'], {'action': 'configure', 'priority': 9, 'scheduled_at': '2099-01-01T00:00:00Z',
                                          'settings': {'max_requests': 10, 'delay': 4}})
        self.assertEqual(updated['priority'], 9); self.assertEqual(updated['settings']['delay'], 4)
        self.assertIsNone(self.m.store.claim_next(job['id']))
        self.m.action(job['id'], {'action': 'configure', 'scheduled_at': None})
        self.assertIsNotNone(self.m.store.claim_next(job['id']))

    def test_extraction_metadata_sidecar_redacts_a_key_echoed_by_source(self):
        from studio.worker import StudioCrawler, build_args
        key = 'SIDECAR_FIXTURE_SECRET_ONLY'
        job = self.m.create_job({'query': 'fixture', 'mode': 'api', 'api_key': key, 'settings': {'demo': True, 'delay': 0}})
        path = self.m._path(job['id']); crawler = StudioCrawler(build_args(path, job, key), path, demo=True)
        crawler.accept_ip(engine.parse_ip('8.8.8.8')); output = io.StringIO()
        with contextlib.redirect_stdout(output):
            crawler.on_host_records({'request_id': 'a'*32, 'finished_at': '2026-10-30T00:00:00Z'},
                                    [{'ip_str': '8.8.8.8', 'org': key, 'port': 443, 'transport': 'tcp'}])
        self.assertNotIn(key, output.getvalue())
        self.assertNotIn(key, (path / 'target-observations.jsonl').read_text())


class SourceRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.m = JobManager(self.tmp.name, autostart=False)
        source = self.m.create_job({'query': 'fixture'}); self.m.store.record_ip_progress(source['id'], ['8.8.8.8'])
        self.ident = self.m.store.targets.select_ids()[0]
        self.job = self.m.create_job({'kind': 'enrichment', 'target_ids': [self.ident], 'mode': 'api',
            'api_key': 'FIXTURE_ENRICHMENT_ONLY', 'settings': {'transport': 'python', 'delay': 0, 'max_retry_wait': 0, 'rate_limit_retries': 0}})
        self.job['source_mode'] = 'auto'
    def tearDown(self): self.m.shutdown(); self.tmp.cleanup()
    def run_fixture(self, api=None, html=HOST_HTML, mode=None):
        job = {**self.job, **({'mode': mode} if mode else {})}
        body = {'job': job, 'api_key': 'FIXTURE_ENRICHMENT_ONLY', 'targets': self.m.store.targets.items(job['id'])}
        stream = io.StringIO()
        with patch('studio.engine.ShodanAPIClient.host', side_effect=api) as host, patch('studio.engine.fetch_html', return_value=html) as fetch, patch('signal.signal'), contextlib.redirect_stdout(stream):
            run_worker(self.m._path(job['id']), body)
        events = [json.loads(line) for line in stream.getvalue().splitlines()]
        for event in events:
            if event.get('kind') in ('target_snapshot', 'enrichment_item'): self.m._target_event(job, event)
        return events, host, fetch
    def test_auto_api_permission_falls_back_to_html_and_saves_source(self):
        events, api, html = self.run_fixture(api=engine.ShodanAPIError('fixture auth', http_status=401))
        self.assertEqual(events[-1]['status'], 'completed'); self.assertEqual((api.call_count, html.call_count), (1, 1))
        target = self.m.store.targets.detail(self.ident)
        self.assertEqual(target['provenance']['city']['source'], 'html')
        self.assertEqual(len(target['discoveries']), 1)
    def test_partial_api_and_html_preserve_both_service_snapshots(self):
        events, api, html = self.run_fixture(api=lambda *_: {'ip_str': '8.8.8.8', 'country_code': 'US', 'data': [{'port': 443, 'transport': 'tcp'}]})
        self.assertEqual(events[-1]['status'], 'completed')
        target = self.m.store.targets.detail(self.ident)
        self.assertEqual({s['port'] for s in target['services']}, {443, 53})
        self.assertEqual({s['source'] for s in target['snapshots']}, {'api', 'html'})
    def test_html_challenge_checkpoints_exact_host_for_interactive_browser(self):
        events, _, _ = self.run_fixture(api=engine.ShodanAPIError('fixture auth', http_status=401), html='<title>Just a moment</title>')
        self.assertEqual((events[-1]['status'], events[-1]['input_reason']), ('waiting_input', 'browser_challenge'))
        from studio.enrichment import pending_url
        self.assertEqual(pending_url(self.job, self.m._path(self.job['id'])), 'https://www.shodan.io/host/8.8.8.8')
    def test_retry_after_survives_restart_and_source_switch_without_early_request(self):
        events, api, html = self.run_fixture(api=engine.ShodanAPIError('fixture limited', http_status=429, retry_after=3600))
        self.assertEqual(events[-1]['input_reason'], 'rate_limit'); html.assert_not_called()
        checkpoint = engine.load_checkpoint(self.m._path(self.job['id']) / 'checkpoint.json')
        deadline = checkpoint['state']['not_before_utc']; self.assertIsNotNone(deadline)
        self.job['source_mode'] = 'html'
        events, api, html = self.run_fixture(mode='html')
        api.assert_not_called(); html.assert_not_called()
        self.assertEqual(engine.load_checkpoint(self.m._path(self.job['id']) / 'checkpoint.json')['state']['not_before_utc'], deadline)
    def test_host_browser_verification_checks_exact_ip_and_login_state(self):
        from studio.browser_session import Session
        s = object.__new__(Session); s.expected = 'https://www.shodan.io/host/8.8.8.8'; s.ready = False
        s.document = {'url': s.expected, 'status': 200}; s.page_url = s.expected
        self.assertEqual(s.inspect_page({'url': s.expected, 'html': HOST_HTML})['state'], 'ready')
        self.assertEqual(s.inspect_page({'url': s.expected, 'html': '<title>Log in</title>'})['state'], 'login_required')
        self.assertNotEqual(s.inspect_page({'url': s.expected, 'html': HOST_HTML.replace('<h2>8.8.8.8</h2>', '<h2>1.1.1.1</h2>')})['state'], 'ready')

    def test_not_found_is_terminal_but_not_fabricated_success(self):
        self.job['source_mode'] = 'api'; self.job['settings']['api_fallback'] = 'stop'
        events, api, html = self.run_fixture(api=engine.ShodanAPIError('not found', http_status=404))
        self.assertEqual(events[-1]['status'], 'completed_warnings')
        self.assertEqual(self.m.store.targets.progress(self.job['id'])['not_found'], 1)
        self.assertIsNone(self.m.store.targets.detail(self.ident)['enriched_at']); html.assert_not_called()

    def test_malformed_api_address_is_rejected_without_corrupting_inventory(self):
        self.job['source_mode'] = 'api'; self.job['settings']['api_fallback'] = 'stop'
        events, _, html = self.run_fixture(api=lambda *_: {'ip_str': '1.1.1.1', 'country_code': 'US'})
        self.assertEqual(events[-1]['status'], 'waiting_input'); html.assert_not_called()
        self.assertEqual(self.m.store.targets.detail(self.ident)['snapshots'], [])

    def test_checkpoint_replays_results_lost_between_worker_and_manager_once(self):
        self.job['source_mode'] = 'api'
        events, _, _ = self.run_fixture(api=lambda *_: {'ip_str': '8.8.8.8', 'country_code': 'US', 'city': 'Mountain View', 'ports': [53]})
        with self.m.store.connection() as c:
            c.execute('DELETE FROM target_snapshots'); c.execute('DELETE FROM target_services')
            c.execute("UPDATE targets SET document='{}',enriched_at=NULL,status='pending'")
            c.execute("UPDATE enrichment_items SET status='pending',document='{}'")
        self.m._replay_target_events(self.job); self.m._replay_target_events(self.job)
        self.assertEqual(len(self.m.store.targets.detail(self.ident)['snapshots']), 1)
        self.assertEqual(self.m.store.targets.progress(self.job['id'])['success'], 1)

    def test_html_enrichment_uses_existing_interactive_browser_rpc(self):
        self.job.update(mode='html', source_mode='html', network_mode='preferred', browser_session_enabled=True)
        with patch('studio.vpn_client.rpc', return_value={'html': HOST_HTML, 'http_status': 200, 'backend': 'patchright', 'user_agent': 'Fixture browser'}) as rpc:
            events, api, http = self.run_fixture(mode='html')
        self.assertEqual(events[-1]['status'], 'completed')
        rpc.assert_called_once_with('browser_fetch', socket_path='/run/shodan-studio-enrichment-vpn/control.sock',
                                  job_id=self.job['id'], url='https://www.shodan.io/host/8.8.8.8')
        api.assert_not_called(); http.assert_not_called()

    def test_import_normalizes_equivalent_ipv6_checkpoint_addresses(self):
        from studio.enrichment import validate_checkpoint
        checkpoint = {'app': 'ShodanSpider', 'schema_version': 1, 'kind': 'enrichment',
            'config': {'settings': self.job['settings'], 'source_mode': 'html'},
            'state': {'items': [{'ip': '2001:0db8:0000:0000:0000:0000:0000:0001', 'status': 'pending'}],
                      'pending_request': {'query': '2001:0db8::1'}}}
        self.assertEqual(validate_checkpoint(checkpoint)['state']['items'][0]['ip'], '2001:db8::1')
