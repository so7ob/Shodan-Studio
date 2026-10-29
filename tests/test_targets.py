"""Repository evidence, filtering, migration and deletion contracts."""
import json
import tempfile
import unittest

from studio.store import Store


class TargetTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.store = Store(self.tmp.name); self.repo = self.store.targets
    def tearDown(self): self.tmp.cleanup()
    def job(self, query='port:443'):
        return self.store.create_job({'title': 'Target fixture', 'query': query, 'settings': {}, 'status': 'paused'})
    def discovery(self, job, ip, number, at='2026-10-30T10:00:00+00:00', query=None):
        self.store.record_ip_progress(job['id'], [ip])
        e = {'request_id': f'{number:032x}', 'origin': 'live', 'status': 'success', 'facet': 'ip',
             'source': 'html', 'finished_at': at, 'query': query or job['query']}
        self.repo.observe_request(job, e, [{'value': ip}]); return e
    def test_deduplicated_ip_preserves_each_discovery_and_survives_job_deletion(self):
        a, b = self.job(), self.job('port:80')
        e = self.discovery(a, '8.8.8.8', 1); self.repo.observe_request(a, e, [{'value': '8.8.8.8'}])
        self.discovery(b, '8.8.8.8', 2, '2026-10-30T12:00:00Z')
        item = self.repo.list()['items'][0]
        self.assertEqual((self.repo.list()['total'], item['job_count'], item['discovery_count']), (1, 2, 2))
        self.assertEqual(item['first_found_at'], '2026-10-30T10:00:00+00:00')
        self.store.delete_job(a['id'])
        d = self.repo.detail(item['id']); self.assertEqual(len(d['discoveries']), 2)
        self.assertTrue(any(x['job_deleted'] for x in d['discoveries']))
    def test_discovery_filters_must_match_same_observation(self):
        a, b = self.job('alpha'), self.job('beta')
        self.discovery(a, '8.8.8.8', 1, query='alpha country:US')
        self.discovery(b, '8.8.8.8', 2, query='beta country:DE')
        self.assertEqual(self.repo.list({'job_id': a['id'], 'query': 'beta'})['total'], 0)
        self.assertEqual(self.repo.list({'job_id': a['id'], 'query': 'US'})['total'], 1)
        self.assertEqual(self.repo.stats({'job_id': a['id']})['jobs'], 1)
        self.assertEqual(self.repo.stats({'from': '2026-10-31T00:00:00Z'})['timeline'], [])
    def test_services_snapshots_and_shared_filter_counts(self):
        job = self.job(); self.discovery(job, '8.8.8.8', 1)
        item = self.repo.list()['items'][0]
        details = {'ip_str': item['ip'], 'country_code': 'US', 'city': 'Mountain View', 'org': '=fixture',
                   'data': [{'port': 53, 'transport': 'udp', 'product': 'DNS', 'timestamp': '2026-10-29T12:00:00Z'},
                            {'port': 53, 'transport': 'tcp', 'product': 'DNS'}]}
        self.repo.snapshot(job['id'], item['id'], 'r1', 'api', details)
        self.repo.snapshot(job['id'], item['id'], 'r1', 'api', details)
        filters = {'country': 'US', 'port': '53', 'protocol': 'udp', 'product': 'DNS'}
        self.assertEqual(self.repo.list(filters)['total'], self.repo.stats(filters)['total'])
        self.assertEqual(self.repo.stats(filters)['services'], 2)
        self.assertEqual(len(self.repo.detail(item['id'])['snapshots']), 1)
        body, _ = self.repo.export(filters, 'csv'); self.assertIn("'=fixture", body.decode('utf-8-sig'))
        body, _ = self.repo.export(filters, 'json'); self.assertEqual(len(json.loads(body)['targets']), 1)
    def test_unknown_times_cache_and_ipv6_ranges(self):
        job = self.job(); self.store.record_ip_progress(job['id'], ['2001:4860:4860::8888'])
        self.repo.backfill(job); self.repo.backfill(job)
        item = self.repo.list({'q': '2001:4860::/32'})['items'][0]
        self.assertIsNone(item['first_found_at']); self.assertTrue(item['unknown_discovery_times'])
        e = {'request_id': 'a'*32, 'origin': 'cache', 'facet': 'ip', 'status': 'success', 'finished_at': '2026-10-30T10:00:00Z'}
        self.repo.observe_request(job, e, [{'value': item['ip']}])
        self.assertEqual(self.repo.detail(item['id'])['discovery_count'], 1)
        self.assertEqual(self.repo.stats()['timeline'], [])
    def test_wrong_host_is_rejected_and_missing_values_do_not_erase_data(self):
        job = self.job(); self.discovery(job, '8.8.8.8', 1); item = self.repo.list()['items'][0]
        with self.assertRaises(ValueError): self.repo.snapshot(job['id'], item['id'], 'r', 'api', {'ip_str': '1.1.1.1'})
        self.repo.snapshot(job['id'], item['id'], 'r1', 'api', {'ip_str': item['ip'], 'country_code': 'US'})
        self.repo.snapshot(job['id'], item['id'], 'r2', 'html', {'ip_str': item['ip'], 'city': 'Mountain View'})
        self.assertEqual(self.repo.detail(item['id'])['country'], 'US')

    def test_replays_do_not_change_discovery_time_and_older_snapshots_do_not_rewind_enrichment(self):
        job = self.job(); entry = self.discovery(job, '8.8.8.8', 1)
        entry['finished_at'] = '2026-10-31T10:00:00Z'
        self.repo.observe_request(job, entry, [{'value': '8.8.8.8'}])
        item = self.repo.list()['items'][0]
        self.assertEqual(item['last_found_at'], '2026-10-30T10:00:00+00:00')
        self.store.record_ip_progress(job['id'], ['8.8.8.8'])
        self.assertFalse(self.repo.detail(item['id'])['unknown_discovery_times'])
        self.repo.snapshot(job['id'], item['id'], 'new', 'api', {'ip_str': item['ip'], 'ports': [53]}, '2026-10-30T12:00:00Z')
        self.repo.snapshot(job['id'], item['id'], 'old', 'html', {'ip_str': item['ip'], 'services': [{'port': 53, 'transport': 'udp'}]}, '2026-10-29T12:00:00Z')
        target = self.repo.detail(item['id'])
        self.assertEqual(target['enriched_at'], '2026-10-30T12:00:00+00:00')
        self.assertEqual(len(target['services']), 1)
