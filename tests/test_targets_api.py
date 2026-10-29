"""Inventory HTTP routes share authentication, validation and CSRF controls."""
import tempfile
import unittest
from studio.server import create_app
from test_server import Client, PASSWORD


class TargetAPITests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.app = create_app(self.tmp.name, autostart=False)
        self.client = Client(self.app)
        self.app.store.setup(self.app.store.setup_token(), 'fixture', PASSWORD)
    def tearDown(self): self.app.close(); self.tmp.cleanup()
    def login(self):
        self.client.request('GET', '/api/session')
        status, data, _ = self.client.request('POST', '/api/login', {'username': 'fixture', 'password': PASSWORD})
        self.assertEqual(status, 200); self.client.csrf = data['csrf_token']
    def test_inventory_requires_auth_and_settings_require_csrf(self):
        self.assertEqual(self.client.request('GET', '/api/targets')[0], 401)
        self.login(); self.client.csrf = ''
        self.assertEqual(self.client.request('POST', '/api/enrichment/settings', {'automatic': False})[0], 403)
    def test_pagination_shared_filters_and_invalid_parameters(self):
        self.login(); m = self.app.manager
        j = m.create_job({'query': 'fixture'})
        m.store.record_ip_progress(j['id'], ['8.8.8.8', '1.1.1.1'])
        status, page, _ = self.client.request('GET', '/api/targets?limit=1')
        self.assertEqual((status, page['total'], len(page['items'])), (200, 2, 1))
        self.assertEqual(self.client.request('GET', '/api/targets?q=8.8.8.0%2F24')[1]['total'], 1)
        self.assertEqual(self.client.request('GET', '/api/targets/stats?q=8.8.8.0%2F24')[1]['total'], 1)
        for query in ('port=70000', 'q=bad%2Fnet', 'unexpected=1', 'limit=1&limit=2', 'from=not-a-date'):
            self.assertEqual(self.client.request('GET', '/api/targets?' + query)[0], 400)
        status, body, headers = self.client.request('GET', '/api/targets/download?format=txt')
        self.assertEqual(status, 200); self.assertIn('attachment', headers['Content-Disposition'])
    def test_create_filtered_enrichment_and_default_legacy_kind(self):
        self.login(); m = self.app.manager; j = m.create_job({'query': 'fixture'})
        m.store.record_ip_progress(j['id'], ['8.8.8.8'])
        status, result, _ = self.client.request('POST', '/api/jobs', {'kind': 'enrichment', 'filters': {'q': '8.8.8.8'}, 'mode': 'html'})
        self.assertEqual((status, result['job']['kind'], result['job']['enrichment_progress']['total']), (201, 'enrichment', 1))
        self.assertEqual(m.get_job(j['id'])['kind'], 'extraction')
