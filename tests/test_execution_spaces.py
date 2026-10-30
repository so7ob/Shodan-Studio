"""Concurrent real offline workers and independent control/network boundaries."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from studio.jobs import JobManager
from studio.lanes import space
from studio.vpn import VPNManager
from studio.vpn_helper import Broker
from studio.premium import Premium, private_json
from studio.enrichment import parse_host_html
from studio.browser_session import Session


# Representative semantic structures visible in the reported host page, without
# CSS. This is a regression fixture, not a capture of a live Shodan response.
HOST = '''<title>203.0.113.5 - Shodan</title><h2>203.0.113.5</h2>
<div id="general"><h2><em>General</em>Information</h2>
<div class="row"><label>Country</label><div><a href='/search?query=country:TW'>Taiwan</a></div></div>
<div class="row"><span>City</span><span><a>Taipei</a></span></div>
<div class="row"><label>Organization</label><div>Example Organization</div></div>
<div class="row"><label>ISP</label><div>Example ISP</div></div></div>
<h2><em>Open</em>Ports</h2><a href='#80'>80</a><a href='#161'>161</a>
<div class="service" id="port-80"><div class="port-heading"><span><strong>80</strong> / tcp</span></div>
<time datetime="2026-10-25T04:24:33Z"></time></div>
<div class="service" id="port-161"><h6><strong>161</strong> / udp</h6></div>'''


class ExecutionSpacesTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.m = JobManager(self.tmp.name, autostart=False, demo=True)
        self.m.enrichment_settings.save({'automatic': False})

    def tearDown(self):
        self.m.shutdown()
        self.tmp.cleanup()

    def jobs(self):
        source = self.m.create_job({'query': 'fixture', 'settings': {'demo': True, 'delay': 0}})
        self.m.store.record_ip_progress(source['id'], ['8.8.8.8'])
        enriched = self.m.create_job({'kind': 'enrichment', 'target_ids': self.m.store.targets.select_ids({'demo': '1'}),
                                     'mode': 'html', 'settings': {'demo': True, 'delay': 0}})
        return source, enriched

    def start(self):
        with patch.object(self.m.vpn.provider, 'get_status', return_value={}), \
             patch.object(self.m.enrichment.vpn.provider, 'get_status', return_value={}):
            self.m.start()

    def wait_done(self, ids):
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            jobs = [self.m.get_job(i) for i in ids]
            if all(j['status'] not in ('running', 'queued') for j in jobs): return jobs
            time.sleep(.03)
        self.fail('Independent workers did not finish: ' + repr(jobs))

    def test_real_workers_live_at_the_same_time_and_results_are_persisted(self):
        source, enriched = self.jobs()
        real_popen = subprocess.Popen
        barrier = threading.Barrier(2)
        processes = []
        def launch(*args, **kwargs):
            proc = real_popen(*args, **kwargs)
            processes.append(proc)
            barrier.wait(timeout=8)
            self.assertEqual(len(processes), 2)
            self.assertTrue(all(p.poll() is None for p in processes))
            return proc
        with patch('studio.jobs.subprocess.Popen', side_effect=launch):
            self.start()
            jobs = self.wait_done([source['id'], enriched['id']])
        self.assertEqual([j['status'] for j in jobs], ['completed', 'completed'])
        self.assertEqual(jobs[1]['enrichment_progress']['success'], 1)
        self.assertGreater(len(self.m.results(source['id'])['items']), 0)

    def test_waiting_browser_pins_only_its_lane(self):
        source, enriched = self.jobs()
        self.m.store.update_job(enriched['id'], status='waiting_input')
        child = self.m.enrichment
        child._browser_job = enriched['id']; child._browser_deadline = time.monotonic() + 300
        queued = self.m.action(enriched['id'], {'action': 'duplicate'})
        self.start()
        self.assertEqual(self.wait_done([source['id']])[0]['status'], 'completed')
        self.assertEqual(self.m.get_job(queued['id'])['status'], 'queued')
        self.assertTrue(self.m.get_job(enriched['id'])['browser_session_open'])
        self.assertFalse(self.m.get_job(source['id'])['browser_session_open'])

    def test_lane_claims_legacy_jobs_and_does_not_cross_kind(self):
        source, enriched = self.jobs()
        with self.m.store.connection() as c:
            job = dict(source); job.pop('kind')
            c.execute('UPDATE jobs SET document=? WHERE id=?', (json.dumps(job), source['id']))
        self.assertEqual(self.m.store.claim_next(kind='enrichment')['id'], enriched['id'])
        self.assertIsNone(self.m.store.claim_next(kind='enrichment'))
        self.assertEqual(self.m.store.claim_next(kind='extraction')['id'], source['id'])

    def test_network_and_browser_controls_use_own_space(self):
        source, enriched = self.jobs()
        self.m.enrichment._active_id = enriched['id']
        self.assertEqual(self.m._vpn_mutation(lambda: 'extraction available'), 'extraction available')
        with self.assertRaises(RuntimeError): self.m.enrichment._vpn_mutation(lambda: None)
        self.m.enrichment._active_id = None
        for kind in ('extraction', 'enrichment'):
            with patch('studio.vpn_client.rpc', return_value={'state':'ready'}) as rpc:
                self.m.lane(kind)._browser_rpc('a'*32, {'action':'verify'})
                self.assertEqual(rpc.call_args.kwargs['socket_path'], space(kind).socket)
        self.m.store.update_job(enriched['id'], status='paused')
        with patch.object(self.m.enrichment, '_browser_rpc', return_value={'state':'ready'}) as rpc:
            self.m.browser_action(enriched['id'], {'action':'verify'})
            rpc.assert_called_once()

    def test_shared_account_edits_exclude_both_lanes(self):
        self.m.enrichment._browser_job = 'a'*32
        with self.assertRaises(RuntimeError): self.m._account_mutation(lambda: None)
        self.m.enrichment._browser_job = None
        self.m.enrichment._active_id = 'b'*32
        with self.assertRaises(RuntimeError): self.m._account_mutation(lambda: None)
        self.m.enrichment._active_id = None
        self.assertEqual(self.m._account_mutation(lambda: 'available'), 'available')
        self.assertFalse(self.m._network_operation or self.m.enrichment._network_operation)

    def test_shutdown_requests_both_workers_before_joining(self):
        source, enriched = self.jobs()
        self.m._active_id = source['id']; self.m.enrichment._active_id = enriched['id']
        def joined():
            self.assertTrue(self.m._stop.is_set() and self.m.enrichment._stop.is_set())
            for item in (source, enriched):
                self.assertEqual(json.loads((self.m._path(item['id'])/'control.json').read_text())['action'], 'pause')
        with patch.object(self.m, '_finish_shutdown', side_effect=joined), \
             patch.object(self.m.enrichment, '_finish_shutdown', side_effect=joined):
            self.m.shutdown()
        self.m._active_id = self.m.enrichment._active_id = None

    def test_vpn_health_preference_and_audit_are_separate(self):
        a, b = self.m.vpn, self.m.enrichment.vpn
        a._save({'id':'a'*32, 'health':'healthy'})
        b._save({'id':'a'*32, 'health':'unhealthy'})
        a.audit('connect'); b.audit('disconnect')
        self.assertEqual(a._saved()['a'*32]['health'], 'healthy')
        self.assertEqual(b._saved()['a'*32]['health'], 'unhealthy')
        self.assertEqual([e['action'] for e in a.events()], ['connect'])
        self.assertEqual([e['action'] for e in b.events()], ['disconnect'])
        self.assertNotEqual(a.preferred_key, b.preferred_key)
        self.assertNotEqual(a.provider.socket, b.provider.socket)

    def test_automatic_seeding_does_not_contact_the_extraction_vpn(self):
        source = self.m.create_job({'query':'offline seeding fixture'})
        self.m.store.record_ip_progress(source['id'], ['8.8.4.4'])
        self.m.enrichment_settings.save({'automatic': True})
        with patch.object(self.m.vpn, 'validate_policy', side_effect=AssertionError('source lane blocked')), \
             patch.object(self.m.enrichment.vpn, 'validate_policy', side_effect=AssertionError('network during seed')):
            self.m._seed_enrichment()
        self.assertTrue(any(j.get('automatic') for j in self.m.list_jobs()['jobs']))

    def test_live_discovery_starts_enrichment_before_extraction_finishes(self):
        self.m.enrichment_settings.save({'automatic': True})
        source = self.m.create_job({'query':'offline orchestration fixture'})
        enriched = threading.Event()
        def extract(job):
            self.m.store.record_ip_progress(job['id'], ['8.8.4.4'])
            request_id = 'e'*32
            self.m.store.requests.save(job['id'], {'request_id':request_id, 'facet':'ip', 'query':job['query'],
                'source':'html', 'status':'parsed', 'finished_at':'2026-10-30T00:00:00Z'})
            self.m.store.requests.values(job['id'], request_id, 0, [{'value':'8.8.4.4','count':1}])
            self.m._observe_request(job['id'], request_id)
            self.assertTrue(enriched.wait(5), 'Enrichment was held until extraction finished')
            self.m.store.update_job(job['id'], status='completed')
        def enrich(job):
            self.assertEqual(job['origin_job_id'], source['id'])
            self.assertEqual(self.m.get_job(source['id'])['status'], 'running')
            self.m.store.update_job(job['id'], status='paused')
            enriched.set()
        with patch.object(self.m, '_execute', side_effect=extract), \
             patch.object(self.m.enrichment, '_execute', side_effect=enrich):
            self.start()
            self.assertEqual(self.wait_done([source['id']])[0]['status'], 'completed')
        self.assertTrue(enriched.is_set())

    def test_private_peer_lease_rejects_simultaneous_key_reuse(self):
        a, b = object.__new__(Broker), object.__new__(Broker)
        a._key_lease = b._key_lease = None
        real_open = os.open
        def local_open(path, *args): return real_open(Path(self.tmp.name) / Path(path).name, *args)
        with patch('studio.vpn_helper.os.open', side_effect=local_open):
            a._reserve_key('public-key-only')
            try:
                with self.assertRaises(RuntimeError): b._reserve_key('public-key-only')
                b._reserve_key('other-public-key')
            finally:
                os.close(a._key_lease)
                if b._key_lease is not None: os.close(b._key_lease)

    def test_subscription_link_creates_independent_device_with_stable_profile_alias(self):
        original = Path(self.tmp.name) / 'original'; original.mkdir()
        target = Path(self.tmp.name) / 'target'; target.mkdir()
        private_json(original/'premium.json', {'api_key':'fixture-secret', 'user_country_code':'DE',
            'installation_uuid':'12345678-1234-5678-1234-567812345678', 'registered':True,
            'countries':[{'location':'de','country':'DE','name':'Germany','supported':True}],
            'last_error':'LIMIT','cooldown_until':99999999999})
        origin = Premium(original, owner=os.getuid()); child = Premium(target, owner=os.getuid())
        child.link_subscription(original)
        self.assertNotEqual(child.state['installation_uuid'], origin.state['installation_uuid'])
        self.assertEqual(child.profiles()[0]['id'], origin.profiles()[0]['id'])
        self.assertFalse(child.state['registered'])
        self.assertEqual(child.state['cooldown_until'], origin.state['cooldown_until'])
        identity = child.state['installation_uuid']; child.link_subscription(original)
        self.assertEqual(child.state['installation_uuid'], identity)


class HostLayoutTests(unittest.TestCase):
    def test_host_labels_without_styles_and_nested_port_heading(self):
        result = parse_host_html(HOST, '203.0.113.5')
        self.assertEqual((result['country_code'], result['city']), ('TW','Taipei'))
        self.assertEqual([(s['port'],s['transport']) for s in result['services']], [(80,'tcp'),(161,'udp')])
        self.assertEqual(result['services'][0]['timestamp'], '2026-10-25T04:24:33+00:00')

    def test_browser_accepts_host_only_when_http_and_ip_match(self):
        session = object.__new__(Session)
        session.expected = 'https://www.shodan.io/host/203.0.113.5'
        session.ready = False; session.page_url = session.expected
        session.document = {'url':session.expected, 'status':200}
        self.assertEqual(session.inspect_page({'url':session.expected, 'html':HOST})['state'], 'ready')
        for html in (HOST.replace('<h2>203.0.113.5</h2>', '<h2>203.0.113.6</h2>'),
                     '<h2>203.0.113.5</h2>', '<title>Just a moment</title>'+HOST):
            self.assertNotEqual(session.inspect_page({'url':session.expected, 'html':html})['state'], 'ready')
        session.document['status'] = 403
        self.assertNotEqual(session.inspect_page({'url':session.expected, 'html':HOST})['state'], 'ready')


class SpaceAPITests(unittest.TestCase):
    def setUp(self):
        from studio.server import create_app
        from test_server import Client, PASSWORD
        from test_vpn import FakeProvider
        self.tmp = tempfile.TemporaryDirectory()
        self.app = create_app(self.tmp.name, autostart=False, demo=True)
        self.m = self.app.manager
        self.m.vpn.provider = FakeProvider(); self.m.enrichment.vpn.provider = FakeProvider()
        self.client = Client(self.app)
        self.client.request('GET', '/api/session')
        self.client.request('POST', '/api/setup', {'setup_token': self.m.store.setup_token(), 'username':'acceptance', 'password':PASSWORD})

    def tearDown(self):
        self.app.close(); self.tmp.cleanup()

    def test_independent_routes_filter_jobs_and_require_authentication_and_csrf(self):
        from test_server import Client
        self.assertEqual(Client(self.app).request('GET', '/api/enrichment/jobs')[0], 401)
        source = self.m.create_job({'query':'fixture', 'settings':{'demo':True}})
        self.m.store.record_ip_progress(source['id'], ['8.8.8.8'])
        payload = {'target_ids':self.m.store.targets.select_ids({'demo':'1'}), 'settings':{'demo':True}}
        status, response, _ = self.client.request('POST', '/api/enrichment/jobs', payload)
        self.assertEqual(status, 201)
        enriched = response['job']
        self.assertEqual(enriched['kind'], 'enrichment')
        status, response, _ = self.client.request('GET', '/api/enrichment/jobs')
        self.assertEqual(status, 200)
        self.assertEqual([j['id'] for j in response['jobs']], [enriched['id']])
        self.assertEqual(response['summary']['total'], 1)
        self.assertEqual(response['lanes']['extraction']['queued'], 1)
        self.assertEqual(self.client.request('GET', '/api/enrichment/jobs/'+source['id'])[0], 404)
        self.assertEqual(self.client.request('GET', '/enrichment')[0], 200)
        self.assertEqual(self.client.request('GET', '/api/enrichment/vpn')[1]['kind'], 'enrichment')
        self.assertEqual(self.client.request('GET', '/api/vpn')[1]['kind'], 'extraction')
        csrf = self.client.csrf; self.client.csrf = ''
        self.assertEqual(self.client.request('POST', '/api/enrichment/vpn/actions', {'action':'disconnect'})[0], 403)
        self.client.csrf = csrf
        self.m._active_id = source['id']
        self.assertEqual(self.client.request('POST', '/api/enrichment/vpn/actions', {'action':'disconnect'})[0], 200)
        self.assertEqual(self.client.request('POST', '/api/vpn/actions', {'action':'disconnect'})[0], 409)
        self.m._active_id = None
