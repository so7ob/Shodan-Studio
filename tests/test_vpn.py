"""Offline VPN contract, recovery, persistence and security acceptance."""
import base64
import contextlib
import io
import json
from pathlib import Path
import signal
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from studio import engine
from studio.config import validate_job
from studio.jobs import JobManager
from studio.store import Store
from studio.vpn import VPNManager
from studio.vpn_config import parse_profile, policy, network_error
from studio.vpn_helper import Broker, ENV, IFACE, NS
from studio.worker import DemoData, StudioCrawler, run_worker
from test_server import Client, PASSWORD
from studio.server import create_app

P1, P2, P3 = '1'*32, '2'*32, '3'*32
KEY = base64.b64encode(bytes(range(32))).decode()
CONFIG = f'''[Interface]
PrivateKey = {KEY}
Address = 10.90.0.2/32
DNS = 1.1.1.1
[Peer]
PublicKey = {KEY}
Endpoint = 192.0.2.10:51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
'''
GOOD = dict(healthy=True, egress_ip='203.0.113.8', leak_protection=True, handshake=True,
            dns=True, tcp=True, tls=True, http=True, checked_at=100, latency_ms=4)


class FakeProvider:
    def __init__(self):
        self.active = None
        self.calls = []
        self.broken = set()
        self.healthy = True
        self.items = [dict(id=i,name=f'Fixture {n}',country='DE',protocol='amneziawg',enabled=True) for n,i in enumerate((P1,P2,P3))]
    def list_profiles(self): return self.items
    def discover_profiles(self): return [dict(source='0:fixture.conf',name='fixture')]
    def get_status(self): return dict(active_profile=self.active,verified=self.healthy,last_check=GOOD)
    def connect(self, ident):
        self.calls.append(ident)
        if ident in self.broken: raise RuntimeError('fixture tunnel verification failed')
        self.active = ident
        return dict(GOOD)
    switch_profile = connect
    def health_check(self, scope='worker'): return dict(GOOD, healthy=self.healthy, scope=scope)
    def disconnect(self): self.active = None; return self.get_status()
    def restore_previous_state(self): return self.connect(P1)
    def add(self, data): parse_profile(data['config']); return self.items[0]
    def update(self, ident, meta): return dict(id=ident,**meta)


class ProfileTests(unittest.TestCase):
    def test_supported_and_no_secret_output(self):
        data = parse_profile(CONFIG)
        self.assertEqual(data['protocol'],'wireguard')
        self.assertEqual(data['dns'],['1.1.1.1'])
        self.assertNotIn('Address', data['config'])
        self.assertEqual(parse_profile(CONFIG.replace('DNS =', 'Jc = 3\nDNS ='))['protocol'],'amneziawg')
    def test_reject_hooks_paths_duplicates_unknown_and_malformed_secrets(self):
        for raw in (CONFIG.replace('DNS =', 'PostUp = touch /tmp/injected\nDNS ='),
                    CONFIG.replace('DNS =','Table = auto\nDNS ='), CONFIG+'[Peer]\n',
                    CONFIG.replace(KEY,'INVALID'), CONFIG.replace('192.0.2.10','$(whoami)'),
                    CONFIG.replace('DNS = 1.1.1.1','DNS = 127.0.0.53'),
                    CONFIG.replace('0.0.0.0/0','192.0.2.0/24')):
            with self.subTest(raw_length=len(raw)):
                with self.assertRaises(ValueError) as caught: parse_profile(raw)
                self.assertNotIn(KEY,str(caught.exception))
    def test_policy_defaults_and_allowlist(self):
        self.assertEqual(policy()['network_mode'],'direct')
        for bad in ({'network_mode':'other'}, {'network_mode':'preferred'},
                    {'max_failovers':True}, {'allowed_vpn_profiles':['../etc/passwd']},
                    {'vpn_failover_enabled':True}, {'network_mode':'failover','preferred_vpn_profile':P1}):
            with self.assertRaises(ValueError): policy(bad)
    def test_network_classification_excludes_http_quota_and_certificate(self):
        for kind in ('DNS','TLS','TIMEOUT','CONNECTION_RESET','NETWORK_UNREACHABLE'):
            self.assertEqual(network_error(engine.SpiderError(f'[{kind}] fixture')),kind)
            self.assertEqual(network_error(engine.ShodanAPIError(f'[API_{kind}] fixture')),kind)
        for exc in (engine.SpiderError('[TLS_CERTIFICATE] fixture'),engine.SpiderError('[HTTP_429] limit',http_status=429),
                    engine.ShodanAPIError('[API_TLS] unrelated body',http_status=403),OSError('disk full')):
            self.assertIsNone(network_error(exc))


class ManagerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(self.tmp.name)
        self.provider = FakeProvider()
        self.manager = JobManager(self.tmp.name,store=self.store,autostart=False,demo=True)
        self.manager.vpn = VPNManager(self.store,self.provider,clock=lambda:1000)
        self.vpn = self.manager.vpn
    def tearDown(self): self.manager.shutdown(); self.tmp.cleanup()
    def job(self, **overrides):
        network = dict(network_mode='failover',preferred_vpn_profile=P1,allowed_vpn_profiles=[P1,P2,P3],vpn_failover_enabled=True,max_failovers=2)
        network.update(overrides)
        return self.manager.create_job(dict(query='country:DE',settings={'demo':True,'delay':0},network=network))
    def test_legacy_jobs_default_direct_without_helper(self):
        job = self.manager.create_job({'query':'country:DE'})
        self.assertEqual(job['network_mode'],'direct')
        self.assertEqual(self.provider.calls,[])
        with patch.object(self.provider,'get_status',side_effect=RuntimeError('offline')):
            self.assertFalse(self.vpn.summary()['available'])
    def test_verified_connect_and_cooldown_audit(self):
        self.vpn.connect(P1)
        self.assertTrue(self.vpn.events()[0]['verified'])
        self.provider.broken.add(P2)
        with self.assertRaises(RuntimeError): self.vpn.connect(P2)
        self.assertEqual(self.vpn._saved()[P2]['failure_count'],1)
        self.assertEqual(self.vpn._saved()[P2]['cooldown_until'],1060)
        self.assertEqual(self.vpn.events()[0]['status'],'failed')
    def test_failover_requires_failed_health_and_respects_bounds_restart(self):
        job = self.job(); self.vpn.prepare(job)
        self.assertIsNone(self.vpn.recover(job))
        self.assertEqual(self.provider.calls,[P1])
        self.provider.healthy = False
        self.provider.broken.add(P2)
        result = self.vpn.recover(job)
        self.assertEqual(result['active_vpn_profile'],P3)
        self.assertEqual(result['failover_count'],2)
        restarted = VPNManager(Store(self.tmp.name),self.provider,clock=lambda:1001)
        self.assertIsNone(restarted.recover(self.store.get_job(job['id'])))
    def test_destination_only_tls_error_does_not_rotate_a_healthy_tunnel(self):
        job=self.job();self.vpn.prepare(job)
        with patch.object(self.provider,'health_check',return_value={**GOOD,'healthy':False,'tls':False,'tunnel_healthy':True}):
            self.assertIsNone(self.vpn.recover(job))
        self.assertEqual(self.provider.calls,[P1])

    def test_dashboard_remains_responsive_during_manual_connection(self):
        import threading,time
        entered=threading.Event();release=threading.Event();errors=[]
        original=self.provider.connect
        def slow(ident):
            entered.set();release.wait(3);return original(ident)
        self.provider.switch_profile=slow
        def connect():
            try:self.manager.vpn_action({'action':'connect','profile_id':P1})
            except Exception as exc:errors.append(exc)
        worker=threading.Thread(target=connect);worker.start()
        try:
            self.assertTrue(entered.wait(2))
            start=time.monotonic();self.manager.list_jobs();state=self.vpn.summary()
            self.assertLess(time.monotonic()-start,.5)
            self.assertTrue(state['status']['busy']);self.assertFalse(state['status']['verified'])
            self.assertTrue(self.manager._network_operation)
            with self.assertRaises(RuntimeError):self.manager.vpn_action({'action':'disconnect'})
        finally:release.set();worker.join(5)
        self.assertEqual(errors,[]);self.assertFalse(self.manager._network_operation)

    def test_all_profiles_fail_and_remain_resumable(self):
        job = self.job(); self.provider.broken = {P1,P2,P3}
        self.manager._execute(job)
        saved = self.manager.get_job(job['id'])
        self.assertEqual(saved['status'],'waiting_input')
        self.assertEqual(saved['failover_count'],2)
        self.assertEqual(saved['network_health'],'unhealthy')
        self.assertEqual(self.provider.calls,[P1,P2,P3])
    def test_manual_preferred_and_disabled_profiles(self):
        job = self.job(network_mode='manual',vpn_failover_enabled=False)
        with self.assertRaises(RuntimeError): self.vpn.prepare(job)
        self.provider.active = P1
        self.assertEqual(self.vpn.prepare(job)['active_vpn_profile'],P1)
        self.assertEqual(self.provider.calls,[])
        self.provider.items[0]['enabled'] = False
        with self.assertRaises(ValueError): self.vpn.validate_policy({'network_mode':'preferred','preferred_vpn_profile':P1})
    def test_cancel_during_network_diagnosis_cannot_be_resurrected(self):
        job=self.job();self.manager.action(job['id'],{'action':'cancel'})
        self.manager._network_wait(job['id'],'fixture network failure')
        self.assertEqual(self.manager.get_job(job['id'])['status'],'cancelled')
        self.assertIsNone(self.vpn.recover(self.store.get_job(job['id']),initial_failure=True))
        self.assertEqual(self.provider.calls,[])

    def test_no_switch_or_policy_change_while_worker_owns_job(self):
        job = self.job(); self.manager._active_id = job['id']
        with self.assertRaises(RuntimeError): self.manager.vpn_action({'action':'connect','profile_id':P2})
        with self.assertRaises(RuntimeError): self.manager.network_settings(job['id'],{'network_mode':'direct'})
        self.assertEqual(self.provider.calls,[])
    def test_namespace_worker_command_and_stdin_key_never_direct(self):
        job = self.job()
        self.store.update_job(job['id'],active_vpn_profile=P1)
        with patch('studio.jobs.subprocess.Popen',side_effect=OSError('fixture stop')) as popen:
            with self.assertRaises(OSError): self.manager._execute_worker(self.store.get_job(job['id']))
        cmd = popen.call_args.args[0]
        self.assertIn('studio.vpn_client',cmd)
        self.assertNotIn('studio.worker',cmd)
    def test_migration_backup_preserves_legacy_rows_and_results(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp)/'studio.sqlite3'
            with sqlite3.connect(db) as con:
                con.execute('CREATE TABLE sentinel(value TEXT)');con.execute("INSERT INTO sentinel VALUES('retained')")
            Store(tmp)
            for path in (db,Path(tmp)/'studio.pre-vpn-v0.sqlite3'):
                with sqlite3.connect(path) as con:
                    self.assertEqual(con.execute('SELECT value FROM sentinel').fetchone()[0],'retained')
                    self.assertEqual(con.execute('PRAGMA integrity_check').fetchone()[0],'ok')
            with sqlite3.connect(db) as con: self.assertEqual(con.execute('PRAGMA user_version').fetchone()[0],1)
    def test_restart_marks_network_unknown_and_retains_saved_ips(self):
        job=self.job()
        self.store.record_ip_progress(job['id'],['192.0.2.1'])
        self.store.update_job(job['id'],status='running',network_health='healthy',current_egress_ip='203.0.113.1',active_vpn_profile=P1)
        self.store.recover_interrupted()
        self.manager._restore_ip_progress()
        saved=self.manager.get_job(job['id'])
        self.assertEqual(saved['status'],'interrupted')
        self.assertEqual(saved['network_health'],'unknown')
        self.assertIsNone(saved['current_egress_ip'])
        self.assertEqual(saved['stats']['unique_ips'],1)

    def test_rollback_guard_does_not_queue_protected_jobs_as_direct(self):
        import importlib.util
        path=Path(__file__).resolve().parents[1]/'tools/pause_vpn_jobs.py'
        spec=importlib.util.spec_from_file_location('pause_vpn_jobs',path)
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        job=self.job();direct=self.manager.create_job({'query':'fixture'})
        self.store.record_ip_progress(job['id'],['192.0.2.1'])
        self.assertEqual(module.pause(self.store.path),1)
        saved=self.store.get_job(job['id'])
        self.assertEqual(saved['status'],'paused');self.assertEqual(saved['network_mode'],'failover')
        self.assertEqual(saved['stats']['unique_ips'],1)
        self.assertEqual(self.store.get_job(direct['id'])['status'],'queued')

    def test_api_auth_csrf_secret_redaction_and_static_assets(self):
        app = create_app(self.tmp.name,manager=self.manager,autostart=False,demo=True)
        client = Client(app)
        self.assertEqual(client.request('GET','/api/vpn')[0],401)
        client.request('GET','/api/session')
        status, _, _ = client.request('POST','/api/setup',dict(setup_token=self.store.setup_token(),username='admin',password=PASSWORD))
        self.assertEqual(status,201)
        self.assertEqual(client.request('POST','/api/vpn/actions',{'action':'connect','profile_id':P1},headers={'HTTP_X_CSRF_TOKEN':'bad'})[0],403)
        status, data, _ = client.request('POST','/api/vpn/profiles',dict(config=CONFIG,metadata={'name':'fixture','country':'DE','enabled':True}))
        self.assertEqual(status,201)
        self.assertNotIn(KEY,json.dumps(data))
        self.assertNotIn(KEY,json.dumps(self.vpn.events()))
        self.assertEqual(client.request('POST','/api/vpn/actions',{'action':'shell','command':'id'})[0],400)
        self.assertEqual(client.request('GET','/static/vpn.js')[0],200)


class WorkerNetworkTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.folder=Path(self.tmp.name)
        self.job,_=validate_job({'query':'country:EG','mode':'html','settings':{'demo':True,'delay':0,'max_requests':100}},allow_demo=True)
    def tearDown(self): self.tmp.cleanup()
    def run_worker(self):
        output=io.StringIO(); old=[signal.getsignal(n) for n in (signal.SIGINT,signal.SIGTERM)]
        try:
            with contextlib.redirect_stdout(output), patch.object(StudioCrawler,'interruptible_sleep'):
                code=run_worker(self.folder,{'job':self.job})
        finally:
            for n,v in zip((signal.SIGINT,signal.SIGTERM),old): signal.signal(n,v)
        return code,[json.loads(x) for x in output.getvalue().splitlines()]
    def test_tls_transient_recovers_and_budget_counts_all_attempts(self):
        original=DemoData.fetch; calls=[]
        def flaky(instance,url):
            calls.append(url)
            if len(calls)==1: raise engine.SpiderError('[TLS] fixture handshake failed')
            return original(instance,url)
        with patch.object(DemoData,'fetch',flaky): code,events=self.run_worker()
        self.assertEqual(code,0)
        self.assertEqual(events[-1]['stats']['requests'],len(calls))
        self.assertEqual(events[-1]['stats']['unique_ips'],292)
        self.assertTrue(any(x.get('phase')=='retry_scheduled' for x in events))
    def test_interrupted_checkpoint_commit_preserves_prior_checkpoint(self):
        code,_=self.run_worker();self.assertEqual(code,0)
        path=self.folder/'checkpoint.json';before=path.read_bytes()
        checkpoint=engine.load_checkpoint(path)
        with patch('studio.engine.os.replace',side_effect=OSError('fixture disk interruption')):
            with self.assertRaises(engine.CheckpointError):
                engine.save_checkpoint(path,checkpoint,allow_replace=True)
        self.assertEqual(path.read_bytes(),before)
        self.assertEqual(engine.load_checkpoint(path),checkpoint)

    def test_dns_outage_preserves_checkpoint_completed_leaves_then_resumes(self):
        original=DemoData.fetch; calls=[]
        def outage(instance,url):
            calls.append(url)
            if len(calls)>8: raise engine.SpiderError('[DNS] fixture unavailable')
            return original(instance,url)
        with patch.object(DemoData,'fetch',outage): code,events=self.run_worker()
        self.assertEqual(code,75)
        self.assertEqual(events[-1]['input_reason'],'network_error')
        checkpoint=engine.load_checkpoint(self.folder/'checkpoint.json')
        saved=(self.folder/'live-ips.txt').read_text().splitlines()
        self.assertTrue(saved)
        self.assertEqual(sum(x.get('phase')=='retry_scheduled' for x in events),2)
        resumed=[]
        def healthy(instance,url): resumed.append(url); return original(instance,url)
        with patch.object(DemoData,'fetch',healthy): code,events=self.run_worker()
        self.assertEqual(code,0);self.assertEqual(events[-1]['stats']['unique_ips'],292)
        self.assertFalse(set(calls[:8]) & set(resumed))
        self.assertTrue(set(saved) <= set((self.folder/'live-ips.txt').read_text().splitlines()))


class ProbeTests(unittest.TestCase):
    def test_egress_is_tested_even_when_destination_tls_fails(self):
        import ssl
        from unittest.mock import MagicMock
        from studio.vpn_probe import probe
        connection=MagicMock();response=MagicMock()
        response.__enter__.return_value=response
        response.status=200;response.read.return_value=b'8.8.8.8'
        opener=MagicMock();opener.open.return_value=response
        with patch('studio.vpn_probe.socket.getaddrinfo'), patch('studio.vpn_probe.socket.create_connection',return_value=connection), patch('studio.vpn_probe.ssl.create_default_context',side_effect=ssl.SSLError('fixture')), patch('studio.vpn_probe.urllib.request.build_opener',return_value=opener):
            result=probe()
        self.assertFalse(result['healthy']);self.assertFalse(result['tls'])
        self.assertTrue(result['http']);self.assertEqual(result['egress_ip'],'8.8.8.8')


class BrokerSecurityTests(unittest.TestCase):
    def test_reject_unapproved_commands_without_exec(self):
        broker=object.__new__(Broker)
        with patch('studio.vpn_helper.command') as command:
            for request in ({'op':'shell','argv':['id']},{'op':'connect','profile_id':P1,'command':'id'}, {'op':'run'}):
                with self.assertRaises(ValueError): broker.dispatch(request)
            command.assert_not_called()
    def test_failed_switch_restores_previous_profile(self):
        broker=object.__new__(Broker);broker.active=P1;broker.previous=None
        with patch.object(broker,'_connect',side_effect=[RuntimeError('failed'),GOOD]) as connect:
            with self.assertRaises(RuntimeError): broker.switch_profile(P2)
        self.assertEqual([call.args[0] for call in connect.call_args_list],[P2,P1])

    def test_live_worker_lease_blocks_switch_and_disconnect(self):
        import threading
        broker=object.__new__(Broker);broker.lock=threading.RLock();broker.running_job=P1
        with patch.object(broker,'connect') as connect:
            for op in ('connect','disconnect','restore'):
                payload={'op':op}
                if op=='connect': payload['profile_id']=P2
                with self.assertRaises(RuntimeError): broker.dispatch(payload)
            connect.assert_not_called()

    def test_namespace_worker_drops_all_capabilities_and_proxy_environment(self):
        broker=object.__new__(Broker);broker.uid=123;broker.gid=123
        argv=broker._unprivileged('studio.worker','--job-dir','/fixed/job')
        self.assertEqual(argv[:4],['/usr/sbin/ip','netns','exec',NS])
        self.assertIn('--bounding-set=-all',argv);self.assertIn('--no-new-privs',argv)
        self.assertFalse(any('PROXY' in key for key in ENV))
    def test_profile_symlink_and_disabled_connection_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            broker=object.__new__(Broker);broker.root=Path(tmp)
            (broker.root/'profiles').mkdir();(broker.root/'profiles'/f'{P1}.conf').symlink_to('/etc/passwd')
            with self.assertRaises(ValueError): broker._path(P1)
            broker.profiles={P1:{'enabled':False}}
            with patch('studio.vpn_helper.command') as command:
                with self.assertRaises(ValueError): broker._connect(P1)
                command.assert_not_called()


if __name__=='__main__': unittest.main()
