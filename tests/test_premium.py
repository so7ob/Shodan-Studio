"""Offline Premium protocol/security contracts. No real subscription requests."""
import base64
import hashlib
import io
import json
import os
import ssl
from pathlib import Path
import tempfile
import unittest
import uuid
import zlib
from unittest.mock import patch, MagicMock

from studio.premium import (Premium, PremiumError, Gateway, countries, decode_key, encrypt_payload,
                            decrypt_payload, check_error, private_json, read_private,
                            subscription, tunnel_config)
from studio.vpn_helper import Broker
from test_vpn import CONFIG, KEY, GOOD, FakeProvider
from test_server import Client, PASSWORD
from studio.server import create_app
from studio.store import Store
from studio.vpn import VPNManager

TOKEN = 'test-subscription-secret-not-a-real-account'
CATALOG = [dict(server_country_code=code, server_country_name=name,
                server_country_code_l10n=flag, available_protocols=protocols)
           for code,name,flag,protocols in [('de','Germany','de',['awg']),
               ('us-east','USA East','us',['awg']),('xx','Unsupported fixture','xx',['vless'])]]
UUID = 'ec18c8c5-034c-4bd9-b852-45218beb8037'


def encode(obj, compressed=True, prefix=True):
    raw = json.dumps(obj).encode()
    if compressed: raw = b'\x00\x00\x00\xff' + zlib.compress(raw)
    return ('vpn://' if prefix else '') + base64.urlsafe_b64encode(raw).decode().rstrip('=')


def subscription_key():
    return encode(dict(config_version=2,api_config={'service_type':'amnezia-premium','user_country_code':'ru'},
                       auth_data={'api_key':TOKEN}))


def config_document(location='de', raw=None):
    raw = raw or CONFIG.replace('PrivateKey = '+KEY, 'PrivateKey = $WIREGUARD_CLIENT_PRIVATE_KEY').replace('DNS =', 'Jc = 3\nDNS =')
    return dict(api_config={'server_country_code':location,'available_countries':CATALOG},
                containers=[{'container':'amnezia-awg','awg':{'last_config':json.dumps({'config':raw})}}])


class Service:
    def __init__(self): self.calls=[]; self.error=None
    def __call__(self, operation, payload):
        self.calls.append((operation,dict(payload)))
        if self.error: return self.error
        if operation=='account_info':
            return dict(available_countries=CATALOG,active_device_count=2,max_device_count=7,
                        issued_configs=[{'source_type':'country_config'}, {'source_type':'device_config','installation_uuid':UUID}],
                        auth_data={'api_key':'MUST_NOT_LEAK'},email='PRIVATE')
        doc=config_document(payload['server_country_code'])
        doc['api_config']['available_countries']=CATALOG[:1]  # Older template cache, not authoritative.
        return {'config':encode(doc)}


class BrowserPremiumProvider(FakeProvider):
    """Browser fixture: synthetic locations, no gateway or network connection."""
    def __init__(self):
        super().__init__();self.configured=False
        for p,code,flag in zip(self.items,('de','us-east','tr'),('DE','US','TR')):
            p.update(provider='amnezia-premium',location=code,country=flag,available=True)
        self.items.extend(dict(id=f'{i:032x}',name=f'Fixture location {i}',country='DE',
                               protocol='amneziawg',enabled=True,provider='amnezia-premium',
                               location=f'de-{i}',available=True) for i in range(4,56))
    def get_status(self):
        return {**super().get_status(),'leak_protection':bool(self.active),'premium':dict(configured=self.configured,registered=bool(self.active),
                device_tag='fixture',location_count=55,catalog_source='gateway',
                account={'active_device_count':2,'max_device_count':7,'issued_config_count':1})}
    def premium(self,payload):
        if payload['action']=='enroll':subscription(payload['key']);self.configured=True
        return self.get_status()['premium']


class PremiumTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
        self.service=Service();self.now=1000
        private_json(self.root/'premium.json',dict(api_key=TOKEN,user_country_code='ru',installation_uuid=UUID,
                                                countries=countries(CATALOG),catalog_source='installed_client'))
        self.premium=self.adapter()
    def tearDown(self):self.tmp.cleanup()
    def adapter(self): return Premium(self.root,transport=self.service,clock=lambda:self.now,owner=os.getuid())
    def test_transport_only_setup_allows_browser_enrollment_without_importing_token(self):
        from tools import setup_premium as setup
        root=self.root/'bootstrap';root.mkdir()
        material=dict(api_key=TOKEN,user_country_code='ru',transport={'fixture':'trust'},
                      countries=countries(CATALOG),catalog_source='installed_client',adapter_version='5.0.3.0')
        with patch.object(setup,'ROOT',root),patch.object(setup,'installed',return_value=material),\
             patch('sys.argv',['setup_premium.py','--apply','--transport-only']),\
             patch('os.geteuid',return_value=0),patch('sys.stdout',new_callable=io.StringIO) as output:
            self.assertEqual(setup.main(),0)
            self.assertNotIn(TOKEN,output.getvalue())
        state=read_private(root/'premium.json',owner=os.getuid())
        self.assertNotIn('api_key',state);self.assertIn('installation_uuid',state)
        self.assertEqual(state['transport'],material['transport'])
    def test_subscription_formats_bounded_and_redacted(self):
        self.assertEqual(subscription(subscription_key())['api_key'],TOKEN)
        for raw in ('vpn://broken',encode({'api_config':{},'auth_data':{'api_key':TOKEN}}),
                    'vpn://'+base64.b64encode(b'\0'*4+zlib.compress(b'x'*1100000)).decode()):
            with self.assertRaises(RuntimeError) as caught: subscription(raw)
            self.assertNotIn(TOKEN,str(caught.exception))
        obj={'example':'value'}
        self.assertEqual(decode_key(encode(obj,False)),obj)
        self.assertEqual(decode_key(' \n'+encode(obj)+'\n'),obj)
        with self.assertRaises(RuntimeError): decode_key(encode(obj)[:12]+'\n'+encode(obj)[12:])
    def test_catalog_ids_persist_and_do_not_export_or_use_gui_identity(self):
        self.premium.refresh(); first=self.premium.profiles()
        self.premium.configuration('de');self.premium.configuration('us-east')
        restarted=self.adapter();restarted.configuration('de')
        self.assertEqual(first,restarted.profiles())
        self.assertEqual({p['installation_uuid'] for _,p in self.service.calls},{UUID})
        self.assertEqual([o for o,_ in self.service.calls],['account_info','config','config','config'])
        self.assertTrue(restarted.status()['registered'])
        self.assertFalse(first[-1]['enabled'])
        pubs=[p['public_key'] for o,p in self.service.calls if o=='config']
        self.assertEqual(len(set(pubs)),3)
        self.assertNotIn(KEY,pubs)
    def test_unknown_or_unsupported_country_never_requests(self):
        for code in ('xx','../de','not-in-account'):
            with self.assertRaises(ValueError): self.premium.configuration(code)
        self.assertEqual(self.service.calls,[])

    def test_broker_persists_only_valid_gateway_index_without_exposing_it(self):
        broker=object.__new__(Broker);broker.premium=self.premium;broker.code=self.root
        self.premium.state['transport']={'endpoints':['https://one.example','https://two.example']}
        for index,expected in [(1,1),(99,1),('https://attacker.invalid',1)]:
            response=MagicMock(returncode=0,stdout=json.dumps({'ok':True,'result':{},'gateway_index':index}))
            with patch.object(broker,'_unprivileged',return_value=['fixed']),patch('studio.vpn_helper.subprocess.run',return_value=response):
                broker._premium_request('account_info',{})
            self.assertEqual(self.adapter().state['transport']['preferred_index'],expected)
        self.assertNotIn('transport',self.premium.status())
    def test_account_limit_auth_expiry_captcha_rate_and_update_cooldown_survive_restart(self):
        for response,code in [({'http_status':409},'LIMIT'),({'http_status':403},'AUTH'),
                              ({'http_status':402},'EXPIRED'),({'http_status':402,'captcha_id':'secret'},'CAPTCHA'),
                              ({'http_status':429},'RATE_LIMIT'),({'http_status':501},'UPDATE')]:
            with self.subTest(code=code):
                self.now+=400;self.service.error={**response,'message':TOKEN}
                with self.assertRaisesRegex(RuntimeError,'PREMIUM_'+code):self.premium.configuration('de')
                restarted=self.adapter();count=len(self.service.calls)
                with self.assertRaises(RuntimeError):restarted.configuration('us-east')
                self.assertEqual(len(self.service.calls),count)
                self.assertEqual(restarted.status()['last_error'],code)
                self.assertNotIn(TOKEN,json.dumps(restarted.status()))
    def test_ambiguous_network_failure_reuses_identity_after_restart(self):
        with patch.object(self.premium,'transport',side_effect=RuntimeError(TOKEN)):
            with self.assertRaises(RuntimeError) as caught:self.premium.configuration('de')
        self.assertNotIn(TOKEN,str(caught.exception));self.now+=31
        self.adapter().configuration('us-east')
        self.assertEqual(self.service.calls[-1][1]['installation_uuid'],UUID)
    def test_upstream_wait_crosses_broker_and_survives_restart(self):
        for wait in (7200, 'unbounded'):
            with self.subTest(wait=wait):
                self.premium.state.update(cooldown_until=0,cooldown_unbounded=False)
                broker=object.__new__(Broker);broker.premium=self.premium;broker.code=self.root
                response=MagicMock(returncode=0,stdout=json.dumps({'ok':False,'code':'RATE_LIMIT','retry_after':wait}))
                with patch.object(broker,'_unprivileged',return_value=['fixed']),patch('studio.vpn_helper.subprocess.run',return_value=response) as launch:
                    self.premium.transport=broker._premium_request
                    with self.assertRaisesRegex(RuntimeError,'PREMIUM_RATE_LIMIT'):self.premium._request('account_info')
                    launch.assert_called_once()
                deadline=self.premium.state['cooldown_until']
                if wait==7200:self.assertEqual(deadline,self.now+7200)
                else:self.assertTrue(self.premium.state['cooldown_unbounded'])
                self.now+=7199
                restarted=self.adapter()
                with patch.object(restarted,'transport') as transport:
                    for _ in range(3):
                        with self.assertRaisesRegex(RuntimeError,'PREMIUM_RATE_LIMIT'):restarted._request('account_info')
                    transport.assert_not_called()
                self.assertEqual(restarted.state['cooldown_until'],deadline)
                if wait==7200:
                    self.now+=1
                    self.assertIn('available_countries',restarted._request('account_info'))
                self.assertNotIn('Infinity',(self.root/'premium.json').read_text())
    def test_no_private_metadata_in_status_or_profile_or_account(self):
        self.premium.refresh()
        raw=json.dumps([self.premium.status(),self.premium.profiles()])
        for secret in (TOKEN,'MUST_NOT_LEAK','PRIVATE','auth_data','public_key'): self.assertNotIn(secret,raw)
        self.assertEqual(self.premium.status()['account']['max_device_count'],7)
        self.assertEqual(self.premium.status()['account']['issued_config_count'],1)
    def test_enrollment_reuses_identity_and_rejects_replacement(self):
        self.premium.enroll(subscription_key())
        self.assertEqual(self.premium.state['installation_uuid'],UUID)
        changed=decode_key(subscription_key());changed['auth_data']['api_key']='another-subscription-key'
        with self.assertRaises(ValueError):self.premium.enroll(encode(changed))
        self.assertEqual(self.premium.state['api_key'],TOKEN)
    def test_private_storage_permissions_and_symlink(self):
        self.assertEqual((self.root/'premium.json').stat().st_mode & 0o777,0o600)
        path=self.root/'link';path.symlink_to(self.root/'premium.json')
        with self.assertRaises(RuntimeError):read_private(path,os.getuid())
        (self.root/'premium.json').chmod(0o644)
        with self.assertRaises(RuntimeError):self.adapter()
    def test_native_tunnel_must_match_requested_country_and_generated_key(self):
        self.assertIn(KEY,tunnel_config(config_document(),KEY,'de'))
        bad_hook=CONFIG.replace('DNS =','PostUp = echo '+TOKEN+'\nDNS =')
        for doc in (config_document('us-east'),config_document(raw=bad_hook),
                    config_document(raw=CONFIG.replace('DNS =','Jc = 3\nDNS ='))):
            with self.assertRaises(RuntimeError) as caught:tunnel_config(doc,KEY,'de')
            self.assertNotIn(TOKEN,str(caught.exception))
    def test_protocol_handles_full_catalog_without_static_profile_limit(self):
        account=type('Account',(),{'pw_uid':os.getuid(),'pw_gid':os.getgid()})()
        with patch('studio.vpn_helper.pwd.getpwnam',return_value=account),patch('studio.premium.read_private',return_value=self.premium.state):
            broker=Broker(root=self.root,runtime=self.root/'run',code=self.root,data=self.root)
        broker.premium=self.premium
        first=broker.list_profiles()[0]
        broker.dispatch({'op':'update','profile_id':first['id'],'metadata':{'name':'Custom Germany','country':'DE','enabled':False}})
        self.assertFalse(broker.list_profiles()[0]['enabled'])
        with self.assertRaises(ValueError):broker.dispatch({'op':'update','profile_id':first['id'],'metadata':{'name':'Spoof','country':'US'}})
        broker.running_job='1'*32
        with self.assertRaises(RuntimeError):broker.dispatch({'op':'premium_refresh'})
        self.assertEqual(self.service.calls,[])

    def test_subscription_errors_do_not_spend_failovers_or_rotate_countries(self):
        provider=FakeProvider();vpn=VPNManager(Store(self.root/'jobs-db'),provider)
        job=dict(id='1'*32,network_mode='failover',vpn_failover_enabled=True,
                 last_network_error='[PREMIUM_LIMIT] subscription limit',max_failovers=2)
        self.assertIsNone(vpn.recover(job,initial_failure=True))
        self.assertEqual(provider.calls,[])
        self.assertEqual(vpn.events()[0]['reason'],'premium_account_or_protocol_error')
        job['last_network_error']='[VPN_DESTINATION] DNS failed on a healthy tunnel'
        self.assertIsNone(vpn.recover(job,initial_failure=True))
        self.assertEqual(provider.calls,[])
        self.assertEqual(vpn.events()[0]['reason'],'tunnel_healthy_destination_error')


class CryptoTests(unittest.TestCase):
    def test_rsa_aes_envelope_matches_upstream(self):
        from cryptography.hazmat.primitives.asymmetric import rsa,padding as rsa_padding
        from cryptography.hazmat.primitives import serialization,padding
        from cryptography.hazmat.primitives.ciphers import Cipher,algorithms,modes
        private=rsa.generate_private_key(public_exponent=65537,key_size=2048)
        pem=private.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo)
        request,key,iv=encrypt_payload({'auth_data':{'api_key':TOKEN}},pem)
        self.assertNotIn(TOKEN.encode(),request)
        envelope=json.loads(request)
        keys=json.loads(private.decrypt(base64.b64decode(envelope['key_payload']),rsa_padding.PKCS1v15()))
        self.assertEqual(base64.b64decode(keys['aes_key']),key)
        self.assertEqual(len(base64.b64decode(keys['aes_iv'])),32)
        self.assertEqual(decrypt_payload(base64.b64decode(envelope['api_payload']),key,iv)['auth_data']['api_key'],TOKEN)
    def test_transport_trust_and_endpoint_allowlist(self):
        for cfg in ({},{'public_key':'malicious','endpoints':['https://example.com']},
                    {'public_key':'fake','endpoints':['http://example.com']},
                    {'public_key':'fake','endpoints':['https://user:password@example.com']}):
            with self.assertRaises(RuntimeError):Gateway(cfg)
        gateway=object.__new__(Gateway)
        for op in ('native_config','revoke_config','../../config'):
            with self.assertRaises(ValueError):gateway(op,{})

    def test_https_gateway_fallback_has_one_request_identity_and_encrypted_body(self):
        from cryptography.hazmat.primitives.asymmetric import rsa,padding as rsa_padding
        from cryptography.hazmat.primitives import serialization,padding
        from cryptography.hazmat.primitives.ciphers import Cipher,algorithms,modes
        private=rsa.generate_private_key(public_exponent=65537,key_size=2048)
        pem=private.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo)
        config={'public_key':pem.decode(),'endpoints':['https://old.example','https://working.example']}
        calls=[]
        def connection(host,**kwargs):
            self.assertTrue(kwargs['context'].check_hostname)
            self.assertEqual(kwargs['context'].verify_mode,ssl.CERT_REQUIRED)
            conn=MagicMock();reply=MagicMock();conn.getresponse.return_value=reply
            def send(method,path,body,headers):
                calls.append((host,method,path,body,headers))
                self.assertNotIn(TOKEN.encode(),body)
                if host=='old.example':raise OSError('fixture connection loss')
                env=json.loads(body);keys=json.loads(private.decrypt(base64.b64decode(env['key_payload']),rsa_padding.PKCS1v15()))
                key=base64.b64decode(keys['aes_key']);iv=base64.b64decode(keys['aes_iv'])
                payload=decrypt_payload(base64.b64decode(env['api_payload']),key,iv)
                self.assertEqual(payload['auth_data']['api_key'],TOKEN)
                pad=padding.PKCS7(128).padder();raw=pad.update(b'{"active_device_count": 2}')+pad.finalize()
                enc=Cipher(algorithms.AES(key),modes.CBC(iv[:16])).encryptor()
                reply.status=200;reply.read1.side_effect=[enc.update(raw)+enc.finalize(),b'']
            conn.request.side_effect=send
            return conn
        with patch('studio.premium.PUBLIC_KEY_SHA256',hashlib.sha256(pem).hexdigest()),\
             patch('studio.premium.socket.getaddrinfo',return_value=[(2,1,6,'',('1.1.1.1',443))]),\
             patch('studio.premium.http.client.HTTPSConnection',side_effect=connection):
            gateway=Gateway(config)
            result=gateway('account_info',{'auth_data':{'api_key':TOKEN}})
            self.assertEqual(gateway.successful_index,1)
            preferred=Gateway(dict(config,preferred_index=1))
            preferred('account_info',{'auth_data':{'api_key':TOKEN}})
            self.assertEqual([x[0] for x in calls],['old.example','working.example','working.example'])
            calls.pop()
            self.assertIsNone(Gateway(dict(config,preferred_index='https://attacker.invalid')).preferred_index)
            self.assertIsNone(Gateway(dict(config,preferred_index=99)).preferred_index)
        self.assertEqual(result,{'active_device_count':2})
        self.assertEqual([x[2] for x in calls],['/v1/account_info']*2)
        self.assertEqual(calls[0][4]['X-Client-Request-ID'],calls[1][4]['X-Client-Request-ID'])
        self.assertEqual(calls[0][3],calls[1][3])

    def test_failed_preferred_gateway_falls_back_to_approved_origin(self):
        gateway=object.__new__(Gateway);gateway.pem=b'unused'
        gateway.endpoints=['https://good.example','https://bad.example'];gateway.preferred_index=1
        response=MagicMock();response.status=200;response.read1.side_effect=[b'encrypted',b'']
        connection=MagicMock();connection.getresponse.return_value=response
        with patch('studio.premium.encrypt_payload',return_value=(b'encrypted',b'k'*32,b'i'*32)),\
             patch('studio.premium.decrypt_payload',return_value={'active_device_count':2}),\
             patch('studio.premium.socket.getaddrinfo',return_value=[(2,1,6,'',('1.1.1.1',443))]),\
             patch('studio.premium.http.client.HTTPSConnection',side_effect=[OSError(),connection]) as connect:
            self.assertEqual(gateway('account_info',{}),{'active_device_count':2})
        self.assertEqual([c.args[0] for c in connect.call_args_list],['bad.example','good.example'])
        self.assertEqual(gateway.successful_index,0)

    def test_http_refusals_are_classified_before_body_without_gateway_fallback(self):
        for status,code in ((401,'AUTH'),(403,'AUTH'),(404,'AUTH'),(429,'RATE_LIMIT')):
            for body in (b'', b'<html>denied private-token</html>'):
                gateway=object.__new__(Gateway);gateway.pem=b'unused'
                gateway.endpoints=['https://one.example','https://two.example']
                reply=MagicMock();reply.status=status;reply.getheader.return_value='7200'
                reply.read1.side_effect=[body,b'']
                conn=MagicMock();conn.getresponse.return_value=reply
                with patch('studio.premium.encrypt_payload',return_value=(b'encrypted',b'k'*32,b'i'*32)),\
                     patch('studio.premium.decrypt_payload') as decrypt,\
                     patch('studio.premium.socket.getaddrinfo',return_value=[(2,1,6,'',('1.1.1.1',443))]),\
                     patch('studio.premium.http.client.HTTPSConnection',return_value=conn) as connect:
                    with self.assertRaisesRegex(PremiumError,'PREMIUM_'+code) as caught:gateway('account_info',{})
                    self.assertEqual(caught.exception.retry_after,7200)
                    connect.assert_called_once();conn.request.assert_called_once();conn.close.assert_called_once()
                    reply.read1.assert_not_called();decrypt.assert_not_called()
                    self.assertNotIn('private-token',str(caught.exception))

    def test_retry_after_http_date_and_unbounded_header_cross_private_pipe(self):
        from studio.premium import gateway_main
        for header,expected in (('Thu, 01 Jan 1970 02:16:40 GMT',7200),('9'*400,'unbounded')):
            gateway=object.__new__(Gateway);gateway.pem=b'unused'
            gateway.endpoints=['https://one.example','https://two.example']
            reply=MagicMock();reply.status=429;reply.getheader.return_value=header
            conn=MagicMock();conn.getresponse.return_value=reply
            request={'transport':{},'operation':'account_info','payload':{}}
            with patch('studio.premium.Gateway',return_value=gateway),\
                 patch('studio.premium.encrypt_payload',return_value=(b'encrypted',b'k'*32,b'i'*32)),\
                 patch('studio.premium.socket.getaddrinfo',return_value=[(2,1,6,'',('1.1.1.1',443))]),\
                 patch('studio.premium.http.client.HTTPSConnection',return_value=conn) as connect,\
                 patch('studio.engine.time.time',return_value=1000),\
                 patch('sys.stdin',new=MagicMock(buffer=io.BytesIO(json.dumps(request).encode()))),\
                 patch('sys.stdout',new_callable=io.StringIO) as out:
                gateway_main()
                self.assertEqual(json.loads(out.getvalue()),{'ok':False,'code':'RATE_LIMIT','retry_after':expected})
                connect.assert_called_once();reply.read1.assert_not_called()

    def test_https_cleartext_success_and_private_dns_are_rejected(self):
        gateway=object.__new__(Gateway);gateway.pem=b'unused';gateway.endpoints=['https://fixture.example']
        reply=MagicMock();reply.status=200;reply.read1.side_effect=[b'{"config":"SECRET"}',b'']
        conn=MagicMock();conn.getresponse.return_value=reply
        with patch('studio.premium.encrypt_payload',return_value=(b'encrypted',b'k'*32,b'i'*32)),\
             patch('studio.premium.socket.getaddrinfo',return_value=[(2,1,6,'',('1.1.1.1',443))]),\
             patch('studio.premium.http.client.HTTPSConnection',return_value=conn):
            with self.assertRaisesRegex(RuntimeError,'PREMIUM_RESPONSE'):gateway('config',{})
        with patch('studio.premium.encrypt_payload',return_value=(b'encrypted',b'k'*32,b'i'*32)),\
             patch('studio.premium.socket.getaddrinfo',return_value=[(2,1,6,'',('127.0.0.1',443))]),\
             patch('studio.premium.http.client.HTTPSConnection') as connect:
            with self.assertRaisesRegex(RuntimeError,'PREMIUM_NETWORK'):gateway('config',{})
            connect.assert_not_called()


class PremiumAPITests(unittest.TestCase):
    def test_authenticated_csrf_route_queue_guard_and_redaction(self):
        with tempfile.TemporaryDirectory() as tmp:
            app=create_app(tmp,autostart=False,demo=True)
            try:
                client=Client(app)
                self.assertEqual(client.request('POST','/api/vpn/premium',{'action':'refresh'})[0],403)
                client.request('GET','/api/session')
                client.request('POST','/api/setup',dict(setup_token=app.store.setup_token(),username='admin',password=PASSWORD))
                provider=FakeProvider();app.manager.vpn.provider=provider
                provider.premium=lambda data: {'configured':True,'device_tag':'fixture'}
                status,result,_=client.request('POST','/api/vpn/premium',{'action':'enroll','key':TOKEN},headers={'HTTP_X_CSRF_TOKEN':'bad'})
                self.assertEqual(status,403)
                status,result,_=client.request('POST','/api/vpn/premium',{'action':'enroll','key':TOKEN})
                self.assertEqual(status,200)
                self.assertNotIn(TOKEN,json.dumps(result))
                self.assertNotIn(TOKEN,json.dumps(app.manager.vpn.events()))
                app.manager._active_id='1'*32
                status,_,_=client.request('POST','/api/vpn/premium',{'action':'refresh'})
                self.assertEqual(status,409)
            finally:app.manager._active_id=None;app.close()


if __name__=='__main__':unittest.main()
