"""Offline credential storage, API boundaries, session identity and login drivers."""
import asyncio
import json
import os
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from studio.shodan_accounts import ShodanAccounts
from studio.store import Store
from studio.jobs import JobManager
from studio.server import create_app
from studio.browser_broker import BrowserBroker
from studio.browser_session import Session
from studio.patchright_session import PatchrightSession
from studio.engine import build_url
from studio.shodan_login import LOGIN_URL, login_expression
from test_server import Client, PASSWORD
from test_vpn import FakeProvider, P1

SECRET='fixture-password-<>&"not-real'
USER='fixture-user'
URL=build_url('fixture','ip')


class VaultTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
        self.store=Store(self.root);self.vault=ShodanAccounts(self.store)
    def tearDown(self):self.tmp.cleanup()
    def add(self):return self.vault.save({'label':'Main','username':USER,'password':SECRET})
    def test_encrypts_credentials_and_keeps_public_api_password_free(self):
        account=self.add();ident=account['id']
        self.assertEqual(account['username'],USER)
        self.assertNotIn(SECRET,json.dumps(self.vault.list()))
        with self.store.connection() as c:
            row=c.execute('SELECT encrypted FROM shodan_accounts').fetchone()[0]
        self.assertNotIn(SECRET,row);self.assertNotIn(USER,row)
        self.assertNotIn(SECRET.encode(),self.store.path.read_bytes())
        self.assertEqual(self.vault.secret(ident)['password'],SECRET)
        self.assertEqual(self.vault.key_path.stat().st_mode&0o777,0o600)
        self.assertEqual(ShodanAccounts(Store(self.root)).secret(ident)['password'],SECRET)
    def test_blank_edit_preserves_password_and_changed_credentials_rotate_cookie_scope(self):
        account=self.add();ident=account['id'];old=self.vault.secret(ident)['scope']
        self.vault.mark_used(ident)
        self.vault.save({'label':'Renamed','username':USER,'password':''},ident)
        self.assertEqual(self.vault.secret(ident)['scope'],old);self.assertTrue(self.vault.used(ident))
        self.vault.save({'label':'Renamed','username':USER,'password':'different'},ident)
        self.assertNotEqual(self.vault.secret(ident)['scope'],old);self.assertFalse(self.vault.used(ident))
        self.vault.delete(ident);self.assertEqual(self.vault.list(),[])
    def test_missing_corrupt_insecure_or_swapped_secrets_fail_closed(self):
        first=self.add();second=self.add()
        with self.store.connection() as c:
            token=c.execute('SELECT encrypted FROM shodan_accounts WHERE id=?',(first['id'],)).fetchone()[0]
            c.execute('UPDATE shodan_accounts SET encrypted=? WHERE id=?',(token,second['id']))
        with self.assertRaises(RuntimeError):self.vault.secret(second['id'])
        self.vault.key_path.chmod(0o644)
        with self.assertRaises(RuntimeError):self.vault.secret(first['id'])
        self.vault.key_path.chmod(0o600);self.vault.key_path.unlink()
        with self.assertRaises(RuntimeError):self.add()
        self.assertFalse(self.vault.key_path.exists())
    def test_validates_values_and_rejects_symlink_keys(self):
        for value in ('',False,123,'a\nb'):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):self.vault.save({'username':USER,'password':value})
        target=self.root/'other';target.write_text('unchanged');self.vault.key_path.symlink_to(target)
        with self.assertRaises(OSError):self.add()
        self.assertEqual(target.read_text(),'unchanged')
    def test_restoring_database_and_key_restores_accounts(self):
        account=self.add()
        with tempfile.TemporaryDirectory() as folder:
            restored=Store(folder)
            with self.store.connection() as source,restored.connection() as dest:source.backup(dest)
            key=Path(folder)/'shodan-accounts.key';key.write_bytes(self.vault.key_path.read_bytes());key.chmod(0o600)
            self.assertEqual(ShodanAccounts(restored).secret(account['id'])['password'],SECRET)


class AccountManagerTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
        self.store=Store(self.root);self.store.setup(self.store.setup_token(),'admin',PASSWORD)
        self.manager=JobManager(self.root,store=self.store,autostart=False,demo=True)
        self.manager.vpn.provider=FakeProvider()
        self.app=create_app(self.root,manager=self.manager,autostart=False,demo=True)
        self.client=Client(self.app)
        self.client.request('GET','/api/session')
        self.client.request('POST','/api/login',{'username':'admin','password':PASSWORD})
        self.account=self.manager.shodan_account_save({'label':'Main','username':USER,'password':SECRET})
        self.job=self.manager.create_job({'query':'fixture','mode':'html','settings':{'demo':True},'network':{'network_mode':'preferred','preferred_vpn_profile':P1}})
        self.store.update_job(self.job['id'],status='waiting_input')
    def tearDown(self):self.manager.shutdown();self.tmp.cleanup()
    def select(self):return self.manager.shodan_account_select(self.job['id'],{'account_id':self.account['id']})
    def test_authenticated_crud_csrf_and_no_secrets_in_jobs_events_or_lists(self):
        anonymous=Client(self.app)
        self.assertEqual(anonymous.request('GET','/api/shodan/accounts')[0],401)
        status,body,_=self.client.request('GET','/api/shodan/accounts');self.assertEqual(status,200)
        self.assertEqual(body['accounts'][0]['username'],USER);self.assertNotIn(SECRET,json.dumps(body))
        status,_,_=self.client.request('POST','/api/shodan/accounts',{'username':USER,'password':SECRET},headers={'HTTP_X_CSRF_TOKEN':''})
        self.assertEqual(status,403)
        status,body,_=self.client.request('POST',f"/api/jobs/{self.job['id']}/shodan-account",{'account_id':self.account['id']})
        self.assertEqual(status,200);self.assertNotIn(SECRET,json.dumps(body))
        self.assertNotIn(SECRET,json.dumps(self.store.list_jobs()))
        self.assertNotIn(SECRET,json.dumps(self.store.events(self.job['id'])))
    def test_selection_checks_status_mode_and_open_browser(self):
        for status in ('running','queued','completed'):
            self.store.update_job(self.job['id'],status=status)
            with self.assertRaises(RuntimeError):self.select()
        self.store.update_job(self.job['id'],status='paused',mode='api')
        with self.assertRaises(RuntimeError):self.select()
        self.store.update_job(self.job['id'],mode='html');self.manager._browser_job=self.job['id']
        with self.assertRaises(RuntimeError):self.select()
        # Adding another account does not disturb an existing browser.
        self.assertTrue(self.manager.shodan_account_save({'username':'another','password':SECRET})['id'])
    def test_scoped_browser_start_and_login_use_only_selected_credentials(self):
        self.select();self.manager._browser_rpc=MagicMock(return_value={'running':True,'state':'off_task_page','backend':'chromium'})
        self.manager.vpn.prepare=MagicMock(return_value={})
        self.manager.browser_action(self.job['id'],{'action':'start'})
        start=self.manager._browser_rpc.call_args.args[1]
        scope=self.manager.shodan_accounts.secret(self.account['id'])['scope']
        self.assertEqual(start['account_scope'],scope);self.assertNotIn(SECRET,json.dumps(start))
        self.manager._browser_rpc.return_value={'state':'off_task_page','login_status':'submitted','password':SECRET,'image':SECRET,'backend':SECRET}
        result=self.manager.browser_action(self.job['id'],{'action':'login'})
        sent=self.manager._browser_rpc.call_args.args[1]
        self.assertEqual(sent['username'],USER);self.assertEqual(sent['password'],SECRET)
        self.assertEqual(sent['return_url'],URL);self.assertNotIn(SECRET,json.dumps(result))
        self.assertNotIn(SECRET,json.dumps(self.manager.vpn.events()))
        self.manager._browser_rpc.side_effect=RuntimeError(SECRET)
        with self.assertRaises(RuntimeError) as error:self.manager.browser_action(self.job['id'],{'action':'login'})
        self.assertNotIn(SECRET,str(error.exception))
    def test_login_cannot_accept_client_credentials_or_arbitrary_urls(self):
        self.select();self.manager._browser_job=self.job['id'];self.manager._browser_rpc=MagicMock()
        for extra in ({'username':'other','password':SECRET},{'url':'https://evil.test'}):
            with self.assertRaises(ValueError):self.manager.browser_action(self.job['id'],{'action':'login',**extra})
        self.manager._browser_rpc.assert_not_called()

    def test_selected_account_cannot_resume_through_anonymous_http(self):
        self.select();self.manager._browser_rpc=MagicMock(return_value={'state':'ready'})
        with self.assertRaises(ValueError):self.manager.action(self.job['id'],{'action':'resume','mode':'html'})
        self.manager._browser_rpc.assert_not_called()
        self.assertEqual(self.store.get_job(self.job['id'])['status'],'waiting_input')
        self.store.update_job(self.job['id'],browser_session_enabled=True)
        self.manager._browser_job=self.job['id']
        result=self.manager.action(self.job['id'],{'action':'resume','mode':'html'})
        self.assertEqual(result['status'],'queued')
        self.manager._browser_rpc.assert_called_once_with(self.job['id'],{'action':'verify'})
    def test_delete_removes_saved_browser_scopes_and_unlinks_jobs(self):
        self.select();vault=self.manager.shodan_accounts;vault.mark_used(self.account['id'])
        scope=vault.secret(self.account['id'])['scope'];self.manager._browser_rpc=MagicMock(return_value={'removed':True})
        self.manager.shodan_account_delete(self.account['id'])
        self.manager._browser_rpc.assert_called_once_with(self.account['id'],{'action':'forget_account','account_scope':scope})
        self.assertIsNone(self.store.get_job(self.job['id']).get('shodan_account_id'));self.assertEqual(vault.list(),[])
    def test_failover_browser_input_keeps_account_scope(self):
        self.select();job=self.store.get_job(self.job['id'])
        first=self.manager._account_browser_input(job)
        job['active_vpn_profile']='b'*32
        self.assertEqual(self.manager._account_browser_input(job),first)


class DriverTests(unittest.TestCase):
    def payload(self):return {'action':'login','username':USER,'password':SECRET,'return_url':URL}
    def test_chromium_login_uses_official_url_and_returns_no_password(self):
        s=object.__new__(Session);s.document={};s.expected=None;s.ready=False;s.page_url=''
        def call(method,data):
            if method=='Page.navigate':s.document={'url':LOGIN_URL,'status':200};s.page_url=LOGIN_URL;return {}
            return {'result':{'value':'submitted' if 'requestSubmit' in data['expression'] else True}}
        s.call=MagicMock(side_effect=call)
        result=s.action(self.payload())
        self.assertEqual(s.call.call_args_list[0].args,('Page.navigate',{'url':LOGIN_URL}))
        self.assertEqual(result['login_status'],'submitted');self.assertEqual(s.expected,URL)
        self.assertNotIn(SECRET,json.dumps(result));self.assertFalse(s.ready)
    def test_patchright_login_uses_guarded_function_and_redacts_exceptions(self):
        class Error(Exception):pass
        module=types.ModuleType('patchright.async_api');module.Error=Error
        async def run():
            s=PatchrightSession('/unused');s.page=MagicMock();s.page.evaluate=AsyncMock(return_value='submitted')
            async def navigate(url,**kwargs):s.document={'url':url,'status':200}
            s.page.goto=AsyncMock(side_effect=navigate)
            with patch.dict('sys.modules',{'patchright':types.ModuleType('patchright'),'patchright.async_api':module}):
                result=await s.action(self.payload());self.assertEqual(result['login_status'],'submitted')
                self.assertNotIn(SECRET,json.dumps(result));self.assertEqual(s.expected,URL)
                s.page.evaluate.side_effect=Error(SECRET)
                with self.assertRaises(RuntimeError) as error:await s.action(self.payload())
                self.assertNotIn(SECRET,str(error.exception))
        asyncio.run(run())
    def test_invalid_login_scope_is_rejected_before_browser_calls(self):
        for url in ('https://evil.test','https://account.shodan.io/login'):
            with self.assertRaises(ValueError):login_expression({**self.payload(),'return_url':url})
    def test_broker_removes_only_scoped_account_profiles(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);scope='a'*32
            for name in ('account-'+scope,'account-'+scope+'-patchright','b'*32):
                (root/name).mkdir();(root/name/'cookie').write_text('fixture')
            broker=BrowserBroker(types.SimpleNamespace(running_job=None))
            with patch('studio.browser_broker.ROOT',root):
                broker.action({'job_id':'c'*32,'input':{'action':'forget_account','account_scope':scope}})
            self.assertFalse((root/('account-'+scope)).exists());self.assertTrue((root/('b'*32)).exists())

    def test_cookie_folder_follows_account_across_vpn_and_isolates_other_accounts(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            owner=types.SimpleNamespace(active='1'*32,uid=500,code=root,launch_check=lambda:{'healthy':True})
            broker=BrowserBroker(owner);broker.backend='chromium'
            process=MagicMock();process.poll.return_value=None;process.pid=123456789
            with patch('studio.browser_broker.ROOT',root), patch('studio.browser_broker.pwd.getpwnam',return_value=types.SimpleNamespace(pw_uid=1001,pw_gid=1001)), \
                 patch('studio.browser_broker.os.chown'), patch('studio.browser_broker.os.killpg'), patch('studio.browser_broker.Path.is_file',return_value=True), \
                 patch('studio.vpn_helper.command'), patch('studio.browser_broker.subprocess.Popen',return_value=process), \
                 patch.object(broker,'reply',return_value={'running':True}), patch.object(broker,'request',return_value={'running':True}):
                broker.start('c'*32,URL,account_scope='a'*32)
                cookie=root/('account-'+'a'*32)/'cookie';cookie.write_text('fixture-cookie')
                with self.assertRaises(RuntimeError):broker.start('c'*32,URL,account_scope='b'*32)
                broker.close();owner.active='2'*32
                broker.start('c'*32,URL,account_scope='a'*32);self.assertTrue(cookie.exists())
                broker.close();broker.start('c'*32,URL,account_scope='b'*32)
                self.assertFalse((root/('account-'+'b'*32)/'cookie').exists())
                broker.close();broker.start('c'*32,URL)
                self.assertTrue((root/('2'*32)).is_dir())
