"""Root-side lifecycle/lease for an unprivileged private browser process."""
import contextlib
import json
import os
from pathlib import Path
import pwd
import selectors
import shutil
import signal
import subprocess
import time

from .browser_session import resource_url as facet_url
from .vpn_config import profile_id

ROOT = Path('/var/lib/shodan-studio-browser')
MAX_REPLY = 12 * 1024 * 1024
PATCHRIGHT_RUNTIME = Path('/opt/shodan-studio/browser-runtime')


def browser_backend():
    value = os.environ.get('SHODAN_STUDIO_BROWSER_BACKEND', 'chromium')
    if value not in ('chromium', 'patchright'): raise RuntimeError('Invalid server browser backend.')
    return value

class BrowserPipeError(RuntimeError): pass


def browser_guard(uid):
    if type(uid) is not int or uid<=0: raise ValueError('Invalid browser UID.')
    return f'''table inet studio_browser {{
  chain output {{
    type filter hook output priority -10; policy accept;
    meta skuid {uid} ip daddr {{ 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/4, 240.0.0.0/4 }} reject;
    meta skuid {uid} ip6 daddr {{ ::/128, ::1/128, fc00::/7, fe80::/10, ff00::/8 }} reject;
  }}
}}
'''


class BrowserBroker:
    def __init__(self,broker):
        self.broker=broker;self.process=None;self.job=None;self.profile=None
        self.last_used=0;self.buffer=b'';self.state='closed'
        self.backend=browser_backend()
        self.identity={}
        self.account_scope=None

    def status(self):
        alive=bool(self.process and self.process.poll() is None)
        return dict(running=alive,job_id=self.job if alive else None,profile_id=self.profile if alive else None,state=self.state if alive else 'closed',backend=self.backend)

    def close(self):
        proc=self.process
        self.process=None;self.job=None;self.profile=None;self.buffer=b'';self.state='closed';self.account_scope=None
        if proc:
            with contextlib.suppress(OSError):proc.stdin.write(b'{"action":"stop"}\n');proc.stdin.flush()
            try:proc.wait(timeout=8)
            except subprocess.TimeoutExpired:
                with contextlib.suppress(ProcessLookupError):os.killpg(proc.pid,signal.SIGTERM)
                try:proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    with contextlib.suppress(ProcessLookupError):os.killpg(proc.pid,signal.SIGKILL)
                    proc.wait()
            for stream in (proc.stdin,proc.stdout):stream.close()
            with contextlib.suppress(ProcessLookupError):os.killpg(proc.pid,signal.SIGKILL)

    def reply(self,timeout=35):
        deadline=time.monotonic()+timeout
        with selectors.DefaultSelector() as selector:
            selector.register(self.process.stdout,selectors.EVENT_READ)
            while b'\n' not in self.buffer:
                if not selector.select(max(0,deadline-time.monotonic())):raise BrowserPipeError('Browser response timed out.')
                chunk=os.read(self.process.stdout.fileno(),65536)
                if not chunk:raise BrowserPipeError('Browser session ended.')
                self.buffer+=chunk
                if len(self.buffer)>MAX_REPLY:raise BrowserPipeError('Browser response exceeds limit.')
            raw,self.buffer=self.buffer.split(b'\n',1)
        response=json.loads(raw)
        if not response.get('ok'):raise RuntimeError(response.get('error','Browser operation failed.'))
        result=response['result'];self.state=result.get('state',self.state)
        if result.get('user_agent'): self.identity={'user_agent':result['user_agent'],'backend':self.backend}
        return result

    def request(self,data):
        if data.get('action')!='frame':self.last_used=time.monotonic()
        if not self.status()['running']:raise RuntimeError('[BROWSER_SESSION] افتح جلسة المتصفح من بطاقة المهمة أولًا.')
        try:
            self.process.stdin.write(json.dumps(data).encode()+b'\n');self.process.stdin.flush()
            return self.reply()
        except (OSError,ValueError,BrowserPipeError):
            self.close();raise RuntimeError('[BROWSER_SESSION] Browser connection lost.') from None

    def start(self,job_id,url,*,defer_navigation=False,account_scope=None):
        from .vpn_helper import IP,NS,SETPRIV,ENV,NFT
        profile_id(job_id);facet_url(url)
        if account_scope is not None:profile_id(account_scope)
        if self.status()['running']:
            if self.job!=job_id:raise RuntimeError('أغلق جلسة المهمة الأخرى أولًا.')
            if self.account_scope!=account_scope:raise RuntimeError('أغلق جلسة المتصفح قبل تغيير حساب Shodan.')
            return self.status() if defer_navigation else self.request({'action':'frame'})
        account=pwd.getpwnam('shodan-browser')
        if account.pw_uid in (0,self.broker.uid):raise RuntimeError('Browser needs a separate unprivileged account.')
        python = '/usr/bin/python3'; module = 'studio.browser_session'
        env = dict(ENV)
        if self.backend == 'patchright':
            python = str(PATCHRIGHT_RUNTIME / 'venv/bin/python3'); module = 'studio.patchright_session'
            if not Path(python).is_file() or not (PATCHRIGHT_RUNTIME / 'browsers').is_dir():
                raise RuntimeError('[BROWSER_DEPENDENCY] Install the pinned Patchright runtime with tools/install_browser.sh --patchright.')
            env['PLAYWRIGHT_BROWSERS_PATH'] = str(PATCHRIGHT_RUNTIME / 'browsers')
        elif not Path('/usr/lib/chromium/chromium').is_file():
            raise RuntimeError('Install the optional Chromium browser dependency.')
        if not Path('/usr/bin/Xvfb').is_file():raise RuntimeError('Install the optional Xvfb browser dependency.')
        if shutil.disk_usage(ROOT).free<200*1024*1024:raise RuntimeError('Browser requires at least 200 MiB free disk space.')
        if not self.broker.launch_check().get('healthy'):raise RuntimeError('تحقق من اتصال VPN قبل فتح المتصفح.')
        self.profile=profile_id(self.broker.active)
        self.account_scope=account_scope
        namespace='account-'+account_scope if account_scope else self.profile
        folder=ROOT/(namespace + ('-patchright' if self.backend == 'patchright' else ''))
        if folder.is_symlink():raise ValueError('Invalid browser profile directory.')
        folder.mkdir(mode=0o700,exist_ok=True);os.chown(folder,account.pw_uid,account.pw_gid);folder.chmod(0o700)
        # Additional browser-only egress guard. Browser pages cannot reach host,
        # metadata, loopback or VPN LAN addresses, even through DNS rebinding.
        from .vpn_helper import command
        command([IP,'netns','exec',NS,NFT,'delete','table','inet','studio_browser'],check=False)
        command([IP,'netns','exec',NS,NFT,'-f','-'],data=browser_guard(account.pw_uid))
        argv=[IP,'netns','exec',NS,SETPRIV,'--reuid',str(account.pw_uid),'--regid',str(account.pw_gid),'--clear-groups','--no-new-privs','--bounding-set=-all',
              python,'-s','-m',module,str(folder)]
        self.process=subprocess.Popen(argv,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,
                                     cwd=self.broker.code,env=env,start_new_session=True)
        self.job=job_id;self.buffer=b'';self.last_used=time.monotonic()
        try:
            ready = self.reply()
            # Failover starts a blank browser. The worker owns the navigation,
            # request budget and saved Retry-After, including for the first page.
            if defer_navigation: return ready
            # Page.navigate can return before Chromium has painted its first
            # compositor frame. Poll it separately; preserve the live session.
            return self.request({'action':'navigate','url':url})
        except Exception:self.close();raise

    def action(self,request):
        job=profile_id(request['job_id']);data=request['input']
        if not isinstance(data,dict):raise ValueError('Invalid browser input.')
        if self.broker.running_job:raise RuntimeError('أوقف المهمة وانتظر حفظ Checkpoint قبل التحكم في المتصفح.')
        if data.get('action')=='forget_account' and set(data)=={'action','account_scope'}:
            scope=profile_id(data['account_scope'])
            if self.account_scope==scope and self.status()['running']:raise RuntimeError('أغلق جلسة حساب Shodan قبل حذفه.')
            for suffix in ('','-patchright'):
                folder=ROOT/('account-'+scope+suffix)
                if folder.is_symlink():raise ValueError('Invalid account browser directory.')
                if folder.exists():shutil.rmtree(folder)
            return {'removed':True}
        if data.get('action')=='start' and 'account_scope' in data and set(data)<= {'action','url','account_scope','defer_navigation'}:
            if 'url' not in data or data.get('defer_navigation',False) not in (True,False):raise ValueError('Invalid browser input.')
            return self.start(job,data['url'],defer_navigation=data.get('defer_navigation',False),account_scope=profile_id(data['account_scope']))
        if data.get('action')=='start' and set(data)=={'action','url'}:return self.start(job,data['url'])
        if data.get('action')=='start' and set(data)=={'action','url','defer_navigation'} and data['defer_navigation'] is True:
            return self.start(job,data['url'],defer_navigation=True)
        if data=={'action':'stop'} and not self.status()['running']:self.close();return self.status()
        if self.job!=job:raise RuntimeError('[BROWSER_SESSION] لا توجد جلسة لهذه المهمة؛ افتحها أولًا.')
        if data=={'action':'stop'}:self.close();return self.status()
        if data.get('action') not in {'frame','click','key','text','scroll','verify','login'}:raise ValueError('Browser operation is not allowed.')
        if data.get('action')=='login' and not self.account_scope:raise RuntimeError('اختر حساب Shodan قبل تسجيل الدخول.')
        isolation=self.broker._isolation()
        if self.profile!=self.broker.active or not isolation['route_verified'] or not isolation['leak_protection']:
            self.close();raise RuntimeError('[BROWSER_SESSION] فقدت الجلسة النفق المعزول؛ أُغلقت بأمان.')
        return self.request(data)

    def fetch(self,job_id,url):
        profile_id(job_id);facet_url(url)
        if job_id!=self.job or self.broker.running_job!=job_id or self.profile!=self.broker.active:raise RuntimeError('[BROWSER_SESSION] Browser worker lease does not match.')
        isolation=self.broker._isolation()
        if not isolation['route_verified'] or not isolation['leak_protection']:
            self.close();raise RuntimeError('[BROWSER_SESSION] Browser tunnel isolation was lost.')
        result = self.request({'action':'fetch','url':url})
        return {**self.identity, **result} if 'html' in result else result
