"""Private, headed Chromium session. No public debugging port or challenge solver."""
from __future__ import annotations
import contextlib
import json
import math
import os
from pathlib import Path
import re
import secrets
import socket
import struct
import subprocess
import sys
import threading
import time
from urllib.parse import parse_qs, urlsplit

WIDTH, HEIGHT = 1100, 760
LIMIT = 8 * 1024 * 1024
ALLOWED_HOSTS = {'shodan.io', 'www.shodan.io', 'account.shodan.io', 'static.shodan.io', 'assets.shodan.io', 'api.shodan.io', 'challenges.cloudflare.com'}
KEYS = {'Enter':13,'Tab':9,'Backspace':8,'Delete':46,'Escape':27,'ArrowLeft':37,'ArrowUp':38,'ArrowRight':39,'ArrowDown':40,'Home':36,'End':35,' ':32}


def allowed_url(url):
    try:
        u=urlsplit(url)
        return u.scheme=='https' and u.hostname in ALLOWED_HOSTS and u.port in (None,443) and not u.username and not u.password
    except (ValueError,TypeError): return False


def facet_url(url):
    from .engine import ENDPOINT
    if not isinstance(url,str) or len(url)>50000 or not allowed_url(url): raise ValueError('Browser URL is not allowed.')
    u=urlsplit(url);q=parse_qs(u.query,keep_blank_values=True,max_num_fields=2)
    if u.scheme+'://'+u.netloc+u.path!=ENDPOINT or u.fragment or set(q)!={'query','facet'} or any(len(v)!=1 for v in q.values()):
        raise ValueError('Only a Shodan facet page is allowed.')
    if not re.fullmatch('[a-z_]{1,32}',q['facet'][0]) or len(q['query'][0])>16384: raise ValueError('Invalid facet parameters.')
    return q['query'][0],q['facet'][0]


def same_facet(url, expected):
    """Compare validated task URLs, allowing equivalent query encoding/order."""
    try:return resource_url(url)==resource_url(expected)
    except (ValueError,TypeError):return False


def resource_url(url):
    """Validated resource identity; host reads never authorize arbitrary URLs."""
    if isinstance(url, str) and url.startswith('https://www.shodan.io/host/'):
        from .enrichment import host_page_url
        return ('host', host_page_url(url))
    return ('facet', *facet_url(url))


def browser_page_failure(state):
    if state == 'browser_challenge':
        raise RuntimeError('[BROWSER_CHALLENGE] أكمل اختبار الأمان الظاهر في المتصفح ثم استكمل المهمة.')
    if state == 'login_required':
        raise RuntimeError('[BROWSER_LOGIN] لم يكتمل تسجيل الدخول إلى Shodan؛ راجع نموذج الدخول في المتصفح.')
    if state == 'access_denied':
        raise RuntimeError('[HTTP_403] رفض Shodan الوصول إلى الصفحة.')


class CDP:
    def __init__(self, process, read_fd, write_fd, event):
        self.process,self.read_fd,self.write_fd,self.event=process,read_fd,write_fd,event
        self.condition=threading.Condition();self.counter=0;self.pending={};self.dead=False
        threading.Thread(target=self._read,daemon=True).start()

    def send(self, method, params=None, session=None, wait=True, timeout=12):
        with self.condition:
            if self.dead: raise RuntimeError('Browser pipe is closed.')
            self.counter+=1;ident=self.counter
            value={'id':ident,'method':method,'params':params or {}}
            if session: value['sessionId']=session
            if wait:self.pending[ident]=None
            data=json.dumps(value).encode()+b'\0'
            while data:
                n=os.write(self.write_fd,data);data=data[n:]
            if not wait:return None
            deadline=time.monotonic()+timeout
            try:
                while self.pending[ident] is None and not self.dead:
                    remaining=deadline-time.monotonic()
                    if remaining<=0:raise RuntimeError('Browser operation timed out.')
                    self.condition.wait(remaining)
                result=self.pending[ident]
                if not result or 'error' in result:raise RuntimeError('Browser operation failed.')
                return result.get('result',{})
            finally:self.pending.pop(ident,None)

    def _read(self):
        buffer=b''
        try:
            while True:
                chunk=os.read(self.read_fd,65536)
                if not chunk:break
                buffer+=chunk
                if len(buffer)>LIMIT+1024*1024:break
                while b'\0' in buffer:
                    raw,buffer=buffer.split(b'\0',1)
                    message=json.loads(raw)
                    if 'id' in message:
                        with self.condition:
                            if message['id'] in self.pending:self.pending[message['id']]=message
                            self.condition.notify_all()
                    else:self.event(message)
        except Exception:pass
        finally:
            with self.condition:self.dead=True;self.condition.notify_all()

    def close(self):
        with contextlib.suppress(Exception):self.send('Browser.close',wait=False)
        try:self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:self.process.kill();self.process.wait()
        for fd in (self.read_fd,self.write_fd):
            with contextlib.suppress(OSError):os.close(fd)


def launch_chromium():
    # This tiny exec trampoline avoids preexec_fn in a multithreaded process.
    read_fd,write_fd=int(sys.argv[2]),int(sys.argv[3])
    r,w=os.dup(read_fd),os.dup(write_fd)
    os.dup2(r,3,inheritable=True);os.dup2(w,4,inheritable=True)
    for fd in {r,w,read_fd,write_fd}-{3,4}:os.close(fd)
    os.execv('/usr/lib/chromium/chromium',['chromium','--remote-debugging-pipe',
        '--user-data-dir='+sys.argv[4],'--no-first-run','--no-default-browser-check',
        '--disable-extensions','--disable-background-networking','--disable-sync',
        '--disable-component-update','--disable-gpu','--window-size=1100,850',
        '--disk-cache-size=16777216','--media-cache-size=16777216','about:blank'])


class Session:
    def __init__(self, folder):
        self.folder=Path(folder);self.target=None;self.session=None;self.cdp=None;self.xvfb=None
        self.document={};self.expected=None;self.ready=False;self.page_url=''
        self.folder.mkdir(mode=0o700,parents=True,exist_ok=True)
        try:
            # Private X11 authentication, no TCP X server and no access-control bypass.
            auth=self.folder/'xauthority'
            fields=[socket.gethostname().encode(),b'77',b'MIT-MAGIC-COOKIE-1',secrets.token_bytes(16)]
            auth.write_bytes(struct.pack('!H',256)+b''.join(struct.pack('!H',len(v))+v for v in fields));auth.chmod(0o600)
            env={**os.environ,'HOME':str(self.folder),'DISPLAY':':77','XAUTHORITY':str(auth)}
            self.xvfb=subprocess.Popen(['/usr/bin/Xvfb',':77','-screen','0','1100x850x24','-nolisten','tcp','-auth',str(auth)],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            for _ in range(50):
                if self.xvfb.poll() is not None:raise RuntimeError('Private browser display failed.')
                if Path('/tmp/.X11-unix/X77').exists():break
                time.sleep(.1)
            cr,cw=os.pipe();rr,rw=os.pipe()
            try:
                proc=subprocess.Popen(['/usr/bin/python3','-s','-m','studio.browser_session','launch',str(cr),str(rw),str(self.folder/'profile')],pass_fds=(cr,rw),env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            finally:os.close(cr);os.close(rw)
            self.cdp=CDP(proc,rr,cw,self.event)
            self.browser_identity=self.cdp.send('Browser.getVersion',timeout=15)
            targets=self.cdp.send('Target.getTargets')['targetInfos']
            self.target=next(t['targetId'] for t in targets if t['type']=='page')
            self.session=self.cdp.send('Target.attachToTarget',{'targetId':self.target,'flatten':True})['sessionId']
            self.main_frame=self.call('Page.getFrameTree')['frameTree']['frame']['id']
            self.cdp.send('Target.setDiscoverTargets',{'discover':True})
            self.cdp.send('Browser.setDownloadBehavior',{'behavior':'deny'})
            for method,params in [('Page.enable',{}),('Network.enable',{}),('Page.setInterceptFileChooserDialog',{'enabled':True}),
                    ('Emulation.setDeviceMetricsOverride',{'width':WIDTH,'height':HEIGHT,'deviceScaleFactor':1,'mobile':False}),
                    ('Fetch.enable',{'patterns':[{'urlPattern':'*'}]})]:self.call(method,params)
        except Exception:
            self.close();raise RuntimeError('Browser startup failed; verify Chromium sandbox and display support.') from None

    def call(self,method,params=None,**kwargs):return self.cdp.send(method,params,self.session,**kwargs)

    def event(self,event):
        method,p=event.get('method'),event.get('params',{})
        if method=='Fetch.requestPaused':
            allowed=allowed_url(p.get('request',{}).get('url',''))
            self.cdp.send('Fetch.continueRequest' if allowed else 'Fetch.failRequest',
                          {'requestId':p['requestId'],**({} if allowed else {'errorReason':'BlockedByClient'})},event.get('sessionId'),wait=False)
        elif method=='Target.targetCreated':
            info=p['targetInfo']
            if info['type']=='page' and self.target and info['targetId']!=self.target:
                self.cdp.send('Target.closeTarget',{'targetId':info['targetId']},wait=False)
        elif method=='Network.responseReceived' and p.get('type')=='Document' and event.get('sessionId')==self.session and p.get('frameId')==getattr(self,'main_frame',None):
            from .engine import parse_retry_after
            self.ready=False
            r=p['response'];headers={k.lower():v for k,v in r.get('headers',{}).items()}
            delay=parse_retry_after(headers.get('retry-after'))
            self.document={'url':r.get('url',''),'status':int(r['status']),'challenge':headers.get('cf-mitigated','').lower()=='challenge','frame':p.get('frameId'),
                           'retry_after':'unbounded' if delay is not None and not math.isfinite(delay) else delay}
            self.page_url=r.get('url','')
        elif method=='Network.requestWillBeSent' and p.get('type')=='Document' and event.get('sessionId')==self.session and p.get('frameId')==getattr(self,'main_frame',None):
            self.ready=False;self.document={};self.page_url=p.get('request',{}).get('url','')
        elif method=='Page.navigatedWithinDocument' and event.get('sessionId')==self.session and p.get('frameId')==getattr(self,'main_frame',None):
            self.ready=False;self.page_url=p.get('url','')
        elif method=='Page.javascriptDialogOpening':self.call('Page.handleJavaScriptDialog',{'accept':False},wait=False)

    def navigate(self,url):
        resource_url(url);self.expected=url;self.document={};self.ready=False;self.page_url=url
        result=self.call('Page.navigate',{'url':url})
        if result.get('errorText'):
            code = 'TLS_CERTIFICATE' if 'ERR_CERT_' in result['errorText'] else 'BROWSER_NETWORK'
            raise RuntimeError(f'[{code}] Browser navigation failed.')
        return self.status()

    def html(self):
        result=self.call('Runtime.evaluate',{'expression':'JSON.stringify({url:location.href,html:document.documentElement.outerHTML})','returnByValue':True})
        value=result.get('result',{}).get('value','')
        if not isinstance(value,str) or len(value.encode())>LIMIT:raise RuntimeError('[RESPONSE_SIZE] Browser page exceeds limit.')
        return json.loads(value)

    def status(self):
        doc=self.document
        current=getattr(self,'page_url','') or doc.get('url','')
        off_task=bool(self.expected and current and not same_facet(current,self.expected))
        checked=getattr(self,'_checked_page',None)
        page_state=checked[2] if checked and checked[0] is doc and checked[1]==current else None
        return {'running':True,'backend':getattr(self,'backend','chromium'),'state':'rate_limited' if doc.get('status')==429 else 'browser_challenge' if doc.get('challenge') else 'access_denied' if doc.get('status') in (401,403) else page_state or ('off_task_page' if off_task else 'ready' if self.ready else 'awaiting_verification'),
                'can_return_to_results':off_task,'http_status':doc.get('status'),'host':urlsplit(current).hostname or '', 'width':WIDTH,'height':HEIGHT,
                'login_status':getattr(self,'login_status',None),
                'browser_version':getattr(self,'browser_identity',{}).get('product',''),
                'user_agent':getattr(self,'browser_identity',{}).get('userAgent','')}

    def inspect_page(self, page):
        from .engine import FacetParseError, parse_facet_html
        self.ready=False
        self._checked_page=None
        self.page_url=page['url']
        doc=self.document
        if not self.expected or doc.get('url')!=page['url'] or doc.get('challenge') or doc.get('status')!=200:
            return self.status()
        resource=resource_url(self.expected)
        on_task=same_facet(page['url'],self.expected) and same_facet(doc.get('url'),self.expected)
        try:
            if resource[0] == 'host':
                from .enrichment import parse_host_html
                parse_host_html(page['html'],resource[1])
            else:
                _,query,facet=resource
                parse_facet_html(page['html'],facet,query,allow_missing_facet=facet!='ip')
        except FacetParseError as exc:
            tag=str(exc).partition(']')[0]
            state={'[LOGIN':'login_required','[ACCESS':'browser_challenge','[DENIED':'access_denied'}.get(tag)
            self._checked_page=(doc,page['url'],state or ('invalid_page' if on_task else 'off_task_page'))
        else:
            self.ready=on_task
        return self.status()

    def verify(self, return_to_results=False):
        self.ready=False
        page=self.html()
        self.page_url=page['url']
        # Explicit user action only. Keep the current tab, cookies, VPN and the
        # exact pending facet selected by the worker; never accept a caller URL.
        if return_to_results and self.expected and not same_facet(page['url'],self.expected):
            return self.navigate(self.expected)
        return self.inspect_page(page)

    def fetch(self,url):
        from .engine import http_failure
        from email.message import Message
        resource_url(url)
        def source_failure():
            # Check the current main document before navigation can erase it.
            # A different facet/login URL does not authorize retrying a denial.
            doc=self.document
            if doc.get('status',0)>=400 or doc.get('challenge'):
                if doc.get('status')==429:
                    return {'http_status':429,'retry_after':doc.get('retry_after')}
                headers=Message()
                if doc.get('challenge'):headers['cf-mitigated']='challenge'
                raise RuntimeError(str(http_failure(403 if doc.get('challenge') else doc['status'],headers)))
            return None
        failure=source_failure()
        if failure is not None:return failure
        verified=self.verify()
        browser_page_failure(verified['state'])
        if not same_facet(self.expected,url) or verified['state']!='ready':
            # Verification reads the DOM while response events can arrive.
            failure=source_failure()
            if failure is not None:return failure
            self.navigate(url)
        deadline=time.monotonic()+25
        while time.monotonic()<deadline:
            failure=source_failure()
            if failure is not None:return failure
            verified=self.verify()
            browser_page_failure(verified['state'])
            if verified['state']=='ready':return {'html':self.html()['html']}
            time.sleep(.25)
        raise RuntimeError('[HTML_PARSE] تعذر قراءة صفحة المرشح المطلوبة؛ لم تظهر صفحة تحقق أو تسجيل دخول. أعد محاولة الطلب.')

    def login(self, data):
        from .shodan_login import LOGIN_URL, login_expression
        expression = login_expression(data)
        self.expected = data['return_url']; self.ready = False; self.login_status = 'verification_required'
        self.document = {}; self.page_url = LOGIN_URL
        result = self.call('Page.navigate', {'url':LOGIN_URL})
        if result.get('errorText'): raise RuntimeError('تعذر فتح صفحة تسجيل الدخول إلى Shodan.')
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            # Wait for the main document; never evaluate credentials on an old
            # task page while a navigation is still pending.
            if self.document.get('url','').startswith(LOGIN_URL):
                loaded = self.call('Runtime.evaluate', {'expression':
                    "location.origin==='https://account.shodan.io' && ['/login','/login/'].includes(location.pathname) && document.readyState!=='loading'", 'returnByValue':True})
                if loaded.get('result',{}).get('value') is True:break
                time.sleep(.1)
                continue
            if self.document.get('url'):
                self.login_status = 'not_login_page'
                return self.status()
            time.sleep(.1)
        self.login_status = 'verification_required'
        if self.document.get('status') == 200 and not self.document.get('challenge'):
            result = self.call('Runtime.evaluate', {'expression':expression,'returnByValue':True})
            value = result.get('result',{}).get('value')
            if value in ('submitted','verification_required','not_login_page','unsafe_form'): self.login_status = value
        return self.status()

    def action(self,data):
        op=data.get('action')
        if op=='login':return self.login(data)
        if op=='navigate' and set(data)=={'action','url'}:return self.navigate(data['url'])
        if op=='fetch' and set(data)=={'action','url'}:return self.fetch(data['url'])
        if op=='verify' and set(data)=={'action'}:return self.verify()
        if op=='verify' and set(data)=={'action','return_to_results'} and data['return_to_results'] is True:
            return self.verify(return_to_results=True)
        if op=='frame' and set(data)=={'action'}:
            # Read the loaded page automatically; never submit, navigate or resume.
            if self.expected and self.document.get('status')==200:
                try:self.verify()
                except (RuntimeError, ValueError):
                    self.ready=False;self._checked_page=None
            for attempt in range(3):
                try:
                    frame=self.call('Page.captureScreenshot',{'format':'jpeg','quality':65,'captureBeyondViewport':False})['data']
                    break
                except RuntimeError:
                    if attempt==2:raise
                    time.sleep(.3)
            if len(frame)>800000:raise RuntimeError('Browser frame exceeds limit.')
            return {**self.status(),'image':'data:image/jpeg;base64,'+frame}
        if op=='click' and set(data)=={'action','x','y'} and all(type(data[k]) is int and 0<=data[k]<bound for k,bound in [('x',WIDTH),('y',HEIGHT)]):
            self.ready=False
            for kind in ('mousePressed','mouseReleased'):self.call('Input.dispatchMouseEvent',{'type':kind,'x':data['x'],'y':data['y'],'button':'left','clickCount':1})
        elif op=='key' and set(data)=={'action','key'} and data['key'] in KEYS:
            self.ready=False
            key=data['key']
            for kind in ('keyDown','keyUp'):self.call('Input.dispatchKeyEvent',{'type':kind,'key':key,'windowsVirtualKeyCode':KEYS[key],**({'text':'\r'} if key=='Enter' and kind=='keyDown' else {})})
        elif op=='text' and set(data)=={'action','text'} and isinstance(data['text'],str) and 0<len(data['text'])<=1024 and all(ord(c)>=32 and ord(c)!=127 for c in data['text']):
            self.ready=False
            self.call('Input.insertText',{'text':data['text']})
        elif op=='scroll' and set(data)=={'action','delta'} and type(data['delta']) is int and abs(data['delta'])<=700:
            self.call('Input.dispatchMouseEvent',{'type':'mouseWheel','x':WIDTH//2,'y':HEIGHT//2,'deltaX':0,'deltaY':data['delta']})
        else:raise ValueError('Browser input is not allowed.')
        return self.status()

    def close(self):
        if self.cdp:self.cdp.close()
        if self.xvfb:
            self.xvfb.terminate()
            try:self.xvfb.wait(timeout=3)
            except subprocess.TimeoutExpired:self.xvfb.kill();self.xvfb.wait()


def main():
    os.umask(0o077)
    session=None
    try:
        session=Session(sys.argv[1])
        print(json.dumps({'ok':True,'result':session.status()}),flush=True)
        for raw in sys.stdin.buffer:
            try:
                if len(raw)>1024*1024:raise ValueError('Browser request exceeds limit.')
                data=json.loads(raw)
                if data=={'action':'stop'}:break
                result=session.action(data)
                print(json.dumps({'ok':True,'result':result}),flush=True)
            except Exception as exc:
                text=str(exc) if type(exc) in (ValueError,RuntimeError) else 'Browser operation failed.'
                print(json.dumps({'ok':False,'error':text[:500]}),flush=True)
    except Exception:print(json.dumps({'ok':False,'error':'Browser startup failed; sandbox/display required.'}),flush=True)
    finally:
        if session:session.close()


if __name__=='__main__':
    if len(sys.argv)>1 and sys.argv[1]=='launch':launch_chromium()
    else:main()
