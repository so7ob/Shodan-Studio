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
    try:return facet_url(url)==facet_url(expected)
    except (ValueError,TypeError):return False


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
            self.cdp.send('Browser.getVersion',timeout=15)
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
            self.document={'url':r.get('url',''),'status':int(r['status']),'challenge':headers.get('cf-mitigated')=='challenge','frame':p.get('frameId'),
                           'retry_after':'unbounded' if delay is not None and not math.isfinite(delay) else delay}
            self.page_url=r.get('url','')
        elif method=='Network.requestWillBeSent' and p.get('type')=='Document' and event.get('sessionId')==self.session and p.get('frameId')==getattr(self,'main_frame',None):
            self.ready=False;self.document={};self.page_url=p.get('request',{}).get('url','')
        elif method=='Page.navigatedWithinDocument' and event.get('sessionId')==self.session and p.get('frameId')==getattr(self,'main_frame',None):
            self.ready=False;self.page_url=p.get('url','')
        elif method=='Page.javascriptDialogOpening':self.call('Page.handleJavaScriptDialog',{'accept':False},wait=False)

    def navigate(self,url):
        facet_url(url);self.expected=url;self.document={};self.ready=False;self.page_url=url
        result=self.call('Page.navigate',{'url':url})
        if result.get('errorText'):raise RuntimeError('[BROWSER_NETWORK] Browser navigation failed.')
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
        return {'running':True,'state':'browser_challenge' if doc.get('challenge') else 'rate_limited' if doc.get('status')==429 else 'access_denied' if doc.get('status') in (401,403) else 'off_task_page' if off_task else 'ready' if self.ready else 'awaiting_verification',
                'can_return_to_results':off_task,'http_status':doc.get('status'),'host':urlsplit(current).hostname or '', 'width':WIDTH,'height':HEIGHT}

    def verify(self, return_to_results=False):
        from .engine import parse_facet_html
        self.ready=False
        page=self.html()
        self.page_url=page['url']
        # Explicit user action only. Keep the current tab, cookies, VPN and the
        # exact pending facet selected by the worker; never accept a caller URL.
        if return_to_results and self.expected and not same_facet(page['url'],self.expected):
            return self.navigate(self.expected)
        result=self.status()
        if not same_facet(page['url'],self.expected) or not same_facet(self.document.get('url'),self.expected) or self.document.get('challenge') or self.document.get('status')!=200:return result
        query,facet=facet_url(self.expected)
        try:parse_facet_html(page['html'],facet,query)
        except Exception:return result
        self.ready=True
        return {**result,'state':'ready'}

    def fetch(self,url):
        from .engine import http_failure
        from email.message import Message
        facet_url(url)
        if not same_facet(self.expected,url) or self.verify()['state']!='ready':self.navigate(url)
        deadline=time.monotonic()+25
        while time.monotonic()<deadline:
            doc=self.document
            if same_facet(doc.get('url'),url) and doc.get('status',0)>=400:
                if doc['status']==429:
                    return {'http_status':429,'retry_after':doc.get('retry_after')}
                headers=Message()
                if doc.get('challenge'):headers['cf-mitigated']='challenge'
                raise RuntimeError(str(http_failure(doc['status'],headers)))
            if self.verify()['state']=='ready':return {'html':self.html()['html']}
            time.sleep(.25)
        raise RuntimeError('[BROWSER_INPUT] افتح جلسة المتصفح وأكمل التحقق أو تسجيل الدخول يدويًا؛ لم تُستخرج نتائج غير متحققة.')

    def action(self,data):
        op=data.get('action')
        if op=='navigate' and set(data)=={'action','url'}:return self.navigate(data['url'])
        if op=='fetch' and set(data)=={'action','url'}:return self.fetch(data['url'])
        if op=='verify' and set(data)=={'action'}:return self.verify()
        if op=='verify' and set(data)=={'action','return_to_results'} and data['return_to_results'] is True:
            return self.verify(return_to_results=True)
        if op=='frame' and set(data)=={'action'}:
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
