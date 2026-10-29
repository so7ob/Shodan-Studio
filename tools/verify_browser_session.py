#!/usr/bin/env python3
"""Opt-in real Chromium test in a separate, disconnected systemd namespace."""
import argparse
import base64
import json
import os
from pathlib import Path
import pwd
import shutil
import socket
import subprocess
import sys
import time
import uuid


def inside(folder, backend='chromium'):
    if backend == 'patchright':
        import asyncio
        return asyncio.run(inside_patchright(folder))
    from studio.browser_session import Session
    from studio.engine import build_url
    from studio.worker import DemoData
    target=build_url('fixture country:DE','ip')
    login='https://account.shodan.io/login'
    landing='https://www.shodan.io/dashboard'
    class LoginFixture(Session):
        """Fulfill synthetic HTTPS responses through CDP in the disconnected lab."""
        def event(self,event):
            if event.get('method')!='Fetch.requestPaused':return super().event(event)
            p=event['params'];request=p['request'];url=request['url']
            headers=[];status=200
            if url==target:
                cookie=next((str(v) for k,v in request.get('headers',{}).items() if k.lower()=='cookie'),'')
                if 'studio_fixture=synthetic' in cookie:
                    body=DemoData('fixture').fetch(target)
                else:status=302;headers=[{'name':'Location','value':login}];body=''
            elif url==login:
                body='<html><body><form action="'+landing+'" method="GET"><button style="position:absolute;left:20px;top:20px;width:200px;height:60px">Synthetic sign in</button></form></body></html>'
            elif url.rstrip('?')==landing:
                body='<html><body>Synthetic account landing page; not facet results</body></html>'
                headers=[{'name':'Set-Cookie','value':'studio_fixture=synthetic; Domain=.shodan.io; Path=/; Secure; HttpOnly; SameSite=Lax'}]
            else:
                self.cdp.send('Fetch.failRequest',{'requestId':p['requestId'],'errorReason':'BlockedByClient'},event.get('sessionId'),wait=False)
                return
            self.cdp.send('Fetch.fulfillRequest',{'requestId':p['requestId'],'responseCode':status,
                'responseHeaders':headers+[{'name':'Content-Type','value':'text/html; charset=utf-8'}],
                'body':base64.b64encode(body.encode()).decode()},event.get('sessionId'),wait=False)
    def until(check):
        deadline=time.monotonic()+8
        while time.monotonic()<deadline:
            if check():return
            time.sleep(.1)
        raise AssertionError('Synthetic browser transition timed out.')
    s=LoginFixture(folder)
    try:
        s.call('Page.setDocumentContent',{'frameId':s.main_frame,'html':'<html><body><input id="field" aria-label="Fixture" style="position:absolute;left:20px;top:20px;width:200px;height:50px"><p>Synthetic offline fixture</p></body></html>'})
        s.action({'action':'click','x':70,'y':40});s.action({'action':'text','text':'fixture-text'})
        value=s.call('Runtime.evaluate',{'expression':'document.getElementById("field").value','returnByValue':True})['result']['value']
        assert value=='fixture-text'
        frame=s.action({'action':'frame'});assert frame['image'].startswith('data:image/jpeg;base64,')
        # A real headed browser follows login/landing redirects, retains its
        # synthetic HttpOnly cookie, and returns to the exact pending task URL.
        s.navigate(target);until(lambda:s.document.get('url')==login)
        until(lambda:s.html()['url']==login)
        s.action({'action':'click','x':70,'y':40})
        until(lambda:s.document.get('url','').rstrip('?')==landing)
        until(lambda:s.html()['url'].rstrip('?')==landing)
        for _ in range(6):assert s.action({'action':'verify'})['state']=='off_task_page'
        s.action({'action':'verify','return_to_results':True})
        until(lambda:s.verify()['state']=='ready')
        assert s.expected==target and s.status()['can_return_to_results'] is False
        s.call('Page.navigate',{'url':'chrome://sandbox'})
        for _ in range(30):
            sandbox=s.call('Runtime.evaluate',{'expression':'document.body.innerText','returnByValue':True})['result'].get('value','')
            if 'Seccomp-BPF' in sandbox:break
            time.sleep(.1)
        assert 'Layer 1 Sandbox\tNamespace' in sandbox and 'PID namespaces\tYes' in sandbox and 'Network namespaces\tYes' in sandbox and 'Seccomp-BPF sandbox\tYes' in sandbox, sandbox
        try:
            socket.create_connection(('1.1.1.1',443),timeout=2).close()
            raise AssertionError('Disconnected test namespace leaked!')
        except OSError:pass
        assert os.readlink('/proc/self/ns/net')!=os.environ['STUDIO_TEST_HOST_NETNS']
        status=Path('/proc/self/status').read_text()
        assert 'CapEff:\t0000000000000000' in status and 'NoNewPrivs:\t1' in status
        print(json.dumps(dict(real_chromium=True,headed_xvfb=True,manual_input_transport=True,
            frame_bytes=len(frame['image']),uid=os.getuid(),namespace_isolated=True,
            disconnected_namespace_leak_blocked=True,namespace_sandbox=True,seccomp_sandbox=True,
            capabilities_zero=True,no_new_privileges=True,no_shodan_requests=True,
            synthetic_login_redirect=True,landing_page_blocked=True,
            explicit_return_to_pending_facet=True,synthetic_cookie_retained=True)))
    finally:s.close()


async def inside_patchright(folder):
    import asyncio
    from studio.patchright_session import PatchrightSession
    from studio.engine import build_url
    from studio.worker import DemoData
    target = build_url('fixture country:DE', 'ip')
    login = 'https://account.shodan.io/login'
    landing = 'https://www.shodan.io/dashboard'
    calls = []
    s = PatchrightSession(folder)
    try:
        await s.start()
        await s.context.unroute('**/*')
        async def fixture(route):
            url = route.request.url; calls.append(url)
            if url == target:
                headers = await route.request.all_headers()
                if 'studio_fixture=synthetic' in headers.get('cookie', ''):
                    return await route.fulfill(status=200, content_type='text/html', body=DemoData('fixture').fetch(target))
                return await route.fulfill(status=403, headers={'cf-mitigated':'challenge','Content-Type':'text/html'},
                    body='<html><body><a href="'+login+'" style="position:absolute;left:20px;top:20px;width:200px;height:60px">Synthetic login</a></body></html>')
            if url == login:
                return await route.fulfill(status=200, content_type='text/html',
                    body='<html><body><form action="'+landing+'"><button style="position:absolute;left:20px;top:20px;width:200px;height:60px">Synthetic sign in</button></form></body></html>')
            if url.rstrip('?') == landing:
                return await route.fulfill(status=200, headers={'Content-Type':'text/html',
                    'Set-Cookie':'studio_fixture=synthetic; Domain=.shodan.io; Path=/; Max-Age=3600; Secure; HttpOnly; SameSite=Lax'},
                    body='<html><body>Account landing; not facet results</body></html>')
            return await s.route(route)
        await s.context.route('**/*', fixture)
        await s.page.set_content('<html><body><input id="field" style="position:absolute;left:20px;top:20px;width:200px;height:50px"></body></html>')
        await s.action({'action':'click','x':70,'y':40})
        await s.action({'action':'text','text':'fixture-text'})
        assert await s.page.locator('#field').input_value() == 'fixture-text'
        frame = await s.action({'action':'frame'})
        assert frame['image'].startswith('data:image/jpeg;base64,')
        assert frame['width'] > 0 and frame['height'] > 0
        await s.navigate(target)
        assert (await s.verify())['state'] == 'browser_challenge'
        count = len(calls)
        for _ in range(6): assert (await s.verify())['state'] == 'browser_challenge'
        assert len(calls) == count
        for _ in range(3):
            try: await s.fetch(target)
            except RuntimeError as exc: assert 'BROWSER_CHALLENGE' in str(exc)
            else: raise AssertionError('Denied document was accepted')
        assert len(calls) == count
        await s.action({'action':'click','x':70,'y':40})
        await s.page.wait_for_url(login)
        await s.action({'action':'click','x':70,'y':40})
        await s.page.wait_for_url(landing+'*')
        for _ in range(6): assert (await s.verify())['state'] == 'off_task_page'
        await s.verify(return_to_results=True)
        assert (await s.verify())['state'] == 'ready'
        assert 'html' in await s.fetch(target)
        assert s.expected == target
        await s.page.set_content('<html><body>Invalid facet content</body></html>')
        assert (await s.verify())['state'] != 'ready'
        await s.page.set_content(DemoData('fixture').fetch(target))
        assert (await s.verify())['state'] == 'ready'
        await s.close()
        s = PatchrightSession(folder)
        await s.start()
        await s.context.unroute('**/*'); await s.context.route('**/*', fixture)
        await s.navigate(target)
        assert (await s.verify())['state'] == 'ready', 'Persistent profile lost its login cookie'
        await s.page.goto('chrome://sandbox')
        sandbox = await s.page.locator('body').inner_text()
        assert 'PID namespaces\tYes' in sandbox and 'Seccomp-BPF sandbox\tYes' in sandbox, sandbox
        try:
            socket.create_connection(('1.1.1.1',443),timeout=2).close()
            raise AssertionError('Disconnected namespace leaked')
        except OSError: pass
        # The normal backend route rejects loopback before any network request.
        try: await s.page.goto('https://127.0.0.1/private', timeout=3000)
        except Exception: pass
        else: raise AssertionError('Disallowed origin accepted')
        status = Path('/proc/self/status').read_text()
        assert os.readlink('/proc/self/ns/net') != os.environ['STUDIO_TEST_HOST_NETNS']
        assert 'CapEff:\t0000000000000000' in status and 'NoNewPrivs:\t1' in status
        await s.close()
        pipe = subprocess.run([sys.executable, '-s', '-m', 'studio.patchright_session', str(Path(folder)/'pipe')],
            input=b'{"action":"frame"}\n{"action":"stop"}\n', capture_output=True, timeout=25, check=True)
        replies = [json.loads(line) for line in pipe.stdout.splitlines()]
        assert len(replies) == 2 and all(reply['ok'] for reply in replies)
        assert replies[0]['result']['backend'] == 'patchright'
        assert replies[1]['result']['image'].startswith('data:image/jpeg;base64,')
        print(json.dumps(dict(backend='patchright',real_browser=True,headed_xvfb=True,
            browser_version=s.browser_version,manual_input=True,frame_bytes=len(frame['image']),
            namespace_isolated=True,seccomp_sandbox=True,capabilities_zero=True,no_new_privileges=True,
            blocked_origin=True,no_shodan_requests=True,challenge_not_reloaded=True,
            login_cookie_retained=True,persistent_cookie_after_restart=True,malformed_facet_rejected=True,private_json_pipe=True,
            landing_page_blocked=True,explicit_return_to_pending_facet=True)))
    finally: await s.close()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run-root-lab',action='store_true')
    parser.add_argument('--inside-lab')
    parser.add_argument('--backend', choices=('chromium','patchright'), default='chromium')
    args=parser.parse_args()
    if args.inside_lab:return inside(args.inside_lab,args.backend)
    if not args.run_root_lab or os.getuid()!=0:parser.error('Explicit --run-root-lab and root required.')
    root=Path(__file__).resolve().parents[1];ident=uuid.uuid4().hex[:10]
    code=Path('/opt/shodan-studio')/('browser-test-'+ident)
    folder=Path('/var/lib/shodan-studio-browser')/('test-'+ident)
    account=pwd.getpwnam('shodan-browser');assert account.pw_uid!=0
    sys.path.insert(0,str(root))
    from studio.browser_broker import browser_guard
    # Parse with the real nft binary in a throwaway network namespace.
    subprocess.run(['unshare','--net','nft','--check','-f','-'],input=browser_guard(account.pw_uid),text=True,check=True)
    try:
        code.mkdir(mode=0o755);shutil.copytree(root/'studio',code/'studio',ignore=shutil.ignore_patterns('__pycache__'))
        shutil.copyfile(__file__,code/'verify_browser.py')
        folder.mkdir(mode=0o700);os.chown(folder,account.pw_uid,account.pw_gid)
        argv=['systemd-run','--quiet','--wait','--pipe','--collect','--unit=shodan-browser-test-'+ident,
            '-p','User=shodan-browser','-p','Group=shodan-browser','-p','PrivateNetwork=yes',
            '-p','PrivateTmp=yes','-p','ProtectSystem=strict','-p','ProtectHome=yes',
            '-p','NoNewPrivileges=yes','-p','CapabilityBoundingSet=',
            '-p','RestrictNamespaces=net mnt user pid ipc uts','-p','RuntimeMaxSec=60',
            '--setenv=STUDIO_TEST_HOST_NETNS='+os.readlink('/proc/self/ns/net'),
            '-p','WorkingDirectory='+str(code),'-p','ReadWritePaths='+str(folder),
            '--setenv=PLAYWRIGHT_BROWSERS_PATH=/opt/shodan-studio/browser-runtime/browsers',
            '/opt/shodan-studio/browser-runtime/venv/bin/python3' if args.backend=='patchright' else '/usr/bin/python3',
            '-s',str(code/'verify_browser.py'),'--inside-lab',str(folder),'--backend',args.backend]
        subprocess.run(argv,check=True,timeout=70)
    finally:
        subprocess.run(['systemctl','stop','shodan-browser-test-'+ident],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        shutil.rmtree(code,ignore_errors=True);shutil.rmtree(folder,ignore_errors=True)


if __name__=='__main__':main()
