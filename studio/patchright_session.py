"""Optional headed Patchright backend; the broker owns identity and isolation."""
from __future__ import annotations

import asyncio
import base64
import contextlib
import json
import math
import os
from pathlib import Path
import secrets
import socket
import struct
import subprocess
import sys

from .browser_session import Session, allowed_url, facet_url, same_facet, LIMIT, KEYS
from .engine import parse_facet_html, parse_retry_after, http_failure
from email.message import Message


class PatchrightSession:
    backend = 'patchright'
    status = Session.status

    def __init__(self, folder):
        self.folder = Path(folder)
        self.document = {}; self.expected = None; self.ready = False; self.page_url = ''
        self.width, self.height = 1100, 760
        self.xvfb = self.driver = self.context = self.page = None

    async def start(self):
        from patchright.async_api import async_playwright
        self.folder.mkdir(mode=0o700, parents=True, exist_ok=True)
        auth = self.folder / 'xauthority'
        fields = [socket.gethostname().encode(), b'77', b'MIT-MAGIC-COOKIE-1', secrets.token_bytes(16)]
        auth.write_bytes(struct.pack('!H', 256) + b''.join(struct.pack('!H', len(v)) + v for v in fields))
        auth.chmod(0o600)
        env = {**os.environ, 'HOME': str(self.folder), 'DISPLAY': ':77', 'XAUTHORITY': str(auth)}
        self.xvfb = subprocess.Popen(['/usr/bin/Xvfb', ':77', '-screen', '0', '1100x850x24',
                                     '-nolisten', 'tcp', '-auth', str(auth)], env=env,
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(50):
            if self.xvfb.poll() is not None: raise RuntimeError('Private browser display failed.')
            if Path('/tmp/.X11-unix/X77').exists(): break
            await asyncio.sleep(.1)
        self.driver = await async_playwright().start()
        self.context = await self.driver.chromium.launch_persistent_context(
            str(self.folder / 'profile'), headless=False, no_viewport=True, chromium_sandbox=True,
            accept_downloads=False, service_workers='block', env=env,
            args=['--window-size=1100,850', '--no-first-run', '--disable-background-networking',
                  '--disable-sync', '--disk-cache-size=16777216', '--media-cache-size=16777216'])
        self.context.set_default_timeout(12000)
        self.context.set_default_navigation_timeout(25000)
        await self.context.route('**/*', self.route)
        await self.context.route_web_socket('**/*', lambda ws: ws.close())
        self.page = self.context.pages[0] if self.context.pages else await self.context.new_page()
        self.context.on('page', lambda page: asyncio.create_task(page.close()) if page != self.page else None)
        self.page.on('filechooser', lambda chooser: None)
        self.page.on('download', lambda download: asyncio.create_task(download.cancel()))
        self.page.on('dialog', lambda dialog: asyncio.create_task(dialog.dismiss()))
        self.page.on('request', self.request_event)
        self.page.on('response', self.response_event)
        self.page.on('framenavigated', self.frame_event)
        self.browser_version = self.context.browser.version
        self.user_agent = await self.page.evaluate('navigator.userAgent')
        return await self.status_result(measure=True)

    async def route(self, route):
        if allowed_url(route.request.url): await route.continue_()
        else: await route.abort()

    def request_event(self, request):
        if request.is_navigation_request() and request.frame == self.page.main_frame:
            self.ready = False; self.document = {}; self.page_url = request.url

    def response_event(self, response):
        request = response.request
        if not request.is_navigation_request() or request.frame != self.page.main_frame: return
        headers = response.headers
        delay = parse_retry_after(headers.get('retry-after'))
        self.ready = False; self.page_url = response.url
        self.document = {'url': response.url, 'status': response.status,
                         'challenge': headers.get('cf-mitigated', '').lower() == 'challenge',
                         'retry_after': 'unbounded' if delay is not None and not math.isfinite(delay) else delay}

    def frame_event(self, frame):
        if frame == self.page.main_frame:
            self.page_url = frame.url; self.ready = False

    async def status_result(self, measure=False):
        if self.page and measure:
            from patchright.async_api import Error
            try:
                dimensions = await self.page.evaluate('({width:innerWidth,height:innerHeight})')
                self.width, self.height = dimensions['width'], dimensions['height']
            except Error as exc:
                if 'Execution context was destroyed' not in str(exc): raise
                self.ready = False
        return {**self.status(), 'width': self.width, 'height': self.height,
                'browser_version': getattr(self, 'browser_version', ''),
                'user_agent': getattr(self, 'user_agent', '')}

    async def navigate(self, url):
        from patchright.async_api import Error
        facet_url(url); self.expected = url; self.ready = False; self.document = {}; self.page_url = url
        try:
            await self.page.goto(url, wait_until='commit', timeout=25000)
        except Error as exc:
            code = 'TLS_CERTIFICATE' if 'ERR_CERT_' in str(exc) else 'BROWSER_NETWORK'
            raise RuntimeError(f'[{code}] Browser navigation failed.') from None
        return await self.status_result()

    async def html(self):
        value = await self.page.evaluate('JSON.stringify({url:location.href,html:document.documentElement.outerHTML})')
        if not isinstance(value, str) or len(value.encode()) > LIMIT:
            raise RuntimeError('[RESPONSE_SIZE] Browser page exceeds limit.')
        return json.loads(value)

    async def verify(self, return_to_results=False):
        self.ready = False
        from patchright.async_api import Error
        try: page = await self.html()
        except Error as exc:
            if 'Execution context was destroyed' not in str(exc): raise
            return await self.status_result()
        self.page_url = page['url']
        if return_to_results and self.expected and not same_facet(page['url'], self.expected):
            return await self.navigate(self.expected)
        result = await self.status_result()
        if (not same_facet(page['url'], self.expected) or not same_facet(self.document.get('url'), self.expected)
                or self.document.get('challenge') or self.document.get('status') != 200): return result
        query, facet = facet_url(self.expected)
        try: parse_facet_html(page['html'], facet, query)
        except (ValueError, RuntimeError): return result
        self.ready = True
        return {**result, 'state': 'ready'}

    def source_failure(self):
        doc = self.document
        if doc.get('status') == 429:
            return {'http_status': 429, 'retry_after': doc.get('retry_after')}
        if doc.get('status', 0) >= 400 or doc.get('challenge'):
            headers = Message()
            if doc.get('challenge'): headers['cf-mitigated'] = 'challenge'
            raise RuntimeError(str(http_failure(doc.get('status', 403), headers)))
        return None

    async def fetch(self, url):
        facet_url(url)
        failure = self.source_failure()
        if failure is not None: return failure
        if not same_facet(self.expected, url) or (await self.verify())['state'] != 'ready':
            failure = self.source_failure()
            if failure is not None: return failure
            await self.navigate(url)
        deadline = asyncio.get_running_loop().time() + 25
        while asyncio.get_running_loop().time() < deadline:
            failure = self.source_failure()
            if failure is not None: return failure
            if (await self.verify())['state'] == 'ready':
                return {'html': (await self.html())['html'], 'user_agent': self.user_agent, 'backend': self.backend}
            await asyncio.sleep(.25)
        raise RuntimeError('[BROWSER_INPUT] أكمل التحقق أو تسجيل الدخول يدويًا ثم افحص الصفحة.')

    async def login(self, data):
        from .shodan_login import LOGIN_URL, LOGIN_FUNCTION, login_payload
        from patchright.async_api import Error
        payload = login_payload(data)
        self.expected = data['return_url']; self.ready = False; self.login_status = 'verification_required'
        self.document = {}; self.page_url = LOGIN_URL
        try:
            await self.page.goto(LOGIN_URL, wait_until='domcontentloaded', timeout=20000)
            if self.document.get('status') == 200 and not self.document.get('challenge'):
                value = await self.page.evaluate(LOGIN_FUNCTION, payload)
                if value in ('submitted','verification_required','not_login_page','unsafe_form'): self.login_status = value
        except Error:
            # Browser exception messages can contain evaluated arguments.
            raise RuntimeError('تعذر إكمال تسجيل الدخول؛ راجع صفحة المتصفح.') from None
        return await self.status_result()

    async def action(self, data):
        op = data.get('action')
        if op == 'login': return await self.login(data)
        if op in ('navigate', 'fetch') and set(data) == {'action', 'url'}:
            return await getattr(self, op)(data['url'])
        if op == 'verify' and (set(data) == {'action'} or
                set(data) == {'action', 'return_to_results'} and data['return_to_results'] is True):
            return await self.verify(data.get('return_to_results', False))
        if op == 'frame' and set(data) == {'action'}:
            frame = await self.page.screenshot(type='jpeg', quality=65, timeout=12000)
            encoded = base64.b64encode(frame).decode()
            if len(encoded) > 800000: raise RuntimeError('Browser frame exceeds limit.')
            return {**await self.status_result(measure=True), 'image': 'data:image/jpeg;base64,' + encoded}
        if op == 'click' and set(data) == {'action', 'x', 'y'} and all(
                type(data[k]) is int and 0 <= data[k] < limit for k, limit in [('x', self.width), ('y', self.height)]):
            self.ready = False; await self.page.mouse.click(data['x'], data['y'])
        elif op == 'key' and set(data) == {'action', 'key'} and data['key'] in KEYS:
            self.ready = False; await self.page.keyboard.press('Space' if data['key'] == ' ' else data['key'])
        elif op == 'text' and set(data) == {'action', 'text'} and isinstance(data['text'], str) and 0 < len(data['text']) <= 1024 and all(ord(c) >= 32 and ord(c) != 127 for c in data['text']):
            self.ready = False; await self.page.keyboard.insert_text(data['text'])
        elif op == 'scroll' and set(data) == {'action', 'delta'} and type(data['delta']) is int and abs(data['delta']) <= 700:
            await self.page.mouse.move(self.width // 2, self.height // 2)
            await self.page.mouse.wheel(0, data['delta'])
        else: raise ValueError('Browser input is not allowed.')
        return await self.status_result()

    async def close(self):
        if self.context:
            with contextlib.suppress(Exception): await self.context.close()
        if self.driver:
            with contextlib.suppress(Exception): await self.driver.stop()
        if self.xvfb:
            self.xvfb.terminate()
            try: self.xvfb.wait(timeout=3)
            except subprocess.TimeoutExpired: self.xvfb.kill(); self.xvfb.wait()


async def main():
    os.umask(0o077)
    session = PatchrightSession(sys.argv[1])
    def reply(result): print(json.dumps({'ok': True, 'result': result}), flush=True)
    try:
        reply(await session.start())
        while True:
            raw = await asyncio.to_thread(sys.stdin.buffer.readline, 1024 * 1024 + 1)
            if not raw: break
            try:
                if len(raw) > 1024 * 1024: raise ValueError('Browser request exceeds limit.')
                data = json.loads(raw)
                if data == {'action': 'stop'}: break
                reply(await session.action(data))
            except Exception as exc:
                error = str(exc) if isinstance(exc, (RuntimeError, ValueError)) else 'Patchright operation failed (' + type(exc).__name__ + ').'
                print(json.dumps({'ok': False, 'error': error[:1000]}), flush=True)
    except Exception as exc:
        print(json.dumps({'ok': False, 'error': 'Patchright startup failed (' + type(exc).__name__ + '); verify the installed runtime, sandbox and display.'}), flush=True)
    finally: await session.close()


if __name__ == '__main__': asyncio.run(main())
