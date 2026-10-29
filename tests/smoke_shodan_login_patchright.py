"""Optional installed-runtime smoke: intercepted pages, no Shodan requests."""
import asyncio
import sys
import tempfile
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from studio.patchright_session import PatchrightSession
from studio.engine import build_url
from patchright.async_api import async_playwright

async def main():
    posts=[]
    async with async_playwright() as p:
        browser=await p.chromium.launch(headless=True,executable_path='/usr/bin/chromium')
        try:
            context=await browser.new_context()
            page=await context.new_page()
            async def route(r):
                if r.request.method=='POST':
                    posts.append(r.request.post_data)
                    await r.fulfill(body='<h1>Fixture account</h1>')
                else:
                    await r.fulfill(content_type='text/html',body='<form action="/login" method="post"><input name="username"><input name="password" type="password"><input type="hidden" name="csrf_token" value="fixture-token"></form>')
            await context.route('**/*',route)
            with tempfile.TemporaryDirectory() as folder:
                session=PatchrightSession(folder);session.page=page;session.context=context
                page.on('request',session.request_event);page.on('response',session.response_event);page.on('framenavigated',session.frame_event)
                result=await session.action({'action':'login','username':'fixture-user','password':'fixture-password','return_url':build_url('fixture','ip')})
                await page.wait_for_selector('h1')
                assert result['login_status']=='submitted',result
                assert len(posts)==1 and 'username=fixture-user' in posts[0] and 'password=fixture-password' in posts[0] and 'csrf_token=fixture-token' in posts[0]
                assert 'fixture-password' not in str(result)
                assert session.expected==build_url('fixture','ip') and not session.ready
                print('PASS installed Patchright driver: isolated fixture login, CSRF preserved, no live requests.')
        finally:await browser.close()

if __name__=='__main__':asyncio.run(main())
