"""Installed Chromium/CDP and Patchright, with every page intercepted locally."""
import asyncio
import json
from pathlib import Path
import sys
import tempfile
from urllib.parse import parse_qs, urlsplit

sys.path[:0]=[str(Path(__file__).resolve().parents[1]),str(Path(__file__).resolve().parent)]
from studio.browser_session import Session
from studio.patchright_session import PatchrightSession
from studio.engine import build_url
from test_empty_facets import empty_html
from test_adaptive import Dataset

def body(url):
    facet=parse_qs(urlsplit(url).query)['facet'][0]
    if facet=='version':return empty_html()
    if facet=='port':return Dataset.html('fixture','port',[('80',80),('443',80)],160)
    if facet=='asn':return '<title>Just a moment...</title><form id="challenge-form"></form>'
    return '<title>Login with Shodan</title><form><input type="password"></form>'

def chromium():
    from patchright.sync_api import sync_playwright
    requests=[]
    with sync_playwright() as p:
        browser=p.chromium.launch(headless=True,executable_path='/usr/bin/chromium')
        try:
            context=browser.new_context()
            def route(r):
                requests.append(r.request.url);r.fulfill(content_type='text/html',body=body(r.request.url))
            context.route('**/*',route);page=context.new_page();cdp=context.new_cdp_session(page)
            s=object.__new__(Session);s.document={};s.expected=None;s.ready=False;s.page_url='';s.session='fixture'
            s.call=lambda method,params=None,**kw:cdp.send(method,params or {})
            s.main_frame=cdp.send('Page.getFrameTree')['frameTree']['frame']['id']
            for method in ('Network.requestWillBeSent','Network.responseReceived','Page.navigatedWithinDocument'):
                cdp.on(method,lambda params,method=method:s.event({'method':method,'params':params,'sessionId':'fixture'}))
            cdp.send('Page.enable');cdp.send('Network.enable')
            s.expected=build_url('fixture','version');page.goto(s.expected,wait_until='domcontentloaded')
            assert s.action({'action':'frame'})['state']=='ready'
            assert 'No information available' in s.fetch(s.expected)['html']
            assert 'Total: 160' in s.fetch(build_url('fixture','port'))['html']
            for facet,code in (('asn','BROWSER_CHALLENGE'),('org','BROWSER_LOGIN')):
                s.expected=build_url('fixture',facet);page.goto(s.expected,wait_until='domcontentloaded')
                count=len(requests)
                try:s.fetch(s.expected)
                except RuntimeError as error:assert code in str(error),str(error)
                else:raise AssertionError('Expected an identified access barrier.')
                assert len(requests)==count
            return len(requests)
        finally:browser.close()

async def patchright():
    from patchright.async_api import async_playwright
    requests=[]
    async with async_playwright() as p:
        browser=await p.chromium.launch(headless=True,executable_path='/usr/bin/chromium')
        try:
            context=await browser.new_context()
            async def route(r):
                requests.append(r.request.url);await r.fulfill(content_type='text/html',body=body(r.request.url))
            await context.route('**/*',route);page=await context.new_page()
            with tempfile.TemporaryDirectory() as folder:
                s=PatchrightSession(folder);s.page=page;s.user_agent='fixture'
                page.on('request',s.request_event);page.on('response',s.response_event);page.on('framenavigated',s.frame_event)
                s.expected=build_url('fixture','version');await page.goto(s.expected,wait_until='domcontentloaded')
                assert (await s.action({'action':'frame'}))['state']=='ready'
                assert 'No information available' in (await s.fetch(s.expected))['html']
                assert 'Total: 160' in (await s.fetch(build_url('fixture','port')))['html']
                for facet,code in (('asn','BROWSER_CHALLENGE'),('org','BROWSER_LOGIN')):
                    s.expected=build_url('fixture',facet);await page.goto(s.expected,wait_until='domcontentloaded')
                    count=len(requests)
                    try:await s.fetch(s.expected)
                    except RuntimeError as error:assert code in str(error),str(error)
                    else:raise AssertionError('Expected an identified access barrier.')
                    assert len(requests)==count
            return len(requests)
        finally:await browser.close()

if __name__=='__main__':
    counts={'chromium':chromium(),'patchright':asyncio.run(patchright())}
    assert counts=={'chromium':4,'patchright':4},counts
    print(json.dumps({'passed':True,'live_shodan_requests':False,'intercepted_documents':counts,
                      'empty_ready_without_click':True,'next_facet_continued':True,'login_and_challenge_preserved':True}))
