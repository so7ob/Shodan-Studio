"""Empty fields are usable browser pages, not proof of an empty query."""
import html
import sys
import types
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from studio import engine
from studio.browser_session import Session
from studio.patchright_session import PatchrightSession
from test_adaptive import Dataset
import test_adaptive


def empty_html(query='fixture', facet='version', total=None):
    counter='' if total is None else f'<h2>Total: {total}</h2>'
    return (f'<html><title>Shodan</title><h1>Facet Analysis</h1>{counter}'
            f'<form><input name="query" value="{html.escape(query, quote=True)}">'
            f'<select name="facet"><option selected value="{facet}">{facet}</option></select></form>'
            '<p>No information available</p><footer>Products</footer></html>')


def native(body, facet='version'):
    s=object.__new__(Session);s.expected=engine.build_url('fixture',facet)
    s.document={'url':s.expected,'status':200};s.ready=False;s.page_url=s.expected
    s.html=MagicMock(return_value={'url':s.expected,'html':body});s.call=MagicMock()
    return s


class EmptyParserTests(unittest.TestCase):
    def test_no_information_does_not_fabricate_a_zero_query_total(self):
        for facet in engine.SUPPORTED_FACETS:
            for total in (None,0,160):
                with self.subTest(facet=facet,total=total):
                    page=engine.parse_facet_html(empty_html(facet=facet,total=total),facet,'fixture')
                    self.assertEqual(page.rows,[]);self.assertEqual(page.total,total)
                    self.assertEqual(page.explicit_empty,total==0)

    def test_empty_marker_requires_facet_identity_and_visible_context(self):
        good=empty_html()
        for body in ('<p>No information available</p>',good.replace('name="facet"','name="other"'),
                     good.replace('name="query"','name="other"'),good.replace('Facet Analysis','Unrelated'),
                     good.replace('<p>No information available</p>','<script>No information available</script>'),
                     good.replace('<p>No information available</p>','<p hidden>No information available</p>')):
            with self.subTest(body=body),self.assertRaisesRegex(engine.FacetParseError,'LAYOUT'):
                engine.parse_facet_html(body,'version','fixture')

    def test_wrong_query_and_facet_remain_rejected(self):
        for body,tag in ((empty_html(query='other'),'QUERY_MISMATCH'),(empty_html(facet='port'),'FACET_MISMATCH')):
            with self.assertRaisesRegex(engine.FacetParseError,tag):engine.parse_facet_html(body,'version','fixture')

    def test_login_challenge_and_denial_take_precedence_over_empty_marker(self):
        for marker,tag in (('<input type="password">','LOGIN'),('<form id="challenge-form"></form>','ACCESS'),
                           ('<title>Access denied</title>','DENIED')):
            with self.assertRaisesRegex(engine.FacetParseError,tag):engine.parse_facet_html(empty_html()+marker,'version','fixture')

    def test_damaged_rows_are_not_silently_marked_empty(self):
        body=empty_html(facet='ip')+'<table class="facet-table"><tr><td>not-an-ip</td><td>2</td></tr></table>'
        with self.assertRaisesRegex(engine.FacetParseError,'LAYOUT'):engine.parse_facet_html(body,'ip','fixture')

    def test_query_text_is_not_mistaken_for_cloudflare_markup(self):
        query='fixture "cf-chl-example"'
        self.assertEqual(engine.parse_facet_html(empty_html(query),'version',query).rows,[])


class NativeEmptyTests(unittest.TestCase):
    def test_empty_message_and_empty_card_are_ready_without_navigation(self):
        for body in (empty_html(),Dataset.html('fixture','version',[],160)):
            s=native(body)
            self.assertEqual(s.fetch(s.expected),{'html':body})
            self.assertEqual(s.status()['state'],'ready');s.call.assert_not_called()

    def test_frame_observation_enables_resume_without_an_explicit_verify_click(self):
        s=native(empty_html());s.call.return_value={'data':'fixture'}
        self.assertEqual(s.action({'action':'frame'})['state'],'ready')
        s.call.assert_called_once_with('Page.captureScreenshot',{'format':'jpeg','quality':65,'captureBeyondViewport':False})

    def test_only_identified_auth_and_challenges_request_browser_input(self):
        for body,state,tag in (('<form><input type="password"></form>','login_required','BROWSER_LOGIN'),
                               ('<title>Just a moment...</title>','browser_challenge','BROWSER_CHALLENGE'),
                               ('<title>Access denied</title>','access_denied','HTTP_403')):
            s=native(body)
            self.assertEqual(s.verify()['state'],state)
            with self.assertRaisesRegex(RuntimeError,tag):s.fetch(s.expected)
            s.call.assert_not_called()

    def test_login_redirect_is_identified_and_not_reloaded(self):
        s=native('<form><input type="password"></form>');url='https://account.shodan.io/login'
        s.document['url']=url;s.html.return_value['url']=url
        self.assertEqual(s.verify()['state'],'login_required')
        with self.assertRaisesRegex(RuntimeError,'BROWSER_LOGIN'):s.fetch(s.expected)
        s.call.assert_not_called()

    def test_unknown_layout_has_a_parse_error_not_a_verification_prompt(self):
        s=native('<h1>Unexpected layout</h1>');s.navigate=MagicMock()
        self.assertEqual(s.verify()['state'],'invalid_page')
        with patch('studio.browser_session.time.monotonic',side_effect=[0,1,26]),patch('studio.browser_session.time.sleep'):
            with self.assertRaisesRegex(RuntimeError,r'^\[HTML_PARSE\]'):s.fetch(s.expected)
        self.assertFalse(s.ready)

    def test_navigation_invalidates_previous_page_classification(self):
        s=native('<input type="password">');self.assertEqual(s.verify()['state'],'login_required')
        s.document={'url':s.expected,'status':200};s.html.return_value['html']=empty_html()
        self.assertEqual(s.status()['state'],'awaiting_verification')
        self.assertEqual(s.verify()['state'],'ready')


class PatchrightEmptyTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.modules=patch.dict(sys.modules,{'patchright.async_api':types.SimpleNamespace(Error=type('DriverError',(Exception,),{}))})
        self.modules.start()
    def tearDown(self):self.modules.stop()
    def session(self,body):
        s=PatchrightSession('/unused');s.expected=engine.build_url('fixture','version')
        s.document={'url':s.expected,'status':200};s.page_url=s.expected;s.user_agent='fixture'
        s.html=AsyncMock(return_value={'url':s.expected,'html':body});s.navigate=AsyncMock()
        return s

    async def test_empty_pages_and_next_facet_continue_without_manual_verification(self):
        for body in (empty_html(),Dataset.html('fixture','version',[],160)):
            s=self.session(body)
            self.assertEqual((await s.fetch(s.expected))['html'],body)
            s.navigate.assert_not_called()
            next_url=engine.build_url('fixture','port');next_html=Dataset.html('fixture','port',[('80',80),('443',80)],160)
            async def navigate(url):
                s.expected=url;s.document={'url':url,'status':200};s.html.return_value={'url':url,'html':next_html}
            s.navigate.side_effect=navigate
            self.assertEqual((await s.fetch(next_url))['html'],next_html)
            s.navigate.assert_awaited_once_with(next_url)

    async def test_known_barriers_remain_distinct_from_unrecognized_layout(self):
        for body,state,tag in (('<input type="password">','login_required','BROWSER_LOGIN'),
                              ('<title>Just a moment</title>','browser_challenge','BROWSER_CHALLENGE'),
                              ('<title>Access denied</title>','access_denied','HTTP_403')):
            s=self.session(body);self.assertEqual((await s.verify())['state'],state)
            with self.assertRaisesRegex(RuntimeError,tag):await s.fetch(s.expected)
            s.navigate.assert_not_called()
        s=self.session('<h1>Unknown</h1>');self.assertEqual((await s.verify())['state'],'invalid_page')
        loop=types.SimpleNamespace(time=MagicMock(side_effect=[0,1,26]))
        with patch('studio.patchright_session.asyncio.get_running_loop',return_value=loop),patch('studio.patchright_session.asyncio.sleep',new=AsyncMock()):
            with self.assertRaisesRegex(RuntimeError,r'^\[HTML_PARSE\]'):await s.fetch(s.expected)

    async def test_frame_marks_empty_page_ready_and_new_document_clears_old_state(self):
        s=self.session(empty_html());s.page=MagicMock(screenshot=AsyncMock(return_value=b'fixture'),evaluate=AsyncMock(return_value={'width':1100,'height':760}))
        self.assertEqual((await s.action({'action':'frame'}))['state'],'ready')
        s.html.return_value['html']='<input type="password">'
        self.assertEqual((await s.verify())['state'],'login_required')
        s.document={'url':s.expected,'status':200};s.ready=False
        self.assertEqual(s.status()['state'],'awaiting_verification')


class EmptyFacetWorkerTests(unittest.TestCase):
    setUp=test_adaptive.AdaptiveWorkerTests.setUp
    tearDown=test_adaptive.AdaptiveWorkerTests.tearDown
    run_capture=test_adaptive.AdaptiveWorkerTests.run_capture
    def test_real_worker_and_browser_continue_from_empty_field_to_productive_split(self):
        class EmptyPort(Dataset):
            def fetch(self,url):
                query,facet=engine.parse_qs(engine.urlsplit(url).query)['query'][0],engine.parse_qs(engine.urlsplit(url).query)['facet'][0]
                if facet=='port':
                    self.calls.append((query,facet));return empty_html(query,facet)
                return super().fetch(url)
        data=EmptyPort();root=engine.build_url('fixture','ip');s=native(data.fetch(root),'ip')
        def navigate(url):
            s.expected=url;s.document={'url':url,'status':200};s.html.return_value={'url':url,'html':data.fetch(url)}
        s.navigate=MagicMock(side_effect=navigate)
        with patch('studio.vpn_client.rpc',side_effect=lambda op,**kw:s.fetch(kw['url'])):
            code,events=self.run_capture()
        self.assertEqual(code,0);self.assertEqual(events[-1]['stats']['unique_ips'],160)
        self.assertEqual([f for _,f in data.calls],['ip','port','version','ip','ip'])
        self.assertFalse(any(e['kind']=='input_required' for e in events))
        self.assertEqual(events[-1]['stats']['requests_this_run'],5)


if __name__=='__main__':unittest.main()
