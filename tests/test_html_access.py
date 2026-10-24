"""Both actual transport adapters classify challenge headers without leaking them."""
from email.message import Message
import io
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch
import urllib.error

from studio import engine

class HTMLAccessTests(unittest.TestCase):
    def test_python_challenge_keeps_http_status_and_never_logs_cookie(self):
        headers=Message();headers['Cf-Mitigated']='challenge';headers['Set-Cookie']='private-cookie'
        opener=MagicMock();error=urllib.error.HTTPError('https://www.shodan.io/search/facet',403,'Forbidden',headers,io.BytesIO(b'secret body'))
        opener.open.side_effect=error
        with self.assertRaises(engine.SpiderError) as caught:
            engine.fetch_html('https://www.shodan.io/search/facet',1,opener=opener)
        self.assertEqual(caught.exception.http_status,403)
        self.assertIn('[BROWSER_CHALLENGE]',str(caught.exception))
        self.assertNotIn('private-cookie',str(caught.exception))
        self.assertNotIn('secret body',str(caught.exception))
        opener.open.assert_called_once()

    def test_curl_challenge_parses_final_headers_without_body_disclosure(self):
        def curl(argv,**kwargs):
            Path(argv[argv.index('--dump-header')+1]).write_text('HTTP/1.1 403 Forbidden\r\nCf-Mitigated: challenge\r\nSet-Cookie: private-cookie\r\nContent-Type: text/html\r\n\r\n')
            Path(argv[argv.index('--output')+1]).write_text('secret body')
            return SimpleNamespace(returncode=0,stdout='403\ntext/html\n',stderr='')
        with patch('studio.engine.shutil.which',return_value='/usr/bin/curl'),patch('studio.engine.subprocess.run',side_effect=curl) as run:
            with self.assertRaises(engine.SpiderError) as caught:
                engine.fetch_html_curl('https://www.shodan.io/search/facet',1)
        self.assertEqual(caught.exception.http_status,403)
        self.assertIn('[BROWSER_CHALLENGE]',str(caught.exception))
        self.assertNotIn('private-cookie',str(caught.exception))
        self.assertNotIn('secret body',str(caught.exception))
        run.assert_called_once()
