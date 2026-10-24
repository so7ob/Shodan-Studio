"""Offline regressions for the worker's source-recovery and rate-limit loop."""
from __future__ import annotations

import contextlib
import io
import json
from pathlib import Path
import signal
import tempfile
import time
import unittest
from unittest.mock import patch

from studio import engine
from studio.config import validate_job
from studio.worker import DemoData, run_worker


FIXTURE_KEY = "WORKER_FIXTURE_NOT_A_REAL_API_KEY"


class WorkerRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.job_dir = Path(self.tmp.name) / "job"
        self.job_dir.mkdir()
        self.job, _ = validate_job({
            "title": "Synthetic worker-recovery fixture", "query": 'http.component:"php" country:"EG"',
            "mode": "api", "settings": {"demo": True, "transport": "python", "delay": 0,
                "max_requests": 25, "api_fallback": "html", "rate_limit_retries": 0,
                "on_rate_limit": "pause", "max_retry_wait": 0, "retry_base_delay": 1},
        }, allow_demo=True)

    def tearDown(self):
        self.tmp.cleanup()

    def run_capture(self):
        output = io.StringIO()
        old_term, old_int = signal.getsignal(signal.SIGTERM), signal.getsignal(signal.SIGINT)
        try:
            with contextlib.ExitStack() as stack:
                stack.enter_context(contextlib.redirect_stdout(output))
                # A regression must fail locally instead of opening a real connection.
                for name in ("fetch_html", "fetch_html_curl"):
                    stack.enter_context(patch.object(engine, name, side_effect=AssertionError("Unexpected real HTML transport")))
                stack.enter_context(patch.object(engine.ShodanAPIClient, "request", side_effect=AssertionError("Unexpected real API transport")))
                stack.enter_context(patch("studio.worker.time.sleep", side_effect=AssertionError("Unexpected sleep in bounded recovery fixture")))
                code = run_worker(self.job_dir, {"job": self.job, "api_key": FIXTURE_KEY})
        finally:
            signal.signal(signal.SIGTERM, old_term)
            signal.signal(signal.SIGINT, old_int)
        return code, [json.loads(line) for line in output.getvalue().splitlines()]

    def report(self):
        return json.loads((self.job_dir / "result.txt.report.json").read_text(encoding="utf-8"))

    def checkpoint(self):
        return engine.load_checkpoint(self.job_dir / "checkpoint.json")

    def test_api_403_falls_back_once_to_html_and_collects_292_ips(self):
        original_fetch = DemoData.fetch
        blocked = engine.ShodanAPIError("[API_HTTP_403] Fixture membership denial", http_status=403, failure_kind="permission")
        with patch.object(DemoData, "request", autospec=True, side_effect=blocked) as api_request:
            with patch.object(DemoData, "fetch", autospec=True, side_effect=original_fetch) as html_request:
                code, events = self.run_capture()
        self.assertEqual(code, 0)
        self.assertEqual(events[-1]["status"], "completed_warnings")
        self.assertEqual(events[-1]["stats"]["unique_ips"], 292)
        self.assertEqual(events[-1]["stats"]["requests"], 10)
        self.assertEqual(events[-1]["stats"]["source"], "html")
        self.assertEqual(api_request.call_count, 1)
        self.assertEqual(html_request.call_count, 9)
        report = self.report()
        self.assertEqual(report["sources_used"], ["api", "html"])
        self.assertEqual(len(report["source_changes"]), 1)
        self.assertEqual(len(report["ips"]), 292)
        self.assertNotIn(FIXTURE_KEY, json.dumps(report))
        self.assertEqual(self.checkpoint()["config"]["mode"], "html")

    def test_api_then_html_403_waits_for_user_after_two_attempts(self):
        api_blocked = engine.ShodanAPIError("[API_HTTP_403] Fixture membership denial", http_status=403, failure_kind="permission")
        html_blocked = engine.SpiderError("[HTTP_403] Fixture website access denial", http_status=403, failure_kind="permission")
        with patch.object(DemoData, "request", autospec=True, side_effect=api_blocked) as api_request:
            with patch.object(DemoData, "fetch", autospec=True, side_effect=html_blocked) as html_request:
                code, events = self.run_capture()
        self.assertEqual(code, 75)
        self.assertEqual(events[-1]["status"], "waiting_input")
        self.assertEqual(events[-1]["input_reason"], "source_error")
        self.assertEqual(events[-1]["stats"]["requests"], 2)
        self.assertEqual(events[-1]["stats"]["unique_ips"], 0)
        self.assertEqual(api_request.call_count, 1)
        self.assertEqual(html_request.call_count, 1)
        self.assertEqual(len(self.report()["source_changes"]), 1)
        self.assertTrue(any(event["kind"] == "input_required" for event in events))
        self.assertEqual(self.checkpoint()["state"]["requests_total"], 2)

    def test_html_browser_challenge_pauses_once_preserving_checkpoint(self):
        from email.message import Message
        from studio.vpn_config import network_error
        headers=Message();headers['cf-mitigated']='challenge'
        headers['Set-Cookie']='DO_NOT_EXPOSE'
        blocked=engine.http_failure(403,headers)
        self.assertIn('[BROWSER_CHALLENGE]',str(blocked))
        self.assertNotIn('DO_NOT_EXPOSE',str(blocked))
        self.assertFalse(network_error(str(blocked)))
        self.job['mode']='html'
        with patch.object(DemoData,'fetch',autospec=True,side_effect=blocked) as fetch:
            code,events=self.run_capture()
        self.assertEqual(code,75);self.assertEqual(fetch.call_count,1)
        self.assertEqual(events[-1]['input_reason'],'source_error')
        self.assertEqual(self.checkpoint()['state']['requests_total'],1)
        self.assertEqual(self.checkpoint()['config']['mode'],'html')

    def test_api_429_preserves_retry_after_and_resume_sends_no_early_request(self):
        rate_limited = engine.ShodanAPIError("[API_HTTP_429] Fixture rate limit", http_status=429,
                                            retry_after=3600, failure_kind="rate_limit")
        started = time.time()
        with patch.object(DemoData, "request", autospec=True, side_effect=rate_limited) as api_request:
            with patch.object(DemoData, "fetch", autospec=True, side_effect=AssertionError("429 must not switch to HTML")) as html_request:
                code, events = self.run_capture()
                self.assertEqual(code, 75)
                self.assertEqual(events[-1]["status"], "waiting_input")
                self.assertEqual(events[-1]["input_reason"], "rate_limit")
                self.assertEqual(events[-1]["stats"]["requests"], 1)
                saved = self.checkpoint()
                deadline = saved["state"]["not_before_utc"]
                self.assertGreaterEqual(deadline, started + 3599)
                self.assertLessEqual(deadline, time.time() + 3601)
                self.assertEqual(saved["state"]["requests_total"], 1)

                # max_retry_wait=0 keeps this resume bounded: the deadline forces
                # another user-input state before any source request or sleep.
                code, resumed = self.run_capture()
                self.assertEqual(code, 75)
                self.assertEqual(resumed[-1]["status"], "waiting_input")
                self.assertEqual(resumed[-1]["input_reason"], "rate_limit")
                self.assertEqual(resumed[-1]["stats"]["requests_this_run"], 0)
                self.assertEqual(resumed[-1]["stats"]["requests"], 1)
                self.assertEqual(self.checkpoint()["state"]["not_before_utc"], deadline)
        self.assertEqual(api_request.call_count, 1)
        html_request.assert_not_called()


if __name__ == "__main__":
    unittest.main()
