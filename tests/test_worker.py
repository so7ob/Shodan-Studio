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
            "mode": "api", "settings": {"strategy": "priority", "demo": True, "transport": "python", "delay": 0,
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
        self.assertEqual(events[-1]['input_reason'],'browser_challenge')
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
                self.assertFalse(events[-1]["stats"]["wait_unbounded"])
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

    def test_unbounded_rate_limit_remains_visible_across_repeated_resume(self):
        blocked = engine.ShodanAPIError("[API_HTTP_429] Fixture rate limit", http_status=429,
                                        retry_after=float("inf"), failure_kind="rate_limit")
        with patch.object(DemoData, "request", autospec=True, side_effect=blocked) as request:
            with patch.object(DemoData, "fetch", side_effect=AssertionError("No source switching on 429")):
                for attempt in range(3):
                    code, events = self.run_capture()
                    final = events[-1]
                    self.assertEqual(code, 75)
                    self.assertEqual(final["status"], "waiting_input")
                    self.assertEqual(final["input_reason"], "rate_limit")
                    self.assertEqual(final["stats"]["phase"], "waiting")
                    self.assertTrue(final["stats"]["wait_unbounded"])
                    self.assertIsNone(final["stats"]["wait_until"])
                    self.assertEqual(final["stats"]["requests_this_run"], 1 if attempt == 0 else 0)
                    self.assertTrue(self.checkpoint()["state"]["wait_unbounded"])
                    self.assertEqual(self.checkpoint()["state"]["requests_total"], 1)
                    prompts = [event for event in events if event["kind"] == "input_required"]
                    self.assertEqual(prompts[-1]["detail"], {"reason": "rate_limit", "choices": ["cancel"]})
                for action, status in (("pause", "paused"), ("cancel", "cancelled")):
                    (self.job_dir / "control.json").write_text(json.dumps({"action": action}))
                    code, events = self.run_capture()
                    self.assertEqual(code, 75)
                    self.assertEqual(events[-1]["status"], status)
                    self.assertEqual(events[-1]["stats"]["requests_this_run"], 0)
                    self.assertTrue(self.checkpoint()["state"]["wait_unbounded"])
        self.assertEqual(request.call_count, 1)




class RequestPacingTests(unittest.TestCase):
    def test_worker_emits_deadline_before_sleep_and_clears_it_on_cancel(self):
        from studio.worker import StudioCrawler, build_args
        with tempfile.TemporaryDirectory() as folder:
            job_dir=Path(folder)
            job={'id':'a'*32,'query':'fixture','mode':'html','settings':{'strategy':'adaptive','delay':30,'demo':True}}
            crawler=StudioCrawler(build_args(job_dir,job,None),job_dir,demo=True)
            snapshots=[]
            with patch('studio.worker.emit',side_effect=lambda kind,**fields: snapshots.append((kind,fields))), patch('studio.worker.time.time',return_value=1700000000):
                def cancel(_):
                    job_dir.joinpath('control.json').write_text('{"action":"cancel"}')
                with patch('studio.worker.time.sleep',side_effect=cancel):
                    with self.assertRaises(engine.PauseRequested):crawler.wait_for_request(30,'request_delay')
            states=[fields['stats']['request_wait'] for kind,fields in snapshots if kind=='progress']
            self.assertEqual(states[0],{'reason':'request_delay','until':1700000030,
                                        'duration':30,'configured_delay':30})
            self.assertIsNone(states[-1])
            self.assertIsNone(crawler.stats()['request_wait'])

    def test_snapshot_cost_counts_toward_the_published_wait(self):
        from studio.worker import StudioCrawler, build_args
        with tempfile.TemporaryDirectory() as folder:
            job_dir=Path(folder)
            job={'id':'a'*32,'query':'fixture','mode':'html','settings':{'delay':18,'demo':True}}
            crawler=StudioCrawler(build_args(job_dir,job,None),job_dir,demo=True)
            clock=[100.0]
            states=[]
            def snapshot(**kwargs):
                states.append((clock[0],crawler._request_wait))
                if crawler._request_wait:
                    clock[0]+=0.4  # Persisting/emitting progress takes real time.
            def sleep(duration):
                clock[0]+=duration
            with patch('studio.worker.time.monotonic',side_effect=lambda:clock[0]), \
                 patch('studio.worker.time.time',side_effect=lambda:1700000000+clock[0]-100), \
                 patch('studio.worker.time.sleep',side_effect=sleep), \
                 patch.object(crawler,'snapshot',side_effect=snapshot):
                crawler.wait_for_request(18,'request_delay')
            self.assertEqual(states[0][1]['until'],1700000018)
            self.assertGreaterEqual(clock[0],118)
            self.assertLess(clock[0],118.4)
            self.assertIsNone(states[-1][1])

    def test_engine_labels_normal_request_pacing_without_changing_its_duration(self):
        from test_adaptive import Dataset
        with tempfile.TemporaryDirectory() as folder:
            args=engine.parse_args(['--query','fixture','--mode','html','--delay','30','--output',str(Path(folder)/'ips.txt')])
            crawler=engine.Crawler(args,fetcher=Dataset().fetch,clock=lambda:100,sleeper=lambda _:None)
            crawler.last_finished=90
            waits=[]
            with contextlib.redirect_stdout(io.StringIO()),contextlib.redirect_stderr(io.StringIO()),patch.object(crawler,'wait_for_request',side_effect=lambda duration,reason:waits.append((duration,reason))):
                crawler.read_page('fixture','ip',None)
            self.assertEqual(waits,[(20,'request_delay')])


if __name__ == "__main__":
    unittest.main()
