"""End-to-end offline queue tests using the real isolated worker and SQLite."""
from __future__ import annotations

import json
from pathlib import Path
import tempfile
import time
import unittest

from studio.config import JobValidationError, validate_job
from studio.jobs import JobManager


class JobsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.manager = JobManager(self.tmp.name, demo=True, autostart=False)

    def tearDown(self):
        self.manager.shutdown()
        self.tmp.cleanup()

    def create(self, **overrides):
        payload = {"title": "Fixture", "query": 'http.component:"php" country:"EG"', "mode": "html",
                   "settings": {"demo": True, "transport": "python", "delay": 0}}
        payload.update(overrides)
        return self.manager.create_job(payload)

    def wait(self, job_id, predicate=None, seconds=12):
        predicate = predicate or (lambda job: job["status"] not in ("queued", "running", "pause_requested", "cancel_requested"))
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            job = self.manager.get_job(job_id)
            if predicate(job):
                return job
            time.sleep(0.03)
        self.fail("Job did not reach its expected state: " + json.dumps(self.manager.get_job(job_id)))

    def test_demo_priority_and_downloads(self):
        job = self.create()
        self.manager.start()
        result = self.wait(job["id"])
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["stats"]["unique_ips"], 292)
        self.assertEqual(result["stats"]["requests"], 9)
        self.assertEqual(result["stats"]["remaining_branches"], 0)
        data, _, _ = self.manager.download(job["id"], "report")
        report = json.loads(data)
        self.assertEqual([leaf["expected_count"] for leaf in report["plan"]["extraction_order"]], [98, 54, 51, 49, 40])
        self.assertFalse(report["complete_export"])
        for format_name in ("txt", "csv", "json", "checkpoint"):
            data, content_type, name = self.manager.download(job["id"], format_name)
            self.assertGreater(len(data), 20)
            self.assertIn("shodan-", name)
        results = self.manager.results(job["id"], offset=250, limit=20, q="")
        self.assertEqual(len(results["items"]), 20)
        self.assertEqual(results["total"], 292)

    def test_pause_resume_uses_saved_pages_and_retains_ips(self):
        job = self.create(settings={"demo": True, "transport": "python", "delay": 0.15})
        self.manager.start()
        self.wait(job["id"], lambda j: j["stats"].get("unique_ips", 0) >= 98)
        self.manager.action(job["id"], {"action": "pause"})
        paused = self.wait(job["id"])
        self.assertEqual(paused["status"], "paused")
        self.assertGreaterEqual(paused["stats"]["unique_ips"], 98)
        self.assertTrue(paused["has_checkpoint"])
        self.manager.action(job["id"], {"action": "resume", "mode": "html"})
        result = self.wait(job["id"])
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["stats"]["unique_ips"], 292)
        self.assertGreater(result["stats"]["cache_hits"], 0)
        self.assertEqual(result["stats"]["session_number"], 2)

    def test_api_to_html_resume_preserves_previous_output(self):
        job = self.create(mode="api", settings={"demo": True, "transport": "python", "delay": 0.15})
        self.manager.start()
        self.wait(job["id"], lambda j: j["stats"].get("unique_ips", 0) >= 98)
        self.manager.action(job["id"], {"action": "pause"})
        self.assertEqual(self.wait(job["id"])["status"], "paused")
        self.manager.action(job["id"], {"action": "resume", "mode": "html"})
        final = self.wait(job["id"])
        self.assertEqual(final["status"], "completed_warnings")
        self.assertEqual(final["mode"], "html")
        self.assertEqual(final["stats"]["unique_ips"], 292)
        data, _, _ = self.manager.download(job["id"], "report")
        self.assertEqual(json.loads(data)["sources_used"], ["api", "html"])

    def test_request_budget_can_be_resumed_without_starting_over(self):
        job = self.create(settings={"demo": True, "transport": "python", "delay": 0, "max_requests": 2})
        self.manager.start()
        for _ in range(6):
            state = self.wait(job["id"])
            if state["status"] == "completed":
                break
            self.assertEqual(state["status"], "waiting_input")
            self.assertEqual(state["input_reason"], "request_budget")
            self.manager.action(job["id"], {"action": "resume"})
        self.assertEqual(state["status"], "completed")
        self.assertEqual(state["stats"]["requests"], 9)
        self.assertEqual(state["stats"]["unique_ips"], 292)

    def test_cancel_preserves_partial_and_cannot_resume(self):
        job = self.create(settings={"demo": True, "transport": "python", "delay": 0.15})
        self.manager.start()
        self.wait(job["id"], lambda j: j["stats"].get("unique_ips", 0) >= 98)
        self.manager.action(job["id"], {"action": "cancel"})
        self.assertEqual(self.wait(job["id"])["status"], "cancelled")
        self.assertGreaterEqual(self.manager.results(job["id"])["total"], 98)
        with self.assertRaises(JobValidationError):
            self.manager.action(job["id"], {"action": "resume"})

    def test_missing_key_waits_without_sending_network_request(self):
        job = self.create(mode="api", settings={"transport": "python"})
        self.assertEqual(job["status"], "waiting_input")
        self.assertEqual(job["stats"]["requests"], 0)
        with self.assertRaises(JobValidationError):
            self.manager.action(job["id"], {"action": "resume", "mode": "api"})

    def test_secret_never_written_to_database_files_or_reports(self):
        key = "FIXTURE_SECRET_MEMORY_ONLY_123456"
        job = self.create(mode="api", api_key=key)
        self.manager.start()
        result = self.wait(job["id"])
        self.assertEqual(result["status"], "completed")
        for path in Path(self.tmp.name).rglob("*"):
            if path.is_file():
                self.assertNotIn(key.encode(), path.read_bytes(), path.name)
        self.assertNotIn(key, json.dumps(self.manager.list_jobs()))

    def test_queue_priority_and_duplicate_does_not_alias_source(self):
        low = self.create(priority=0)
        high = self.create(priority=9)
        claim = self.manager.store.claim_next()
        self.assertEqual(claim["id"], high["id"])
        copied = self.manager.action(low["id"], {"action": "duplicate"})
        self.assertNotEqual(copied["id"], low["id"])
        self.assertEqual(copied["query"], low["query"])
        self.assertEqual(copied["status"], "queued")
        self.assertFalse(copied["has_checkpoint"])

    def test_data_directory_exclusive_lock(self):
        self.manager.start()
        other = JobManager(self.tmp.name, demo=True, autostart=False)
        try:
            with self.assertRaises(ValueError):
                other.start()
        finally:
            other.shutdown()

    def test_restart_retains_jobs_but_not_keys(self):
        job = self.create(mode="api", api_key="FIXTURE_KEY_REENTER_AFTER_RESTART", settings={"transport": "python"})
        self.manager.shutdown()
        self.manager = JobManager(self.tmp.name, demo=True)
        result = self.wait(job["id"])
        self.assertEqual(result["status"], "waiting_input")
        self.assertFalse(result["has_key"])
        self.assertEqual(result["stats"]["requests"], 0)

    def test_import_rebinds_paths_and_preserves_demo_no_network(self):
        job = self.create()
        self.manager.start()
        self.assertEqual(self.wait(job["id"])["status"], "completed")
        data, _, _ = self.manager.download(job["id"], "checkpoint")
        checkpoint = json.loads(data)
        checkpoint["config"]["output"] = "/etc/never-write-here"
        imported = self.manager.import_checkpoint({"checkpoint": checkpoint, "title": "Imported", "mode": "api"})
        self.assertTrue(imported["settings"]["demo"])
        self.manager.action(imported["id"], {"action": "resume", "mode": "html"})
        result = self.wait(imported["id"])
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["stats"]["unique_ips"], 292)
        data, _, _ = self.manager.download(imported["id"], "checkpoint")
        self.assertIn(imported["id"], json.loads(data)["config"]["output"])

    def test_corrupt_import_is_rejected_without_a_durable_job(self):
        before = len(self.manager.list_jobs()["jobs"])
        with self.assertRaises(JobValidationError):
            self.manager.import_checkpoint({"checkpoint": {"app": "ShodanSpider", "schema_version": 1, "config": {}, "state": {}}})
        self.assertEqual(len(self.manager.list_jobs()["jobs"]), before)

    def test_public_fields_cannot_contain_given_key(self):
        key = "KEY_CANNOT_BE_STORED_IN_TITLE"
        with self.assertRaises(JobValidationError):
            self.create(title=key, api_key=key)
        job = self.create(title=key)
        with self.assertRaises(JobValidationError):
            self.manager.action(job["id"], {"action": "duplicate", "api_key": key})

    def test_paths_and_shell_options_cannot_be_injected(self):
        with self.assertRaises(KeyError):
            self.manager.get_job("../../etc/passwd")
        with self.assertRaises(JobValidationError):
            self.create(command="touch /tmp/not-authorized")
        with self.assertRaises(JobValidationError):
            self.create(settings={"output": "/tmp/not-authorized"})
        job = self.create(query='example $(touch /tmp/never) `whoami` country:"EG"')
        self.assertIn("$(touch", job["query"])
        self.assertFalse(Path("/tmp/never").exists())


if __name__ == "__main__":
    unittest.main()
