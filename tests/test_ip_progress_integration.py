"""IP estimates against the actual planner, durable store, worker and HTTP API."""
import contextlib
import io
import ipaddress
import json
from pathlib import Path
import signal
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from studio import engine
from studio.ip_progress import crawler_progress_inputs, progress_from_job, terminal_leaves, compact_branches, validate_progress_inputs
from studio.jobs import JobManager
from studio.server import create_app
from studio.worker import DemoData, StudioCrawler, build_args, run_worker
from test_server import Client, PASSWORD


def leaf(query, count, path=(), status="pending"):
    return {"query": query, "expected_count": count, "status": status,
            "path": [{"facet": field, "value": value} for field, value in path]}


def crawler(leaves, *, progress=None, warnings=(), phase="extracting", mode="api"):
    return SimpleNamespace(report={"plan": {"extraction_order": leaves}, "planning_stage": phase,
                                   "warnings": list(warnings)},
                           args=SimpleNamespace(mode=mode), api_progress=progress or {})


class PlanProgressTests(unittest.TestCase):
    def test_large_plan_summary_stays_bounded_and_retains_exact_cardinalities(self):
        branches = [{"completed": False, "expected_records": 100, "processed_records": 70}] * 60000
        branches += [{"completed": True, "expected_records": 100, "processed_records": None}] * 10
        inputs = validate_progress_inputs({"branches": compact_branches(branches), "planning_complete": True,
                                           "traversal_completed": False})
        self.assertLess(len(json.dumps(inputs)), 1000)
        p = progress_from_job({"stats": {"unique_ips": 512}, "_ip_progress_inputs": inputs})
        self.assertEqual((p["total_leaves"], p["completed_leaves"]), (60010, 10))
        self.assertEqual(p["remaining_estimated_ips"], 60000 * 30)

    def test_deduplicates_terminal_queries_and_excludes_parent(self):
        parent = (("country", "EG"), ("city", "Cairo"), ("asn", "AS1"))
        first = leaf("port80", 100, parent + (("port", "80"),))
        second = leaf("port443", 50, parent + (("port", "443"),))
        c = crawler([leaf("asn", 150, parent), first, second, dict(first)])
        rows = crawler_progress_inputs(c)["branches"]
        self.assertEqual(len(rows), 2)
        self.assertEqual(sum(row["expected_records"] for row in rows), 150)

    def test_product_and_version_siblings_cannot_claim_disjointness(self):
        for field in ("product", "version", "org", "os"):
            with self.subTest(field=field):
                c = crawler([leaf("one", 100, ((field, "one"),)), leaf("two", 50, ((field, "two"),))])
                inputs = crawler_progress_inputs(c)
                self.assertEqual(inputs["denominator_reason"], "overlapping_or_unproven_scopes")
                p = progress_from_job({"stats": {"unique_ips": 50}, "_ip_progress_inputs": inputs})
                self.assertIsNone(p["progress_percent"])

    def test_mixed_split_facets_and_duplicate_scopes_are_unknown(self):
        for leaves in ([leaf("a", 1, (("asn", "AS1"),)), leaf("b", 1, (("port", "80"),))],
                       [leaf("a", 1), leaf("b", 1)]):
            self.assertFalse(terminal_leaves({"extraction_order": leaves})[1])

    def test_single_product_scope_does_not_block_known_count(self):
        self.assertEqual(crawler_progress_inputs(crawler([leaf("p", 15, (("product", "nginx"),))]))["branches"][0]["expected_records"], 15)

    def partial(self, *, received=100, ids=100, warning=None, mode="api"):
        saved = {"first_total": 250, "received": received, "next_page": 2,
                 "target_pages": 3, "known_ids": [str(n) for n in range(ids)],
                 "counts": {"192.0.2.1": received}}
        return crawler_progress_inputs(crawler([leaf("q", 300)], progress={"q": saved},
            warnings=[{"query": "q", "code": warning}] if warning else [], mode=mode))["branches"][0]

    def test_partial_api_page_uses_committed_unique_record_ids_not_ips(self):
        row = self.partial()
        self.assertEqual(row["expected_records"], 250)
        self.assertEqual(row["processed_records"], 100)

    def test_replayed_missing_ids_short_pages_and_changed_totals_are_not_processed(self):
        for args in ({"ids": 99}, {"ids": 0}, {"received": 70, "ids": 70},
                     {"warning": "API_TOTAL_CHANGED"}, {"warning": "API_REPEATED_BANNER"},
                     {"mode": "html"}):
            with self.subTest(args=args):
                self.assertIsNone(self.partial(**args)["processed_records"])

    def test_cache_saved_before_html_collection_is_not_completed(self):
        c = crawler([leaf("q", 20, status="extracting")], mode="html")
        c.cache = {("q", "ip"): object()}
        self.assertFalse(crawler_progress_inputs(c)["branches"][0]["completed"])

    def test_success_requires_traversal_and_all_leaves(self):
        inputs = crawler_progress_inputs(crawler([leaf("q", 5, status="completed")]))
        job = {"status": "completed", "stats": {"unique_ips": 1}, "_ip_progress_inputs": inputs}
        self.assertEqual(progress_from_job(job)["progress_percent"], 99)
        inputs["traversal_completed"] = True
        self.assertEqual(progress_from_job(job)["progress_percent"], 100)
        for status in ("failed", "interrupted", "paused", "cancelled", "waiting_input"):
            self.assertLess(progress_from_job({**job, "status": status})["progress_percent"], 100)

    def test_tree_planning_is_unknown_but_successful_traversal_can_complete(self):
        c = crawler([])
        c.report = {"traversal_completed": False}
        self.assertFalse(crawler_progress_inputs(c)["planning_complete"])
        c.report["traversal_completed"] = True
        job = {"status": "completed_warnings", "stats": {"unique_ips": 0}, "_ip_progress_inputs": crawler_progress_inputs(c)}
        self.assertEqual(progress_from_job(job)["progress_percent"], 100)


class DurableProgressTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.manager = JobManager(self.temp.name, autostart=False, demo=True)

    def tearDown(self):
        self.manager.shutdown()
        self.temp.cleanup()

    def create(self, **changes):
        return self.manager.create_job({"query": 'fixture country:"EG"', "mode": "html",
            "settings": {"demo": True, "delay": 0, "transport": "python"}, **changes})

    def wait(self, job_id):
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            job = self.manager.get_job(job_id)
            if job["status"] not in {"queued", "running"}:
                return job
            time.sleep(.03)
        self.fail("worker did not finish")

    def test_sqlite_dedup_replay_ipv6_and_job_scope(self):
        job, other = self.create(), self.create()
        inputs = {"planning_complete": True, "traversal_completed": False,
                  "branches": [{"expected_records": 270, "completed": False}]}
        addresses = [str(ipaddress.ip_address(0xc0000200 + n)) for n in range(512)]
        for _ in range(2):
            self.manager.store.record_ip_progress(job["id"], addresses, inputs,
                                                  stats={"unique_ips": 99999, "requests": 9876})
        p = self.manager.get_job(job["id"])["ip_progress"]
        self.assertEqual((p["extracted_unique_ips"], p["estimated_total_ips"], p["progress_percent"]), (512, 782, 65))
        self.assertEqual(self.manager.get_job(other["id"])["ip_progress"]["extracted_unique_ips"], 0)
        self.manager.store.record_ip_progress(other["id"], ["2001:db8::1", "2001:0db8:0:0:0:0:0:1"])
        self.assertEqual(self.manager.get_job(other["id"])["stats"]["unique_ips"], 1)

    def test_real_worker_list_detail_events_and_no_poll_requests(self):
        job = self.create()
        self.manager.start()
        result = self.wait(job["id"])
        self.assertEqual(result["status"], "completed")
        p = result["ip_progress"]
        self.assertEqual((p["extracted_unique_ips"], p["progress_percent"]), (292, 100))
        self.assertEqual(result["stats"]["requests"], 9)
        # The final job update commits before its event is appended. Wait for
        # that asynchronous append rather than comparing the previous event.
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            events = self.manager.store.events(job["id"], limit=1000)["events"]
            if events and events[-1]["kind"] == "final":
                break
            time.sleep(.01)
        self.assertEqual(events[-1]["kind"], "final")
        self.assertFalse(any(event["kind"] == "ip_batch" for event in events))
        self.assertEqual(events[-1]["ip_progress"], p)
        with self.manager.store.connection() as con:
            self.assertEqual(con.execute("SELECT COUNT(*) FROM job_ips WHERE job_id=?", (job["id"],)).fetchone()[0], 292)
        with patch.object(engine.ShodanAPIClient, "request", side_effect=AssertionError("network")), patch.object(engine, "fetch_html", side_effect=AssertionError("network")):
            app = create_app(self.temp.name, manager=self.manager, demo=True)
            client = Client(app)
            client.request("GET", "/api/session")
            self.assertEqual(client.request("POST", "/api/setup", {"username": "admin", "password": PASSWORD,
                "setup_token": self.manager.store.setup_token()})[0], 201)
            for _ in range(5):
                self.assertEqual(client.request("GET", "/api/jobs")[1]["jobs"][0]["ip_progress"], p)
                detail = client.request("GET", "/api/jobs/" + job["id"])[1]["job"]
                self.assertEqual(detail["ip_progress"], p)
                self.assertEqual(detail["stats"]["requests"], 9)
                self.assertNotIn("_ip_progress_inputs", detail)
            for url in ("/static/ip_progress.js", "/static/ip_progress.css"):
                self.assertEqual(client.request("GET", url)[0], 200)

    def test_pause_resume_restart_preserves_exact_ips_and_final_success(self):
        job = self.create(mode="api", settings={"demo": True, "delay": 0, "max_requests": 5, "transport": "python"})
        self.manager.start()
        partial = self.wait(job["id"])
        self.assertEqual(partial["status"], "waiting_input")
        self.assertEqual(partial["ip_progress"]["extracted_unique_ips"], 98)
        self.assertLess(partial["ip_progress"]["progress_percent"], 100)
        self.manager.shutdown()
        self.manager = JobManager(self.temp.name, demo=True)
        self.assertEqual(self.manager.get_job(job["id"])["ip_progress"], partial["ip_progress"])
        self.manager.action(job["id"], {"action": "resume", "mode": "html"})
        final = self.wait(job["id"])
        self.assertEqual(final["status"], "completed_warnings")
        self.assertEqual(final["ip_progress"]["progress_percent"], 100)
        self.assertEqual(final["stats"]["unique_ips"], 292)

    def test_legacy_backfill_is_offline_and_idempotent(self):
        job = self.create()
        self.manager.start()
        self.wait(job["id"])
        self.manager.shutdown()
        cp_path = self.manager._path(job["id"]) / "checkpoint.json"
        cp = engine.load_checkpoint(cp_path)
        del cp["config"]["studio_ip_progress"]
        engine.save_checkpoint(cp_path, cp, allow_replace=True)
        # Simulate the original database without any progress extension.
        self.manager.store.update_job(job["id"], _ip_progress_stored=False, _ip_progress_inputs=None)
        with self.manager.store.connection() as con:
            con.execute("DELETE FROM job_ips")
        self.manager = JobManager(self.temp.name, demo=True)
        self.assertEqual(self.manager.get_job(job["id"])["ip_progress"]["progress_percent"], 100)
        self.manager._restore_job_progress(self.manager._get(job["id"]))
        self.assertEqual(self.manager.get_job(job["id"])["stats"]["unique_ips"], 292)

    def test_crash_after_checkpoint_before_ipc_reconciles_and_never_shows_success(self):
        job = self.create()
        self.manager.store.update_job(job["id"], status="running")
        path = self.manager._path(job["id"])
        class Crash(BaseException):
            pass
        old_term, old_int = signal.getsignal(signal.SIGTERM), signal.getsignal(signal.SIGINT)
        try:
            with contextlib.redirect_stdout(io.StringIO()), patch.object(engine, "save_results", side_effect=Crash):
                with self.assertRaises(Crash):
                    run_worker(path, {"job": job, "api_key": None})
        finally:
            signal.signal(signal.SIGTERM, old_term)
            signal.signal(signal.SIGINT, old_int)
        # IPC output was lost, SQLite still has no addresses. Simulate a stale
        # live file too, so recovery must include checkpoint candidates.
        (path / "live-ips.txt").write_text("")
        self.assertEqual(self.manager.get_job(job["id"])["stats"]["unique_ips"], 0)
        self.manager.start()
        recovered = self.manager.get_job(job["id"])
        self.assertEqual(recovered["status"], "interrupted")
        self.assertEqual(recovered["ip_progress"]["extracted_unique_ips"], 292)
        self.assertEqual(self.manager.results(job["id"])["total"], 292)
        self.assertEqual(recovered["ip_progress"]["progress_percent"], 99)
        self.manager.action(job["id"], {"action": "resume"})
        final = self.wait(job["id"])
        self.assertEqual(final["ip_progress"]["progress_percent"], 100)
        self.assertEqual(final["stats"]["requests_this_run"], 0)

    def test_duplicate_ips_across_api_services_remain_one_db_row(self):
        job = self.create(mode="api")
        path = self.manager._path(job["id"])
        original = DemoData.request
        def duplicate(data, endpoint, params):
            payload = original(data, endpoint, params)
            for record in payload.get("matches", []):
                record["ip_str"] = "192.0.2.1"
            return payload
        old_term, old_int = signal.getsignal(signal.SIGTERM), signal.getsignal(signal.SIGINT)
        try:
            with contextlib.redirect_stdout(io.StringIO()), patch.object(DemoData, "request", duplicate):
                self.assertEqual(run_worker(path, {"job": job, "api_key": None}), 0)
        finally:
            signal.signal(signal.SIGTERM, old_term)
            signal.signal(signal.SIGINT, old_int)
        self.manager._restore_job_progress(self.manager._get(job["id"]))
        self.assertEqual(self.manager.get_job(job["id"])["stats"]["unique_ips"], 1)

    def test_real_api_pagination_checkpoint_preserves_partial_page_without_replay(self):
        job = self.create(mode="api", settings={"demo": True, "delay": 0, "transport": "python", "max_requests": 1})
        path = self.manager._path(job["id"])
        with contextlib.redirect_stdout(io.StringIO()):
            c = StudioCrawler(build_args(path, job, None), path, demo=True)
            c.report.update(plan={"extraction_order": [leaf(job["query"], 250, status="extracting")]}, planning_stage="extracting")
            payload = {"total": 250, "matches": [{"ip_str": f"192.0.2.{i+1}", "_shodan": {"id": str(i)}} for i in range(100)]}
            with patch.object(c.client, "request", return_value=payload) as network:
                with self.assertRaisesRegex(engine.SpiderError, "REQUEST_LIMIT"):
                    c.read_page(job["query"], "ip", 250)
                self.assertEqual(network.call_count, 1)
            cp = engine.load_checkpoint(path / "checkpoint.json")
            row = cp["config"]["studio_ip_progress"]["branches"][0]
            self.assertEqual((row["expected_records"], row["processed_records"]), (250, 100))
        self.manager.store.update_job(job["id"], status="interrupted")
        self.manager._restore_job_progress(self.manager._get(job["id"]))
        p = self.manager.get_job(job["id"])["ip_progress"]
        self.assertEqual((p["extracted_unique_ips"], p["remaining_estimated_ips"], p["progress_percent"]), (100, 150, 40))
        self.manager._restore_job_progress(self.manager._get(job["id"]))
        self.assertEqual(self.manager.get_job(job["id"])["ip_progress"], p)

    def test_real_empty_html_traversal_completes_with_zero_ips(self):
        job = self.create()
        path = self.manager._path(job["id"])
        old_term, old_int = signal.getsignal(signal.SIGTERM), signal.getsignal(signal.SIGINT)
        try:
            with contextlib.redirect_stdout(io.StringIO()), patch.object(DemoData, "values", return_value=([], 0)):
                self.assertEqual(run_worker(path, {"job": job, "api_key": None}), 0)
        finally:
            signal.signal(signal.SIGTERM, old_term)
            signal.signal(signal.SIGINT, old_int)
        self.manager.store.update_job(job["id"], status="completed")
        self.manager._restore_job_progress(self.manager._get(job["id"]))
        p = self.manager.get_job(job["id"])["ip_progress"]
        self.assertEqual((p["extracted_unique_ips"], p["estimated_total_ips"], p["progress_percent"]), (0, 0, 100))

    def test_reupgrade_reconciles_files_written_by_an_older_release(self):
        job = self.create()
        self.manager.store.record_ip_progress(job["id"], ["192.0.2.1"], status="paused")
        previous_time = self.manager.get_job(job["id"])["updated_at"]
        (self.manager._path(job["id"]) / "live-ips.txt").write_text("192.0.2.1\n192.0.2.2\n")
        self.manager.start()
        result = self.manager.get_job(job["id"])
        self.assertEqual(result["stats"]["unique_ips"], 2)
        self.assertEqual(result["updated_at"], previous_time)


if __name__ == "__main__":
    unittest.main()
