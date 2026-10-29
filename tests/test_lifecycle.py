"""Focused regressions for queue shutdown, immediate controls and crash recovery."""
from __future__ import annotations

import contextlib
import io
import json
from pathlib import Path
import signal
import tempfile
import threading
import unittest
from unittest.mock import patch

from studio import engine
from studio.config import validate_job
from studio.jobs import JobManager
from studio.worker import build_args, run_worker


class QueueLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.manager = JobManager(self.tmp.name, autostart=False, demo=True)

    def tearDown(self):
        self.manager.shutdown()
        self.tmp.cleanup()

    def create_api_job_without_retained_key(self):
        job = self.manager.create_job({"title": "Lifecycle fixture", "query": "fixture", "mode": "api",
            "api_key": "LIFECYCLE_FIXTURE_NOT_A_REAL_KEY", "settings": {"transport": "python"}})
        claimed = self.manager.store.claim_next()
        self.manager._keys.clear()
        return job, claimed

    def test_stop_while_waiting_for_queue_lock_never_claims_new_job(self):
        job = self.manager.create_job({"query": "fixture", "settings": {"demo": True, "transport": "python"}})
        manager = self.manager
        class StopBeforeLockAcquisition:
            def __enter__(self):
                manager._stop.set()
            def __exit__(self, *unused):
                pass
        original_lock = manager._lock
        try:
            manager._lock = StopBeforeLockAcquisition()
            with patch.object(manager, "_execute") as execute:
                manager._loop()
            execute.assert_not_called()
        finally:
            manager._lock = original_lock
        self.assertEqual(manager.get_job(job["id"])["status"], "queued")
        self.assertEqual(manager.get_job(job["id"])["attempts"], 0)

    def test_pause_and_cancel_before_start_take_precedence_over_missing_key(self):
        for action, expected in [("pause", "paused"), ("cancel", "cancelled")]:
            with self.subTest(action=action):
                job, claimed = self.create_api_job_without_retained_key()
                self.manager.action(job["id"], {"action": action})
                with patch("studio.jobs.subprocess.Popen") as launch:
                    self.manager._execute(claimed)
                launch.assert_not_called()
                self.assertEqual(self.manager.get_job(job["id"])["status"], expected)

    def test_concurrent_cancel_is_not_overwritten_by_missing_key_update(self):
        job, claimed = self.create_api_job_without_retained_key()
        entering_update, release_update = threading.Event(), threading.Event()
        cancel_started, cancel_finished = threading.Event(), threading.Event()
        errors = []
        original_update = self.manager.store.update_job
        def delayed_update(job_id, **changes):
            if changes.get("status") == "waiting_input":
                entering_update.set()
                if not release_update.wait(3):
                    raise RuntimeError("Fixture update was never released")
            return original_update(job_id, **changes)
        def execute():
            try:
                self.manager._execute(claimed)
            except Exception as exc:
                errors.append(exc)
        def cancel():
            cancel_started.set()
            try:
                self.manager.action(job["id"], {"action": "cancel"})
            except Exception as exc:
                errors.append(exc)
            finally:
                cancel_finished.set()
        with patch.object(self.manager.store, "update_job", side_effect=delayed_update):
            worker = threading.Thread(target=execute, daemon=True)
            action = threading.Thread(target=cancel, daemon=True)
            worker.start()
            try:
                self.assertTrue(entering_update.wait(2))
                action.start()
                self.assertTrue(cancel_started.wait(2))
                # Cancel must serialize behind the missing-key state transition.
                self.assertFalse(cancel_finished.wait(0.05))
            finally:
                release_update.set()
                worker.join(timeout=3)
                if action.ident is not None:
                    action.join(timeout=3)
        self.assertFalse(worker.is_alive())
        self.assertFalse(action.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(self.manager.get_job(job["id"])["status"], "cancelled")

    def test_process_exiting_between_poll_and_kill_does_not_abort_shutdown(self):
        class ExitingProcess:
            pid = 42424242
            def poll(self):
                return None
            def wait(self, timeout=None):
                return 0
        self.manager._process = ExitingProcess()
        self.manager._keys["fixture"] = "NOT_A_REAL_KEY"
        try:
            with patch("studio.jobs.os.killpg", side_effect=ProcessLookupError):
                self.manager.shutdown()
            self.assertEqual(self.manager._keys, {})
        finally:
            self.manager._process = None


class WorkerLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.job_dir = Path(self.tmp.name) / "job"
        self.job_dir.mkdir()
        self.job, _ = validate_job({"title": "Synthetic lifecycle fixture",
            "query": 'http.component:"php" country:"EG"', "mode": "html",
            "settings": {"demo": True, "transport": "python", "delay": 0}}, allow_demo=True)

    def tearDown(self):
        self.tmp.cleanup()

    def run_capture(self, job=None):
        output = io.StringIO()
        old_term, old_int = signal.getsignal(signal.SIGTERM), signal.getsignal(signal.SIGINT)
        try:
            with contextlib.redirect_stdout(output):
                code = run_worker(self.job_dir, {"job": job or self.job, "api_key": None})
        finally:
            signal.signal(signal.SIGTERM, old_term)
            signal.signal(signal.SIGINT, old_int)
        events = [json.loads(line) for line in output.getvalue().splitlines()]
        return code, events

    def test_immediate_pause_during_source_switch_initialization_is_paused(self):
        self.assertEqual(self.run_capture()[0], 0)
        (self.job_dir / "control.json").write_text('{"action":"pause"}', encoding="utf-8")
        code, events = self.run_capture({**self.job, "mode": "api"})
        self.assertEqual(code, 75)
        self.assertEqual(events[-1]["kind"], "final")
        self.assertEqual(events[-1]["status"], "paused")
        self.assertEqual(events[-1]["stats"]["unique_ips"], 292)
        self.assertEqual(len(engine.load_checkpoint(self.job_dir / "checkpoint.json")["state"]["candidates"]), 292)

    def test_duplicate_launch_preserves_live_progress_and_emits_no_events(self):
        # The active worker may have collected IPs since its last checkpoint.
        # A duplicate must not regenerate live-ips from that older checkpoint.
        self.assertEqual(self.run_capture()[0], 0)
        live = self.job_dir / "live-ips.txt"
        live.write_text(live.read_text() + "203.0.113.42\n")
        before = {p.name: p.read_bytes() for p in self.job_dir.iterdir() if p.is_file()}
        with engine.CheckpointLock(self.job_dir / "checkpoint.json"):
            with patch("studio.worker.build_args", wraps=build_args) as build:
                with patch("studio.worker.emit") as emit:
                    with self.assertRaisesRegex(engine.CheckpointError, "CHECKPOINT_BUSY"):
                        self.run_capture()
                emit.assert_not_called()
            build.assert_not_called()
        after = {p.name: p.read_bytes() for p in self.job_dir.iterdir() if p.is_file()}
        self.assertEqual(after, before)

    def test_duplicate_fresh_launch_creates_no_progress_files(self):
        with engine.CheckpointLock(self.job_dir / "checkpoint.json"):
            with self.assertRaisesRegex(engine.CheckpointError, "CHECKPOINT_BUSY"):
                self.run_capture()
        self.assertEqual({p.name for p in self.job_dir.iterdir()}, {"checkpoint.json.lock"})
        self.assertEqual(self.run_capture()[0], 0)

    def test_setup_failure_releases_lock_for_corrected_resume(self):
        with patch("studio.worker.build_args", side_effect=engine.SpiderError("fixture setup failure")):
            with self.assertRaisesRegex(engine.SpiderError, "fixture setup failure"):
                self.run_capture()
        self.assertEqual(self.run_capture()[0], 0)
        # Repeated resume must preserve deduplication and use cached pages.
        for _ in range(2):
            code, events = self.run_capture()
            self.assertEqual(code, 0)
            self.assertEqual(events[-1]["stats"]["requests_this_run"], 0)
            ips = (self.job_dir / "result.txt").read_text().splitlines()
            self.assertEqual(len(ips), 292)
            self.assertEqual(len(set(ips)), 292)

    def test_resume_recovers_crash_after_output_commit_before_hash_checkpoint(self):
        class InjectedCrash(BaseException):
            pass
        save_results = engine.save_results
        def crash_after_commit(args, report):
            save_results(args, report)
            raise InjectedCrash()
        with patch.object(engine, "save_results", side_effect=crash_after_commit):
            with self.assertRaises(InjectedCrash):
                self.run_capture()
        saved = engine.load_checkpoint(self.job_dir / "checkpoint.json")
        self.assertEqual(saved["state"]["output_hashes"], {})
        self.assertEqual(len((self.job_dir / "result.txt").read_text().splitlines()), 292)
        code, events = self.run_capture()
        self.assertEqual(code, 0)
        self.assertEqual(events[-1]["status"], "completed")
        self.assertEqual(events[-1]["stats"]["unique_ips"], 292)
        self.assertEqual(events[-1]["stats"]["requests_this_run"], 0)
        saved = engine.load_checkpoint(self.job_dir / "checkpoint.json")
        self.assertEqual(len(saved["state"]["output_hashes"]), 2)

    def test_resume_regeneration_rejects_checkpoint_output_escape_and_format_change(self):
        self.run_capture()
        checkpoint_path = self.job_dir / "checkpoint.json"
        original = engine.load_checkpoint(checkpoint_path)
        outside = Path(self.tmp.name) / "must-not-change.txt"
        outside.write_text("untouched", encoding="utf-8")
        for field, value in [("output", str(outside)), ("format", "json")]:
            with self.subTest(field=field):
                checkpoint = json.loads(json.dumps(original))
                checkpoint["config"][field] = value
                engine.save_checkpoint(checkpoint_path, checkpoint, allow_replace=True)
                with self.assertRaisesRegex(engine.SpiderError, "JOB_PATH"):
                    build_args(self.job_dir, self.job, None)
                self.assertEqual(outside.read_text(), "untouched")

    def test_resume_regeneration_still_rejects_symlink_outputs(self):
        self.run_capture()
        outside = Path(self.tmp.name) / "must-not-follow.txt"
        outside.write_text("untouched", encoding="utf-8")
        output = self.job_dir / "result.txt"
        output.unlink()
        output.symlink_to(outside)
        args = build_args(self.job_dir, self.job, None)
        self.assertTrue(args.force)
        with self.assertRaisesRegex(engine.SpiderError, "symbolic-link"):
            engine.preflight(args)
        self.assertEqual(outside.read_text(), "untouched")


if __name__ == "__main__":
    unittest.main()
