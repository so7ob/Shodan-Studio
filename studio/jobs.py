"""Durable job queue and one isolated worker process at a time."""
from __future__ import annotations

import contextlib
import csv
import fcntl
import io
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import signal
import subprocess
import sys
import threading
import time
import urllib.parse

from . import engine
from .config import JobValidationError, settings_from, validate_job, validate_key, text
from .store import Store, utc_now
from .worker import atomic_text
from .ip_progress import crawler_progress_inputs, progress_from_job


FINAL = {"completed", "completed_warnings", "cancelled", "failed"}
ACTIVE = {"running", "pause_requested", "cancel_requested"}
RESUMABLE = {"paused", "waiting_input", "interrupted", "failed"}


class JobManager:
    def __init__(self, data_dir, store=None, demo=False, autostart=True):
        self.data_dir = Path(data_dir).expanduser().resolve()
        self.store = store or Store(self.data_dir)
        self.demo = demo
        self.jobs_dir = self.data_dir / "jobs"
        if self.jobs_dir.is_symlink():
            raise ValueError("مجلد المهام لا يقبل الروابط الرمزية.")
        self.jobs_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.jobs_dir.chmod(0o700)
        self._lock = threading.RLock()
        self._keys = {}
        self._secret_history = set()
        self._stop = threading.Event()
        self._wake = threading.Event()
        self._thread = None
        self._process = None
        self._active_id = None
        self._ownership = None
        self._ip_cache = {}
        if autostart:
            self.start()

    def start(self):
        with self._lock:
            if self._thread and self._thread.is_alive():
                return
            lock_path = self.data_dir / "worker-manager.lock"
            if lock_path.is_symlink():
                raise ValueError("ملف قفل الخدمة غير صالح.")
            self._ownership = lock_path.open("a+")
            os.chmod(lock_path, 0o600)
            try:
                fcntl.flock(self._ownership, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                self._ownership.close()
                self._ownership = None
                raise ValueError("توجد خدمة أخرى تستخدم مجلد البيانات نفسه.") from None
            self.store.recover_interrupted()
            self._restore_ip_progress()
            self._stop.clear()
            self._thread = threading.Thread(target=self._loop, name="studio-queue", daemon=True)
            self._thread.start()

    def _path(self, job_id: str) -> Path:
        if not isinstance(job_id, str) or not re.fullmatch(r"[a-f0-9]{32}", job_id):
            raise KeyError(job_id)
        path = self.jobs_dir / job_id
        if path.is_symlink():
            raise JobValidationError("مسار المهمة غير صالح.")
        return path

    def _get(self, job_id):
        self._path(job_id)
        job = self.store.get_job(job_id)
        if job is None:
            raise KeyError(job_id)
        return job

    def _redact(self, value):
        with self._lock:
            keys = list(self._secret_history)
        def visit(item):
            if isinstance(item, str):
                for key in keys:
                    for encoded in (key, urllib.parse.quote(key, safe=""), urllib.parse.quote_plus(key, safe="")):
                        item = item.replace(encoded, "[REDACTED]")
                return item
            if isinstance(item, list):
                return [visit(x) for x in item]
            if isinstance(item, dict):
                return {k: visit(v) for k, v in item.items()}
            return item
        return visit(value)

    def _remember(self, job_id, key):
        if key:
            with self._lock:
                self._keys[job_id] = key
                self._secret_history.add(key)

    def _public(self, job):
        result = dict(job)
        result["ip_progress"] = progress_from_job(job)
        result.pop("_ip_progress_inputs", None)
        result.pop("_ip_progress_stored", None)
        with self._lock:
            result["has_key"] = result["id"] in self._keys
        path = self._path(result["id"])
        result["has_checkpoint"] = (path / "checkpoint.json").is_file()
        result["has_results"] = bool(result.get("stats", {}).get("unique_ips")) or (path / "live-ips.txt").is_file() or (path / "result.txt").is_file()
        return self._redact(result)

    def _restore_ip_progress(self):
        """One-time legacy backfill and crash reconciliation, entirely offline.

        Reconcile after acquiring manager ownership, before starting the queue.
        An unreadable checkpoint leaves the estimate unknown, never invented.
        """
        with self.store.connection() as con:
            jobs = [json.loads(row[0]) for row in con.execute("SELECT document FROM jobs")]
        for job in jobs:
            # Also reconcile finished jobs: an older release may have written
            # their files during a rollback, leaving the additive SQLite table
            # behind. Startup is offline; normal dashboard polls do no scanning.
            self._restore_job_progress(job)

    def _restore_job_progress(self, job):
        path = self._path(job["id"])
        try:
            ips = set(self._ips(job["id"]))
        except (JobValidationError, OSError):
            ips = set()
        inputs = job.get("_ip_progress_inputs")
        if (path / "checkpoint.json").is_file():
            try:
                from .worker import build_args
                crawler = engine.Crawler(build_args(path, {**job, "mode": "html"}, None))
                ips.update(str(ip) for ip in crawler.accepted)
                saved = crawler.args.resume_payload["config"].get("studio_ip_progress")
                if isinstance(saved, dict):
                    # Store only the recognized, numeric estimator input fields.
                    from .ip_progress import validate_progress_inputs
                    inputs = validate_progress_inputs(saved)
                else:
                    inputs = None
                    report_path = path / "result.txt.report.json"
                    if report_path.is_file() and not report_path.is_symlink() and report_path.stat().st_size <= 64 * 1024 * 1024:
                        report = json.loads(report_path.read_text(encoding="utf-8"))
                        if report.get("status") == crawler.args.resume_payload["state"].get("status"):
                            crawler.report = report
                            inputs = crawler_progress_inputs(crawler)
            except (ValueError, TypeError, KeyError, AttributeError, OSError,
                    engine.SpiderError, engine.CheckpointError, SystemExit):
                inputs = None
        self.store.record_ip_progress(job["id"], ips, inputs or {
            "branches": [], "planning_complete": False, "traversal_completed": False},
            updated_at=job["updated_at"])

    def list_jobs(self):
        jobs = [self._public(j) for j in self.store.list_jobs()]
        summary = {
            "total": len(jobs), "running": sum(j["status"] in ACTIVE for j in jobs),
            "queued": sum(j["status"] == "queued" for j in jobs),
            "completed": sum(j["status"] in ("completed", "completed_warnings") for j in jobs),
            "needs_attention": sum(j["status"] in ("waiting_input", "interrupted", "failed") for j in jobs),
            "unique_ips": sum(j.get("stats", {}).get("unique_ips", 0) for j in jobs),
            "requests": sum(j.get("stats", {}).get("requests", 0) for j in jobs),
        }
        # unique_ips is a sum across jobs, never a cross-job deduplicated union.
        summary["ip_count_scope"] = "sum_per_job"
        return {"jobs": jobs, "summary": summary}

    def get_job(self, job_id):
        return self._public(self._get(job_id))

    def _new_job(self, fields, key, *, start=True):
        job_id = secrets.token_hex(16)
        path = self._path(job_id)
        path.mkdir(mode=0o700)
        self._remember(job_id, key)
        missing = fields["mode"] == "api" and not key and not fields["settings"]["demo"]
        status = "waiting_input" if missing else "queued" if start else "paused"
        job = {**fields, "id": job_id, "status": status, "stats": {"phase": "queued", "unique_ips": 0, "requests": 0,
                   "request_budget": fields["settings"]["max_requests"], "plan_known": False,
                   "completed_branches": 0, "ready_branches": None, "remaining_branches": None,
                   "percent": None, "source": fields["mode"], "warnings": 0, "demo": fields["settings"]["demo"]},
               "_ip_progress_stored": True,
               "error": "أدخل مفتاح API لاستكمال المهمة." if missing else None,
               "created_at": utc_now(), "started_at": None, "finished_at": None, "attempts": 0}
        try:
            self.store.create_job(job)
        except Exception:
            with self._lock:
                self._keys.pop(job_id, None)
            shutil.rmtree(path)
            raise
        self.store.append_event(job_id, {"kind": "state", "status": status, "level": "info", "message": "أُنشئت المهمة."})
        if start:
            self._wake.set()
        return self.get_job(job_id)

    def create_job(self, payload):
        fields, key = validate_job(payload, allow_demo=self.demo)
        with self._lock:
            return self._new_job(fields, key)

    def _control(self, job_id, action):
        atomic_text(self._path(job_id) / "control.json", json.dumps({"action": action}))

    def action(self, job_id, payload):
        if not isinstance(payload, dict) or set(payload) - {"action", "mode", "api_key"}:
            raise JobValidationError("طلب الإجراء غير صالح.")
        action = payload.get("action")
        with self._lock:
            job = self._get(job_id)
            state = job["status"]
            if action == "duplicate":
                fields = {k: job[k] for k in ("title", "query", "mode", "settings", "priority")}
                fields["title"] = fields["title"][:150] + " — نسخة"
                key = validate_key(payload.get("api_key")) or self._keys.get(job_id)
                if key and (any(key in fields[name] for name in ("title", "query")) or key in fields["settings"]["user_agent"]):
                    raise JobValidationError("ضع مفتاح API في حقل المفتاح فقط.")
                if payload.get("mode"):
                    mode = payload["mode"]
                    if mode not in ("html", "api", "auto"):
                        raise JobValidationError("مصدر غير صالح.")
                    fields["mode"] = ("api" if key else "html") if mode == "auto" else mode
                return self._new_job(fields, key)
            if action == "pause":
                if state == "queued":
                    self.store.update_job(job_id, status="paused")
                elif state in ACTIVE:
                    if state == "cancel_requested":
                        raise JobValidationError("إلغاء المهمة قيد التنفيذ.")
                    self._control(job_id, "pause")
                    self.store.update_job(job_id, status="pause_requested")
                else:
                    raise JobValidationError("هذه المهمة ليست قيد التنفيذ أو الانتظار.")
            elif action == "cancel":
                if state in ("completed", "completed_warnings", "cancelled"):
                    raise JobValidationError("المهمة انتهت بالفعل.")
                if state in ACTIVE:
                    self._control(job_id, "cancel")
                    self.store.update_job(job_id, status="cancel_requested")
                else:
                    self.store.update_job(job_id, status="cancelled", finished_at=utc_now())
                    self._keys.pop(job_id, None)
            elif action == "resume":
                if state not in RESUMABLE:
                    raise JobValidationError("يمكن الاستكمال بعد توقف المهمة فقط.")
                key = validate_key(payload.get("api_key")) or self._keys.get(job_id)
                mode = payload.get("mode", job["mode"])
                if mode not in ("html", "api", "auto"):
                    raise JobValidationError("مصدر غير صالح.")
                if mode == "auto":
                    mode = "api" if key else "html"
                if key and (key in job["query"] or key in job["title"] or key in job["settings"]["user_agent"]):
                    raise JobValidationError("المفتاح موجود في حقل نصي للمهمة؛ استخدم مهمة جديدة دون تضمين المفتاح.")
                if mode == "api" and not key and not job["settings"]["demo"]:
                    raise JobValidationError("أدخل مفتاح API أو اختر HTML.")
                self._remember(job_id, key)
                (self._path(job_id) / "control.json").unlink(missing_ok=True)
                self.store.update_job(job_id, status="queued", mode=mode, error=None, finished_at=None, input_reason=None)
                self._wake.set()
            else:
                raise JobValidationError("إجراء غير مدعوم.")
            updated = self.get_job(job_id)
            self.store.append_event(job_id, {"kind": "state", "status": updated["status"], "level": "info", "message": {
                "pause": "طُلب إيقاف المهمة مؤقتًا. يُحفظ الطلب الجاري قبل التوقف.",
                "cancel": "طُلب إلغاء المهمة.", "resume": "أُعيدت المهمة إلى الطابور للاستكمال."}[action]})
            return updated

    def _loop(self):
        while not self._stop.is_set():
            try:
                with self._lock:
                    if self._stop.is_set():
                        break
                    job = self.store.claim_next()
                    if job:
                        self._active_id = job["id"]
                if job:
                    self._execute(job)
                    with self._lock:
                        self._active_id = None
                    continue
            except Exception as exc:
                if self._active_id:
                    with contextlib.suppress(Exception):
                        self.store.update_job(self._active_id, status="failed", error=self._redact(str(exc))[:1000], finished_at=utc_now())
                self._active_id = None
            self._wake.wait(0.5)
            self._wake.clear()

    def _execute(self, job):
        job_id, path = job["id"], self._path(job["id"])
        with self._lock:
            key = self._keys.get(job_id)
            current = self._get(job_id)
            if current["status"] in ("pause_requested", "cancel_requested") or self._stop.is_set():
                state = "cancelled" if current["status"] == "cancel_requested" else "paused"
                self.store.update_job(job_id, status=state, finished_at=utc_now() if state == "cancelled" else None)
                if state == "cancelled":
                    self._keys.pop(job_id, None)
                return
            if job["mode"] == "api" and not key and not job["settings"]["demo"]:
                self.store.update_job(job_id, status="waiting_input", error="المفتاح غير موجود في ذاكرة الخدمة. أدخله من نافذة الاستكمال.", input_reason="api_key")
                self.store.append_event(job_id, {"kind": "input_required", "level": "warning", "message": "أدخل مفتاح API أو اختر HTML."})
                return
        env = os.environ.copy()
        env.pop("SHODAN_API_KEY", None)
        env["PYTHONUNBUFFERED"] = "1"
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        command = [sys.executable, "-m", "studio.worker", "--job-dir", str(path)]
        # No shell, user-controlled executable, credential argv, or target URL.
        process = subprocess.Popen(command, cwd=Path(__file__).resolve().parent.parent,
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                   env=env, text=True, encoding="utf-8", errors="replace", bufsize=1, start_new_session=True)
        with self._lock:
            self._process = process
        final = None
        try:
            process.stdin.write(json.dumps({"job": job, "api_key": key}, ensure_ascii=False) + "\n")
            process.stdin.close()
            for line in process.stdout:
                if len(line) > 2 * 1024 * 1024:
                    process.terminate()
                    raise RuntimeError("تجاوز حدث العامل الحجم المسموح.")
                try:
                    event = json.loads(line)
                except ValueError:
                    self.store.append_event(job_id, {"kind": "log", "level": "warning", "message": self._redact(line.strip())[:2000]})
                    continue
                if not isinstance(event, dict):
                    continue
                event = self._redact(event)
                kind = event.get("kind")
                if kind == "ip_batch":
                    self.store.record_ip_progress(job_id, event.get("ips", []))
                    continue
                with self._lock:
                    current = self._get(job_id)
                    changes = {}
                    if isinstance(event.get("stats"), dict):
                        changes["stats"] = event["stats"]
                        if event["stats"].get("source") in ("api", "html"):
                            changes["mode"] = event["stats"]["source"]
                    if kind == "final":
                        final = event
                        state = event.get("status", "failed")
                        if current["status"] == "cancel_requested":
                            state = "cancelled"
                        elif current["status"] == "pause_requested" and state == "completed":
                            # A just-completed job is complete even if the click raced its final write.
                            state = "completed"
                        if state not in FINAL | RESUMABLE:
                            state = "failed"
                        changes.update(status=state, error=event.get("error"), input_reason=event.get("input_reason"),
                                       finished_at=utc_now() if state in FINAL else None)
                    if changes:
                        updated = self.store.record_ip_progress(job_id,
                            inputs=event.pop("ip_progress_inputs", None), **changes)
                        event["stats"] = updated["stats"]
                        event["ip_progress"] = progress_from_job(updated)
                self.store.append_event(job_id, event)
            process.wait()
            if final is None:
                current = self._get(job_id)
                state = "cancelled" if current["status"] == "cancel_requested" else "interrupted"
                self.store.update_job(job_id, status=state, error="توقف عامل التنفيذ قبل اكتماله. آخر نقطة استكمال ونتائج محفوظة متاحة.", finished_at=utc_now() if state == "cancelled" else None)
                self._restore_job_progress(self._get(job_id))
                self.store.append_event(job_id, {"kind": "state", "status": state, "level": "warning", "message": "توقف عامل التنفيذ؛ يمكن استكمال آخر حالة محفوظة."})
        finally:
            if process.poll() is None:
                with contextlib.suppress(ProcessLookupError):
                    os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    with contextlib.suppress(ProcessLookupError):
                        os.killpg(process.pid, signal.SIGKILL)
                    process.wait()
            process.stdout.close()
            with self._lock:
                self._process = None
                current = self._get(job_id)
                if current["status"] in ("completed", "completed_warnings", "cancelled"):
                    self._keys.pop(job_id, None)

    def _ips(self, job_id):
        self._get(job_id)
        folder = self._path(job_id)
        path = folder / "live-ips.txt"
        if not path.exists():
            path = folder / "result.txt"
        if not path.exists():
            return []
        if path.is_symlink() or not path.is_file():
            raise JobValidationError("ملف النتائج غير صالح.")
        stat = path.stat()
        if stat.st_size > 128 * 1024 * 1024:
            raise JobValidationError("حجم النتائج يتجاوز حد المعاينة والتنزيل من المتصفح.")
        version = (stat.st_mtime_ns, stat.st_size)
        with self._lock:
            old = self._ip_cache.get(job_id)
            if old and old[0] == version:
                return old[1]
        ips = set()
        with path.open(encoding="ascii", errors="replace") as stream:
            for line in stream:
                # Skip an unfinished concurrent append rather than displaying a prefix.
                if not line.endswith("\n"):
                    continue
                try:
                    ips.add(ipaddress.ip_address(line.strip()))
                except ValueError:
                    continue
        values = [str(ip) for ip in sorted(ips, key=lambda x: (x.version, int(x)))]
        with self._lock:
            self._ip_cache[job_id] = (version, values)
        return values

    def results(self, job_id, offset=0, limit=100, q=""):
        offset, limit = max(0, int(offset)), min(1000, max(1, int(limit)))
        if not isinstance(q, str) or len(q) > 128:
            raise JobValidationError("بحث النتائج غير صالح.")
        ips = self._result_ips(job_id)
        selected = [ip for ip in ips if q.casefold() in ip.casefold()] if q else ips
        return {"items": selected[offset:offset+limit], "total": len(selected), "all_total": len(ips), "offset": offset, "limit": limit}

    def _result_ips(self, job_id):
        job = self._get(job_id)
        if not job.get("_ip_progress_stored"):
            return self._ips(job_id)
        with self.store.connection() as con:
            values = [ipaddress.ip_address(row[0]) for row in con.execute(
                "SELECT ip FROM job_ips WHERE job_id=?", (job_id,))]
        return [str(ip) for ip in sorted(values, key=lambda ip: (ip.version, int(ip)))]

    def download(self, job_id, format_name):
        job = self.get_job(job_id)
        name = "shodan-" + job_id[:12]
        if format_name in ("report", "checkpoint"):
            path = self._path(job_id) / ("result.txt.report.json" if format_name == "report" else "checkpoint.json")
            if not path.is_file() or path.is_symlink():
                raise JobValidationError("الملف غير متاح بعد؛ يُحفظ التقرير عند نهاية التنفيذ أو التوقف.")
            if path.stat().st_size > 64 * 1024 * 1024:
                raise JobValidationError("الملف أكبر من الحد المسموح للتنزيل.")
            return path.read_bytes(), "application/json; charset=utf-8", name + "." + format_name + ".json"
        ips = self._result_ips(job_id)
        if format_name == "txt":
            return ("".join(ip + "\n" for ip in ips)).encode(), "text/plain; charset=utf-8", name + ".txt"
        if format_name == "csv":
            stream = io.StringIO(newline="")
            writer = csv.writer(stream)
            writer.writerow(["ip"])
            writer.writerows((ip,) for ip in ips)
            return stream.getvalue().encode(), "text/csv; charset=utf-8", name + ".csv"
        if format_name == "json":
            body = {"job_id": job_id, "query": job["query"], "status": job["status"], "unique_ip_count": len(ips),
                    "complete_export_guaranteed": False, "demo": job["settings"]["demo"], "ips": ips}
            return json.dumps(body, ensure_ascii=False, indent=2).encode(), "application/json; charset=utf-8", name + ".json"
        raise JobValidationError("صيغة تنزيل غير مدعومة.")

    def import_checkpoint(self, payload):
        if not isinstance(payload, dict) or set(payload) - {"checkpoint", "filename", "title", "mode", "api_key"}:
            raise JobValidationError("طلب استيراد نقطة الاستكمال غير صالح.")
        raw = payload.get("checkpoint")
        try:
            engine._checkpoint_validate(raw)
            serialized = json.dumps(raw, ensure_ascii=False, allow_nan=False)
            if len(serialized.encode()) > 32 * 1024 * 1024:
                raise JobValidationError("نقطة الاستكمال تتجاوز 32 MiB.")
            checkpoint = json.loads(serialized)
            cfg = checkpoint["config"]
            engine.validate_saved_config(cfg)
        except (engine.CheckpointError, engine.SpiderError, TypeError, ValueError, RecursionError):
            raise JobValidationError("نقطة الاستكمال غير صالحة أو تحتوي بيانات اعتماد. استخدم ملف ShodanSpider v6/v7 JSON الأصلي.") from None
        key = validate_key(payload.get("api_key"))
        mode = payload.get("mode", cfg["mode"])
        if mode not in ("html", "api", "auto"):
            raise JobValidationError("مصدر غير صالح.")
        if mode == "auto":
            mode = "api" if key else "html"
        runtime = cfg["runtime"]
        if type(cfg.get("studio_demo", False)) is not bool:
            raise JobValidationError("علامة الوضع التجريبي في نقطة الاستكمال غير صالحة.")
        settings = settings_from({
            "ip_version": cfg["ip_version"], "include_non_global": cfg["include_non_global"],
            "strategy": cfg.get("strategy", "tree"), "split_facets": cfg.get("split_facets", ["asn", "port", "version", "product"]),
            "max_plan_nodes": cfg.get("max_plan_nodes", 20000), "api_facet_limit": cfg["api_facet_limit"],
            "always_asn": cfg["always_asn"], "rotate_user_agents": runtime.get("rotate_user_agents", False),
            "user_agent": runtime.get("user_agent") or "", "on_rate_limit": "pause", "api_fallback": runtime.get("api_fallback", "html"),
            "demo": cfg.get("studio_demo", False),
        }, allow_demo=self.demo)
        query = text(cfg["effective_query"], "استعلام نقطة الاستكمال", 8192)
        title = text(payload.get("title", "نقطة استكمال مستوردة"), "اسم المهمة", 160)
        if key and (key in serialized or key in title):
            raise JobValidationError("نقطة الاستكمال تحتوي المفتاح ضمن نصوصها؛ احذفه قبل الاستيراد.")
        # Stage and fully validate all cached data without networking before enqueuing.
        with self._lock:
            job = self._new_job({"query": query, "title": title, "mode": mode, "settings": settings, "priority": 0}, key, start=False)
            path = self._path(job["id"])
            cfg["output"], cfg["format"] = str(path / "result.txt"), "txt"
            checkpoint["state"]["output_hashes"] = {}
            try:
                engine.save_checkpoint(path / "checkpoint.json", checkpoint)
                from .worker import build_args
                # Validation may use HTML while retaining original cache provenance.
                validation_job = {**job, "mode": "html"}
                args = build_args(path, validation_job, None)
                crawler = engine.Crawler(args)
                atomic_text(path / "live-ips.txt", "".join(str(ip)+"\n" for ip in sorted(crawler.accepted, key=lambda ip: (ip.version, int(ip)))))
                stats = {**job["stats"], "unique_ips": len(crawler.accepted), "requests": crawler.previous_requests,
                         "warnings": len(crawler.report["warnings"]), "wait_until": crawler.not_before_utc}
                missing = mode == "api" and not key and not settings["demo"]
                self.store.update_job(job["id"], status="waiting_input" if missing else "paused", stats=stats,
                                      error="أدخل مفتاح API للاستكمال." if missing else None, imported=True)
                self._restore_job_progress(self._get(job["id"]))
                self.store.append_event(job["id"], {"kind": "log", "level": "info", "message": "استُوردت نقطة الاستكمال؛ راجع المصدر ثم اختر استكمال."})
                return self.get_job(job["id"])
            except (Exception, SystemExit):
                self.store.delete_job(job["id"])
                self._keys.pop(job["id"], None)
                shutil.rmtree(path)
                raise JobValidationError("تعذر التحقق من حالة نقطة الاستكمال؛ لم تُرسل أي طلبات خارجية.") from None

    def shutdown(self):
        self._stop.set()
        self._wake.set()
        with self._lock:
            active = self._active_id
            if active:
                self._control(active, "pause")
                if self._get(active)["status"] == "running":
                    self.store.update_job(active, status="pause_requested")
        thread = self._thread
        if thread and thread is not threading.current_thread():
            thread.join(timeout=35)
        with self._lock:
            process = self._process
        if process and process.poll() is None:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                with contextlib.suppress(ProcessLookupError):
                    os.killpg(process.pid, signal.SIGKILL)
                process.wait()
        if thread and thread.is_alive() and thread is not threading.current_thread():
            thread.join(timeout=5)
        with self._lock:
            self._keys.clear()
            self._secret_history.clear()
            if self._ownership:
                fcntl.flock(self._ownership, fcntl.LOCK_UN)
                self._ownership.close()
                self._ownership = None

