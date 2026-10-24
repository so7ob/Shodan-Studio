"""Isolated worker. JSON arrives on stdin; credentials never enter argv or disk."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import html
import ipaddress
import json
import os
from pathlib import Path
import signal
import sys
import time
import urllib.parse

from . import engine
from .config import settings_from, validate_key
from .ip_progress import crawler_progress_inputs
from .vpn_config import network_error


def atomic_text(path: Path, content: str) -> None:
    temp = path.with_name(path.name + ".new")
    with temp.open("w", encoding="utf-8") as stream:
        os.chmod(temp, 0o600)
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temp, path)


def emit(kind: str, **fields) -> None:
    event = engine.redact_report({"kind": kind, **fields}, None)
    sys.stdout.write(json.dumps(event, ensure_ascii=False, allow_nan=False) + "\n")
    sys.stdout.flush()


def build_args(job_dir: Path, job: dict, key: str | None):
    """Construct a fixed CLI argument vector; shell syntax is never evaluated."""
    cfg = settings_from(job["settings"], allow_demo=True)
    checkpoint = job_dir / "checkpoint.json"
    argv = ["--mode", job["mode"], "--save-partial", "--on-source-error", "pause"]
    if checkpoint.exists():
        argv += ["--resume", str(checkpoint)]
    else:
        argv += ["--query", job["query"], "--output", str(job_dir / "result.txt"),
                 "--checkpoint", str(checkpoint), "--strategy", cfg["strategy"],
                 "--split-facets", ",".join(cfg["split_facets"]),
                 "--max-plan-nodes", str(cfg["max_plan_nodes"]),
                 "--ip-version", cfg["ip_version"], "--api-facet-limit", str(cfg["api_facet_limit"])]
        if cfg["always_asn"]:
            argv += ["--always-asn"]
        if cfg["include_non_global"] or cfg["demo"]:
            argv += ["--include-non-global"]
    for name in ("transport", "timeout", "delay", "max_requests", "api_fallback", "on_rate_limit",
                 "rate_limit_retries", "retry_base_delay", "max_retry_wait"):
        argv += ["--" + name.replace("_", "-"), str(cfg[name])]
    argv += ["--rotate-user-agents" if cfg["rotate_user_agents"] else "--no-rotate-user-agents"]
    if cfg["user_agent"]:
        argv += ["--user-agent", cfg["user_agent"]]
    # Explicit mode keeps an inherited environment key from choosing the source.
    os.environ.pop("SHODAN_API_KEY", None)
    args = engine.parse_args(argv)
    # Checkpoints are data, never authority to choose a filesystem destination.
    if args.output is None or args.output.absolute() != job_dir / "result.txt" or args.report_path.absolute() != job_dir / "result.txt.report.json" or args.format != "txt":
        raise engine.SpiderError("[JOB_PATH] مسار نتائج نقطة الاستكمال لا يطابق مجلد المهمة.")
    if args.resume_payload is not None:
        # Both outputs are regenerable from this job's authoritative checkpoint.
        # A crash between the output pair commit and its checksum checkpoint must
        # not make a server-owned job permanently unresumable.
        args.force = True
    if key:
        engine._REGISTERED_SECRETS.add(key)
    args.api_key = None
    args.api_key_resolved = key if args.mode == "api" else None
    args.api_key_source = "browser-memory" if args.api_key_resolved else None
    if args.mode == "api" and not args.api_key_resolved:
        if cfg["demo"]:
            args.api_key_resolved = "STUDIO_DEMO_NOT_A_REAL_API_KEY"
            args.api_key_source = "demo"
        else:
            raise engine.SpiderError("[API_KEY] أدخل مفتاح API من نافذة الاستكمال.")
    return args


class DemoData:
    """Synthetic record buckets; no Shodan or target network request is made."""
    def __init__(self, query: str):
        fields = engine.scope_filters(query)
        self.country = next((v[0] for _, _, v, neg in fields.get("country", []) if not neg and len(v) == 1), "EG")

    def values(self, query: str, facet: str):
        fields = engine.scope_filters(query)
        def chosen(name):
            return next((v[0].casefold() for _, _, v, neg in fields.get(name, []) if not neg and len(v) == 1), "")
        city, asn, port = chosen("city"), chosen("asn"), chosen("port")
        if facet == "country":
            return [(self.country, 292)], 292
        if facet == "city":
            return [("Cairo", 194), ("Giza", 98)], 292
        if facet == "asn" and city == "cairo":
            return [("AS8452", 140), ("AS24863", 54)], 194
        if facet == "port" and asn == "as8452":
            return [("443", 51), ("8080", 49), ("80", 40)], 140
        if facet == "ip":
            offset, count = ((0, 98) if city == "giza" else (98, 54) if asn == "as24863" else
                             (152, 51) if port == "443" else (203, 49) if port == "8080" else (252, 40))
            result = []
            for number in range(offset, offset + count):
                address = (f"192.0.2.{number + 1}" if number < 254 else f"198.51.100.{number - 253}")
                result.append((address, 1))
            return result, count
        return [], 0

    def fetch(self, url: str) -> str:
        params = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)
        facet, query = params["facet"][0], params["query"][0]
        rows, total = self.values(query, facet)
        # Match the real parser's facet table with links retaining the query.
        body = [f'<html><head><title>Shodan demo facet</title></head><body><h2>Total: {total}</h2><table class="facet-table">']
        for value, count in rows:
            child = engine.narrow_query(query, facet, value) if facet != "ip" else query + ' ip:"' + value + '"'
            href = "/search?" + urllib.parse.urlencode({"query": child})
            body.append(f'<tr><td><a href="{html.escape(href, quote=True)}">{html.escape(value)}</a></td><td>{count}</td></tr>')
        body.append("</table></body></html>")
        return "".join(body)

    def request(self, path: str, params: dict):
        query = params["query"]
        if path.endswith("/count"):
            facet = params["facets"].split(":")[0]
            rows, total = self.values(query, facet)
            return {"total": total, "facets": {facet: [{"value": value, "count": count} for value, count in rows]}}
        rows, total = self.values(query, "ip")
        page = int(params.get("page", 1))
        return {"total": total, "matches": [{"ip_str": ip, "port": 443, "_shodan": {"id": ip}} for ip, _ in rows[(page-1)*100:page*100]]}


class StudioCrawler(engine.Crawler):
    def __init__(self, args, job_dir: Path, *, demo=False):
        self.job_dir = job_dir
        self.demo_data = DemoData(args.effective_query) if demo else None
        self.stop_reason = None
        self.input_reason = None
        self._last_snapshot = 0.0
        self._live_seen = None
        self._reported_ips = set()
        self._finalizing = False
        self._initializing = True
        self._current_query = args.effective_query
        super().__init__(args, fetcher=self.demo_data.fetch if demo else None,
                         sleeper=self.interruptible_sleep, continue_prompt=self.needs_input)
        if args.mode == "api":
            self.configure_source("api")
        self._live_seen = set(self.accepted)
        atomic_text(self.job_dir / "live-ips.txt", "".join(str(ip) + "\n" for ip in sorted(self.accepted, key=lambda ip: (ip.version, int(ip)))))
        self._initializing = False

    def configure_source(self, mode, client=None):
        return super().configure_source(mode, client=self.demo_data if mode == "api" and self.demo_data else client)

    def saved_config(self):
        return {**super().saved_config(), "studio_demo": self.demo_data is not None,
                "studio_ip_progress": crawler_progress_inputs(self)}

    def check_control(self):
        if self._finalizing or self._initializing:
            return
        path = self.job_dir / "control.json"
        try:
            payload = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
        except (OSError, ValueError):
            payload = {}
        action = payload.get("action")
        if self.stop_reason or action in ("pause", "cancel"):
            self.stop_reason = self.stop_reason or action
            raise engine.PauseRequested("[CANCELLED] أُلغيت المهمة مع الاحتفاظ بما جُمع." if self.stop_reason == "cancel" else "[PAUSED] حُفظ التقدم؛ يمكنك الاستكمال من لوحة التحكم.")

    def interruptible_sleep(self, duration):
        end = time.monotonic() + duration
        while True:
            self.check_control()
            remaining = end - time.monotonic()
            if remaining <= 0:
                return
            self.snapshot()
            time.sleep(min(0.25, remaining))

    def needs_input(self, message):
        self.input_reason = "rate_limit"
        emit("input_required", level="warning", message=message,
             detail={"reason": "rate_limit", "choices": ["resume", "cancel"]})
        return False

    def _sync_live(self):
        if self._live_seen is None:
            return
        new = self.accepted - self._live_seen
        if new:
            with (self.job_dir / "live-ips.txt").open("a", encoding="ascii") as stream:
                os.chmod(stream.name, 0o600)
                for address in sorted(new, key=lambda ip: (ip.version, int(ip))):
                    stream.write(str(address) + "\n")
            self._live_seen.update(new)

    def stats(self):
        plan = self.report.get("plan")
        known = isinstance(plan, dict)
        branches = plan.get("extraction_order", []) if known else []
        done = int(plan.get("completed_leaves", 0)) if known else 0
        total = len(branches) if known else None
        phase = self.report.get("planning_stage", "discovering")
        if self.not_before_utc and self.not_before_utc > time.time():
            phase = "waiting"
        return {
            "phase": phase, "unique_ips": len(self.accepted), "filtered_ips": len(self.candidates)-len(self.accepted),
            "requests": self.previous_requests + self.report["requests_attempted"],
            "requests_this_run": self.report["requests_attempted"], "request_budget": self.args.max_requests,
            "completed_branches": done, "ready_branches": total,
            "remaining_branches": max(0, total-done) if total is not None else None,
            "plan_known": known, "percent": round(100*done/total, 1) if total else (100 if known and self.report.get("traversal_completed") else None),
            "current_query": self._current_query, "source": self.args.mode,
            "warnings": len(self.report["warnings"]), "wait_until": self.not_before_utc,
            "cache_hits": self.report.get("cache_hits", 0), "visited": self.report.get("visited", {}),
            "session_number": self.session_number, "demo": self.demo_data is not None,
            "traversal_completed": self.report.get("traversal_completed", False),
        }

    def snapshot(self, force=False):
        if not force and time.monotonic() - self._last_snapshot < 1:
            return
        self._last_snapshot = time.monotonic()
        self._sync_live()
        new = self.accepted - self._reported_ips
        addresses = sorted(str(ip) for ip in new)
        # Bound IPC messages, including a large restored checkpoint. These
        # batches are consumed into SQLite, never copied into the event log.
        for offset in range(0, len(addresses), 1000):
            emit("ip_batch", ips=addresses[offset:offset + 1000])
        self._reported_ips.update(new)
        emit("progress", stats=self.stats(), ip_progress_inputs=crawler_progress_inputs(self))

    def progress(self, text):
        self.check_control()
        if " | " in text:
            self._current_query = text.split(" | ", 1)[1]
        emit("log", level="info", message=text)
        self.snapshot(force=True)

    def warning(self, code, message, query, facet):
        self.report["warnings"].append({"code": code, "message": message, "query": query, "facet": facet})
        emit("warning", level="warning", message=f"[{code}] {message}", detail={"facet": facet, "query": query})
        self.snapshot(force=True)

    def checkpoint(self, status=None):
        super().checkpoint(status)
        self.snapshot(force=True)

    def _request_with_rate_limits(self, operation, template, label, counter=None):
        # Retry at the existing request boundary so every attempt is budgeted,
        # recorded, and cannot mark a failed page complete.
        for attempt in range(3):
            try:
                result = super()._request_with_rate_limits(operation, template, label, counter)
                if attempt:
                    emit('network', phase='resuming_extraction', message='استعاد الطلب الاتصال.', error=None)
                return result
            except (engine.SpiderError, engine.ShodanAPIError, OSError) as exc:
                category = network_error(exc)
                if not category: raise
                detail = engine.safe_detail(exc)
                emit('network', phase='connection_lost', error=detail, message=detail)
                self.checkpoint('network_retry')
                if attempt == 2:
                    self.input_reason = 'network_error'
                    raise engine.PauseRequested(detail) from None
                emit('network', phase='retry_scheduled', error=detail,
                     message=f'إعادة محاولة الاتصال بعد {2 ** attempt} ثانية.')
                self.interruptible_sleep(2 ** attempt)

    def read_page(self, query, facet, expected=None):
        self.check_control()
        self._current_query = query
        return super().read_page(query, facet, expected)

    def collect_ips(self, page):
        super().collect_ips(page)
        self._sync_live()


def run_worker(job_dir: Path, payload: dict) -> int:
    os.umask(0o077)
    job, key = payload["job"], validate_key(payload.get("api_key"))
    if key:
        engine._REGISTERED_SECRETS.add(key)
    args = build_args(job_dir, job, key)
    engine.preflight(args)
    crawler = StudioCrawler(args, job_dir, demo=job["settings"].get("demo", False))
    def stop_signal(_number, _frame):
        crawler.stop_reason = "pause"
    signal.signal(signal.SIGTERM, stop_signal)
    signal.signal(signal.SIGINT, stop_signal)
    automatic_fallback_used = False
    state, error = "failed", None
    with engine.CheckpointLock(args.checkpoint):
        crawler.checkpoint("starting")
        emit("state", status="running", message="بدأ عامل التنفيذ.")
        try:
            while True:
                crawler.check_control()
                try:
                    report = crawler.run()
                    state = "completed_warnings" if report["warnings"] else "completed"
                    break
                except (engine.SpiderError, engine.ShodanAPIError, OSError) as exc:
                    if isinstance(exc, engine.PauseRequested):
                        raise
                    recoverable = engine.recoverable_source_error(exc)
                    access_failure = getattr(exc, "http_status", None) in (401, 402, 403) or getattr(exc, "failure_kind", None) in ("auth", "permission", "quota")
                    if recoverable and args.mode == "api" and args.api_fallback == "html" and access_failure and not automatic_fallback_used and crawler.report["requests_attempted"] < args.max_requests:
                        automatic_fallback_used = True
                        emit("warning", level="warning", message="تعذر الوصول عبر API؛ محاولة HTML مع حفظ النطاق والتقدم. " + engine.safe_detail(exc))
                        crawler.switch_source("html", "automatic API fallback: " + engine.safe_detail(exc))
                        continue
                    if recoverable or str(exc).startswith("[REQUEST_LIMIT]"):
                        crawler.input_reason = "source_error" if recoverable else "request_budget"
                        emit("input_required", level="warning", message=engine.safe_detail(exc),
                             detail={"reason": crawler.input_reason, "choices": ["resume", "change_source", "new_key", "cancel"]})
                        raise engine.PauseRequested(engine.safe_detail(exc)) from None
                    raise
        except (engine.SpiderError, engine.ShodanAPIError, OSError, KeyboardInterrupt) as exc:
            error = engine.safe_detail(exc)
            paused = isinstance(exc, (engine.PauseRequested, KeyboardInterrupt))
            state = "cancelled" if crawler.stop_reason == "cancel" else "waiting_input" if crawler.input_reason else "paused" if paused else "failed"
            report = crawler.finish("paused" if paused else "failed", error)
            report["partial_saved"] = True
        crawler._finalizing = True
        crawler.checkpoint(report["status"])
        engine.save_results(args, report)
        crawler.capture_output_hashes()
        crawler.checkpoint(report["status"])
        crawler._sync_live()
        emit("final", status=state, error=error, stats=crawler.stats(),
             ip_progress_inputs=crawler_progress_inputs(crawler),
             message="اكتمل تنفيذ الفروع المكتشفة." if state.startswith("completed") else error,
             input_reason=crawler.input_reason)
    return 0 if state.startswith("completed") else 75 if state in ("paused", "waiting_input", "cancelled") else 1


def main(argv=None):
    parser = argparse.ArgumentParser(description="Private Shodan Studio worker")
    parser.add_argument("--job-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        body = sys.stdin.buffer.read(1024 * 1024 + 1)
        if len(body) > 1024 * 1024:
            raise ValueError("Worker input exceeds its limit.")
        payload = json.loads(body)
        return run_worker(args.job_dir.resolve(), payload)
    except (Exception, SystemExit) as exc:
        # Detailed exceptions are redacted, and no traceback includes stdin.
        emit("final", status="failed", error=engine.safe_detail(exc), message="تعذر إعداد عامل التنفيذ.")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
