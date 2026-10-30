"""Durable extraction and enrichment queues with independent execution spaces."""
from __future__ import annotations

import contextlib
import csv
import fcntl
from functools import wraps
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
from .store import Store, utc_now, _json
from .worker import atomic_text
from .ip_progress import crawler_progress_inputs, progress_from_job
from .vpn import NON_FAILOVER_ERRORS, VPNManager
from .vpn_config import NETWORK_DEFAULTS, can_failover


FINAL = {"completed", "completed_warnings", "cancelled", "failed"}
ACTIVE = {"running", "pause_requested", "cancel_requested"}
RESUMABLE = {"paused", "waiting_input", "interrupted", "failed"}


def in_job_lane(method):
    """Route job controls, including internal/test callers, to their owning lane."""
    @wraps(method)
    def routed(self, job, *args, **kwargs):
        document = job if isinstance(job, dict) else self._get(job)
        lane = self._root.lane(document.get('kind', 'extraction'))
        return method(lane, job, *args, **kwargs)
    return routed


class JobManager:
    def __init__(self, data_dir, store=None, demo=False, autostart=True, *, _kind='extraction', _root=None):
        self.data_dir = Path(data_dir).expanduser().resolve()
        self.store = store or Store(self.data_dir)
        self.demo = demo
        self.kind = _kind
        self._root = _root or self
        self.vpn = VPNManager(self.store, kind=_kind)
        from .shodan_accounts import ShodanAccounts
        self.shodan_accounts = ShodanAccounts(self.store)
        from .enrichment import EnrichmentSettings
        self.enrichment_settings = EnrichmentSettings(self.store, self.shodan_accounts)
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
        self._network_operation = False
        self._browser_job = None
        self._browser_deadline = 0
        self._ownership = None
        self._ip_cache = {}
        self._seed_requested = threading.Event()
        self._seed_requested.set()
        self._seed_lock = threading.RLock()
        self._credential_lock = _root._credential_lock if _root else threading.RLock()
        if _root:
            self._keys = _root._keys
            self._secret_history = _root._secret_history
        else:
            self.enrichment = JobManager(data_dir, store=self.store, demo=demo, autostart=False,
                                         _kind='enrichment', _root=self)
        if autostart:
            self.start()

    def lane(self, kind='extraction'):
        from .lanes import space
        space(kind)
        return self._root.enrichment if kind == 'enrichment' else self._root

    def _start_lane(self):
        with contextlib.suppress(Exception):
            browser = self.vpn.provider.get_status().get('browser', {})
            job = self.store.get_job(browser.get('job_id')) if browser.get('running') else None
            if job and job.get('kind', 'extraction') == self.kind:
                self._browser_job = job['id']
                self._browser_deadline = time.monotonic() + 1800
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name='studio-' + self.kind, daemon=True)
        self._thread.start()

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
            restored_jobs = self._restore_ip_progress()
            self.store.requests.interrupt()
            for job in restored_jobs:
                try:
                    self.store.requests.backfill(job['id'], self._path(job['id']))
                except (ValueError, OSError, KeyError, TypeError, AttributeError):
                    self.store.append_event(job['id'],{'kind':'warning','level':'warning',
                        'message':'تعذر استعادة بعض تفاصيل الطلبات القديمة؛ بقيت البيانات الأصلية محفوظة.'})
                try:
                    self.store.targets.backfill(job)
                    self._replay_target_events(job)
                except (ValueError, OSError, KeyError, TypeError, engine.CheckpointError):
                    self.store.append_event(job['id'], {'kind': 'warning', 'message': 'تعذر استعادة بعض تفاصيل الأهداف؛ بقيت البيانات الأصلية محفوظة.'})
            self._start_lane()
            self.enrichment._start_lane()

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
        with self._credential_lock:
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
            with self._credential_lock:
                self._keys[job_id] = key
                self._secret_history.add(key)

    @in_job_lane
    def _public(self, job):
        result = {**NETWORK_DEFAULTS, "active_vpn_profile": None, "current_egress_ip": None,
                  "network_health": "unknown", "last_network_error": None, "last_failover_at": None,
                  "failover_count": 0, 'kind': 'extraction', **job}
        result["ip_progress"] = progress_from_job(job)
        if result['kind'] == 'enrichment':
            progress = self.store.targets.progress(job['id'])
            result['enrichment_progress'] = progress
            result['ip_progress'] = {'extracted_unique_ips': progress['processed'], 'estimated_total_ips': progress['total'],
                                     'progress_percent': progress['percent'], 'enrichment': progress,
                                     'job_finished_successfully': job['status'] in ('completed', 'completed_warnings')}
            result['stats'] = {**result.get('stats', {}), 'unique_ips': progress['processed'], 'completed_branches': progress['processed'],
                               'ready_branches': progress['total'], 'remaining_branches': progress['pending'], 'plan_known': True}
        result['latest_request'] = self.store.requests.latest(job['id'])
        result.pop("_ip_progress_inputs", None)
        result.pop("_ip_progress_stored", None)
        with self._lock:
            result["has_key"] = result["id"] in self._keys or (result['kind'] == 'enrichment' and self.enrichment_settings.public()['has_key'])
            result["network_busy"] = self._active_id == result["id"]
            result['browser_session_open'] = self._browser_job == result['id']
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
            if job.get('browser_recovery_attempt', {}).get('state') == 'opening':
                self.store.update_job(job['id'], browser_recovery_attempt={**job['browser_recovery_attempt'],
                    'state': 'failed', 'error': 'توقف الخادم أثناء فتح المتصفح؛ راجع الجلسة يدويًا.'})
            if job.get("network_mode", "direct") != "direct" and job["status"] not in FINAL:
                self.store.update_job(job["id"], network_health="unknown", current_egress_ip=None, network_phase="checking_network")
            # Also reconcile finished jobs: an older release may have written
            # their files during a rollback, leaving the additive SQLite table
            # behind. Startup is offline; normal dashboard polls do no scanning.
            self._restore_job_progress(job)
        return jobs

    def _restore_job_progress(self, job):
        if job.get('kind') == 'enrichment':
            try: self._replay_target_events(job)
            except (ValueError, OSError, KeyError, TypeError, engine.CheckpointError):
                self.store.update_job(job['id'], status='waiting_input', input_reason='checkpoint', error='تعذر التحقق من نقطة استكمال الإثراء. بقيت بيانات المستودع محفوظة.')
            return
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

    def list_jobs(self, kind=None):
        stored_jobs = self.store.list_jobs()
        jobs = [self._public(j) for j in stored_jobs if kind is None or j.get('kind', 'extraction') == kind]
        summary = {
            "total": len(jobs), "running": sum(j["status"] in ACTIVE for j in jobs),
            "queued": sum(j["status"] == "queued" for j in jobs),
            "completed": sum(j["status"] in ("completed", "completed_warnings") for j in jobs),
            "needs_attention": sum(j["status"] in ("waiting_input", "interrupted", "failed") for j in jobs),
            "unique_ips": sum(j.get("stats", {}).get("unique_ips", 0) for j in jobs if j.get('kind', 'extraction') == 'extraction'),
            "requests": sum(j.get("stats", {}).get("requests", 0) for j in jobs),
        }
        # unique_ips is a sum across jobs, never a cross-job deduplicated union.
        summary["ip_count_scope"] = "sum_per_job"
        return {"jobs": jobs, "summary": summary, "lanes": {
            kind: {'active_job_id': self.lane(kind)._active_id,
                   'browser_job_id': self.lane(kind)._browser_job,
                   'network_busy': self.lane(kind)._network_operation,
                   'queued': sum(j['status'] == 'queued' and j.get('kind', 'extraction') == kind for j in stored_jobs)}
            for kind in ('extraction', 'enrichment')}}

    def get_job(self, job_id):
        return self._public(self._get(job_id))

    @in_job_lane
    def _new_job(self, fields, key, *, start=True):
        fields = {**NETWORK_DEFAULTS, 'kind': 'extraction', **fields}
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
        if isinstance(payload, dict) and payload.get('kind') == 'enrichment':
            return self._create_enrichment(payload)
        payload = dict(payload) if isinstance(payload, dict) else payload
        if isinstance(payload, dict) and payload.pop('kind', 'extraction') != 'extraction':
            raise JobValidationError('نوع المهمة غير صالح.')
        fields, key = validate_job(payload, allow_demo=self.demo)
        self.vpn.validate_policy({k: fields[k] for k in NETWORK_DEFAULTS})
        with self._lock:
            return self._new_job(fields, key)

    def _create_enrichment(self, payload, *, automatic=False, context=None):
        if self.kind != 'enrichment':
            return self.enrichment._create_enrichment(payload, automatic=automatic, context=context)
        allowed = {'kind', 'title', 'target_ids', 'filters', 'mode', 'api_key', 'settings', 'priority', 'network', 'scheduled_at'}
        if set(payload) - allowed: raise JobValidationError('حقول مهمة الإثراء غير صالحة.')
        if 'target_ids' in payload and 'filters' in payload: raise JobValidationError('اختر عناوين محددة أو فلاتر.')
        ids = payload.get('target_ids')
        if ids is None: ids = self.store.targets.select_ids(payload.get('filters', {}))
        if not isinstance(ids, list) or not ids or len(ids) > 100000 or any(not isinstance(x, str) or not re.fullmatch('[a-f0-9]{32}', x) for x in ids):
            raise JobValidationError('اختر من 1 إلى 100000 هدف صالح.')
        ids = list(dict.fromkeys(ids))
        demos = set()
        with self.store.connection() as c:
            for offset in range(0, len(ids), 500):
                batch = ids[offset:offset+500]
                rows = c.execute('SELECT demo FROM targets WHERE id IN (' + ','.join('?' for _ in batch) + ')', batch).fetchall()
                if len(rows) != len(batch): raise JobValidationError('أحد الأهداف غير موجود.')
                demos.update(r[0] for r in rows)
        if len(demos) != 1: raise JobValidationError('اختر الأهداف الحقيقية أو التجريبية في مهمة مستقلة.')
        options = self.enrichment_settings.public()
        source = payload.get('mode', options['source_mode'])
        key = validate_key(payload.get('api_key'))
        key_error = None
        if not key and source != 'html':
            try: key = self.enrichment_settings.key()
            except RuntimeError as exc:
                if not automatic: raise
                key_error = str(exc)
        base = context or {}
        candidate = {'query': 'enrichment', 'title': payload.get('title', 'إثراء الأهداف'), 'mode': source,
                     'settings': payload.get('settings', base.get('settings', {})), 'priority': payload.get('priority', 0 if automatic else 5),
                     'network': payload.get('network', {k: base.get(k, v) for k, v in NETWORK_DEFAULTS.items()})}
        if key: candidate['api_key'] = key
        fields, key = validate_job(candidate, allow_demo=self.demo)
        if demos == {1}:
            if not self.demo: raise JobValidationError('يلزم تفعيل وضع التجربة لمعالجة أهداف تجريبية.')
            fields['settings']['demo'] = True
        fields.update(kind='enrichment', source_mode=source, automatic=automatic, origin_job_id=base.get('id'))
        if base.get('shodan_account_id'): fields['shodan_account_id'] = base['shodan_account_id']
        scheduled = payload.get('scheduled_at')
        if scheduled:
            from .targets import timestamp
            scheduled = timestamp(scheduled)
            if scheduled is None: raise JobValidationError('موعد المهمة غير صالح.')
            fields['scheduled_at'] = scheduled
        policy_error = None
        try:
            if not automatic: self.vpn.validate_policy({k: fields[k] for k in NETWORK_DEFAULTS})
        except (ValueError, RuntimeError) as exc:
            if not automatic: raise
            policy_error = str(exc)
        with self._lock:
            job = self._new_job(fields, key, start=False)
            try:
                self.store.targets.add_items(job['id'], ids, automatic)
                if not self.store.targets.items(job['id']): raise JobValidationError('الأهداف محجوزة بالفعل لمهام إثراء.')
                missing = fields['mode'] == 'api' and not key and not fields['settings']['demo']
                self.store.update_job(job['id'], status='waiting_input' if missing or policy_error or key_error else 'queued',
                                      **({'input_reason': 'network_error', 'error': policy_error} if policy_error else
                                         {'input_reason': 'api_key', 'error': key_error} if key_error else {'input_reason': 'api_key'} if missing else {}))
            except Exception:
                self.store.delete_job(job['id']); shutil.rmtree(self._path(job['id'])); self._keys.pop(job['id'], None)
                raise
            self._wake.set()
            return self.get_job(job['id'])

    def _seed_enrichment(self):
        lane = self.lane('enrichment')
        with lane._seed_lock, lane._lock:
            return lane._seed_enrichment_locked()

    def _seed_enrichment_locked(self):
        if not self.enrichment_settings.public()['automatic']: return
        for group in self.store.targets.automatic_candidates():
            context = group['context']
            queued = next((j for j in self.store.list_jobs() if j.get('kind') == 'enrichment' and j.get('automatic')
                           and j.get('origin_job_id') == context['id'] and j['status'] == 'queued' and not j.get('attempts')), None)
            if queued:
                self.store.targets.add_items(queued['id'], group['ids'], automatic=True)
            else:
                self._create_enrichment({'kind': 'enrichment', 'title': 'إثراء — ' + (context.get('title') or context.get('query', ''))[:145],
                                         'target_ids': group['ids']}, automatic=True, context=context)

    def _observe_request(self, job_id, request_id):
        job = self._get(job_id)
        if job.get('kind', 'extraction') != 'extraction': return
        with self.store.connection() as c:
            row = c.execute('SELECT document FROM request_history WHERE job_id=? AND request_id=?', (job_id, request_id)).fetchone()
            values = [json.loads(x[0]) for x in c.execute('SELECT document FROM request_values WHERE job_id=? AND request_id=? ORDER BY position', (job_id, request_id))]
        if row:
            entry = json.loads(row[0])
            self.store.targets.observe_request(job, entry, values)
            # API search emits its already-fetched host metadata immediately
            # after request values. Let those snapshots land before reserving
            # automatic enrichment; HTML results can be seeded while extracting.
            if values and entry.get('source') == 'html':
                self.lane('enrichment')._seed_requested.set()
                self.lane('enrichment')._wake.set()

    def _target_event(self, job, event):
        repo = self.store.targets
        if event.get('kind') == 'enrichment_item':
            item = event['item']
            with self.store.connection() as c:
                if not c.execute('SELECT 1 FROM enrichment_items WHERE job_id=? AND target_id=?', (job['id'], item['target_id'])).fetchone(): raise ValueError('هدف خارج مهمة الإثراء.')
            repo.apply_item(job['id'], item)
            return
        ident = event.get('target_id')
        if job.get('kind') == 'enrichment':
            with self.store.connection() as c:
                if not c.execute('SELECT 1 FROM enrichment_items WHERE job_id=? AND target_id=?', (job['id'], ident)).fetchone(): raise ValueError('هدف خارج مهمة الإثراء.')
        else:
            ip = str(ipaddress.ip_address(event['ip']))
            with self.store.connection() as c:
                if not c.execute('SELECT 1 FROM job_ips WHERE job_id=? AND ip=?', (job['id'], ip)).fetchone(): return
                row = c.execute('SELECT id FROM targets WHERE ip=? AND demo=?', (ip, int(job['settings'].get('demo', False)))).fetchone()
            if row is None: return
            ident = row[0]
        repo.snapshot(job['id'], ident, event['request_id'], event['source'], event['details'], event.get('fetched_at'))

    def _replay_target_events(self, job):
        path = self._path(job['id'])
        if job.get('kind') == 'enrichment':
            if not (path / 'checkpoint.json').exists(): return
            from .enrichment import validate_checkpoint
            saved = validate_checkpoint(engine.load_checkpoint(path / 'checkpoint.json'))
            by_ip = {x['ip']: x['target_id'] for x in self.store.targets.items(job['id'])}
            for item in saved['state']['items']:
                if item['ip'] not in by_ip: raise ValueError('هدف استكمال خارج المهمة.')
                item = {**item, 'target_id': by_ip[item['ip']]}
                for snap in item.get('snapshots', []): self._target_event(job, {'kind': 'target_snapshot', 'target_id': item['target_id'], **snap})
                if item['status'] != 'pending': self._target_event(job, {'kind': 'enrichment_item', 'item': item})
            return
        journal = path / 'target-observations.jsonl'
        if not journal.exists() or journal.is_symlink(): return
        with journal.open(encoding='utf-8') as stream:
            for line in stream:
                if not line.endswith('\n') or len(line.encode()) > 2 * 1024 * 1024: continue
                try: self._target_event(job, json.loads(line))
                except (ValueError, KeyError, TypeError): continue

    def _control(self, job_id, action):
        atomic_text(self._path(job_id) / "control.json", json.dumps({"action": action}))

    @in_job_lane
    def action(self, job_id, payload):
        if isinstance(payload, dict) and payload.get('action') == 'configure':
            if set(payload) - {'action', 'priority', 'scheduled_at', 'settings'}: raise JobValidationError('إعدادات تشغيل غير صالحة.')
            from .config import bounded
            from .targets import timestamp
            with self._lock:
                job = self._get(job_id)
                if job['status'] not in RESUMABLE | {'queued'} or self._active_id == job_id or self._browser_job == job_id:
                    raise JobValidationError('أوقف المهمة وأغلق متصفحها قبل تعديل إعدادات التشغيل.')
                changes = {}
                if 'priority' in payload: changes['priority'] = bounded(payload['priority'], 'priority', 0, 10, True)
                if 'scheduled_at' in payload:
                    changes['scheduled_at'] = timestamp(payload['scheduled_at']) if payload['scheduled_at'] else None
                    if payload['scheduled_at'] and changes['scheduled_at'] is None: raise JobValidationError('موعد المهمة غير صالح.')
                if 'settings' in payload:
                    if not isinstance(payload['settings'], dict) or 'demo' in payload['settings']: raise JobValidationError('إعدادات تشغيل غير صالحة.')
                    changes['settings'] = settings_from({**job['settings'], **payload['settings']}, allow_demo=self.demo)
                if self._redact(_json(changes)) != _json(changes): raise JobValidationError('ضع بيانات الاعتماد في الحقل المخصص.')
                self.store.update_job(job_id, **changes)
                self.store.append_event(job_id, {'kind': 'state', 'message': 'حُدثت إعدادات التشغيل والأولوية والموعد.'})
                self._wake.set()
                return self.get_job(job_id)
        if not isinstance(payload, dict) or set(payload) - {"action", "mode", "api_key"}:
            raise JobValidationError("طلب الإجراء غير صالح.")
        action = payload.get("action")
        with self._lock:
            job = self._get(job_id)
            state = job["status"]
            if action == "duplicate":
                if job.get('kind') == 'enrichment':
                    return self._create_enrichment({'kind': 'enrichment', 'title': job['title'][:150] + ' — نسخة',
                        'target_ids': [x['target_id'] for x in self.store.targets.items(job_id)],
                        'mode': payload.get('mode', job.get('source_mode', job['mode'])), 'api_key': payload.get('api_key'),
                        'settings': job['settings'], 'priority': job['priority'],
                        'network': {k: job.get(k, v) for k, v in NETWORK_DEFAULTS.items()}}, context=job)
                fields = {k: job[k] for k in ("title", "query", "mode", "settings", "priority")}
                fields.update({k: job.get(k, v) for k, v in NETWORK_DEFAULTS.items()})
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
                if state == "queued" or (state == 'waiting_input' and self._active_id == job_id):
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
                if self._active_id == job_id and job.get("network_mode", "direct") != "direct":
                    raise RuntimeError("جارٍ حفظ التقدم أو التحقق من الشبكة؛ انتظر انتهاء العملية.")
                if state not in RESUMABLE:
                    raise JobValidationError("يمكن الاستكمال بعد توقف المهمة فقط.")
                key = validate_key(payload.get("api_key")) or self._keys.get(job_id)
                mode = payload.get("mode", job["mode"])
                if job.get('kind') == 'enrichment' and not key and mode != 'html': key = self.enrichment_settings.key()
                if mode not in ("html", "api", "auto"):
                    raise JobValidationError("مصدر غير صالح.")
                if mode == "auto":
                    mode = "api" if key else "html"
                if mode == 'html' and job.get('shodan_account_id') and (not job.get('browser_session_enabled') or self._browser_job != job_id):
                    raise JobValidationError('افتح متصفح المهمة بالحساب المختار وسجّل الدخول وافحص صفحة النتائج قبل الاستكمال.')
                if job.get('browser_session_enabled'):
                    if mode != 'html' and self._browser_job == job_id: raise JobValidationError('أغلق جلسة المتصفح قبل تغيير مصدر المهمة.')
                    if mode == 'html':
                        verified = self._browser_rpc(job_id, {'action':'verify'})
                        if verified.get('state') != 'ready':
                            messages = {
                                'browser_challenge':'أكمل اختبار الأمان الظاهر في متصفح Shodan قبل الاستكمال.',
                                'login_required':'لم يكتمل تسجيل الدخول إلى Shodan؛ سجّل الدخول بالحساب ثم عد إلى نتائج المهمة.',
                                'off_task_page':'عد إلى نتائج المهمة داخل المتصفح قبل الاستكمال.',
                                'invalid_page':'تعذر قراءة صفحة المرشح؛ أعد محاولة الطلب أو راجع سجل المهمة.',
                                'rate_limited':'قيّد Shodan الطلبات؛ انتظر موعد الاستكمال المحفوظ.',
                                'access_denied':'رفض Shodan الوصول؛ راجع صلاحيات الحساب.'}
                            raise JobValidationError(messages.get(verified.get('state'),'انتظر اكتمال تحميل صفحة المهمة في Shodan قبل الاستكمال.'))
                if key and (key in job["query"] or key in job["title"] or key in job["settings"]["user_agent"]):
                    raise JobValidationError("المفتاح موجود في حقل نصي للمهمة؛ استخدم مهمة جديدة دون تضمين المفتاح.")
                if mode == "api" and not key and not job["settings"]["demo"]:
                    raise JobValidationError("أدخل مفتاح API أو اختر HTML.")
                self._remember(job_id, key)
                (self._path(job_id) / "control.json").unlink(missing_ok=True)
                source_policy = payload.get('mode', job.get('source_mode', mode))
                if job.get('kind') == 'enrichment' and job.get('source_mode') == 'auto' and mode == 'html' and self._browser_job == job_id:
                    source_policy = 'auto'
                extra = {'source_mode': source_policy} if job.get('kind') == 'enrichment' else {}
                self.store.update_job(job_id, status="queued", mode=mode, error=None, finished_at=None, input_reason=None, **extra,
                                      browser_session_enabled=bool(job.get('browser_session_enabled') and mode=='html'))
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
                if self._browser_job and (time.monotonic() > self._browser_deadline or self._get(self._browser_job)['status'] in FINAL - {'failed'}):
                    with contextlib.suppress(Exception): self.browser_action(self._browser_job, {'action':'stop'})
                if self.kind == 'enrichment' and self._seed_requested.is_set():
                    self._seed_requested.clear()
                    try: self._seed_enrichment()
                    except Exception:
                        self._seed_requested.set()
                        raise
                with self._lock:
                    if self._stop.is_set():
                        break
                    job = None if self._network_operation else self.store.claim_next(self._browser_job, kind=self.kind)
                    if job:
                        self._active_id = job["id"]
                if job:
                    self._execute(job)
                    self.lane('enrichment')._seed_requested.set()
                    self.lane('enrichment')._wake.set()
                    with self._lock:
                        self._active_id = None
                        if self._browser_job == job['id']:
                            self._browser_deadline = time.monotonic() + 1800
                    self._auto_browser_recovery(job['id'])
                    if self._browser_job == job['id'] and self._get(job['id'])['status'] in FINAL - {'failed'}:
                        with contextlib.suppress(Exception): self.browser_action(job['id'], {'action':'stop'})
                    continue
            except Exception as exc:
                if self._active_id:
                    with contextlib.suppress(Exception):
                        self.store.update_job(self._active_id, status="failed", error=self._redact(str(exc))[:1000], finished_at=utc_now())
                self._active_id = None
            self._wake.wait(0.5)
            self._wake.clear()

    @in_job_lane
    def network_settings(self, job_id, payload):
        with self._lock:
            job = self._get(job_id)
            if self._browser_job == job_id: raise RuntimeError('أغلق جلسة المتصفح قبل تغيير اتصال المهمة.')
            if self._active_id == job_id or job['status'] in ACTIVE or job['status'] == 'queued':
                raise RuntimeError('أوقف المهمة وانتظر حفظ Checkpoint قبل تغيير اتصالها.')
            cfg = self.vpn.validate_policy(payload)
            self.store.update_job(job_id, **cfg, active_vpn_profile=None,
                                  current_egress_ip=None, network_health='unknown')
            self.vpn.audit('job_network_settings', job_id=job_id, new=cfg['preferred_vpn_profile'])
            return self.get_job(job_id)

    def _vpn_mutation(self, operation):
        with self._lock:
            if self._active_id or self._network_operation:
                raise RuntimeError('توجد مهمة أو عملية اتصال نشطة؛ انتظر اكتمالها أولًا.')
            self._network_operation = True
        try:
            return operation()
        finally:
            with self._lock:
                self._network_operation = False
            self._wake.set()

    def vpn_action(self, payload):
        return self._vpn_mutation(lambda: self.vpn.action(payload))

    def vpn_update(self, ident, payload):
        return self._vpn_mutation(lambda: self.vpn.update(ident, payload))

    def vpn_premium(self, payload):
        return self._vpn_mutation(lambda: self.vpn.premium(payload))

    def _browser_rpc(self, job_id, payload):
        from .vpn_client import rpc
        from .lanes import space
        return rpc('browser', socket_path=space(self.kind).socket, job_id=job_id, input=payload)

    def _account_mutation(self, operation):
        # Accounts are shared; credential rotation/removal must exclude both
        # workers and both browser profiles. Always acquire locks in this order.
        root, child = self._root, self._root.enrichment
        with root._lock, child._lock:
            if any(lane._active_id or lane._network_operation or lane._browser_job for lane in (root, child)):
                raise RuntimeError('أوقف المهام وأغلق المتصفحات في المساحتين قبل تعديل الحساب أو حذفه.')
            root._network_operation = child._network_operation = True
        try:
            return operation()
        finally:
            with root._lock, child._lock:
                root._network_operation = child._network_operation = False
            root._wake.set(); child._wake.set()

    def _forget_account(self, ident, scope):
        self._root._browser_rpc(ident, {'action':'forget_account', 'account_scope':scope})
        # A profile can outlive its originating job, so always ask both helpers.
        self._root.enrichment._browser_rpc(ident, {'action':'forget_account', 'account_scope':scope})

    def shodan_account_save(self, payload, ident=None):
        if ident is None:
            with self._lock:return self.shodan_accounts.save(payload)
        def operation():
            if self._browser_job: raise RuntimeError('أغلق جلسة المتصفح قبل تعديل حسابات Shodan.')
            username, password, _, previous = self.shodan_accounts.validate(payload, ident)
            if previous and (username, password) != (previous['username'], previous['password']) and self.shodan_accounts.used(ident):
                self._forget_account(ident, previous['scope'])
            return self.shodan_accounts.save(payload, ident)
        return self._account_mutation(operation)

    def shodan_account_delete(self, ident):
        def operation():
            if self._browser_job: raise RuntimeError('أغلق جلسة المتصفح قبل حذف حساب Shodan.')
            saved = self.shodan_accounts.secret(ident)
            if self.shodan_accounts.used(ident):
                self._forget_account(ident, saved['scope'])
            self.shodan_accounts.delete(ident)
            with self.store.connection() as con:
                jobs = [row[0] for row in con.execute('SELECT id FROM jobs')]
            for job_id in jobs:
                job = self._get(job_id)
                if job.get('shodan_account_id') == ident:
                    self.store.update_job(job_id, shodan_account_id=None, browser_session_enabled=False)
            return {'deleted':True}
        return self._account_mutation(operation)

    @in_job_lane
    def shodan_account_select(self, job_id, payload):
        if not isinstance(payload,dict) or set(payload)!={'account_id'}:raise ValueError('اختر حساب Shodan صالحًا.')
        def operation():
            job = self._get(job_id)
            if job['status'] not in RESUMABLE or job['mode']!='html' or self._browser_job:
                raise RuntimeError('اختر مهمة HTML متوقفة وأغلق جلسة المتصفح قبل تغيير الحساب.')
            ident=payload['account_id']
            if ident is not None:self.shodan_accounts.metadata(ident)
            self.store.update_job(job_id, shodan_account_id=ident, browser_session_enabled=False)
            return self.get_job(job_id)
        return self._vpn_mutation(operation)

    def _account_browser_input(self, job):
        ident = job.get('shodan_account_id')
        if not ident:return {}
        scope = self.shodan_accounts.secret(ident)['scope']
        self.shodan_accounts.mark_used(ident)
        return {'account_scope':scope}

    def _shodan_login(self, job):
        from .browser_recovery import pending_url
        if not job.get('shodan_account_id'):raise ValueError('اختر حساب Shodan للمهمة أولًا.')
        if self._browser_job != job['id']:raise RuntimeError('افتح متصفح المهمة قبل تسجيل الدخول.')
        saved = self.shodan_accounts.secret(job['shodan_account_id'])
        try:
            result = self._browser_rpc(job['id'], {'action':'login','username':saved['username'],
                'password':saved['password'],'return_url':pending_url(job,self._path(job['id']))})
        except Exception:
            # RPC/driver exception arguments may contain evaluated credentials.
            raise RuntimeError('تعذر تسجيل الدخول إلى Shodan؛ راجع صفحة المتصفح ثم حاول مجددًا.') from None
        # Never forward raw credential-operation responses to a client or log.
        safe = {}
        enums = {'backend':('chromium','patchright'), 'state':('rate_limited','browser_challenge','login_required','invalid_page','access_denied','off_task_page','ready','awaiting_verification'),
                 'login_status':('submitted','verification_required','not_login_page','unsafe_form')}
        for key, values in enums.items():
            if result.get(key) in values:safe[key]=result[key]
        for key in ('running','can_return_to_results'):
            if type(result.get(key)) is bool:safe[key]=result[key]
        for key in ('width','height','http_status'):
            if type(result.get(key)) is int and 0 < result[key] < 10000:safe[key]=result[key]
        result = safe
        self.vpn.audit('shodan_login',job_id=job['id'],status='submitted' if result.get('login_status')=='submitted' else 'verification_required')
        return result

    @in_job_lane
    def browser_policy(self, job_id, payload):
        if not isinstance(payload, dict) or set(payload) != {'browser_recovery'} or payload['browser_recovery'] not in ('manual', 'on_challenge'):
            raise JobValidationError('اختر سياسة استرداد المتصفح المدعومة.')
        with self._lock:
            job = self._get(job_id)
            if job['status'] not in RESUMABLE or self._active_id or self._network_operation or self._browser_job == job_id:
                raise JobValidationError('أوقف المهمة وأغلق جلسة المتصفح قبل تغيير السياسة.')
            self.store.update_job(job_id, settings={**job['settings'], **payload})
            return self.get_job(job_id)

    def _auto_browser_recovery(self, job_id):
        from .browser_recovery import eligible, reserve
        current = self._get(job_id)
        if current.get('input_reason') != 'browser_challenge' or not eligible(current): return
        def operation():
            job = self._get(job_id)
            if (self._stop.is_set() or job['status'] != 'waiting_input' or job.get('input_reason') != 'browser_challenge'
                    or not eligible(job) or job['settings'].get('browser_recovery') != 'on_challenge'):
                return
            # Repeated challenges in a browser retain the same session and VPN lease.
            if self._browser_job:
                return
            attempt = reserve(self.store, job, self._path(job_id))
            if attempt is None: return
            self.store.append_event(job_id, {'kind': 'browser_recovery', 'state': 'opening',
                'message': 'جارٍ فتح متصفح التحقق؛ التقدم محفوظ والاستكمال يدوي.'})
            deadline = time.monotonic() + job['settings']['delay']
            while time.monotonic() < deadline:
                if self._stop.wait(min(.25, deadline - time.monotonic())) or self._get(job_id)['status'] != 'waiting_input':
                    raise RuntimeError('أُلغي فتح المتصفح؛ المهمة متوقفة.')
            self._open_browser(self._get(job_id))
        try:
            self._vpn_mutation(operation)
        except (RuntimeError, ValueError, OSError, engine.SpiderError, engine.CheckpointError) as exc:
            job = self._get(job_id)
            attempt = {**job.get('browser_recovery_attempt', {}), 'challenge_id': job.get('browser_challenge_id'),
                       'state': 'failed', 'error': self._redact(str(exc))[:1000]}
            self.store.update_job(job_id, browser_recovery_attempt=attempt)
            self.store.append_event(job_id, {'kind': 'browser_recovery', 'state': 'failed',
                                          'level': 'warning', 'message': attempt['error']})

    def _open_browser(self, job):
        from .browser_recovery import pending_url
        job_id = job['id']
        if job['status'] not in RESUMABLE or job['mode'] != 'html' or job.get('network_mode', 'direct') == 'direct':
            raise RuntimeError('اختر مهمة HTML متوقفة وملف VPN معزولًا.')
        if not self._browser_job:
            # An existing browser task is pinned to its selected tunnel by VPNManager.
            prepared = self.vpn.prepare(job)
            self.store.update_job(job_id, **prepared)
        if self._get(job_id)['status'] not in RESUMABLE or self._stop.is_set():
            raise RuntimeError('أُلغي فتح المتصفح؛ المهمة متوقفة.')
        result = self._browser_rpc(job_id, {'action': 'start', 'url': pending_url(job, self._path(job_id)), **self._account_browser_input(job)})
        self._browser_job = job_id; self._browser_deadline = time.monotonic() + 1800
        attempt = {**job.get('browser_recovery_attempt', {}), 'state': result.get('state', 'awaiting_verification')}
        self.store.update_job(job_id, browser_session_enabled=True, browser_recovery_attempt=attempt,
                              browser_backend=result.get('backend', 'chromium'))
        return result

    @in_job_lane
    def browser_action(self, job_id, payload):
        if not isinstance(payload,dict) or payload.get('action') not in {'start','stop','frame','click','key','text','scroll','verify','login'}:
            raise ValueError('طلب المتصفح غير صالح.')
        def operation():
            job=self._get(job_id)
            action=payload['action']
            if job['status'] not in RESUMABLE and action!='stop': raise RuntimeError('أوقف المهمة وانتظر حفظ التقدم أولًا.')
            if self._browser_job and self._browser_job != job_id: raise RuntimeError('أغلق جلسة المهمة الأخرى أولًا.')
            if action=='start':
                if set(payload)!={'action'}:raise ValueError('طلب بدء المتصفح غير صالح.')
                if job['mode']!='html' or job.get('network_mode','direct')=='direct':raise RuntimeError('اختر HTML وملف VPN معزولًا لهذه المهمة أولًا.')
                result=self._open_browser(job)
            elif action=='login':
                if set(payload)!={'action'}:raise ValueError('طلب تسجيل الدخول غير صالح.')
                result=self._shodan_login(job)
            else:
                result=self._browser_rpc(job_id,payload)
                self.store.update_job(job_id, browser_recovery_attempt={**job.get('browser_recovery_attempt', {}),
                    'state':result.get('state','awaiting_verification')}, browser_backend=result.get('backend',job.get('browser_backend','chromium')))
                if action=='stop':
                    self._browser_job=None
            if action!='frame':self._browser_deadline=time.monotonic()+1800
            if action in {'start','stop','verify'}:
                audit_action='return_to_results' if action=='verify' and payload.get('return_to_results') is True else action
                self.vpn.audit('browser_'+audit_action,job_id=job_id,verified=result.get('state')=='ready')
            return result
        return self._vpn_mutation(operation)

    def _network_wait(self, job_id, error):
        with self._lock:
            job = self._get(job_id)
            state = 'cancelled' if job['status'] in ('cancel_requested', 'cancelled') else 'paused' if job['status'] in ('pause_requested', 'paused') else 'waiting_input'
            self.store.update_job(job_id, status=state, network_health='unhealthy', network_phase='connection_lost',
                                  input_reason='network_error', error=str(error), last_network_error=str(error),
                                  current_egress_ip=None)
            self.store.append_event(job_id, {'kind': 'network', 'level': 'warning', 'message': str(error),
                                            'phase': 'connection_lost'})

    def _recover_vpn(self, job, *, initial_failure=False):
        """The worker has exited and released its lease before this boundary."""
        if not can_failover(job) or self._stop.is_set(): return None
        if str(job.get('last_network_error', '')).startswith(NON_FAILOVER_ERRORS): return None
        if self._get(job['id'])['status'] != 'waiting_input': return None
        browser = job.get('browser_session_enabled', False)
        try:
            if browser:
                self._browser_rpc(job['id'], {'action': 'stop'})
                self._browser_job = None
                self.vpn.audit('browser_stop', job_id=job['id'], reason='vpn_failover')
            recovered = self.vpn.recover(self._get(job['id']), initial_failure=initial_failure)
        except (RuntimeError, ValueError) as exc:
            self.vpn.audit('failover', job_id=job['id'], reason=self._redact(str(exc)), status='failed')
            return None
        if not recovered: return None
        with self._lock:
            if self._get(job['id'])['status'] != 'waiting_input' or self._stop.is_set(): return None
            self.store.update_job(job['id'], **recovered)
        if browser:
            from .browser_recovery import pending_url
            try:
                result = self._browser_rpc(job['id'], {'action': 'start',
                    'url': pending_url(self._get(job['id']), self._path(job['id'])), 'defer_navigation': True,
                    **self._account_browser_input(self._get(job['id']))})
                with self._lock:
                    stopped = self._get(job['id'])['status'] != 'waiting_input' or self._stop.is_set()
                    if not stopped:
                        self._browser_job = job['id']
                        self._browser_deadline = time.monotonic() + 1800
                        self.store.update_job(job['id'], browser_backend=result.get('backend', 'chromium'),
                            browser_recovery_attempt={**job.get('browser_recovery_attempt', {}), 'state': 'reconnected'})
                if stopped:
                    self._browser_rpc(job['id'], {'action': 'stop'})
                    return None
                self.vpn.audit('browser_start', job_id=job['id'], reason='vpn_failover')
            except (RuntimeError, ValueError, OSError) as exc:
                with self._lock:
                    if self._get(job['id'])['status'] == 'waiting_input':
                        self.store.update_job(job['id'], input_reason='source_error',
                            error='[BROWSER_SESSION] ' + self._redact(str(exc)))
                self.vpn.audit('browser_start', job_id=job['id'], reason='vpn_failover', status='failed')
                return None
        return recovered

    @in_job_lane
    def _execute(self, job):
        if job.get('network_mode', 'direct') == 'direct':
            self.store.update_job(job['id'], **self.vpn.prepare(job))
            return self._execute_worker(self._get(job['id']))
        remaining_requests = job['settings']['max_requests']
        prepared = None
        while not self._stop.is_set():
            job = self._get(job['id'])
            if prepared is None:
                try:
                    self.store.update_job(job['id'], network_phase='checking_network')
                    prepared = self.vpn.prepare(job)
                except (RuntimeError, ValueError) as exc:
                    self._network_wait(job['id'], exc)
                    prepared = self._recover_vpn(self._get(job['id']), initial_failure=True)
                    if not prepared: return
            with self._lock:
                current = self._get(job['id'])
                if current['status'] in ('cancelled', 'paused', 'cancel_requested', 'pause_requested') or self._stop.is_set():
                    if current['status'] in ('cancel_requested', 'pause_requested'):
                        self.store.update_job(job['id'], status='cancelled' if current['status'] == 'cancel_requested' else 'paused')
                    return
                self.store.update_job(job['id'], **prepared, status='running', error=None, input_reason=None,
                                      vpn_failover_requested=False)
            prepared = None
            worker_job = self._get(job['id'])
            worker_job['settings'] = {**worker_job['settings'], 'max_requests': remaining_requests}
            self._execute_worker(worker_job)
            current = self._get(job['id'])
            remaining_requests -= current.get('stats', {}).get('requests_this_run', 0)
            failed = current.get('input_reason') == 'network_error' or (
                current.get('input_reason') == 'rate_limit' and current.get('vpn_failover_requested'))
            if current['status'] != 'waiting_input' or not failed or self._stop.is_set() or remaining_requests <= 0:
                return
            if current.get('input_reason') == 'network_error':
                self._network_wait(job['id'], current.get('error') or 'Network unavailable.')
            prepared = self._recover_vpn(self._get(job['id']))
            if not prepared: return

    @in_job_lane
    def _execute_worker(self, job):
        job_id, path = job["id"], self._path(job["id"])
        with self._lock:
            key = self._keys.get(job_id)
            if job.get('kind') == 'enrichment' and job.get('source_mode') != 'html' and not job.get('browser_session_enabled'):
                try: key = key or self.enrichment_settings.key()
                except RuntimeError as exc:
                    self.store.update_job(job_id, status='waiting_input', input_reason='api_key', error=str(exc)); return
                if job.get('source_mode') == 'auto' and not job.get('browser_session_enabled'):
                    job = {**job, 'mode': 'api' if key else 'html'}
                    self.store.update_job(job_id, mode=job['mode'])
                self._remember(job_id, key)
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
        env["SHODAN_STUDIO_EXECUTION_SPACE"] = self.kind
        env["PYTHONUNBUFFERED"] = "1"
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        command = [sys.executable, "-m", "studio.worker", "--job-dir", str(path)]
        if job.get("network_mode", "direct") != "direct":
            command = [sys.executable, "-m", "studio.vpn_client", "--job-id", job_id, "--kind", self.kind]
        # No shell, user-controlled executable, credential argv, or target URL.
        process = subprocess.Popen(command, cwd=Path(__file__).resolve().parent.parent,
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                   env=env, text=True, encoding="utf-8", errors="replace", bufsize=1, start_new_session=True)
        with self._lock:
            self._process = process
        final = None
        try:
            worker_input = {"job": job, "api_key": key}
            if job.get('kind') == 'enrichment':
                manifest = path / 'enrichment-targets.json'
                if manifest.is_symlink(): raise JobValidationError('ملف أهداف الإثراء غير صالح.')
                atomic_text(manifest, json.dumps([{k: x[k] for k in ('target_id', 'ip', 'demo')}
                                                 for x in self.store.targets.items(job_id)], ensure_ascii=False))
            process.stdin.write(json.dumps(worker_input, ensure_ascii=False) + "\n")
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
                if kind in ('target_snapshot', 'enrichment_item'):
                    self._target_event(job, event)
                    continue
                if kind == "ip_batch":
                    self.store.record_ip_progress(job_id, event.get("ips", []),request_id=event.get('request_id'))
                    continue
                if kind == 'request':
                    stored=self.store.requests.save(job_id,event['request'])
                    self.store.append_event(job_id,{'kind':'request','request':stored})
                    self._observe_request(job_id, event['request']['request_id'])
                    continue
                if kind == 'request_values':
                    self.store.requests.values(job_id,event['request_id'],event['offset'],event['rows'])
                    self._observe_request(job_id, event['request_id'])
                    continue
                with self._lock:
                    current = self._get(job_id)
                    changes = {}
                    if kind == "network":
                        changes.update(network_phase=event.get("phase"), last_network_error=event.get("error"))
                    if isinstance(event.get("stats"), dict):
                        changes["stats"] = event["stats"]
                        if event["stats"].get("source") in ("api", "html"):
                            changes["mode"] = event["stats"]["source"]
                    if kind == "final":
                        final = event
                        state = event.get("status", "failed")
                        if current["status"] == "cancel_requested":
                            state = "cancelled"
                        elif current["status"] == "pause_requested" and not state.startswith('completed'):
                            state = "paused"
                        if state not in FINAL | RESUMABLE:
                            state = "failed"
                        changes["network_phase"] = "completed" if state.startswith("completed") else "connection_lost" if event.get("input_reason") == "network_error" else state
                        changes.update(status=state, error=event.get("error"), input_reason=event.get("input_reason"),
                                       vpn_failover_requested=event.get('vpn_failover_requested') is True,
                                       finished_at=utc_now() if state in FINAL else None)
                        if event.get('input_reason') == 'browser_challenge':
                            changes['browser_challenge_id'] = secrets.token_hex(16)
                            changes['browser_recovery_attempt'] = {**current.get('browser_recovery_attempt', {}), 'state': 'browser_challenge'}
                    if changes:
                        updated = (self.store.update_job(job_id, **changes) if job.get('kind') == 'enrichment' else
                                   self.store.record_ip_progress(job_id, inputs=event.pop("ip_progress_inputs", None), **changes))
                        event["stats"] = updated["stats"]
                        event["ip_progress"] = self._public(updated)['ip_progress'] if job.get('kind') == 'enrichment' else progress_from_job(updated)
                        if job.get('kind') == 'enrichment': event['enrichment_progress'] = self.store.targets.progress(job_id)
                self.store.append_event(job_id, event)
            process.wait()
            self.store.requests.interrupt(job_id)
            self._replay_target_events(self._get(job_id))
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
            self.store.requests.interrupt(job_id)
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
        result = {"items": selected[offset:offset+limit], "total": len(selected), "all_total": len(ips), "offset": offset, "limit": limit}
        if self._get(job_id).get('kind') == 'enrichment':
            visible = set(result['items'])
            result['target_items'] = [{**x, 'document': json.loads(x['document'])} for x in self.store.targets.items(job_id) if x['ip'] in visible]
        return result

    def _result_ips(self, job_id):
        job = self._get(job_id)
        if job.get('kind') == 'enrichment':
            return [x['ip'] for x in self.store.targets.items(job_id) if x['status'] != 'pending']
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
            content = path.read_bytes()
            if format_name == "report":
                report = json.loads(content)
                report["job_network"] = {k: job.get(k) for k in (*NETWORK_DEFAULTS, "active_vpn_profile", "current_egress_ip", "network_health", "last_network_error", "failover_count")}
                report["network_events"] = self.vpn.events(job_id)
                content = json.dumps(report, ensure_ascii=False, indent=2).encode()
            return content, "application/json; charset=utf-8", name + "." + format_name + ".json"
        ips = self._result_ips(job_id)
        if job.get('kind') == 'enrichment' and format_name in ('csv', 'json'):
            items = [{**x, 'document': json.loads(x['document'])} for x in self.store.targets.items(job_id)]
            if format_name == 'json':
                return json.dumps({'job_id': job_id, 'kind': 'enrichment', 'items': items}, ensure_ascii=False, indent=2).encode(), 'application/json; charset=utf-8', name + '.json'
            stream = io.StringIO(newline=''); writer = csv.writer(stream); writer.writerow(['ip', 'status', 'details'])
            for item in items: writer.writerow([item['ip'], item['status'], json.dumps(item['document'], ensure_ascii=False)])
            return stream.getvalue().encode('utf-8-sig'), 'text/csv; charset=utf-8', name + '.csv'
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
            if checkpoint.get('kind') == 'enrichment':
                return self._import_enrichment_checkpoint(checkpoint, payload)
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
                self.store.requests.backfill(job['id'],path)
                self.store.append_event(job["id"], {"kind": "log", "level": "info", "message": "استُوردت نقطة الاستكمال؛ راجع المصدر ثم اختر استكمال."})
                return self.get_job(job["id"])
            except (Exception, SystemExit):
                self.store.delete_job(job["id"])
                self._keys.pop(job["id"], None)
                shutil.rmtree(path)
                raise JobValidationError("تعذر التحقق من حالة نقطة الاستكمال؛ لم تُرسل أي طلبات خارجية.") from None

    def _import_enrichment_checkpoint(self, checkpoint, payload):
        if self.kind != 'enrichment': return self.enrichment._import_enrichment_checkpoint(checkpoint, payload)
        from .enrichment import validate_checkpoint
        validate_checkpoint(checkpoint)
        cfg = checkpoint['config']
        demo = cfg.get('settings', {}).get('demo', False)
        if demo and not self.demo: raise JobValidationError('نقطة استكمال تجريبية؛ فعّل وضع التجربة أولًا.')
        with self._lock:
            with self.store.connection() as c:
                c.execute('BEGIN IMMEDIATE')
                ids = [self.store.targets._target(c, item['ip'], demo) for item in checkpoint['state']['items']]
                c.commit()
            job = self._create_enrichment({'kind': 'enrichment', 'title': payload.get('title', cfg.get('title', 'إثراء مستورد')),
                                          'target_ids': ids, 'mode': payload.get('mode', cfg['source_mode']),
                                          'api_key': payload.get('api_key'), 'settings': cfg.get('settings', {})})
            self.store.update_job(job['id'], status='paused', imported=True)
            mapping = dict(zip((x['ip'] for x in checkpoint['state']['items']), ids))
            for item in checkpoint['state']['items']: item['target_id'] = mapping[item['ip']]
            engine.save_checkpoint(self._path(job['id']) / 'checkpoint.json', checkpoint)
            self._replay_target_events(self._get(job['id']))
            self.store.append_event(job['id'], {'kind': 'state', 'status': 'paused', 'message': 'استُوردت مهمة الإثراء؛ راجع الاتصال والمصدر ثم استكمل.'})
            return self.get_job(job['id'])

    def _request_shutdown(self):
        self._stop.set()
        self._wake.set()
        with self._lock:
            active = self._active_id
            if active:
                self._control(active, "pause")
                if self._get(active)["status"] == "running":
                    self.store.update_job(active, status="pause_requested")
    def shutdown(self):
        lanes = (self, self.enrichment) if self is self._root else (self,)
        for lane in lanes: lane._request_shutdown()
        for lane in reversed(lanes): lane._finish_shutdown()

    def _finish_shutdown(self):
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
            if self is self._root:
                self._keys.clear()
                self._secret_history.clear()
            if self._ownership:
                fcntl.flock(self._ownership, fcntl.LOCK_UN)
                self._ownership.close()
                self._ownership = None

