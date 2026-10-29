"""VPN provider boundary, public registry, diagnostics and bounded failover policy."""
from __future__ import annotations
import json
import threading
import time
from typing import Protocol

from .store import _json, utc_now
from .vpn_client import rpc
from .vpn_config import DEFAULT_FAILOVERS, NETWORK_DEFAULTS, can_failover, policy, profile_id

PREMIUM_TERMINAL = tuple('[PREMIUM_' + code + ']' for code in
                         ('LIMIT', 'AUTH', 'EXPIRED', 'CAPTCHA', 'RATE_LIMIT', 'UPDATE', 'RESPONSE'))
NON_FAILOVER_ERRORS = PREMIUM_TERMINAL + ('[TLS_CERTIFICATE]', '[API_TLS_CERTIFICATE]')


class VPNProvider(Protocol):
    def discover_profiles(self): ...
    def list_profiles(self): ...
    def get_status(self): ...
    def connect(self, profile_id): ...
    def disconnect(self): ...
    def switch_profile(self, profile_id): ...
    def verify_tunnel(self): ...
    def get_egress_ip(self): ...
    def health_check(self, scope='worker'): ...
    def restore_previous_state(self): ...


class HelperProvider:
    def discover_profiles(self): return rpc('discover')
    def list_profiles(self): return rpc('profiles')
    def get_status(self): return rpc('status')
    def connect(self, ident): return rpc('connect', profile_id=ident)
    switch_profile = connect
    def disconnect(self): return rpc('disconnect')
    def health_check(self, scope='worker'): return rpc('health', scope=scope)
    def diagnostics(self, scope='worker'): return rpc('diagnostics', scope=scope)
    verify_tunnel = health_check
    def get_egress_ip(self): return self.health_check().get('egress_ip')
    def restore_previous_state(self): return rpc('restore')
    def add(self, payload):
        if set(payload) == {'config', 'metadata'}:
            return rpc('import', **payload)
        if set(payload) == {'source', 'metadata'}:
            return rpc('import_existing', **payload)
        raise ValueError('اختر ملف اتصال أو مصدرًا مكتشفًا وبياناته.')
    def update(self, ident, meta): return rpc('update', profile_id=ident, metadata=meta)
    def premium(self, payload):
        if payload == {'action': 'refresh'}: return rpc('premium_refresh')
        if set(payload) == {'action', 'key'} and payload['action'] == 'enroll':
            return rpc('premium_enroll', key=payload['key'])
        raise ValueError('طلب Premium غير صالح.')


class VPNManager:
    def __init__(self, store, provider=None, clock=time.time):
        self.store = store
        self.provider = provider or HelperProvider()
        self.clock = clock
        self.lock = threading.RLock()
        self._status = None
        self._status_at = 0
        self._diag_at = {}

    def audit(self, action, *, job_id=None, previous=None, new=None, reason=None,
              verified=False, duration_ms=0, status='success'):
        event = dict(at=utc_now(), action=action, job_id=job_id, previous_profile=previous,
                     new_profile=new, reason=reason, verified=bool(verified),
                     duration_ms=duration_ms, status=status)
        with self.store.connection() as con:
            con.execute('INSERT INTO vpn_audit(at,job_id,document) VALUES(?,?,?)',
                        (event['at'], job_id, _json(event)))
        return event

    def events(self, job_id=None):
        with self.store.connection() as con:
            sql = 'SELECT document FROM vpn_audit' + (' WHERE job_id=?' if job_id else '') + ' ORDER BY id DESC LIMIT 200'
            return [json.loads(row[0]) for row in con.execute(sql, (job_id,) if job_id else ())]

    def _saved(self):
        with self.store.connection() as con:
            return {row[0]: json.loads(row[1]) for row in con.execute('SELECT id,document FROM vpn_profiles')}

    def _save(self, item):
        with self.store.connection() as con:
            con.execute('INSERT INTO vpn_profiles(id,document) VALUES(?,?) ON CONFLICT(id) DO UPDATE SET document=excluded.document',
                        (item['id'], _json(item)))

    def profiles(self):
        old = self._saved()
        result = []
        for item in self.provider.list_profiles():
            record = {**old.get(item['id'], dict(status='disconnected', health='unknown', failure_count=0,
                                               cooldown_until=0, egress_ip=None, last_check=None, latency_ms=None)), **item}
            self._save(record)
            result.append(record)
        return result

    def summary(self):
        # Dashboard polling must remain responsive during a bounded connect/probe.
        if not self.lock.acquire(blocking=False):
            cached = self._status or dict(available=True, profiles=list(self._saved().values()), events=self.events())
            return {**cached, 'status': {**cached.get('status', {}), 'verified': False, 'busy': True},
                    'error': 'جارٍ التحقق من الاتصال؛ لم يثبت نجاح العملية بعد.'}
        try:
            return self._summary_locked()
        finally:
            self.lock.release()

    def _summary_locked(self):
        with self.lock:
            if self._status and self.clock() - self._status_at < 2:
                return self._status
            try:
                profiles = self.profiles()
                status = self.provider.get_status()
                active = status.get('active_profile')
                check = status.get('last_check') or {}
                for item in profiles:
                    is_active = item['id'] == active
                    item['status'] = 'connected' if is_active and status.get('verified') else 'unverified' if is_active else 'disconnected'
                    if is_active:
                        item.update(egress_ip=check.get('egress_ip'), last_check=check.get('checked_at'),
                                    latency_ms=check.get('latency_ms'), health='healthy' if status.get('verified') else 'unhealthy')
                result = dict(available=True, profiles=profiles, status=status, error=None,
                              direct_description='Direct يستخدم مسار الخادم الحالي، وقد يمر عبر Amnezia المثبت.')
            except RuntimeError as exc:
                profiles = list(self._saved().values())
                for p in profiles: p.update(status='unknown', health='unknown')
                result = dict(available=False, profiles=profiles, status={}, error=str(exc))
            with self.store.connection() as con:
                preferred = con.execute("SELECT value FROM settings WHERE name='vpn_preferred'").fetchone()
            result['preferred_profile'] = preferred[0] if preferred else None
            result['events'] = self.events()
            self._status, self._status_at = result, self.clock()
            return result

    def invalidate(self):
        self._status = None

    def validate_policy(self, payload):
        result = policy(payload)
        if result['network_mode'] != 'direct':
            profiles = {p['id']: p for p in self.profiles()}
            selected = set(result['allowed_vpn_profiles']) | {result['preferred_vpn_profile']}
            if any(p not in profiles or not profiles[p]['enabled'] for p in selected):
                raise ValueError('اختر ملفات VPN متاحة ومفعّلة فقط.')
        return result

    def add(self, payload):
        with self.lock:
            record = self.provider.add(payload)
            self.audit('import', new=record['id'])
            self.invalidate()
            return record

    def update(self, ident, meta):
        with self.lock:
            record = self.provider.update(profile_id(ident), meta)
            self.audit('profile_update', new=ident)
            self.invalidate()
            return record

    def premium(self, payload):
        if not isinstance(payload, dict): raise ValueError('طلب Premium غير صالح.')
        with self.lock:
            action = payload.get('action')
            if action not in {'refresh', 'enroll'}: raise ValueError('طلب Premium غير صالح.')
            try:
                result = self.provider.premium(payload)
            except (RuntimeError, ValueError):
                self.audit('premium_' + action, status='failed')
                raise
            finally:
                self.invalidate()
            self.audit('premium_' + action)
            self.profiles()
            return result

    def _record_check(self, ident, check):
        item = self._saved().get(ident)
        if item is None: return
        ok = bool(check.get('healthy'))
        item.update(health='healthy' if ok else 'unhealthy', last_check=check.get('checked_at', self.clock()),
                    egress_ip=check.get('egress_ip') if ok else None, latency_ms=check.get('latency_ms'))
        if not ok:
            item['failure_count'] = item.get('failure_count', 0) + 1
            item['cooldown_until'] = self.clock() + 60
        else:
            item['cooldown_until'] = 0
        self._save(item)
        self.invalidate()

    def connect(self, ident, *, job_id=None, reason='manual'):
        with self.lock:
            profile_id(ident)
            self.profiles()
            previous = self.provider.get_status().get('active_profile')
            start = self.clock()
            try:
                result = self.provider.switch_profile(ident)
                if not result.get('healthy') or not result.get('egress_ip') or not result.get('leak_protection'):
                    raise RuntimeError('لم ينجح التحقق من النفق وعنوان الخروج.')
            except RuntimeError:
                self._record_check(ident, {'healthy': False})
                self.audit('connect', job_id=job_id, previous=previous, new=ident, reason=reason,
                           status='failed', duration_ms=round((self.clock() - start)*1000))
                raise
            self._record_check(ident, result)
            self.audit('connect', job_id=job_id, previous=previous, new=ident, reason=reason,
                       verified=True, duration_ms=round((self.clock() - start)*1000))
            return result

    def action(self, payload):
        if not isinstance(payload, dict) or set(payload) - {'action', 'profile_id'}:
            raise ValueError('إجراء VPN غير صالح.')
        action = payload.get('action')
        if action == 'prefer':
            ident = profile_id(payload.get('profile_id'))
            if not any(p['id'] == ident and p['enabled'] for p in self.profiles()):
                raise ValueError('ملف VPN غير متاح.')
            with self.store.connection() as con:
                con.execute("INSERT INTO settings(name,value) VALUES('vpn_preferred',?) ON CONFLICT(name) DO UPDATE SET value=excluded.value", (ident,))
            self.audit('preferred_profile', new=ident)
            self.invalidate()
            return {'preferred_profile': ident}
        if action == 'connect': return self.connect(payload.get('profile_id'))
        if action not in {'disconnect', 'restore'}: raise ValueError('إجراء VPN غير مدعوم.')
        with self.lock:
            old = self.provider.get_status().get('active_profile')
            try:
                result = self.provider.disconnect() if action == 'disconnect' else self.provider.restore_previous_state()
            except RuntimeError:
                self.audit(action, previous=old, status='failed')
                raise
            self.audit(action, previous=old, verified=bool(result.get('healthy')))
            self.invalidate()
            return result

    def diagnostics(self, scope):
        if scope not in {'host', 'worker'}: raise ValueError('اختر الخادم أو العامل المعزول.')
        with self.lock:
            if self.clock() - self._diag_at.get(scope, -100) < 5:
                raise RuntimeError('انتظر خمس ثوانٍ قبل إعادة الاختبار.')
            self._diag_at[scope] = self.clock()
            result = getattr(self.provider, 'diagnostics', self.provider.health_check)(scope)
            if scope == 'worker':
                ident = self.provider.get_status().get('active_profile')
                if ident: self._record_check(ident, result)
            self.audit('diagnostics', reason=scope, verified=bool(result.get('healthy')))
            return result

    def prepare(self, job):
        cfg = policy({k: job.get(k, v) for k, v in NETWORK_DEFAULTS.items()})
        if cfg['network_mode'] == 'direct':
            return dict(active_vpn_profile=None, current_egress_ip=None, network_health='host_route', network_phase='preparing_job')
        ident = job.get('active_vpn_profile') or cfg['preferred_vpn_profile']
        if cfg['network_mode'] == 'failover' and ident not in cfg['allowed_vpn_profiles']:
            raise RuntimeError('Active VPN is outside the job allowlist.')
        if cfg['network_mode'] == 'manual':
            if self.provider.get_status().get('active_profile') != ident:
                raise RuntimeError('Manual: اتصل بالملف المحدد من VPN Manager أولًا.')
            check = self.provider.health_check()
            if not check.get('healthy'): raise RuntimeError('Manual VPN health check failed.')
        else:
            self.store.update_job(job['id'], network_phase='connecting_vpn')
            check = self.connect(ident, job_id=job['id'], reason='job_prepare')
        return dict(active_vpn_profile=ident, current_egress_ip=check.get('egress_ip'),
                    network_health='healthy', network_phase='resuming_extraction', last_network_error=None)

    def recover(self, job, *, initial_failure=False):
        """Called only after worker exit/final checkpoint; never during writes."""
        if not can_failover(job):
            return None
        if str(job.get('last_network_error', '')).startswith(NON_FAILOVER_ERRORS):
            reason = 'premium_account_or_protocol_error' if str(job['last_network_error']).startswith(PREMIUM_TERMINAL) else 'certificate_trust_error'
            self.audit('no_switch', job_id=job['id'], reason=reason)
            return None
        count = job.get('failover_count', 0)
        current = job.get('active_vpn_profile') or job.get('preferred_vpn_profile')
        if not initial_failure:
            try:
                check = self.provider.health_check()
            except RuntimeError as exc:
                if str(exc).startswith(NON_FAILOVER_ERRORS): return None
                check = {'healthy': False}
            self._record_check(current, check)
        candidates = {p['id']: p for p in self.profiles()}
        # A working tunnel may still fail for Shodan. Cool down that exit and
        # start after it in the allowlist so all configured profiles get a turn.
        if current in candidates:
            self._save({**candidates[current], 'cooldown_until': self.clock() + 60})
        allowed = job.get('allowed_vpn_profiles', [])
        if current in allowed:
            start = allowed.index(current) + 1
            allowed = allowed[start:] + allowed[:start]
        for ident in allowed:
            latest = self.store.get_job(job['id'])
            if latest and latest['status'] in {'cancelled', 'paused', 'cancel_requested', 'pause_requested'}:
                return None
            p = candidates.get(ident)
            if ident == current or not p or not p['enabled'] or p.get('cooldown_until', 0) > self.clock(): continue
            if count >= job.get('max_failovers', DEFAULT_FAILOVERS): break
            count += 1
            # Persist attempts BEFORE the side effect. Restart cannot reset the bound.
            self.store.update_job(job['id'], failover_count=count, network_phase='switching_vpn',
                                  last_failover_at=utc_now(), previous_vpn_profile=current)
            try:
                check = self.connect(ident, job_id=job['id'], reason=job.get('last_network_error') or 'network_unavailable')
            except RuntimeError as exc:
                if str(exc).startswith(NON_FAILOVER_ERRORS): return None
                continue
            return dict(active_vpn_profile=ident, current_egress_ip=check['egress_ip'], network_health='healthy',
                        network_phase='resuming_extraction', last_network_error=None,
                        last_failover_at=utc_now(), failover_count=count)
        return None
