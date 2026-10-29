"""Offline policy migration and checkpoint-bound browser navigation accounting."""
import hashlib
import json
import time

from . import engine
from .store import _json

MIGRATION = 'browser_recovery_v1'


def eligible(job):
    return job.get('mode') == 'html' and job.get('network_mode', 'direct') != 'direct' and not job.get('settings', {}).get('demo')


def migrate(store):
    with store.connection() as con:
        con.execute('BEGIN IMMEDIATE')
        if con.execute('SELECT 1 FROM settings WHERE name=?', (MIGRATION,)).fetchone():
            con.rollback(); return
        for row in con.execute('SELECT id,document FROM jobs').fetchall():
            job = json.loads(row['document'])
            if eligible(job) and job['status'] not in ('completed', 'completed_warnings', 'cancelled'):
                settings = dict(job.get('settings', {}))
                if 'browser_recovery' not in settings:
                    settings['browser_recovery'] = 'on_challenge'; job['settings'] = settings
                    con.execute('UPDATE jobs SET document=? WHERE id=?', (_json(job), row['id']))
        con.execute('INSERT INTO settings(name,value) VALUES(?,?)', (MIGRATION, '1'))
        con.commit()


def pending_url(job, path):
    if job.get('kind') == 'enrichment':
        from .enrichment import pending_url as host_pending_url
        return host_pending_url(job, path)
    checkpoint = path / 'checkpoint.json'
    if checkpoint.exists():
        # build_args validates checkpoint paths/scope/config; saved URLs are not authority.
        from .worker import build_args
        args = build_args(path, {**job, 'mode': 'html'}, None)
        pending = args.resume_payload['state'].get('pending_request') if args.resume_payload else None
        if pending:
            query, facet = pending.get('query'), pending.get('facet')
            from .browser_session import facet_url
            if not isinstance(query, str) or not isinstance(facet, str): raise ValueError('Invalid pending browser request.')
            engine.validate_scope_query(query)
            url = engine.build_url(query, facet); facet_url(url)
            return url
    return engine.build_url(job['query'], 'ip')


def reserve(store, job, path):
    """Charge one navigation before launch; an uncertain launch is never replayed."""
    with engine.CheckpointLock(path / 'checkpoint.json'):
        checkpoint = engine.load_checkpoint(path / 'checkpoint.json')
        state = checkpoint['state']
        token = hashlib.sha256(json.dumps([checkpoint['saved_at_utc'], state.get('session_number'),
            state.get('requests_total'), state.get('pending_request')], sort_keys=True).encode()).hexdigest()
        if job.get('browser_recovery_attempt', {}).get('challenge_id') == job.get('browser_challenge_id'):
            return None
        stats = dict(job['stats'])
        if stats.get('requests_this_run', 0) >= job['settings']['max_requests']:
            raise RuntimeError('[REQUEST_LIMIT] لا توجد ميزانية لفتح صفحة التحقق تلقائيًا.')
        if state.get('wait_unbounded') or (state.get('not_before_utc') or 0) > time.time():
            raise RuntimeError('[RATE_LIMIT] انتظر مهلة المصدر المحفوظة قبل فتح المتصفح.')
        attempt = {'challenge_id': job.get('browser_challenge_id'), 'token': token, 'state': 'opening'}
        # Mark first: a crash between database and checkpoint cannot trigger a second launch.
        store.update_job(job['id'], browser_recovery_attempt=attempt)
        state['requests_total'] = state.get('requests_total', 0) + 1
        engine.save_checkpoint(path / 'checkpoint.json', checkpoint, allow_replace=True)
        stats['requests'] = state['requests_total']
        stats['requests_this_run'] = stats.get('requests_this_run', 0) + 1
        store.update_job(job['id'], stats=stats)
        return attempt
