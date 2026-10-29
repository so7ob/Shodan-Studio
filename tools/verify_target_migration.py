#!/usr/bin/env python3
"""Verify inventory migration on a disposable SQLite backup, without networking."""
import argparse
import json
from pathlib import Path
import shutil
import sqlite3
import sys
import tempfile
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from studio.jobs import JobManager


def verify(source):
    source = Path(source).resolve()
    db = source / 'studio.sqlite3'
    with tempfile.TemporaryDirectory(prefix='studio-target-migration-') as folder:
        copy = Path(folder)
        original = sqlite3.connect(db.as_uri() + '?mode=ro', uri=True)
        backup = sqlite3.connect(copy / 'studio.sqlite3')
        original.backup(backup); backup.close(); original.close()
        for name in ('live-ips.txt', 'result.txt', 'result.txt.report.json', 'checkpoint.json', 'target-observations.jsonl'):
            for file in (source / 'jobs').glob('*/' + name):
                if file.is_symlink() or not file.is_file(): continue
                target = copy / 'jobs' / file.parent.name / name
                target.parent.mkdir(parents=True, exist_ok=True); shutil.copyfile(file, target)
        # No key files or browser profiles are copied. No scheduler is started.
        with patch('socket.socket', side_effect=AssertionError('Migration attempted a network connection')):
            manager = JobManager(copy, autostart=False)
            try:
                with manager.store.connection() as c:
                    before = {r[0]: json.loads(r[1]) for r in c.execute('SELECT id,document FROM jobs')}
                    ip_count = c.execute('SELECT COUNT(*) FROM job_ips').fetchone()[0]
                    unique = c.execute("SELECT COUNT(DISTINCT i.ip) FROM job_ips i JOIN jobs j ON j.id=i.job_id WHERE COALESCE(json_extract(j.document,'$.settings.demo'),0)=0 AND COALESCE(json_extract(j.document,'$.kind'),'extraction')='extraction'").fetchone()[0]
                jobs = manager._restore_ip_progress()
                for job in jobs:
                    manager.store.requests.backfill(job['id'], manager._path(job['id']))
                    manager.store.targets.backfill(job); manager._replay_target_events(job)
                cached = list(manager.vpn._saved().values())
                class OfflineProvider:
                    def list_profiles(self): return cached
                manager.vpn.provider = OfflineProvider()
                manager.enrichment_settings.key = lambda: None
                manager._seed_enrichment()
                with manager.store.connection() as c:
                    first_seed = (c.execute('SELECT COUNT(*) FROM jobs').fetchone()[0], c.execute('SELECT COUNT(*) FROM target_auto_claims').fetchone()[0])
                manager._seed_enrichment()
                with manager.store.connection() as c:
                    after = {r[0]: json.loads(r[1]) for r in c.execute('SELECT id,document FROM jobs')}
                    kept_ips = c.execute('SELECT COUNT(*) FROM job_ips').fetchone()[0]
                    discoveries = c.execute('SELECT COUNT(*) FROM target_discoveries').fetchone()[0]
                    unknown = c.execute('SELECT COUNT(*) FROM target_discoveries WHERE found_at IS NULL').fetchone()[0]
                    claims = c.execute('SELECT COUNT(*) FROM target_auto_claims').fetchone()[0]
                    integrity = c.execute('PRAGMA integrity_check').fetchone()[0]
                assert first_seed == (len(after), claims), 'Repeated seeding changed automatic work'
                for ident, job in before.items():
                    for field in ('status', 'query', 'settings', 'priority', 'created_at', 'attempts'):
                        assert after[ident].get(field) == job.get(field), 'Original task contract changed: ' + field
                total = manager.store.targets.list()['total']
                assert total == unique and kept_ips == ip_count and integrity == 'ok'
                return {'isolated_copy': True, 'scheduler_started': False, 'network_connections': 0,
                        'source_jobs': len(before), 'source_job_ip_links': ip_count, 'unique_source_ips': unique,
                        'repository_targets': total, 'discovery_records': discoveries, 'unknown_discovery_times': unknown,
                        'automatic_enrichment_jobs': len(after)-len(before), 'automatic_claims': claims,
                        'repeated_seed_is_idempotent': True, 'original_job_contracts_preserved': True,
                        'sqlite_integrity': integrity, 'credentials_and_browser_profiles_copied': False}
            finally: manager.shutdown()


def main():
    parser = argparse.ArgumentParser(); parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path); args = parser.parse_args()
    report = json.dumps(verify(args.source), ensure_ascii=False, indent=2) + '\n'
    if args.output: args.output.parent.mkdir(parents=True, exist_ok=True); args.output.write_text(report)
    print(report, end='')

if __name__ == '__main__': main()
