"""Additive VPN migration. Back up and integrity-check before changing a legacy DB."""
from pathlib import Path
import os
import sqlite3

VERSION = 1


def migrate(path: Path):
    with sqlite3.connect(path) as db:
        version = db.execute('PRAGMA user_version').fetchone()[0]
        if version > VERSION:
            raise ValueError('Database schema is newer than this application.')
        if version == VERSION:
            return
        if db.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
            raise ValueError('Database integrity check failed; migration refused.')
        backup = path.with_name('studio.pre-vpn-v0.sqlite3')
        # Exclusive creation: never overwrite the first restorable snapshot.
        try:
            fd = os.open(backup, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            if backup.is_symlink():
                raise ValueError('Unsafe migration backup path.') from None
        else:
            os.close(fd)
            with sqlite3.connect(backup) as saved:
                db.backup(saved)
                if saved.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
                    raise ValueError('Migration backup verification failed.')
            with backup.open('rb') as stream:
                os.fsync(stream.fileno())
        with sqlite3.connect(f'file:{backup}?mode=ro', uri=True) as saved:
            if saved.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
                raise ValueError('Migration backup verification failed.')
        db.executescript('''
            BEGIN IMMEDIATE;
            CREATE TABLE IF NOT EXISTS vpn_profiles (
                id TEXT PRIMARY KEY, document TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS vpn_audit (
                id INTEGER PRIMARY KEY AUTOINCREMENT, at TEXT NOT NULL,
                job_id TEXT, document TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS vpn_audit_job ON vpn_audit(job_id,id);
            PRAGMA user_version=1;
            COMMIT;
        ''')
