"""Additive VPN migration with a verified, restorable pre-migration snapshot."""
from contextlib import closing
import hashlib
from pathlib import Path
import os
import sqlite3
import tempfile
import uuid

VERSION = 1


def _signature(db):
    """Compare schema and every row without trusting integrity_check alone."""
    digest = hashlib.sha256()
    for pragma in ('user_version', 'application_id'):
        digest.update(str(db.execute('PRAGMA ' + pragma).fetchone()[0]).encode())
        digest.update(b'\n')
    for line in db.iterdump():
        digest.update(line.encode('utf-8'))
        digest.update(b'\n')
    return digest.digest()


def _check(db, expected):
    if db.execute('PRAGMA integrity_check').fetchall() != [('ok',)] or _signature(db) != expected:
        raise ValueError('Migration backup verification failed; schema was not changed.')


def _verified_backup(path):
    # Caller holds BEGIN IMMEDIATE on another connection: no writer can change
    # the source between snapshot verification and the schema transaction.
    with closing(sqlite3.connect(path.as_uri() + '?mode=ro', uri=True)) as source:
        expected = _signature(source)
        fd, name = tempfile.mkstemp(prefix='.studio-pre-vpn-', suffix='.sqlite3', dir=path.parent)
        os.close(fd)
        staged = Path(name)
        try:
            with closing(sqlite3.connect(staged)) as saved:
                source.backup(saved)
            if staged.stat().st_size == 0:
                raise ValueError('Migration backup is empty; schema was not changed.')
            # Reopen the completed file and prove restoration into a distinct DB.
            with closing(sqlite3.connect(staged.as_uri() + '?mode=ro', uri=True)) as saved:
                _check(saved, expected)
                with tempfile.TemporaryDirectory(prefix='.studio-restore-', dir=path.parent) as folder:
                    with closing(sqlite3.connect(Path(folder) / 'restored.sqlite3')) as restored:
                        saved.backup(restored)
                        _check(restored, expected)
            with staged.open('rb') as stream:
                os.fsync(stream.fileno())
            target = path.with_name('studio.pre-vpn-v0.sqlite3')
            while True:
                try:
                    # Publish a fully verified file without overwriting any old
                    # snapshot, partial file, directory or symbolic link.
                    os.link(staged, target)
                    break
                except FileExistsError:
                    target = path.with_name('studio.pre-vpn-v0.' + uuid.uuid4().hex + '.sqlite3')
            directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
            return target
        finally:
            staged.unlink(missing_ok=True)


def migrate(path: Path):
    path = Path(path).absolute()
    with closing(sqlite3.connect(path)) as db, db:
        # Serialize migrators and writers before reading the version. Using
        # execute (not executescript) keeps backup + DDL in this transaction.
        db.execute('BEGIN IMMEDIATE')
        version = db.execute('PRAGMA user_version').fetchone()[0]
        if version > VERSION:
            raise ValueError('Database schema is newer than this application.')
        if version == VERSION:
            return
        if db.execute('PRAGMA integrity_check').fetchall() != [('ok',)]:
            raise ValueError('Database integrity check failed; migration refused.')
        backup = _verified_backup(path)
        db.execute('CREATE TABLE IF NOT EXISTS vpn_profiles (id TEXT PRIMARY KEY, document TEXT NOT NULL)')
        db.execute('''CREATE TABLE IF NOT EXISTS vpn_audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT, at TEXT NOT NULL,
            job_id TEXT, document TEXT NOT NULL
        )''')
        db.execute('CREATE INDEX IF NOT EXISTS vpn_audit_job ON vpn_audit(job_id,id)')
        db.execute('PRAGMA user_version=1')
        return backup
