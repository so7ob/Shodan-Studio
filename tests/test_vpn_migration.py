"""Restore and crash fixtures for migration backups; no live databases/services."""
from contextlib import closing
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from studio import vpn_schema


class MigrationBackupTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='migration fixture # ')
        self.root = Path(self.tmp.name)
        self.path = self.root / 'studio.sqlite3'
        self.canonical = self.root / 'studio.pre-vpn-v0.sqlite3'
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute('CREATE TABLE jobs(id TEXT PRIMARY KEY, document BLOB)')
            db.execute('INSERT INTO jobs VALUES(?,?)', ('fixture', b'\x00retained\xff'))
        self.connect = sqlite3.connect

    def tearDown(self):
        self.tmp.cleanup()

    def snapshot(self, path):
        with closing(self.connect(path)) as db:
            return (db.execute('PRAGMA user_version').fetchone()[0],
                    db.execute('SELECT * FROM jobs ORDER BY id').fetchall(),
                    db.execute("SELECT name FROM sqlite_master WHERE name LIKE 'vpn_%'").fetchall())

    def backups(self):
        return list(self.root.glob('studio.pre-vpn-v0*.sqlite3'))

    def test_existing_empty_corrupt_wrong_source_and_stale_backups_are_preserved(self):
        for kind in ('empty', 'corrupt', 'wrong_source', 'stale'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory(dir=self.root) as folder:
                path = Path(folder) / 'source.sqlite3'
                old = Path(folder) / self.canonical.name
                with closing(self.connect(self.path)) as source, closing(self.connect(path)) as copy:
                    source.backup(copy)
                if kind in ('empty', 'corrupt'):
                    old.write_bytes(b'' if kind == 'empty' else b'not a SQLite database')
                else:
                    with closing(self.connect(old)) as db, db:
                        db.execute('CREATE TABLE jobs(id TEXT PRIMARY KEY, document BLOB)')
                        db.execute('INSERT INTO jobs VALUES(?,?)', ('other' if kind == 'wrong_source' else 'fixture', b'old'))
                previous = old.read_bytes()
                chosen = vpn_schema.migrate(path)
                self.assertEqual(old.read_bytes(), previous)
                fresh = [p for p in Path(folder).glob('studio.pre-vpn-v0*.sqlite3') if p != old]
                self.assertEqual(len(fresh), 1)
                self.assertEqual(chosen, fresh[0])
                self.assertEqual(self.snapshot(fresh[0]), (0, [('fixture', b'\x00retained\xff')], []))
                self.assertEqual(fresh[0].stat().st_mode & 0o777, 0o600)
                self.assertEqual(self.snapshot(path)[0], 1)

    def test_orphaned_partial_staging_file_is_not_reused(self):
        orphan = self.root / '.studio-pre-vpn-interrupted.sqlite3'
        orphan.write_bytes(b'incomplete previous copy')
        vpn_schema.migrate(self.path)
        self.assertEqual(orphan.read_bytes(), b'incomplete previous copy')
        self.assertEqual(self.snapshot(self.canonical)[0], 0)

    def test_existing_symlink_and_its_target_are_preserved(self):
        target = self.root / 'untouched.txt'
        target.write_bytes(b'keep existing file')
        self.canonical.symlink_to(target)
        chosen = vpn_schema.migrate(self.path)
        self.assertTrue(self.canonical.is_symlink())
        self.assertEqual(target.read_bytes(), b'keep existing file')
        self.assertNotEqual(chosen, self.canonical)
        self.assertEqual(self.snapshot(chosen)[0], 0)

    def test_corrupt_source_is_not_changed_or_backed_up_as_valid(self):
        self.path.write_bytes(b'corrupted fixture database')
        with self.assertRaises(sqlite3.DatabaseError): vpn_schema.migrate(self.path)
        self.assertEqual(self.path.read_bytes(), b'corrupted fixture database')
        self.assertEqual(self.backups(), [])

    def test_interrupted_copy_does_not_migrate_and_retry_succeeds(self):
        class InterruptedCopy(sqlite3.Connection):
            def backup(self, target, **kwargs):
                target.execute('CREATE TABLE partial(value)')
                target.commit()
                raise InterruptedError('fixture interrupted write')
        def connect(database, *args, **kwargs):
            if str(database) == self.path.as_uri() + '?mode=ro':
                kwargs['factory'] = InterruptedCopy
            return self.connect(database, *args, **kwargs)
        before = self.snapshot(self.path)
        with patch('studio.vpn_schema.sqlite3.connect', side_effect=connect):
            with self.assertRaises(InterruptedError): vpn_schema.migrate(self.path)
        self.assertEqual(self.snapshot(self.path), before)
        self.assertEqual(self.backups(), [])
        self.assertEqual(list(self.root.glob('.studio-pre-vpn-*')), [])
        vpn_schema.migrate(self.path)
        self.assertEqual(self.snapshot(self.canonical), before)

    def test_valid_but_inconsistent_copy_fails_verification_before_ddl(self):
        class AlteredCopy(sqlite3.Connection):
            def backup(self, target, **kwargs):
                super().backup(target, **kwargs)
                target.execute("UPDATE jobs SET document=X'00'")
                target.commit()
        def connect(database, *args, **kwargs):
            if str(database) == self.path.as_uri() + '?mode=ro': kwargs['factory'] = AlteredCopy
            return self.connect(database, *args, **kwargs)
        before = self.snapshot(self.path)
        with patch('studio.vpn_schema.sqlite3.connect', side_effect=connect):
            with self.assertRaisesRegex(ValueError, 'verification failed'): vpn_schema.migrate(self.path)
        self.assertEqual(self.snapshot(self.path), before)
        self.assertEqual(self.backups(), [])

    def test_restore_verification_failure_prevents_migration(self):
        original = vpn_schema._check
        checks = []
        def check(db, expected):
            checks.append(1)
            original(db, expected)
            if len(checks) == 2: raise ValueError('fixture restore failure')
        before = self.snapshot(self.path)
        with patch.object(vpn_schema, '_check', side_effect=check):
            with self.assertRaisesRegex(ValueError, 'restore failure'): vpn_schema.migrate(self.path)
        self.assertEqual(len(checks), 2)
        self.assertEqual(self.snapshot(self.path), before)
        self.assertEqual(self.backups(), [])

    def test_schema_failure_rolls_back_and_retry_preserves_first_backup(self):
        class FailedMigration(sqlite3.Connection):
            def execute(self, sql, *args):
                if sql.startswith('CREATE INDEX IF NOT EXISTS vpn_audit_job'):
                    raise sqlite3.OperationalError('fixture DDL failure')
                return super().execute(sql, *args)
        def connect(database, *args, **kwargs):
            if database == self.path: kwargs['factory'] = FailedMigration
            return self.connect(database, *args, **kwargs)
        before = self.snapshot(self.path)
        with patch('studio.vpn_schema.sqlite3.connect', side_effect=connect):
            with self.assertRaisesRegex(sqlite3.OperationalError, 'DDL failure'): vpn_schema.migrate(self.path)
        self.assertEqual(self.snapshot(self.path), before)
        self.assertEqual(self.snapshot(self.canonical), before)
        first = self.canonical.read_bytes()
        vpn_schema.migrate(self.path)
        self.assertEqual(self.canonical.read_bytes(), first)
        self.assertEqual(len(self.backups()), 2)
        self.assertEqual(self.snapshot(self.path)[0], 1)
        vpn_schema.migrate(self.path)  # Already migrated: no additional snapshot.
        self.assertEqual(len(self.backups()), 2)

    def test_writer_lock_wal_contents_and_real_restore(self):
        with closing(self.connect(self.path)) as live:
            live.execute('PRAGMA journal_mode=WAL')
            live.execute('INSERT INTO jobs VALUES(?,?)', ('wal-row', b'committed WAL'))
            live.commit()
            original = vpn_schema._verified_backup
            def backup(path):
                with closing(self.connect(path, timeout=0)) as competing:
                    with self.assertRaisesRegex(sqlite3.OperationalError, 'locked'):
                        competing.execute("INSERT INTO jobs VALUES('racing',NULL)")
                return original(path)
            with patch.object(vpn_schema, '_verified_backup', side_effect=backup): vpn_schema.migrate(self.path)
        restored = self.root / 'restored.sqlite3'
        with closing(self.connect(self.canonical)) as backup, closing(self.connect(restored)) as target:
            backup.backup(target)
        self.assertEqual(self.snapshot(restored), self.snapshot(self.canonical))
        self.assertEqual(len(self.snapshot(restored)[1]), 2)
        vpn_schema.migrate(restored)
        self.assertEqual(self.snapshot(restored)[0], 1)

    def test_directory_fsync_failure_does_not_migrate(self):
        before = self.snapshot(self.path)
        real_fsync = vpn_schema.os.fsync
        calls = []
        def fsync(fd):
            calls.append(fd)
            if len(calls) == 2: raise OSError('fixture directory fsync failure')
            return real_fsync(fd)
        with patch('studio.vpn_schema.os.fsync', side_effect=fsync):
            with self.assertRaisesRegex(OSError, 'fsync failure'): vpn_schema.migrate(self.path)
        self.assertEqual(self.snapshot(self.path), before)
        self.assertEqual(self.snapshot(self.canonical), before)
        vpn_schema.migrate(self.path)
        self.assertEqual(self.snapshot(self.path)[0], 1)


if __name__ == '__main__': unittest.main()
