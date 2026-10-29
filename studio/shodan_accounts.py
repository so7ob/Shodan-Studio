"""Local Shodan credentials, separate from jobs, events and exports."""
from __future__ import annotations

import json
import os
import re
import secrets
import stat
from datetime import datetime, timezone


def account_id(value):
    if not isinstance(value, str) or not re.fullmatch('[a-f0-9]{32}', value):
        raise ValueError('معرّف حساب Shodan غير صالح.')
    return value


def credentials(username, password):
    if not isinstance(username, str) or not 1 <= len(username.strip()) <= 128 or any(ord(c) < 32 or ord(c) == 127 for c in username):
        raise ValueError('أدخل اسم مستخدم Shodan صالحًا.')
    if not isinstance(password, str) or not 1 <= len(password) <= 1024 or any(ord(c) < 32 or ord(c) == 127 for c in password):
        raise ValueError('أدخل كلمة مرور Shodan صالحة.')
    return username.strip(), password


class ShodanAccounts:
    def __init__(self, store):
        self.store = store
        self.key_path = store.data_dir / 'shodan-accounts.key'
        with store.connection() as con:
            con.execute('''CREATE TABLE IF NOT EXISTS shodan_accounts (
                id TEXT PRIMARY KEY, label TEXT NOT NULL, encrypted TEXT NOT NULL,
                created_at TEXT NOT NULL, updated_at TEXT NOT NULL, used INTEGER NOT NULL DEFAULT 0)''')

    def _cipher(self, create=False):
        try: from cryptography.fernet import Fernet
        except ImportError:
            raise RuntimeError('يلزم تثبيت python3-cryptography على الخادم لحفظ حسابات Shodan.') from None
        try:
            fd = os.open(self.key_path, os.O_RDONLY | os.O_NOFOLLOW)
        except FileNotFoundError:
            if not create:
                raise RuntimeError('مفتاح حسابات Shodan غير متاح؛ استعد المفتاح من النسخة الاحتياطية.') from None
            # Called inside a SQLite write transaction: concurrent creators wait.
            key = Fernet.generate_key()
            fd = os.open(self.key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, 'wb') as f:
                f.write(key); f.flush(); os.fsync(f.fileno())
            return Fernet(key)
        with os.fdopen(fd, 'rb') as f:
            info = os.fstat(f.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or info.st_uid != os.geteuid():
                raise RuntimeError('ملف مفتاح Shodan يحتاج إلى ملكية الخدمة وصلاحيات 0600.')
            key = f.read(100)
        try: return Fernet(key)
        except ValueError: raise RuntimeError('مفتاح حسابات Shodan غير صالح.') from None

    def _decode(self, row):
        cipher = self._cipher()
        from cryptography.fernet import InvalidToken
        try:
            secret = json.loads(cipher.decrypt(row['encrypted'].encode()))
            if secret['id'] != row['id']: raise ValueError()
            account_id(secret['scope'])
            credentials(secret['username'], secret['password'])
            return secret
        except (InvalidToken, ValueError, KeyError, TypeError):
            raise RuntimeError('تعذر فتح بيانات حساب Shodan المحفوظة.') from None

    def _row(self, ident):
        with self.store.connection() as con:
            row = con.execute('SELECT * FROM shodan_accounts WHERE id=?', (account_id(ident),)).fetchone()
        if row is None: raise ValueError('حساب Shodan غير موجود.')
        return row

    def secret(self, ident):
        return self._decode(self._row(ident))

    def metadata(self, ident):
        row = self._row(ident)
        return self._public(row)

    def _public(self, row):
        return {key: row[key] for key in ('id', 'label', 'created_at', 'updated_at')} | {'username': self._decode(row)['username']}

    def list(self):
        with self.store.connection() as con:
            rows = con.execute('SELECT * FROM shodan_accounts ORDER BY created_at,id').fetchall()
        return [self._public(row) for row in rows]

    def used(self, ident):
        return bool(self._row(ident)['used'])

    def mark_used(self, ident):
        with self.store.connection() as con:
            con.execute('UPDATE shodan_accounts SET used=1 WHERE id=?', (account_id(ident),))

    def validate(self, payload, ident=None):
        if not isinstance(payload, dict) or set(payload) - {'label', 'username', 'password'}:
            raise ValueError('بيانات حساب Shodan غير صالحة.')
        previous = self.secret(ident) if ident else None
        password = payload.get('password')
        if previous and password in (None, ''): password = previous['password']
        username, password = credentials(payload.get('username'), password)
        label = payload.get('label', '')
        if label == '': label = 'حساب Shodan'
        if not isinstance(label, str) or len(label.strip()) > 100 or any(ord(c) < 32 or ord(c) == 127 for c in label):
            raise ValueError('اسم الحساب طويل أو غير صالح.')
        return username, password, label.strip() or 'حساب Shodan', previous

    def save(self, payload, ident=None):
        username, password, label, previous = self.validate(payload, ident)
        ident = account_id(ident) if ident else secrets.token_hex(16)
        # A changed credential pair gets a new cookie namespace.
        changed = not previous or (username, password) != (previous['username'], previous['password'])
        secret = {'id': ident, 'scope': secrets.token_hex(16) if changed else previous['scope'], 'username': username, 'password': password}
        now = datetime.now(timezone.utc).isoformat()
        with self.store.connection() as con:
            con.execute('BEGIN IMMEDIATE')
            try:
                count = con.execute('SELECT COUNT(*) FROM shodan_accounts').fetchone()[0]
                if not previous and count >= 100: raise ValueError('وصلت إلى حد 100 حساب محفوظ.')
                cipher = self._cipher(create=count == 0)
                encoded = cipher.encrypt(json.dumps(secret).encode()).decode()
                if previous:
                    con.execute('UPDATE shodan_accounts SET label=?,encrypted=?,updated_at=?,used=CASE WHEN ? THEN 0 ELSE used END WHERE id=?', (label.strip(), encoded, now, changed, ident))
                else:
                    con.execute('INSERT INTO shodan_accounts(id,label,encrypted,created_at,updated_at) VALUES(?,?,?,?,?)', (ident,label.strip(),encoded,now,now))
                con.commit()
            except Exception:
                con.rollback(); raise
        return self.metadata(ident)

    def delete(self, ident):
        self._row(ident)
        with self.store.connection() as con:
            con.execute('DELETE FROM shodan_accounts WHERE id=?', (ident,))
