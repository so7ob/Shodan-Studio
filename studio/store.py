"""Durable local state and authentication for Shodan Studio (stdlib only)."""
from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import sqlite3
import time
from typing import Any


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _json(value: Any) -> str:
    """Do not accidentally persist credentials in job documents or events."""
    forbidden = {"api_key", "api_key_resolved", "authorization", "cookie", "password", "setup_token"}
    def visit(item: Any, depth: int = 0) -> None:
        if depth > 40:
            raise ValueError("بيانات متداخلة أكثر من الحد المسموح.")
        if isinstance(item, dict):
            for key, val in item.items():
                if str(key).casefold() in forbidden and val not in (None, "", False):
                    raise ValueError("لا يمكن حفظ بيانات الاعتماد داخل المهمة أو السجل.")
                visit(val, depth + 1)
        elif isinstance(item, (list, tuple)):
            for val in item:
                visit(val, depth + 1)
    visit(value)
    encoded = json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":"))
    if len(encoded.encode("utf-8")) > 4 * 1024 * 1024:
        raise ValueError("البيانات أكبر من الحد المسموح.")
    return encoded


class Store:
    def __init__(self, data_dir: str | Path):
        self.data_dir = Path(data_dir).expanduser().resolve()
        self.data_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.data_dir.chmod(0o700)
        self.path = self.data_dir / "studio.sqlite3"
        self.setup_path = self.data_dir / "setup-token.txt"
        if self.path.is_symlink() or self.setup_path.is_symlink():
            raise ValueError("مسارات قاعدة البيانات ورمز التهيئة لا تقبل الروابط الرمزية.")
        with self.connection() as con:
            con.executescript("""
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS jobs (
                    id TEXT PRIMARY KEY, status TEXT NOT NULL,
                    priority INTEGER NOT NULL DEFAULT 5,
                    created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
                    document TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS jobs_queue ON jobs(status,priority DESC,created_at);
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, job_id TEXT NOT NULL,
                    at TEXT NOT NULL, document TEXT NOT NULL,
                    FOREIGN KEY(job_id) REFERENCES jobs(id) ON DELETE CASCADE
                );
                CREATE INDEX IF NOT EXISTS events_job ON events(job_id,id);
                CREATE TABLE IF NOT EXISTS settings (name TEXT PRIMARY KEY, value TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS users (
                    username TEXT PRIMARY KEY, salt TEXT NOT NULL,
                    password_hash TEXT NOT NULL, iterations INTEGER NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS sessions (
                    token_hash TEXT PRIMARY KEY, username TEXT,
                    csrf_token TEXT NOT NULL, expires REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS login_limits (
                    address TEXT PRIMARY KEY, failures INTEGER NOT NULL, since REAL NOT NULL
                );
            """)
        self.path.chmod(0o600)
        if self.setup_required():
            self._ensure_setup_token()

    @contextmanager
    def connection(self):
        con = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        con.row_factory = sqlite3.Row
        con.execute("PRAGMA foreign_keys=ON")
        con.execute("PRAGMA busy_timeout=10000")
        try:
            yield con
        finally:
            con.close()

    def _ensure_setup_token(self) -> None:
        if self.setup_path.exists():
            if not self.setup_path.is_file():
                raise ValueError("ملف رمز التهيئة غير صالح.")
            self.setup_path.chmod(0o600)
            return
        try:
            descriptor = os.open(self.setup_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            return
        with os.fdopen(descriptor, "w", encoding="ascii") as stream:
            stream.write(secrets.token_urlsafe(24) + "\n")

    def setup_required(self) -> bool:
        with self.connection() as con:
            return con.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0

    def setup_token(self) -> str | None:
        if not self.setup_required():
            return None
        return self.setup_path.read_text(encoding="ascii").strip()

    def setup(self, token: str, username: str, password: str) -> dict[str, str]:
        if not isinstance(username, str) or not 3 <= len(username.strip()) <= 64 or not all(c.isalnum() or c in "_-" for c in username.strip()):
            raise ValueError("اسم المستخدم من 3 إلى 64 حرفًا أو رقمًا أو شرطة.")
        if not isinstance(password, str) or not 12 <= len(password) <= 256:
            raise ValueError("كلمة المرور من 12 إلى 256 حرفًا.")
        expected = self.setup_token()
        if expected is None:
            raise ValueError("اكتملت تهيئة النظام بالفعل.")
        if not isinstance(token, str) or len(token) > 128 or not hmac.compare_digest(token.encode("utf-8", errors="replace"), expected.encode("ascii")):
            raise PermissionError("رمز التهيئة غير صحيح.")
        username = username.strip()
        salt = secrets.token_hex(24)
        iterations = 600_000
        digest = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), iterations).hex()
        with self.connection() as con:
            con.execute("BEGIN IMMEDIATE")
            if con.execute("SELECT COUNT(*) FROM users").fetchone()[0]:
                con.rollback()
                raise ValueError("اكتملت تهيئة النظام بالفعل.")
            con.execute("INSERT INTO users VALUES(?,?,?,?,?)", (username, salt, digest, iterations, utc_now()))
            con.commit()
        try:
            self.setup_path.unlink(missing_ok=True)
        except OSError:
            pass  # Database state makes any old setup token unusable.
        return {"username": username}

    def authenticate(self, username: str, password: str) -> dict[str, str] | None:
        if not isinstance(username, str) or len(username) > 64 or not isinstance(password, str) or len(password) > 256:
            return None
        with self.connection() as con:
            row = con.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        salt = bytes.fromhex(row["salt"]) if row else b"studio-unknown-user-padding"
        iterations = row["iterations"] if row else 600_000
        computed = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations).hex()
        if row and hmac.compare_digest(computed, row["password_hash"]):
            return {"username": row["username"]}
        return None

    def create_session(self, username: str | None = None) -> dict[str, Any]:
        token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        expires = time.time() + (12 * 3600 if username else 1800)
        with self.connection() as con:
            con.execute("DELETE FROM sessions WHERE expires < ?", (time.time(),))
            con.execute("INSERT INTO sessions VALUES(?,?,?,?)", (hashlib.sha256(token.encode()).hexdigest(), username, csrf, expires))
        return {"token": token, "username": username, "csrf_token": csrf, "expires": expires}

    def get_session(self, token: str) -> dict[str, Any] | None:
        if not isinstance(token, str) or len(token) > 128:
            return None
        with self.connection() as con:
            row = con.execute("SELECT username,csrf_token,expires FROM sessions WHERE token_hash=? AND expires>?",
                              (hashlib.sha256(token.encode()).hexdigest(), time.time())).fetchone()
        return dict(row) if row else None

    def delete_session(self, token: str) -> None:
        with self.connection() as con:
            con.execute("DELETE FROM sessions WHERE token_hash=?", (hashlib.sha256(token.encode()).hexdigest(),))

    def login_allowed(self, address: str) -> bool:
        with self.connection() as con:
            row = con.execute("SELECT * FROM login_limits WHERE address=?", (address,)).fetchone()
        return not row or time.time() - row["since"] >= 300 or row["failures"] < 5

    def login_result(self, address: str, success: bool) -> None:
        now = time.time()
        with self.connection() as con:
            con.execute("BEGIN IMMEDIATE")
            if success:
                con.execute("DELETE FROM login_limits WHERE address=?", (address,))
            else:
                con.execute("DELETE FROM login_limits WHERE since < ?", (now - 300,))
                con.execute("INSERT INTO login_limits(address,failures,since) VALUES(?,1,?) "
                            "ON CONFLICT(address) DO UPDATE SET failures=failures+1", (address, now))
            con.commit()

    def create_job(self, job: dict[str, Any]) -> dict[str, Any]:
        document = dict(job)
        document.setdefault("id", secrets.token_hex(16))
        document.setdefault("status", "queued")
        document.setdefault("priority", 5)
        document.setdefault("created_at", utc_now())
        document["updated_at"] = utc_now()
        encoded = _json(document)
        with self.connection() as con:
            con.execute("INSERT INTO jobs(id,status,priority,created_at,updated_at,document) VALUES(?,?,?,?,?,?)",
                        (document["id"], document["status"], document["priority"], document["created_at"], document["updated_at"], encoded))
        return document

    def get_job(self, job_id: str) -> dict[str, Any] | None:
        with self.connection() as con:
            row = con.execute("SELECT document FROM jobs WHERE id=?", (job_id,)).fetchone()
        return json.loads(row[0]) if row else None

    def list_jobs(self, status: str | None = None, limit: int = 1000) -> list[dict[str, Any]]:
        limit = min(5000, max(1, int(limit)))
        with self.connection() as con:
            if status:
                rows = con.execute("SELECT document FROM jobs WHERE status=? ORDER BY created_at DESC LIMIT ?", (status, limit)).fetchall()
            else:
                rows = con.execute("SELECT document FROM jobs ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
        return [json.loads(row[0]) for row in rows]

    def update_job(self, job_id: str, **changes: Any) -> dict[str, Any]:
        if "id" in changes and changes["id"] != job_id:
            raise ValueError("لا يمكن تغيير معرف المهمة.")
        with self.connection() as con:
            con.execute("BEGIN IMMEDIATE")
            row = con.execute("SELECT document FROM jobs WHERE id=?", (job_id,)).fetchone()
            if row is None:
                con.rollback()
                raise KeyError(job_id)
            job = json.loads(row[0])
            job.update(changes)
            job["updated_at"] = utc_now()
            con.execute("UPDATE jobs SET status=?,priority=?,updated_at=?,document=? WHERE id=?",
                        (job["status"], job.get("priority", 5), job["updated_at"], _json(job), job_id))
            con.commit()
        return job

    def claim_next(self) -> dict[str, Any] | None:
        with self.connection() as con:
            con.execute("BEGIN IMMEDIATE")
            rows = con.execute("SELECT id,document FROM jobs WHERE status='queued' ORDER BY priority DESC,created_at").fetchall()
            for row in rows:
                job = json.loads(row["document"])
                scheduled = job.get("scheduled_at")
                if scheduled and str(scheduled) > utc_now():
                    continue
                job.update(status="running", updated_at=utc_now(), started_at=job.get("started_at") or utc_now(),
                           attempts=int(job.get("attempts", 0)) + 1)
                con.execute("UPDATE jobs SET status='running',updated_at=?,document=? WHERE id=?", (job["updated_at"], _json(job), row["id"]))
                con.commit()
                return job
            con.commit()
        return None

    def recover_interrupted(self) -> int:
        changed = 0
        with self.connection() as con:
            con.execute("BEGIN IMMEDIATE")
            rows = con.execute("SELECT id,document FROM jobs WHERE status IN ('running','pause_requested','cancel_requested')").fetchall()
            for row in rows:
                job = json.loads(row["document"])
                job.update(status="interrupted", updated_at=utc_now(), error="توقف الخادم أثناء تنفيذ المهمة. يمكنك استكمالها من آخر حالة محفوظة.")
                con.execute("UPDATE jobs SET status=?,updated_at=?,document=? WHERE id=?", (job["status"], job["updated_at"], _json(job), row["id"]))
                changed += 1
            con.commit()
        return changed

    def append_event(self, job_id: str, event: dict[str, Any]) -> dict[str, Any]:
        document = dict(event)
        document.setdefault("at", utc_now())
        with self.connection() as con:
            cur = con.execute("INSERT INTO events(job_id,at,document) VALUES(?,?,?)", (job_id, document["at"], _json(document)))
            document["id"] = cur.lastrowid
            # Keep a bounded live log; full engine reports stay on disk.
            con.execute("DELETE FROM events WHERE job_id=? AND id < COALESCE((SELECT id FROM events WHERE job_id=? ORDER BY id DESC LIMIT 1 OFFSET 9999),0)", (job_id, job_id))
        return document

    def events(self, job_id: str, after: int = 0, limit: int = 200) -> dict[str, Any]:
        limit = min(1000, max(1, int(limit)))
        with self.connection() as con:
            rows = con.execute("SELECT id,document FROM events WHERE job_id=? AND id>? ORDER BY id LIMIT ?", (job_id, int(after), limit + 1)).fetchall()
        result = [{**json.loads(row["document"]), "id": row["id"]} for row in rows[:limit]]
        return {"events": result, "last_id": result[-1]["id"] if result else int(after), "has_more": len(rows) > limit}

    def get_setting(self, name: str, default: Any = None) -> Any:
        with self.connection() as con:
            row = con.execute("SELECT value FROM settings WHERE name=?", (name,)).fetchone()
        return json.loads(row[0]) if row else default

    def set_setting(self, name: str, value: Any) -> None:
        if name.casefold() in {"api_key", "password", "authorization", "cookie"}:
            raise ValueError("لا تُحفظ بيانات الاعتماد ضمن الإعدادات العامة.")
        with self.connection() as con:
            con.execute("INSERT INTO settings VALUES(?,?) ON CONFLICT(name) DO UPDATE SET value=excluded.value", (name, _json(value)))

    def delete_job(self, job_id: str) -> None:
        with self.connection() as con:
            con.execute("DELETE FROM jobs WHERE id=?", (job_id,))
