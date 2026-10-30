"""Authenticated, same-origin browser API for Shodan Studio.

The server has no third-party dependencies and is intended for personal use on
a trusted internal network. An HTTPS proxy encrypts browser traffic; it does
not turn this standard-library reference server into a hardened public service.
The default listener is loopback.
"""
from __future__ import annotations

import argparse
from http import HTTPStatus
from http.cookies import SimpleCookie, CookieError
import hmac
import ipaddress
import json
from pathlib import Path
import re
import signal
from socketserver import ThreadingMixIn
import sys
import threading
import time
from typing import Any
from urllib.parse import parse_qs, quote, urlsplit
from wsgiref.simple_server import WSGIRequestHandler, WSGIServer, make_server

from . import __version__ as VERSION
from .store import Store


COOKIE_NAME = "studio_session"
MAX_BODY = 32 * 1024 * 1024
JOB_ID = re.compile(r"^[A-Za-z0-9_-]{1,80}$")
CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self'; "
    "img-src 'self' data:; connect-src 'self'; font-src 'self'; "
    "object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
)


class HTTPError(Exception):
    def __init__(self, status: int, message: str, code: str = "request_error"):
        self.status, self.message, self.code = status, message, code
        super().__init__(message)


def normalize_host(value: str) -> str:
    """Allow exact host[:port] values; never a wildcard or a URL."""
    if not isinstance(value, str) or not value or len(value) > 300:
        raise ValueError("Invalid allowed host; use an exact hostname or IP with its port.")
    if any(c.isspace() or c in "/\\@?#,*" for c in value):
        raise ValueError("Allowed hosts must be exact host:port values without wildcards or URLs.")
    try:
        parsed = urlsplit("//" + value)
        hostname, port = parsed.hostname, parsed.port
    except ValueError as exc:
        raise ValueError("Invalid host or port.") from exc
    if not hostname or parsed.username or parsed.password or parsed.path:
        raise ValueError("Invalid host.")
    if hostname in {"0.0.0.0", "::"}:
        raise ValueError("Use the machine's reachable address in --allowed-hosts, not the bind address.")
    if port is not None and not 1 <= port <= 65535:
        raise ValueError("Invalid host port.")
    if ":" in hostname:
        try:
            ipaddress.IPv6Address(hostname)
        except ValueError as exc:
            raise ValueError("Invalid IPv6 host.") from exc
    elif not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?", hostname):
        raise ValueError("Invalid host name.")
    return value.lower()


class StudioApp:
    def __init__(self, data_dir: str | Path, manager: Any = None,
                 allowed_hosts: tuple[str, ...] | list[str] = ("localhost:8787", "127.0.0.1:8787"),
                 demo: bool = False, secure_cookies: bool = False, autostart: bool = True):
        hosts = frozenset(normalize_host(host) for host in allowed_hosts)
        if not hosts:
            raise ValueError("At least one exact allowed host is required.")
        self.allowed_hosts = hosts
        self.secure_cookies = bool(secure_cookies)
        self.demo = bool(demo)
        if manager is None:
            from .jobs import JobManager
            self.store = Store(data_dir)
            self.manager = JobManager(data_dir, store=self.store, demo=demo, autostart=autostart)
        else:
            self.manager = manager
            self.store = manager.store
        self.static_dir = Path(__file__).resolve().parent / "static"

    def close(self) -> None:
        self.manager.shutdown()

    def __call__(self, environ, start_response):
        headers: list[tuple[str, str]] = []
        try:
            status, body, content_type = self.dispatch(environ, headers)
        except HTTPError as exc:
            status, body, content_type = self.error(exc.status, exc.message, exc.code)
            if exc.status == 429:
                headers.append(("Retry-After", "300"))
        except KeyError:
            status, body, content_type = self.error(404, "المهمة غير موجودة.", "not_found")
        except PermissionError:
            status, body, content_type = self.error(403, "غير مصرح بتنفيذ هذا الطلب.", "forbidden")
        except ValueError as exc:
            status, body, content_type = self.error(400, str(exc), "validation_error")
        except RuntimeError as exc:
            status, body, content_type = self.error(409, str(exc), "conflict")
        except Exception as exc:
            # Never log bodies, credentials, exception arguments or tracebacks.
            print(f"Shodan Studio request failed ({type(exc).__name__}).", file=sys.stderr)
            status, body, content_type = self.error(500, "تعذر إتمام الطلب. راجع حالة الخادم.", "server_error")
        headers.extend([
            ("X-Studio-Server-Time", f"{time.time():.6f}"),
            ("Content-Type", content_type), ("Content-Length", str(len(body))),
            ("Cache-Control", "no-store"), ("Pragma", "no-cache"),
            ("X-Content-Type-Options", "nosniff"), ("X-Frame-Options", "DENY"),
            ("Referrer-Policy", "no-referrer"), ("Content-Security-Policy", CSP),
            ("Permissions-Policy", "camera=(), microphone=(), geolocation=()"),
        ])
        start_response(f"{status} {HTTPStatus(status).phrase}", headers)
        return [b"" if environ.get("REQUEST_METHOD") == "HEAD" else body]

    @staticmethod
    def json_response(value: Any, status: int = 200):
        return status, json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode("utf-8"), "application/json; charset=utf-8"

    @classmethod
    def error(cls, status: int, message: str, code: str):
        return cls.json_response({"error": message, "code": code}, status)

    def validate_origin(self, env) -> None:
        raw_host = env.get("HTTP_HOST", "")
        try:
            host = normalize_host(raw_host)
        except ValueError:
            raise HTTPError(400, "عنوان Host غير مسموح.", "invalid_host") from None
        if host not in self.allowed_hosts:
            raise HTTPError(400, "عنوان Host غير مسموح.", "invalid_host")
        origin = env.get("HTTP_ORIGIN")
        if origin:
            try:
                parsed = urlsplit(origin)
                expected_scheme = "https" if self.secure_cookies else env.get("wsgi.url_scheme", "http")
                valid = (parsed.scheme == expected_scheme and normalize_host(parsed.netloc) == host
                         and not parsed.path and not parsed.query and not parsed.fragment)
            except ValueError:
                valid = False
            if not valid:
                raise HTTPError(403, "يجب أن يأتي الطلب من عنوان لوحة التحكم نفسه.", "invalid_origin")
        if env.get("HTTP_SEC_FETCH_SITE", "").lower() == "cross-site":
            raise HTTPError(403, "الطلبات من مواقع أخرى غير مسموحة.", "cross_site")

    def session(self, env):
        token = ""
        cookie_header = env.get("HTTP_COOKIE", "")
        if len(cookie_header) <= 8192:
            try:
                cookies = SimpleCookie(cookie_header)
                morsel = cookies.get(COOKIE_NAME)
                token = morsel.value if morsel else ""
            except CookieError:
                pass
        return token, self.store.get_session(token) if token else None

    def set_cookie(self, headers, token: str, env, authenticated: bool = False) -> None:
        cookie = SimpleCookie()
        cookie[COOKIE_NAME] = token
        cookie[COOKIE_NAME]["path"] = "/"
        cookie[COOKIE_NAME]["httponly"] = True
        cookie[COOKIE_NAME]["samesite"] = "Strict"
        cookie[COOKIE_NAME]["max-age"] = 12 * 3600 if authenticated else 1800
        if self.secure_cookies or env.get("wsgi.url_scheme") == "https":
            cookie[COOKIE_NAME]["secure"] = True
        headers.append(("Set-Cookie", cookie.output(header="").strip()))

    def rotate_session(self, old_token: str, username: str | None, env, headers):
        if old_token:
            self.store.delete_session(old_token)
        session = self.store.create_session(username)
        self.set_cookie(headers, session["token"], env, bool(username))
        return session

    def session_payload(self, session):
        authenticated = bool(session and session.get("username"))
        return {"setup_required": self.store.setup_required(), "authenticated": authenticated,
                "user": {"username": session["username"]} if authenticated else None,
                "csrf_token": session["csrf_token"] if session else None, "demo": self.demo}

    @staticmethod
    def require_csrf(env, session) -> None:
        csrf = env.get("HTTP_X_CSRF_TOKEN", "")
        if (not session or not isinstance(csrf, str) or len(csrf) > 128 or
                not hmac.compare_digest(csrf.encode("utf-8", errors="replace"), session["csrf_token"].encode("ascii"))):
            raise HTTPError(403, "انتهت جلسة الأمان. أعد تحميل الصفحة ثم حاول مرة أخرى.", "invalid_csrf")

    @staticmethod
    def read_json(env):
        if env.get("CONTENT_TYPE", "").split(";", 1)[0].strip().lower() != "application/json":
            raise HTTPError(415, "يجب إرسال الطلب بصيغة JSON.", "json_required")
        try:
            length = int(env.get("CONTENT_LENGTH", "0"))
        except (TypeError, ValueError):
            raise HTTPError(400, "طول الطلب غير صالح.", "invalid_length") from None
        if length < 0:
            raise HTTPError(400, "طول الطلب غير صالح.", "invalid_length")
        if length > MAX_BODY:
            raise HTTPError(413, "حجم الطلب يتجاوز 32 ميجابايت.", "body_too_large")
        body = env["wsgi.input"].read(length)
        if len(body) != length:
            raise HTTPError(400, "لم يكتمل وصول الطلب.", "incomplete_body")
        try:
            def invalid_constant(value):
                raise ValueError("Non-finite JSON number")
            payload = json.loads(body.decode("utf-8"), parse_constant=invalid_constant)
        except (ValueError, UnicodeError, RecursionError):
            raise HTTPError(400, "محتوى JSON غير صالح.", "invalid_json") from None
        if not isinstance(payload, dict):
            raise HTTPError(400, "الطلب يجب أن يحتوي كائن JSON.", "invalid_json")
        return payload

    @staticmethod
    def query_int(params, name: str, default: int, minimum: int = 0, maximum: int = 2_147_483_647) -> int:
        values = params.get(name, [str(default)])
        try:
            value = int(values[0])
            if len(values) != 1 or not minimum <= value <= maximum:
                raise ValueError
        except (ValueError, TypeError):
            raise HTTPError(400, "قيمة غير صالحة لمعامل " + name + ".", "invalid_parameter") from None
        return value

    def dispatch(self, env, headers):
        self.validate_origin(env)
        method = env.get("REQUEST_METHOD", "GET").upper()
        path = env.get("PATH_INFO", "/")
        if len(path) > 2048 or len(env.get("QUERY_STRING", "")) > 8192:
            raise HTTPError(414, "عنوان الطلب أطول من المسموح.", "uri_too_long")
        if method not in {"GET", "HEAD", "POST"}:
            raise HTTPError(405, "طريقة الطلب غير مدعومة.", "method_not_allowed")
        if path == "/health" and method in {"GET", "HEAD"}:
            return self.json_response({"ok": True, "version": VERSION})
        if not path.startswith("/api/"):
            return self.static(path, method)
        token, session = self.session(env)
        if path == "/api/session" and method in {"GET", "HEAD"}:
            if not session:
                session = self.rotate_session(token, None, env, headers)
            return self.json_response(self.session_payload(session))
        if method == "POST":
            self.require_csrf(env, session)
            payload = self.read_json(env)
            if path == "/api/setup":
                if not self.store.setup_required():
                    raise HTTPError(409, "اكتملت تهيئة النظام بالفعل.", "already_configured")
                address = env.get("REMOTE_ADDR", "unknown")[:100]
                self.auth_attempt(address)
                try:
                    user = self.store.setup(payload.get("setup_token"), payload.get("username", "admin"), payload.get("password"))
                except PermissionError:
                    raise HTTPError(403, "رمز التهيئة غير صحيح.", "invalid_setup_token") from None
                self.store.login_result(address, True)
                session = self.rotate_session(token, user["username"], env, headers)
                return self.json_response(self.session_payload(session), 201)
            if path == "/api/login":
                if self.store.setup_required():
                    raise HTTPError(409, "يلزم إكمال التهيئة أولًا.", "setup_required")
                address = env.get("REMOTE_ADDR", "unknown")[:100]
                self.auth_attempt(address)
                user = self.store.authenticate(payload.get("username", "admin"), payload.get("password"))
                if not user:
                    raise HTTPError(401, "اسم المستخدم أو كلمة المرور غير صحيح.", "invalid_credentials")
                self.store.login_result(address, True)
                session = self.rotate_session(token, user["username"], env, headers)
                return self.json_response(self.session_payload(session))
        if not session or not session.get("username"):
            raise HTTPError(401, "سجّل الدخول للمتابعة.", "authentication_required")
        lane_kind = 'extraction'
        if path == '/api/enrichment/jobs' or path.startswith('/api/enrichment/jobs/') or path == '/api/enrichment/vpn' or path.startswith('/api/enrichment/vpn/'):
            lane_kind = 'enrichment'
            path = '/api/' + path[len('/api/enrichment/'):]
            if path.startswith('/api/jobs/'):
                ident = path.split('/')[3]
                job = self.manager.get_job(ident)
                if job.get('kind', 'extraction') != 'enrichment':
                    raise HTTPError(404, 'المهمة غير موجودة في مساحة الإثراء.', 'not_found')
        lane_manager = self.manager.lane(lane_kind) if lane_kind == 'enrichment' else self.manager
        if path == "/api/logout" and method == "POST":
            session = self.rotate_session(token, None, env, headers)
            return self.json_response(self.session_payload(session))
        if path == '/api/enrichment/settings':
            if method in {'GET', 'HEAD'}: return self.json_response(self.manager.enrichment_settings.public())
            if method == 'POST':
                with self.manager._lock:
                    result = self.manager.enrichment_settings.save(payload)
                    key = self.manager.enrichment_settings.key()
                    if key: self.manager._secret_history.add(key)
                    self.manager._seed_enrichment()
                    return self.json_response(result)
            raise HTTPError(405, 'طريقة الطلب غير مدعومة.', 'method_not_allowed')
        if path == '/api/targets' or path.startswith('/api/targets/'):
            if method not in {'GET', 'HEAD'}: raise HTTPError(405, 'طريقة الطلب غير مدعومة.', 'method_not_allowed')
            from .targets import FILTERS
            params = parse_qs(env.get('QUERY_STRING', ''), keep_blank_values=True, max_num_fields=32)
            if set(params) - FILTERS - {'offset', 'limit', 'format'} or any(len(v) != 1 for v in params.values()):
                raise HTTPError(400, 'فلاتر المستودع غير صالحة.', 'invalid_parameter')
            filters = {k: v[0] for k, v in params.items() if k in FILTERS and v[0] != ''}
            if path == '/api/targets/stats': return self.json_response(self.store.targets.stats(filters))
            if path == '/api/targets/download':
                format_name = params.get('format', ['csv'])[0]
                content, mime = self.store.targets.export(filters, format_name)
                headers.append(('Content-Disposition', f'attachment; filename="shodan-targets.{format_name}"'))
                return 200, content, mime
            offset, limit = self.query_int(params, 'offset', 0), self.query_int(params, 'limit', 100, 1, 1000)
            if path == '/api/targets': return self.json_response(self.store.targets.list(filters, offset, limit))
            match = re.fullmatch('/api/targets/([a-f0-9]{32})', path)
            if match: return self.json_response({'target': self.store.targets.detail(match[1], offset, limit)})
            raise HTTPError(404, 'الهدف غير موجود.', 'not_found')
        if path == "/api/vpn" and method in {"GET", "HEAD"}:
            return self.json_response(lane_manager.vpn.summary())
        if path == '/api/shodan/accounts':
            if method in {'GET','HEAD'}:return self.json_response({'accounts':self.manager.shodan_accounts.list()})
            if method == 'POST':return self.json_response({'account':self.manager.shodan_account_save(payload)},201)
        account_match = re.fullmatch(r'/api/shodan/accounts/([a-f0-9]{32})',path)
        if account_match and method == 'POST':
            if payload == {'action':'delete'}:return self.json_response(self.manager.shodan_account_delete(account_match[1]))
            if payload.get('action')!='update':raise ValueError('عملية الحساب غير صالحة.')
            return self.json_response({'account':self.manager.shodan_account_save({k:v for k,v in payload.items() if k!='action'},account_match[1])})
        account_job = re.fullmatch(r'/api/jobs/([a-f0-9]{32})/shodan-account',path)
        if account_job and method == 'POST':
            return self.json_response({'job':self.manager.shodan_account_select(account_job[1],payload)})
        if path == "/api/vpn/discover" and method in {"GET", "HEAD"}:
            return self.json_response({"candidates": lane_manager.vpn.provider.discover_profiles()})
        if path == "/api/vpn/profiles" and method == "POST":
            return self.json_response({"profile": lane_manager.vpn.add(payload)}, 201)
        if path == "/api/vpn/actions" and method == "POST":
            return self.json_response(lane_manager.vpn_action(payload))
        if path == "/api/vpn/premium" and method == "POST":
            return self.json_response(lane_manager.vpn_premium(payload))
        if path == "/api/vpn/diagnostics" and method == "POST":
            if set(payload) != {"scope"}:
                raise ValueError('طلب التشخيص غير صالح.')
            return self.json_response(lane_manager.vpn.diagnostics(payload['scope']))
        vpn_match = re.fullmatch(r"/api/vpn/profiles/([a-f0-9]{32})", path)
        if vpn_match and method == "POST":
            return self.json_response({"profile": lane_manager.vpn_update(vpn_match[1], payload)})
        network_match = re.fullmatch(r"/api/jobs/([a-f0-9]{32})/network", path)
        browser_match = re.fullmatch(r"/api/jobs/([a-f0-9]{32})/browser", path)
        browser_policy_match = re.fullmatch(r"/api/jobs/([a-f0-9]{32})/browser-policy", path)
        if browser_policy_match and method == 'POST':
            return self.json_response({'job': self.manager.browser_policy(browser_policy_match[1], payload)})
        if browser_match and method == 'POST':
            return self.json_response(self.manager.browser_action(browser_match[1],payload))
        if network_match and method == "POST":
            return self.json_response({"job": self.manager.network_settings(network_match[1], payload)})
        if path == "/api/jobs":
            if method in {"GET", "HEAD"}:
                result = self.manager.list_jobs(kind='enrichment') if lane_kind == 'enrichment' else self.manager.list_jobs()
                return self.json_response(result)
            if lane_kind == 'enrichment':
                if payload.get('kind', 'enrichment') != 'enrichment': raise ValueError('نوع مهمة الإثراء غير صالح.')
                payload = {**payload, 'kind': 'enrichment'}
            return self.json_response({"job": self.manager.create_job(payload)}, 201)
        if path == "/api/checkpoints/import" and method == "POST":
            return self.json_response({"job": self.manager.import_checkpoint(payload)}, 201)
        request_match = re.fullmatch(r'/api/jobs/([a-f0-9]{32})/requests(?:/([a-f0-9]{32}))?',path)
        if request_match:
            if method not in {'GET','HEAD'}: raise HTTPError(405,'طريقة الطلب غير مدعومة.','method_not_allowed')
            job_id,request_id=request_match.groups()
            if self.manager.get_job(job_id) is None: raise KeyError(job_id)
            params=parse_qs(env.get('QUERY_STRING',''),keep_blank_values=True,max_num_fields=20)
            if request_id:
                return self.json_response(self.store.requests.detail(job_id,request_id,
                    offset=self.query_int(params,'offset',0),limit=self.query_int(params,'limit',100,1,1000)))
            return self.json_response(self.store.requests.list(job_id,
                before=self.query_int(params,'before',0),limit=self.query_int(params,'limit',50,1,200)))
        match = re.fullmatch(r"/api/jobs/([^/]+)(?:/(actions|events|results|download))?", path)
        if not match or not JOB_ID.fullmatch(match[1]):
            raise HTTPError(404, "المسار غير موجود.", "not_found")
        job_id, endpoint = match.groups()
        if endpoint is None and method in {"GET", "HEAD"}:
            job = self.manager.get_job(job_id)
            if job is None:
                raise KeyError(job_id)
            return self.json_response({"job": job})
        if endpoint == "actions" and method == "POST":
            return self.json_response({"job": self.manager.action(job_id, payload)})
        if method not in {"GET", "HEAD"} or endpoint not in {"events", "results", "download"}:
            raise HTTPError(405, "طريقة الطلب غير مدعومة لهذا المسار.", "method_not_allowed")
        if self.manager.get_job(job_id) is None:
            raise KeyError(job_id)
        try:
            params = parse_qs(env.get("QUERY_STRING", ""), keep_blank_values=True, max_num_fields=20)
        except ValueError:
            raise HTTPError(400, "معاملات الطلب غير صالحة.", "invalid_parameter") from None
        if endpoint == "events":
            after = self.query_int(params, "after", 0)
            limit = self.query_int(params, "limit", 200, 1, 1000)
            return self.json_response(self.store.events(job_id, after=after, limit=limit))
        if endpoint == "results":
            offset = self.query_int(params, "offset", 0)
            limit = self.query_int(params, "limit", 100, 1, 1000)
            query = params.get("q", [""])[0]
            if len(query) > 512:
                raise HTTPError(400, "نص البحث أطول من المسموح.", "invalid_parameter")
            return self.json_response(self.manager.results(job_id, offset=offset, limit=limit, q=query))
        format_name = params.get("format", ["txt"])[0]
        if format_name not in {"txt", "csv", "json", "report", "checkpoint"}:
            raise HTTPError(400, "صيغة التنزيل غير مدعومة.", "invalid_format")
        body, content_type, filename = self.manager.download(job_id, format_name)
        if not isinstance(body, bytes):
            raise RuntimeError("تعذر تجهيز ملف التنزيل.")
        filename = Path(str(filename)).name.replace("\r", "").replace("\n", "")[:180]
        fallback = re.sub(r"[^A-Za-z0-9._-]", "_", filename) or "download.txt"
        headers.append(("Content-Disposition", f"attachment; filename=\"{fallback}\"; filename*=UTF-8''{quote(filename, safe='')}"))
        return 200, body, content_type

    def auth_attempt(self, address: str) -> None:
        if not self.store.login_allowed(address):
            raise HTTPError(429, "محاولات كثيرة. انتظر خمس دقائق ثم حاول مرة أخرى.", "login_rate_limited")
        # Reserve an attempt before costly password verification.
        self.store.login_result(address, False)

    def static(self, path: str, method: str):
        if method not in {"GET", "HEAD"}:
            raise HTTPError(405, "طريقة الطلب غير مدعومة.", "method_not_allowed")
        files = {
            "/": ("index.html", "text/html; charset=utf-8"),
            "/index.html": ("index.html", "text/html; charset=utf-8"),
            "/enrichment": ("index.html", "text/html; charset=utf-8"),
            "/extraction": ("index.html", "text/html; charset=utf-8"),
            "/app.js": ("app.js", "text/javascript; charset=utf-8"),
            "/app.css": ("app.css", "text/css; charset=utf-8"),
            "/static/app.js": ("app.js", "text/javascript; charset=utf-8"),
            "/static/app.css": ("app.css", "text/css; charset=utf-8"),
            "/static/job_guidance.js": ("job_guidance.js", "text/javascript; charset=utf-8"),
            "/static/ip_progress.js": ("ip_progress.js", "text/javascript; charset=utf-8"),
            "/static/ip_progress.css": ("ip_progress.css", "text/css; charset=utf-8"),
            "/static/vpn.js": ("vpn.js", "text/javascript; charset=utf-8"),
            "/static/browser.js": ("browser.js", "text/javascript; charset=utf-8"),
            "/static/accounts.js": ("accounts.js", "text/javascript; charset=utf-8"),
            "/static/requests.js": ("requests.js", "text/javascript; charset=utf-8"),
            "/static/requests.css": ("requests.css", "text/css; charset=utf-8"),
            '/static/targets.js': ('targets.js', 'text/javascript; charset=utf-8'),
            '/static/targets.css': ('targets.css', 'text/css; charset=utf-8'),
            "/static/vpn.css": ("vpn.css", "text/css; charset=utf-8"),
            "/favicon.svg": ("favicon.svg", "image/svg+xml"),
        }
        item = files.get(path)
        if not item:
            raise HTTPError(404, "الملف غير موجود.", "not_found")
        location = self.static_dir / item[0]
        if not location.is_file() or location.is_symlink():
            raise HTTPError(404, "ملف الواجهة غير موجود.", "not_found")
        return 200, location.read_bytes(), item[1]


def create_app(data_dir: str | Path = "./data", manager: Any = None,
               allowed_hosts=("localhost:8787", "127.0.0.1:8787"),
               demo: bool = False, secure_cookies: bool = False, autostart: bool = True) -> StudioApp:
    return StudioApp(data_dir, manager, allowed_hosts, demo, secure_cookies, autostart)


class ThreadingWSGIServer(ThreadingMixIn, WSGIServer):
    daemon_threads = True
    request_queue_size = 32

    def get_request(self):
        connection, address = super().get_request()
        connection.settimeout(45)
        return connection, address


class QuietRequestHandler(WSGIRequestHandler):
    def log_message(self, format, *args):
        # The default request log may contain queries. Keep only status and path.
        status = str(args[1]) if len(args) > 1 else "-"
        path = urlsplit(getattr(self, "path", "/")).path
        safe_path = re.sub(r"[^/A-Za-z0-9_.-]", "_", path)[:180]
        print(f"{getattr(self, 'command', 'GET')} {safe_path} {status}", file=sys.stderr)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Shodan Studio — لوحة تشغيل محلية آمنة")
    parser.add_argument("--host", default="127.0.0.1", help="Bind address (default: 127.0.0.1)")
    parser.add_argument("--port", default=8787, type=int)
    parser.add_argument("--data-dir", default="./data")
    parser.add_argument("--allowed-hosts", action="append", default=[], metavar="HOST:PORT[,HOST:PORT]",
                        help="Exact browser/proxy Host values; repeatable, required for LAN binding")
    parser.add_argument("--secure-cookies", action="store_true", help="Require HTTPS browser sessions behind a TLS proxy")
    parser.add_argument("--demo", action="store_true", help="Enable optional synthetic demo jobs; only jobs marked demo avoid Shodan requests")
    parser.add_argument("--version", action="version", version=f"Shodan Studio {VERSION}")
    args = parser.parse_args(argv)
    if not 1 <= args.port <= 65535:
        parser.error("--port must be between 1 and 65535")
    try:
        loopback = args.host == "localhost" or ipaddress.ip_address(args.host).is_loopback
    except ValueError:
        parser.error("--host must be a literal IPv4/IPv6 address or localhost")
    if not loopback and not args.allowed_hosts:
        parser.error("LAN binding requires --allowed-hosts with the browser address, for example 192.168.1.20:8787")
    hosts = [part.strip() for item in args.allowed_hosts for part in item.split(",") if part.strip()]
    if not hosts:
        hosts = [f"127.0.0.1:{args.port}", f"localhost:{args.port}"]
        if ":" in args.host:
            hosts.append(f"[{args.host}]:{args.port}")
    try:
        app = create_app(args.data_dir, allowed_hosts=hosts, demo=args.demo,
                         secure_cookies=args.secure_cookies, autostart=False)
    except (ValueError, OSError) as exc:
        parser.error(str(exc))
    server_class = ThreadingWSGIServer
    if ":" in args.host:
        import socket
        class IPv6Server(ThreadingWSGIServer):
            address_family = socket.AF_INET6
        server_class = IPv6Server
    try:
        server = make_server(args.host, args.port, app, server_class=server_class, handler_class=QuietRequestHandler)
    except OSError as exc:
        app.close()
        print(f"Cannot start Shodan Studio: {exc}", file=sys.stderr)
        return 1
    try:
        # A failed listener must not begin executing previously queued work.
        app.manager.start()
    except (ValueError, OSError) as exc:
        server.server_close()
        app.close()
        print(f"Cannot start Shodan Studio: {exc}", file=sys.stderr)
        return 1
    stop_started = threading.Event()

    def shutdown_signal(signum, frame):
        if not stop_started.is_set():
            stop_started.set()
            threading.Thread(target=server.shutdown, name="studio-shutdown", daemon=True).start()

    signal.signal(signal.SIGTERM, shutdown_signal)
    signal.signal(signal.SIGINT, shutdown_signal)
    scheme = "https" if args.secure_cookies else "http"
    print(f"Shodan Studio {VERSION} | Python {sys.version_info.major}.{sys.version_info.minor}", flush=True)
    for host in sorted(app.allowed_hosts):
        print(f"  Open: {scheme}://{host}", flush=True)
    setup_token = app.store.setup_token()
    if setup_token:
        print(f"  First setup code: {setup_token}", flush=True)
        print(f"  Private code file: {app.store.setup_path}", flush=True)
    if args.demo:
        print("  Demo jobs enabled: jobs marked demo use synthetic data; other jobs can contact Shodan.", flush=True)
    try:
        server.serve_forever(poll_interval=0.25)
    finally:
        server.server_close()
        app.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
