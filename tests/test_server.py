"""Offline tests for the WSGI/authentication and durable-state boundaries."""
from concurrent.futures import ThreadPoolExecutor
from http.cookies import SimpleCookie
import io
import json
from pathlib import Path
import sqlite3
import tempfile
import time
import unittest
from unittest.mock import patch

from studio import __version__
from studio.server import COOKIE_NAME, MAX_BODY, create_app, main, normalize_host
from studio.store import Store


PASSWORD = "fixture-password-only-123!"


class FakeManager:
    def __init__(self, store):
        self.store = store
        self.closed = False
        self.last_results = None

    def shutdown(self):
        self.closed = True

    def create_job(self, payload):
        return self.store.create_job({"title": payload.get("title", "Test"), "query": payload.get("query", "test"), "status": "queued"})

    def get_job(self, job_id):
        job = self.store.get_job(job_id)
        if job is None:
            raise KeyError(job_id)
        return job

    def list_jobs(self):
        jobs = self.store.list_jobs()
        return {"jobs": jobs, "summary": {"jobs": len(jobs)}}

    def action(self, job_id, payload):
        if payload.get("action") == "pause":
            return self.store.update_job(job_id, status="paused")
        raise ValueError("Unsupported action")

    def results(self, job_id, offset, limit, q):
        self.last_results = (job_id, offset, limit, q)
        return {"total": 1, "items": ["192.0.2.10"], "offset": offset, "limit": limit}

    def download(self, job_id, format):
        return b"192.0.2.10\n", "text/plain; charset=utf-8", "results.txt"

    def import_checkpoint(self, payload):
        if not isinstance(payload.get("checkpoint"), dict):
            raise ValueError("Invalid checkpoint")
        return self.create_job({"title": "Imported", "query": "fixture"})


class Client:
    def __init__(self, app):
        self.app = app
        self.cookie = ""
        self.csrf = ""

    def request(self, method, path, payload=None, *, headers=None, raw=None, content_length=None):
        pathname, separator, query = path.partition("?")
        body = raw if raw is not None else json.dumps(payload or {}).encode()
        env = {
            "REQUEST_METHOD": method, "PATH_INFO": pathname, "QUERY_STRING": query,
            "HTTP_HOST": "localhost:8787", "SERVER_NAME": "localhost", "SERVER_PORT": "8787",
            "SERVER_PROTOCOL": "HTTP/1.1", "wsgi.url_scheme": "http", "wsgi.version": (1, 0),
            "wsgi.input": io.BytesIO(body), "wsgi.errors": io.StringIO(),
            "wsgi.multithread": True, "wsgi.multiprocess": False, "wsgi.run_once": False,
            "CONTENT_TYPE": "application/json", "CONTENT_LENGTH": str(len(body) if content_length is None else content_length),
            "REMOTE_ADDR": "127.0.0.1", "HTTP_COOKIE": self.cookie,
            "HTTP_X_CSRF_TOKEN": self.csrf,
        }
        env.update(headers or {})
        captured = {}
        def start_response(status, response_headers):
            captured["status"] = int(status.split(" ")[0])
            captured["headers"] = dict(response_headers)
        chunks = self.app(env, start_response)
        content = b"".join(chunks)
        if hasattr(chunks, "close"):
            chunks.close()
        if "Set-Cookie" in captured["headers"]:
            morsel = SimpleCookie(captured["headers"]["Set-Cookie"])[COOKIE_NAME]
            self.cookie = COOKIE_NAME + "=" + morsel.value
        if content and "application/json" in captured["headers"]["Content-Type"]:
            data = json.loads(content)
            if data.get("csrf_token"):
                self.csrf = data["csrf_token"]
        else:
            data = content
        return captured["status"], data, captured["headers"]


class ServerTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.store = Store(self.directory.name)
        self.manager = FakeManager(self.store)
        self.app = create_app(self.directory.name, manager=self.manager)
        self.client = Client(self.app)
        self.client.request("GET", "/api/session")

    def tearDown(self):
        self.app.close()
        self.directory.cleanup()

    def setup_admin(self):
        response = self.client.request("POST", "/api/setup", {
            "setup_token": self.store.setup_token(), "username": "admin", "password": PASSWORD,
        })
        self.assertEqual(response[0], 201, response[1])
        return response

    def job(self):
        return self.manager.create_job({"query": 'test country:"ZZ"'})

    def test_anonymous_session_has_csrf_and_safe_cookie(self):
        client = Client(self.app)
        status, data, headers = client.request("GET", "/api/session")
        self.assertEqual(status, 200)
        self.assertTrue(data["setup_required"])
        self.assertFalse(data["authenticated"])
        self.assertIsNone(data["user"])
        self.assertGreater(len(data["csrf_token"]), 30)
        self.assertIn("HttpOnly", headers["Set-Cookie"])
        self.assertIn("SameSite=Strict", headers["Set-Cookie"])
        self.assertNotIn("setup_token", data)
        self.assertNotIn(str(self.store.path), json.dumps(data))

    def test_authentication_required_for_jobs_events_results_download(self):
        job = self.job()
        for endpoint in ["/api/jobs", f"/api/jobs/{job['id']}", f"/api/jobs/{job['id']}/events",
                         f"/api/jobs/{job['id']}/results", f"/api/jobs/{job['id']}/download"]:
            with self.subTest(endpoint=endpoint):
                status, data, _ = self.client.request("GET", endpoint)
                self.assertEqual(status, 401)
                self.assertNotIn(job["query"], json.dumps(data))

    def test_setup_needs_csrf_before_creating_account(self):
        status, data, _ = self.client.request("POST", "/api/setup", {
            "setup_token": self.store.setup_token(), "username": "admin", "password": PASSWORD,
        }, headers={"HTTP_X_CSRF_TOKEN": ""})
        self.assertEqual(status, 403)
        self.assertEqual(data["code"], "invalid_csrf")
        self.assertTrue(self.store.setup_required())

    def test_setup_rejects_wrong_code_and_short_password(self):
        status, _, _ = self.client.request("POST", "/api/setup", {
            "setup_token": "incorrect", "username": "admin", "password": PASSWORD,
        })
        self.assertEqual(status, 403)
        status, _, _ = self.client.request("POST", "/api/setup", {
            "setup_token": self.store.setup_token(), "username": "admin", "password": "short",
        })
        self.assertEqual(status, 400)
        self.assertTrue(self.store.setup_required())

    def test_non_ascii_security_tokens_are_rejected_without_server_error(self):
        status, _, _ = self.client.request("POST", "/api/setup", {
            "setup_token": "رمز غير صحيح", "username": "admin", "password": PASSWORD,
        })
        self.assertEqual(status, 403)
        status, data, _ = self.client.request("POST", "/api/setup", {}, headers={"HTTP_X_CSRF_TOKEN": "رمز غير صحيح"})
        self.assertEqual(status, 403)
        self.assertEqual(data["code"], "invalid_csrf")

    def test_setup_rotates_session_and_erases_setup_token(self):
        old_cookie, old_csrf = self.client.cookie, self.client.csrf
        status, data, _ = self.setup_admin()
        self.assertTrue(data["authenticated"])
        self.assertEqual(data["user"]["username"], "admin")
        self.assertNotEqual(old_cookie, self.client.cookie)
        self.assertNotEqual(old_csrf, self.client.csrf)
        self.assertFalse(self.store.setup_path.exists())
        self.assertIsNone(self.store.setup_token())
        stale = Client(self.app)
        stale.cookie, stale.csrf = old_cookie, old_csrf
        self.assertEqual(stale.request("GET", "/api/jobs")[0], 401)
        status, data, _ = self.client.request("POST", "/api/setup", {})
        self.assertEqual(status, 409)
        self.assertEqual(data["code"], "already_configured")

    def test_password_and_session_tokens_are_hashed_at_rest(self):
        self.setup_admin()
        session_token = self.client.cookie.split("=", 1)[1]
        with self.store.connection() as con:
            user = dict(con.execute("SELECT * FROM users").fetchone())
            tokens = [row[0] for row in con.execute("SELECT token_hash FROM sessions")]
        self.assertNotIn(PASSWORD, json.dumps(user))
        self.assertGreaterEqual(user["iterations"], 600_000)
        self.assertNotEqual(user["password_hash"], PASSWORD)
        self.assertNotIn(session_token, tokens)
        self.assertEqual(self.store.path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(Path(self.directory.name).stat().st_mode & 0o777, 0o700)

    def test_logout_invalidates_old_session_and_login_rotates(self):
        self.setup_admin()
        old_cookie = self.client.cookie
        status, data, _ = self.client.request("POST", "/api/logout")
        self.assertEqual(status, 200)
        self.assertFalse(data["authenticated"])
        self.assertNotEqual(old_cookie, self.client.cookie)
        old_client = Client(self.app)
        old_client.cookie = old_cookie
        self.assertEqual(old_client.request("GET", "/api/jobs")[0], 401)
        status, data, _ = self.client.request("POST", "/api/login", {"username": "admin", "password": PASSWORD})
        self.assertEqual(status, 200)
        self.assertTrue(data["authenticated"])

    def test_login_is_throttled(self):
        self.setup_admin()
        self.client.request("POST", "/api/logout")
        for _ in range(5):
            status, _, _ = self.client.request("POST", "/api/login", {"username": "admin", "password": "wrong"})
            self.assertEqual(status, 401)
        status, data, headers = self.client.request("POST", "/api/login", {"username": "admin", "password": PASSWORD})
        self.assertEqual(status, 429)
        self.assertEqual(headers["Retry-After"], "300")
        self.assertEqual(data["code"], "login_rate_limited")

    def test_host_allowlist_blocks_dns_rebinding(self):
        for host in ["attacker.invalid:8787", "localhost:8787,evil.invalid", "http://localhost:8787", "user@localhost:8787", "0.0.0.0:8787"]:
            with self.subTest(host=host):
                status, _, _ = self.client.request("GET", "/api/session", headers={"HTTP_HOST": host})
                self.assertEqual(status, 400)
        self.assertEqual(self.client.request("GET", "/health", headers={"HTTP_HOST": "LOCALHOST:8787"})[0], 200)

    def test_cross_origin_is_denied_even_with_valid_csrf(self):
        for origin in ["http://attacker.invalid", "https://localhost:8787", "null", "http://localhost:8787/path"]:
            with self.subTest(origin=origin):
                status, _, _ = self.client.request("POST", "/api/setup", {}, headers={"HTTP_ORIGIN": origin})
                self.assertEqual(status, 403)
        self.assertEqual(self.client.request("GET", "/health", headers={"HTTP_ORIGIN": "http://localhost:8787"})[0], 200)
        self.assertEqual(self.client.request("GET", "/health", headers={"HTTP_SEC_FETCH_SITE": "cross-site"})[0], 403)

    def test_secure_cookie_proxy_setting_accepts_https_origin(self):
        secure_app = create_app(self.directory.name, manager=self.manager, secure_cookies=True)
        client = Client(secure_app)
        status, data, headers = client.request("GET", "/api/session", headers={"HTTP_ORIGIN": "https://localhost:8787"})
        self.assertEqual(status, 200)
        self.assertIn("Secure", headers["Set-Cookie"])
        self.assertEqual(client.request("GET", "/health", headers={"HTTP_ORIGIN": "http://localhost:8787"})[0], 403)

    def test_mutation_json_is_bounded_and_strict(self):
        for raw in [b"{", b"[]", b'{"value":NaN}', b'{"value":Infinity}', b"\xff"]:
            with self.subTest(raw=raw):
                status, data, _ = self.client.request("POST", "/api/setup", raw=raw)
                self.assertEqual(status, 400)
                self.assertEqual(data["code"], "invalid_json")
        self.assertEqual(self.client.request("POST", "/api/setup", raw=b"{}", content_length=MAX_BODY + 1)[0], 413)
        self.assertEqual(self.client.request("POST", "/api/setup", raw=b"{}", content_length=10)[0], 400)
        self.assertEqual(self.client.request("POST", "/api/setup", headers={"CONTENT_TYPE": "text/plain"})[0], 415)

    def test_authenticated_job_api_and_wrapped_response_contract(self):
        self.setup_admin()
        status, data, _ = self.client.request("POST", "/api/jobs", {"title": "Offline job", "query": "fixture"})
        self.assertEqual(status, 201)
        job = data["job"]
        self.assertEqual(self.client.request("GET", "/api/jobs")[1]["jobs"][0]["id"], job["id"])
        self.assertEqual(self.client.request("GET", f"/api/jobs/{job['id']}")[1]["job"]["id"], job["id"])
        status, data, _ = self.client.request("POST", f"/api/jobs/{job['id']}/actions", {"action": "pause"})
        self.assertEqual(status, 200)
        self.assertEqual(data["job"]["status"], "paused")
        self.store.append_event(job["id"], {"kind": "log", "message": "Offline fixture"})
        self.assertEqual(len(self.client.request("GET", f"/api/jobs/{job['id']}/events?after=0")[1]["events"]), 1)
        self.assertEqual(self.client.request("GET", f"/api/jobs/{job['id']}/results?limit=25&offset=2&q=192.0.2")[0], 200)
        self.assertEqual(self.manager.last_results, (job["id"], 2, 25, "192.0.2"))
        status, data, headers = self.client.request("GET", f"/api/jobs/{job['id']}/download?format=txt")
        self.assertEqual(status, 200)
        self.assertEqual(data, b"192.0.2.10\n")
        self.assertIn("attachment", headers["Content-Disposition"])
        status, data, _ = self.client.request("POST", "/api/checkpoints/import", {"checkpoint": {"fixture": True}})
        self.assertEqual(status, 201)
        self.assertEqual(data["job"]["title"], "Imported")

    def test_all_authenticated_mutations_still_need_csrf(self):
        self.setup_admin()
        job = self.job()
        for path in ["/api/jobs", "/api/logout", "/api/checkpoints/import", f"/api/jobs/{job['id']}/actions"]:
            with self.subTest(path=path):
                self.assertEqual(self.client.request("POST", path, {}, headers={"HTTP_X_CSRF_TOKEN": "bad"})[0], 403)

    def test_query_parameters_and_download_formats_are_validated(self):
        self.setup_admin()
        job_id = self.job()["id"]
        for suffix in ["results?limit=1001", "results?limit=0", "results?offset=-1", "results?limit=x", "results?limit=1&limit=2",
                       "events?after=-1", "download?format=exe", "results?" + "&".join("x=1" for _ in range(21))]:
            with self.subTest(suffix=suffix):
                self.assertEqual(self.client.request("GET", f"/api/jobs/{job_id}/{suffix}")[0], 400)

    def test_download_filename_cannot_inject_headers(self):
        self.setup_admin()
        job_id = self.job()["id"]
        with patch.object(self.manager, "download", return_value=(b"x", "text/plain", '../../a"\r\nHeader:evil.txt')):
            status, _, headers = self.client.request("GET", f"/api/jobs/{job_id}/download")
        self.assertEqual(status, 200)
        self.assertNotIn("\r", headers["Content-Disposition"])
        self.assertNotIn("\n", headers["Content-Disposition"])
        self.assertNotIn("../", headers["Content-Disposition"])

    def test_static_is_an_explicit_allowlist_and_headers_are_restrictive(self):
        static = Path(self.directory.name) / "static"
        static.mkdir()
        (static / "index.html").write_text("<!doctype html><title>fixture</title>", encoding="utf-8")
        (static / "app.js").write_text("'use strict';", encoding="utf-8")
        self.app.static_dir = static
        status, body, headers = self.client.request("GET", "/")
        self.assertEqual(status, 200)
        self.assertIn(b"fixture", body)
        self.assertIn("frame-ancestors 'none'", headers["Content-Security-Policy"])
        self.assertIn("script-src 'self'", headers["Content-Security-Policy"])
        self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertNotIn("Access-Control-Allow-Origin", headers)
        for path in ["/../studio.sqlite3", "/static/../store.py", "/store.py", "/data/setup-token.txt", "/api"]:
            self.assertEqual(self.client.request("GET", path)[0], 404)
        self.assertEqual(self.client.request("HEAD", "/")[1], b"")

    def test_health_does_not_expose_state_or_secrets(self):
        status, data, _ = self.client.request("GET", "/health")
        self.assertEqual(status, 200)
        self.assertEqual(set(data), {"ok", "version"})
        self.assertEqual(data, {"ok": True, "version": __version__})

    def test_missing_jobs_and_unsupported_methods(self):
        self.setup_admin()
        self.assertEqual(self.client.request("GET", "/api/jobs/absent")[0], 404)
        self.assertEqual(self.client.request("DELETE", "/api/jobs")[0], 405)
        self.assertEqual(self.client.request("POST", "/api/jobs/absent/results")[0], 405)

    def test_internal_errors_never_return_exception_arguments(self):
        self.setup_admin()
        with patch.object(self.manager, "list_jobs", side_effect=OSError("private-fixture-only")):
            with patch("sys.stderr", new_callable=io.StringIO) as stderr:
                status, data, _ = self.client.request("GET", "/api/jobs")
        self.assertEqual(status, 500)
        self.assertNotIn("private-fixture-only", json.dumps(data))
        self.assertNotIn("private-fixture-only", stderr.getvalue())
        self.assertNotIn("Traceback", stderr.getvalue())


class RealManagerIntegrationTests(unittest.TestCase):
    """Exercise the browser boundary with the actual isolated demo worker."""
    def setUp(self):
        from studio.jobs import JobManager
        self.directory = tempfile.TemporaryDirectory()
        self.manager = JobManager(self.directory.name, demo=True, autostart=False)
        self.app = create_app(self.directory.name, manager=self.manager, demo=True)
        self.client = Client(self.app)
        self.client.request("GET", "/api/session")
        status, _, _ = self.client.request("POST", "/api/setup", {
            "setup_token": self.manager.store.setup_token(), "username": "admin", "password": PASSWORD,
        })
        self.assertEqual(status, 201)

    def tearDown(self):
        self.app.close()
        self.directory.cleanup()

    def payload(self, **changes):
        return {"title": "Synthetic integration fixture", "query": 'http.component:"php" country:"EG"',
                "mode": "html", "settings": {"demo": True, "transport": "python", "delay": 0}, **changes}

    def test_typed_job_validation_rejects_commands_paths_and_unknown_settings(self):
        invalid = [
            {**self.payload(), "command": "touch /tmp/not-executed"},
            {**self.payload(), "output": "/tmp/not-written"},
            self.payload(settings={"endpoint": "file:///etc/passwd"}),
            self.payload(settings={"transport": "bash"}),
            self.payload(settings={"max_requests": 0}),
            self.payload(settings={"max_requests": True}),
            self.payload(settings={"split_facets": ["asn", "asn"]}),
            self.payload(query=""), self.payload(priority=100),
        ]
        for payload in invalid:
            with self.subTest(payload=payload):
                status, data, _ = self.client.request("POST", "/api/jobs", payload)
                self.assertEqual(status, 400, data)
        self.assertEqual(self.client.request("GET", "/api/jobs")[1]["jobs"], [])

    def test_bind_failure_never_starts_queued_work(self):
        job = self.manager.create_job(self.payload())
        with patch("studio.server.make_server", side_effect=OSError("fixture port is occupied")):
            with patch("studio.jobs.JobManager.start") as start:
                with patch("sys.stderr", new_callable=io.StringIO):
                    result = main(["--data-dir", self.directory.name, "--demo"])
        self.assertEqual(result, 1)
        start.assert_not_called()
        unchanged = self.manager.get_job(job["id"])
        self.assertEqual(unchanged["status"], "queued")
        self.assertEqual(unchanged["attempts"], 0)

    def test_api_key_stays_in_memory_while_pause_resume_changes_source(self):
        fixture_key = "STUDIO_FIXTURE_NOT_A_REAL_API_KEY_123"
        status, data, _ = self.client.request("POST", "/api/jobs", self.payload(mode="api", api_key=fixture_key))
        self.assertEqual(status, 201, data)
        job_id = data["job"]["id"]
        self.assertTrue(data["job"]["has_key"])
        self.assertNotIn(fixture_key, json.dumps(data))
        status, data, _ = self.client.request("POST", f"/api/jobs/{job_id}/actions", {"action": "pause"})
        self.assertEqual(data["job"]["status"], "paused")
        status, data, _ = self.client.request("POST", f"/api/jobs/{job_id}/actions", {"action": "resume", "mode": "html"})
        self.assertEqual(status, 200)
        self.assertEqual(data["job"]["mode"], "html")
        self.assertEqual(data["job"]["status"], "queued")
        status, _, _ = self.client.request("POST", f"/api/jobs/{job_id}/actions", {"action": "resume", "shell": "x"})
        self.assertEqual(status, 400)
        self.client.request("POST", f"/api/jobs/{job_id}/actions", {"action": "cancel"})
        self.assertFalse(self.manager.get_job(job_id)["has_key"])
        for path in Path(self.directory.name).rglob("*"):
            if path.is_file():
                self.assertNotIn(fixture_key.encode(), path.read_bytes(), str(path))

    def test_missing_api_key_waits_for_input_without_starting_worker(self):
        status, data, _ = self.client.request("POST", "/api/jobs", self.payload(mode="api", settings={"demo": False}))
        self.assertEqual(status, 201)
        self.assertEqual(data["job"]["status"], "waiting_input")
        job_id = data["job"]["id"]
        status, data, _ = self.client.request("POST", f"/api/jobs/{job_id}/actions", {"action": "resume"})
        self.assertEqual(status, 400)
        self.assertEqual(self.manager.get_job(job_id)["status"], "waiting_input")
        self.assertIsNone(self.manager._process)

    def test_html_demo_worker_end_to_end_download_and_checkpoint_import(self):
        status, data, _ = self.client.request("POST", "/api/jobs", self.payload())
        self.assertEqual(status, 201, data)
        job_id = data["job"]["id"]
        self.manager.start()
        deadline = time.monotonic() + 12
        while True:
            status, data, _ = self.client.request("GET", f"/api/jobs/{job_id}")
            job = data["job"]
            if job["status"] in {"completed", "completed_warnings", "failed", "waiting_input", "paused", "interrupted"}:
                break
            if time.monotonic() >= deadline:
                self.fail("Demo worker did not finish within 12 seconds: " + json.dumps(job))
            time.sleep(0.025)
        self.assertEqual(job["status"], "completed", job.get("error"))
        self.assertEqual(job["stats"]["unique_ips"], 292)
        self.assertEqual(job["stats"]["requests"], 9)
        self.assertEqual(job["stats"]["percent"], 100)
        self.assertEqual(job["stats"]["completed_branches"], 5)
        status, results, _ = self.client.request("GET", f"/api/jobs/{job_id}/results?limit=100")
        self.assertEqual(status, 200)
        self.assertEqual(results["all_total"], 292)
        self.assertEqual(len(results["items"]), 100)
        self.assertEqual(self.client.request("GET", f"/api/jobs/{job_id}/results?offset=290&limit=100")[1]["items"].__len__(), 2)
        status, data, _ = self.client.request("GET", f"/api/jobs/{job_id}/download?format=json")
        self.assertEqual(status, 200)
        self.assertEqual(len(data["ips"]), 292)
        self.assertTrue(data["demo"])
        self.assertFalse(data["complete_export_guaranteed"])
        status, plain, _ = self.client.request("GET", f"/api/jobs/{job_id}/download?format=txt")
        self.assertEqual(len(plain.splitlines()), 292)
        status, report, _ = self.client.request("GET", f"/api/jobs/{job_id}/download?format=report")
        self.assertEqual(status, 200)
        self.assertEqual(report["unique_ip_count"], 292)
        status, checkpoint, _ = self.client.request("GET", f"/api/jobs/{job_id}/download?format=checkpoint")
        self.assertEqual(status, 200)
        self.assertIn("state", checkpoint)
        status, imported, _ = self.client.request("POST", "/api/checkpoints/import", {
            "filename": "../../ignored-by-server.json", "checkpoint": checkpoint, "mode": "html",
        })
        self.assertEqual(status, 201, imported)
        self.assertEqual(imported["job"]["status"], "paused")
        self.assertEqual(imported["job"]["stats"]["unique_ips"], 292)
        # Imported checkpoints remain paused; this test never resumes a live source.
        status, events, _ = self.client.request("GET", f"/api/jobs/{job_id}/events?after=0&limit=1000")
        self.assertEqual(status, 200)
        self.assertTrue(any(event["kind"] == "progress" for event in events["events"]))
        self.assertTrue(any(event["kind"] == "final" for event in events["events"]))


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.store = Store(self.directory.name)

    def tearDown(self):
        self.directory.cleanup()

    def test_claim_is_atomic_and_uses_priority(self):
        low = self.store.create_job({"title": "Low", "priority": 1})
        high = self.store.create_job({"title": "High", "priority": 9})
        self.assertEqual(self.store.claim_next()["id"], high["id"])
        with ThreadPoolExecutor(max_workers=6) as pool:
            claims = list(pool.map(lambda _: self.store.claim_next(), range(6)))
        actual = [job for job in claims if job is not None]
        self.assertEqual(len(actual), 1)
        self.assertEqual(actual[0]["id"], low["id"])
        self.assertEqual(actual[0]["attempts"], 1)

    def test_recovery_only_marks_in_flight_jobs_interrupted(self):
        jobs = {status: self.store.create_job({"status": status}) for status in
                ["running", "pause_requested", "cancel_requested", "queued", "completed", "paused"]}
        self.assertEqual(self.store.recover_interrupted(), 3)
        for status, job in jobs.items():
            self.assertEqual(self.store.get_job(job["id"])["status"],
                             "interrupted" if status in {"running", "pause_requested", "cancel_requested"} else status)

    def test_events_paginate_with_monotonic_ids(self):
        job_id = self.store.create_job({})["id"]
        for index in range(5):
            self.store.append_event(job_id, {"kind": "log", "message": f"Item {index}"})
        first = self.store.events(job_id, limit=3)
        self.assertTrue(first["has_more"])
        self.assertEqual(len(first["events"]), 3)
        second = self.store.events(job_id, after=first["last_id"], limit=3)
        self.assertFalse(second["has_more"])
        self.assertEqual(len(second["events"]), 2)
        self.assertGreater(second["events"][0]["id"], first["last_id"])
        self.store.delete_job(job_id)
        self.assertEqual(self.store.events(job_id)["events"], [])

    def test_secret_fields_cannot_be_persisted(self):
        for key in ["api_key", "API_KEY", "api_key_resolved", "password", "authorization", "cookie", "setup_token"]:
            with self.subTest(key=key):
                with self.assertRaises(ValueError):
                    self.store.create_job({"settings": {key: "fixture-secret"}})
        self.store.create_job({"settings": {"api_key": None}})
        job_id = self.store.create_job({})["id"]
        with self.assertRaises(ValueError):
            self.store.append_event(job_id, {"detail": {"api_key": "fixture-secret"}})
        with self.assertRaises(ValueError):
            self.store.set_setting("api_key", "fixture-secret")
        self.assertEqual(self.store.events(job_id)["events"], [])

    def test_settings_round_trip_and_jobs_survive_reopen(self):
        job = self.store.create_job({"query": "fixture", "stats": {"ips": 15}})
        self.store.set_setting("ui", {"theme": "dark"})
        reopened = Store(self.directory.name)
        self.assertEqual(reopened.get_job(job["id"])["stats"]["ips"], 15)
        self.assertEqual(reopened.get_setting("ui"), {"theme": "dark"})
        self.assertEqual(reopened.get_setting("unknown", 42), 42)
        with reopened.connection() as con:
            self.assertEqual(con.execute("PRAGMA journal_mode").fetchone()[0], "wal")

    def test_sessions_expire(self):
        session = self.store.create_session()
        self.assertIsNotNone(self.store.get_session(session["token"]))
        with self.store.connection() as con:
            con.execute("UPDATE sessions SET expires=0")
        self.assertIsNone(self.store.get_session(session["token"]))

    def test_database_paths_cannot_be_symlinks(self):
        other = Path(self.directory.name) / "alternate"
        other.mkdir()
        (other / "studio.sqlite3").symlink_to(self.store.path)
        with self.assertRaises(ValueError):
            Store(other)

    def test_host_configuration_rejects_wildcards_and_urls(self):
        for host in ["*", "*.example.com", "http://localhost:8787", "0.0.0.0:8787", "localhost:99999", "localhost/path", "user@localhost"]:
            with self.subTest(host=host):
                with self.assertRaises(ValueError):
                    normalize_host(host)
        self.assertEqual(normalize_host("192.168.1.25:8787"), "192.168.1.25:8787")
        self.assertEqual(normalize_host("[::1]:8787"), "[::1]:8787")


if __name__ == "__main__":
    unittest.main()
