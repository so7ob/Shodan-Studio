#!/usr/bin/env python3
"""Offline Debian 12/systemd acceptance in a disposable, separately named service.

Run as root: python3 tools/verify_ip_progress_service.py [--browser]
No production service/config/state is changed. All jobs use DemoData.
"""
import argparse
import http.cookiejar
import ipaddress
import json
import os
from pathlib import Path
import shutil
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from studio import __version__
from studio.jobs import JobManager


def systemctl(*args):
    return subprocess.check_output(["systemctl", *args], text=True).strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--browser", action="store_true")
    args = parser.parse_args()
    assert os.geteuid() == 0, "requires root for a disposable systemd unit"
    assert 'VERSION_ID="12"' in Path("/etc/os-release").read_text()
    assert Path("/run/systemd/system").is_dir()
    production_before = systemctl("show", "shodan-studio.service", "-p", "MainPID", "-p", "ActiveEnterTimestampMonotonic")
    sandbox = Path(tempfile.mkdtemp(prefix="shodan-ip-acceptance-", dir="/run"))
    sandbox.chmod(0o755)
    name = sandbox.name
    unit = Path("/run/systemd/system") / (name + ".service")
    state = Path("/var/lib") / name
    assert not state.exists() and not unit.exists()
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    base = f"http://127.0.0.1:{port}"
    code = sandbox / "code"
    code.mkdir(mode=0o755)
    shutil.copytree(ROOT / "studio", code / "studio", ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    manager = JobManager(state, demo=True, autostart=False)
    fixture = manager.create_job({"title": "IP acceptance 512/782 — synthetic", "query": "synthetic",
        "settings": {"demo": True, "transport": "python", "delay": 0}})
    manager.store.record_ip_progress(fixture["id"],
        [str(ipaddress.ip_address(0xc0000200 + i)) for i in range(512)],
        {"planning_complete": True, "traversal_completed": False, "denominator_reason": "terminal_record_scopes",
         "branches": [{"completed": True, "expected_records": 100}] * 16 +
                     [{"completed": False, "expected_records": 4}] * 60 +
                     [{"completed": False, "expected_records": 30}]}, status="paused",
        stats={"unique_ips": 0, "plan_known": True, "ready_branches": 77,
               "completed_branches": 16, "remaining_branches": 61, "percent": 20.8, "requests": 0})
    manager.shutdown()
    template = (ROOT / "deploy/shodan-studio.service").read_text()
    template = template.replace("User=shodan-studio", "User=nobody").replace("Group=shodan-studio", "Group=nogroup")
    template = template.replace("/opt/shodan-studio/current", str(code)).replace("/var/lib/shodan-studio", str(state))
    template = template.replace("StateDirectory=shodan-studio", f"StateDirectory={name}")
    template = "\n".join(line for line in template.splitlines() if not line.startswith(("EnvironmentFile=", "ExecStart=")))
    template = template.replace("[Service]", f"[Service]\nExecStart=/usr/bin/python3 -m studio.server --host 127.0.0.1 --port {port} --allowed-hosts 127.0.0.1:{port} --data-dir {state} --demo\nIPAddressDeny=any\nIPAddressAllow=localhost")
    unit.write_text(template + "\n")
    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar), urllib.request.ProxyHandler({}))
    csrf = ""
    def request(path, payload=None):
        nonlocal csrf
        req = urllib.request.Request(base + path, data=json.dumps(payload).encode() if payload is not None else None,
            headers={"Content-Type": "application/json", "X-CSRF-Token": csrf})
        with opener.open(req, timeout=5) as response:
            raw = response.read()
            value = json.loads(raw) if "application/json" in response.headers.get("Content-Type", "") else raw
            if isinstance(value, dict) and value.get("csrf_token"):
                csrf = value["csrf_token"]
            return value
    def ready():
        for _ in range(100):
            try:
                if request("/health") == {"ok": True, "version": __version__}:
                    return
            except OSError:
                pass
            time.sleep(.1)
        raise AssertionError("test service failed readiness")
    def wait_job(job_id):
        for _ in range(200):
            value = request("/api/jobs/" + job_id)["job"]
            if value["status"] not in {"queued", "running", "pause_requested"}:
                return value
            time.sleep(.05)
        raise AssertionError("test worker timed out")
    try:
        systemctl("daemon-reload")
        systemctl("start", unit.name)
        ready()
        request("/api/session")
        request("/api/setup", {"setup_token": (state / "setup-token.txt").read_text().strip(),
                               "username": "acceptance", "password": "local-fixture-password-123!"})
        for path in ("/", "/static/app.js", "/static/ip_progress.js", "/static/ip_progress.css"):
            assert request(path)
        p = request("/api/jobs/" + fixture["id"])["job"]["ip_progress"]
        assert (p["extracted_unique_ips"], p["estimated_total_ips"], p["progress_percent"]) == (512, 782, 65)
        demo = request("/api/jobs", {"title": "Offline service worker", "query": 'fixture country:"EG"',
            "mode": "api", "settings": {"demo": True, "transport": "python", "delay": 0, "max_requests": 5}})["job"]
        partial = wait_job(demo["id"])
        assert partial["status"] == "waiting_input" and partial["ip_progress"]["extracted_unique_ips"] == 98
        pid_before = systemctl("show", unit.name, "-p", "MainPID", "--value")
        systemctl("restart", unit.name)
        ready()
        assert pid_before != systemctl("show", unit.name, "-p", "MainPID", "--value")
        assert request("/api/jobs/" + demo["id"])["job"]["ip_progress"] == partial["ip_progress"]
        request("/api/jobs/" + demo["id"] + "/actions", {"action": "resume"})
        complete = wait_job(demo["id"])
        assert complete["status"] == "completed"
        assert complete["ip_progress"]["progress_percent"] == 100
        assert complete["stats"]["unique_ips"] == 292 and complete["stats"]["requests"] == 9
        systemctl("restart", unit.name)
        ready()
        assert request("/api/jobs/" + demo["id"])["job"]["ip_progress"] == complete["ip_progress"]
        with sqlite3.connect(state / "studio.sqlite3") as con:
            assert con.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
            assert con.execute("SELECT COUNT(*) FROM job_ips WHERE job_id=?", (demo["id"],)).fetchone()[0] == 292
        print(json.dumps({"os": "Debian 12", "python": sys.version.split()[0], "unit": unit.name,
            "service": systemctl("is-active", unit.name), "health": request("/health"), "restart_checks": 2,
            "fixture": p, "partial_ips": 98, "final_ips": 292, "demo_requests": 9,
            "integrity_check": "ok", "shodan_network_requests": 0}, ensure_ascii=False), flush=True)
        if args.browser:
            subprocess.run(["node", str(ROOT / "tests/browser_ip_progress.cjs"), base, fixture["id"]], check=True)
        assert production_before == systemctl("show", "shodan-studio.service", "-p", "MainPID", "-p", "ActiveEnterTimestampMonotonic")
        print("PASS: original service PID/start timestamp unchanged; isolated service verified.", flush=True)
    finally:
        subprocess.run(["systemctl", "stop", unit.name], check=False, capture_output=True)
        unit.unlink(missing_ok=True)
        systemctl("daemon-reload")
        shutil.rmtree(state)
        shutil.rmtree(sandbox)


if __name__ == "__main__":
    main()
