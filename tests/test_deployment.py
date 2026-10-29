"""Deployment checks that never install a service or contact Shodan."""
import ast
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


class DeploymentTests(unittest.TestCase):
    def command(self, *args, env=None):
        return subprocess.run(args, cwd=ROOT, env=env, text=True,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              timeout=15)

    def test_bash_syntax(self):
        for name in ("start.sh", "install-debian.sh", "tools/install_vpn_helper.sh"):
            with self.subTest(script=name):
                result = self.command("bash", "-n", str(ROOT / name))
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_application_syntax_accepts_python_311_grammar(self):
        for path in (ROOT / "studio").rglob("*.py"):
            with self.subTest(module=path.name):
                ast.parse(path.read_text(encoding="utf-8"), filename=str(path),
                          feature_version=(3, 11))

    def test_installer_help_is_read_only(self):
        result = self.command("bash", str(ROOT / "install-debian.sh"), "--help")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("--check", result.stdout)
        self.assertIn("preserved", result.stdout)

    def test_installer_rejects_unrecognized_option(self):
        result = self.command("bash", str(ROOT / "install-debian.sh"), "--not-an-option")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Unknown option", result.stderr)

    def test_installer_rejects_shell_text_in_host(self):
        result = self.command("bash", str(ROOT / "install-debian.sh"), "--check",
                              "--host", "127.0.0.1;true")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("check failed", result.stderr)

    def test_installer_refuses_public_bind_without_explicit_hosts(self):
        result = self.command("bash", str(ROOT / "install-debian.sh"), "--check",
                              "--host", "0.0.0.0")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("--allowed-hosts", result.stderr)

    def test_installer_rejects_wildcard_allowlist(self):
        result = self.command("bash", str(ROOT / "install-debian.sh"), "--check",
                              "--allowed-hosts", "*:8787")
        self.assertNotEqual(result.returncode, 0)

    def test_installer_checks_complete_bundle_without_writes(self):
        result = self.command("bash", str(ROOT / "install-debian.sh"), "--check",
                              "--host", "0.0.0.0", "--allowed-hosts", "192.0.2.10:8787")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Check only", result.stdout)

    def test_start_preserves_argument_boundaries_and_changes_cwd(self):
        with tempfile.TemporaryDirectory() as temporary:
            temp = Path(temporary)
            recorder = temp / "python-recorder"
            logfile = temp / "args.jsonl"
            real_python = shutil.which("python3")
            recorder.write_text(
                f"#!{real_python}\n"
                "import json, os, sys\n"
                "with open(os.environ['STUDIO_TEST_RECORD'], 'a') as f:\n"
                "    f.write(json.dumps({'argv': sys.argv[1:], 'cwd': os.getcwd()}) + '\\n')\n",
                encoding="utf-8",
            )
            recorder.chmod(0o700)
            env = dict(os.environ, SHODAN_STUDIO_PYTHON=str(recorder),
                       STUDIO_TEST_RECORD=str(logfile))
            arguments = ["--data-dir", "folder with spaces", "--allowed-hosts", "localhost:8787"]
            result = subprocess.run(["bash", str(ROOT / "start.sh"), *arguments],
                                    cwd=temp, env=env, text=True, capture_output=True, timeout=15)
            self.assertEqual(result.returncode, 0, result.stderr)
            records = [json.loads(line) for line in logfile.read_text().splitlines()]
            self.assertEqual(records[-1]["argv"], ["-m", "studio.server", *arguments])
            self.assertEqual(records[-1]["cwd"], str(ROOT))

    def test_service_runs_unprivileged_and_keeps_state_separate(self):
        unit = (ROOT / "deploy/shodan-studio.service").read_text()
        self.assertIn("User=shodan-studio\n", unit)
        self.assertIn("ProtectSystem=strict\n", unit)
        self.assertIn("StateDirectory=shodan-studio\n", unit)
        self.assertIn("--data-dir /var/lib/shodan-studio", unit)
        self.assertIn("WorkingDirectory=/opt/shodan-studio/current\n", unit)
        self.assertNotIn("api-key", unit)

    @unittest.skipUnless(shutil.which("systemd-tmpfiles"), "requires systemd-tmpfiles")
    def test_vpn_runtime_directories_recover_after_reboot_without_deleting_state(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = root / "etc/tmpfiles.d/shodan-studio-vpn.conf"
            config.parent.mkdir(parents=True)
            # Exercise creation/recreation without requiring root in CI.
            rules = (ROOT / "deploy/shodan-studio-vpn.conf").read_text()
            config.write_text(rules.replace("root root", f"{os.geteuid()} {os.getegid()}"))
            command = ["systemd-tmpfiles", "--root", str(root), "--create", "shodan-studio-vpn.conf"]
            for boot in range(2):
                result = self.command(*command)
                self.assertEqual(result.returncode, 0, result.stderr)
                for name in ("netns", "amneziawg"):
                    directory = root / "run" / name
                    self.assertTrue(directory.is_dir())
                    self.assertEqual(directory.stat().st_mode & 0o777, 0o755)
                    sentinel = directory / "existing-resource"
                    sentinel.write_text("preserve")
                result = self.command(*command)
                self.assertEqual(result.returncode, 0, result.stderr)
                for name in ("netns", "amneziawg"):
                    sentinel = root / "run" / name / "existing-resource"
                    self.assertEqual(sentinel.read_text(), "preserve")
                if boot == 0:
                    shutil.rmtree(root / "run")  # Reboot clears this fixture's volatile state.


if __name__ == "__main__":
    unittest.main()
