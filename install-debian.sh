#!/usr/bin/env bash
# Install/upgrade the application code without replacing the persistent data.
set -euo pipefail
umask 022

STUDIO_SOURCE="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
STUDIO_BIND=127.0.0.1
STUDIO_PORT=8787
STUDIO_HOSTS=''
STUDIO_OPTIONS=''
STUDIO_RECONFIGURE=0
STUDIO_START=1
STUDIO_CHECK=0

usage() {
  cat <<'USAGE'
Usage: sudo bash install-debian.sh [options]

Debian 12 installer for a single-user Shodan Studio service.
Application: /opt/shodan-studio/current (versioned code releases)
State:       /var/lib/shodan-studio (preserved on upgrades)
Config:      /etc/default/shodan-studio

  --host IP              Bind address (default: 127.0.0.1)
  --port N               TCP port, 1024..65535 (default: 8787)
  --allowed-hosts LIST   Comma-separated exact browser host:port values
  --secure-cookies       Require HTTPS for browser session cookies
  --demo                 Enable synthetic offline demo jobs
  --no-start             Install without enabling/restarting the service
  --check                Validate bundle/config without changing the system
  -h, --help             Show this help

On an upgrade, omitting all connection options preserves existing config.
Supplying any connection option creates a full new config using defaults
for omitted options. Include all settings you intend to keep.

LAN example:
  sudo bash install-debian.sh --host 0.0.0.0 --allowed-hosts 192.168.1.50:8787

No firewall rules, OS packages, or public hosting are changed by this script.
USAGE
}

fail() { printf 'Error: %s\n' "$*" >&2; exit 1; }
need_value() { [[ $# -ge 2 && -n "$2" ]] || fail "Missing value for $1"; }
while [[ $# -gt 0 ]]; do
  case "$1" in
    --host) need_value "$@"; STUDIO_BIND=$2; STUDIO_RECONFIGURE=1; shift 2 ;;
    --port) need_value "$@"; STUDIO_PORT=$2; STUDIO_RECONFIGURE=1; shift 2 ;;
    --allowed-hosts) need_value "$@"; STUDIO_HOSTS=$2; STUDIO_RECONFIGURE=1; shift 2 ;;
    --secure-cookies) STUDIO_OPTIONS="$STUDIO_OPTIONS --secure-cookies"; STUDIO_RECONFIGURE=1; shift ;;
    --demo) STUDIO_OPTIONS="$STUDIO_OPTIONS --demo"; STUDIO_RECONFIGURE=1; shift ;;
    --no-start) STUDIO_START=0; shift ;;
    --check) STUDIO_CHECK=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) fail "Unknown option: $1" ;;
  esac
done

command -v python3 >/dev/null 2>&1 || fail 'Install Python first: sudo apt install python3'
if [[ -z "$STUDIO_HOSTS" && "$STUDIO_BIND" == 127.0.0.1 ]]; then
  STUDIO_HOSTS="127.0.0.1:$STUDIO_PORT,localhost:$STUDIO_PORT"
fi

# These values become literal EnvironmentFile fields, never shell commands.
python3 - "$STUDIO_BIND" "$STUDIO_PORT" "$STUDIO_HOSTS" "$STUDIO_SOURCE" <<'PY'
import ast
import ipaddress
import pathlib
import re
import sys

if sys.version_info < (3, 10):
    sys.exit("Python 3.10 or newer is required")
bind, raw_port, hosts, source = sys.argv[1:]
try:
    address = ipaddress.ip_address(bind)
    if address.version != 4:
        raise ValueError("this installer currently binds IPv4 only")
    if not raw_port.isascii() or not raw_port.isdecimal():
        raise ValueError("port must be an integer")
    port = int(raw_port)
    if not 1024 <= port <= 65535:
        raise ValueError("port must be between 1024 and 65535")
    if not hosts or len(hosts) > 2048:
        raise ValueError("supply --allowed-hosts with the address used in the browser")
    for host in hosts.split(","):
        if not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?:[0-9]{1,5}", host):
            raise ValueError("allowed hosts must be comma-separated exact host:port values")
        name, host_port = host.rsplit(":", 1)
        if not 1 <= int(host_port) <= 65535 or ".." in name or name == "0.0.0.0":
            raise ValueError("invalid browser host or port")
    root = pathlib.Path(source)
    required = ["studio/server.py", "studio/jobs.py", "studio/worker.py", "studio/engine.py", "studio/ip_progress.py",
                "studio/static/index.html", "studio/static/app.js", "studio/static/app.css",
                "studio/static/ip_progress.js", "studio/static/ip_progress.css",
                "studio/vpn.py", "studio/vpn_helper.py", "studio/vpn_schema.py",
                "studio/static/vpn.js", "studio/static/vpn.css",
                "deploy/shodan-studio.service", "start.sh"]
    for relative in required:
        item = root / relative
        if not item.is_file() or item.is_symlink():
            raise ValueError(f"missing or symlinked application file: {relative}")
    for item in (root / "studio").rglob("*"):
        if item.is_symlink():
            raise ValueError("source tree must not contain symlinks")
        if item.suffix == ".py":
            ast.parse(item.read_text(encoding="utf-8"), filename=str(item))
except (ValueError, SyntaxError, OSError) as exc:
    sys.exit(f"Configuration/bundle check failed: {exc}")
print(f"Bundle valid. Bind {bind}:{port}; allowed browser hosts: {hosts}")
PY

if [[ "$STUDIO_CHECK" == 1 ]]; then
  printf 'Check only: no files, accounts, services, or network settings changed.\n'
  exit 0
fi

[[ "$EUID" -eq 0 ]] || fail 'Run the installer with sudo; use start.sh for a user-owned launch.'
[[ -d /run/systemd/system ]] || fail 'systemd must be running. Use start.sh for a manual launch.'
python3 - <<'PY'
import pathlib
import shlex
import sys
values = {}
for line in pathlib.Path("/etc/os-release").read_text().splitlines():
    if "=" in line and not line.startswith("#"):
        key, value = line.split("=", 1)
        parsed = shlex.split(value)
        values[key] = parsed[0] if parsed else ""
if values.get("ID") != "debian" or values.get("VERSION_ID") != "12":
    sys.exit("This service installer targets Debian 12. Use start.sh on other systems.")
PY
for STUDIO_TARGET in /opt/shodan-studio /opt/shodan-studio/releases /var/lib/shodan-studio /etc/default/shodan-studio; do
  [[ ! -L "$STUDIO_TARGET" ]] || fail "Refusing symlinked installation/state/config path: $STUDIO_TARGET"
done

if id shodan-studio >/dev/null 2>&1; then
  [[ "$(id -u shodan-studio)" != 0 ]] || fail 'The shodan-studio account must not be root.'
else
  useradd --system --user-group --home-dir /var/lib/shodan-studio --shell /usr/sbin/nologin shodan-studio
fi
getent group shodan-studio >/dev/null || fail 'The shodan-studio group is missing.'
install -d -m 0755 /opt/shodan-studio /opt/shodan-studio/releases
install -d -m 0700 -o shodan-studio -g shodan-studio /var/lib/shodan-studio
STUDIO_RELEASE="$(mktemp -d /opt/shodan-studio/releases/release-XXXXXXXX)"
chmod 0755 "$STUDIO_RELEASE"

python3 - "$STUDIO_SOURCE" "$STUDIO_RELEASE" <<'PY'
import pathlib
import shutil
import sys
source, target = map(pathlib.Path, sys.argv[1:])
ignore = shutil.ignore_patterns("__pycache__", "*.pyc", ".DS_Store")
for name in ("studio", "deploy", "tests", "tools", "docs"):
    if (source / name).is_dir():
        shutil.copytree(source / name, target / name, ignore=ignore)
for name in ("start.sh", "install-debian.sh", "README.md", "README_AR.md", "ARCHITECTURE.md", "DESIGN.md", "VALIDATION.md", "SHA256SUMS"):
    if (source / name).is_file():
        shutil.copy2(source / name, target / name)
for item in target.rglob("*"):
    item.chmod(0o755 if item.is_dir() or item.suffix == ".sh" else 0o644)
PY

if [[ ! -e /etc/default/shodan-studio || "$STUDIO_RECONFIGURE" == 1 ]]; then
  STUDIO_CONFIG_TEMP="$(mktemp /etc/default/.shodan-studio.XXXXXXXX)"
  {
    printf '# Shodan Studio service settings. No API credentials belong here.\n'
    printf 'SHODAN_STUDIO_HOST=%s\n' "$STUDIO_BIND"
    printf 'SHODAN_STUDIO_PORT=%s\n' "$STUDIO_PORT"
    printf 'SHODAN_STUDIO_ALLOWED_HOSTS=%s\n' "$STUDIO_HOSTS"
    printf 'SHODAN_STUDIO_OPTIONS="%s"\n' "${STUDIO_OPTIONS# }"
  } > "$STUDIO_CONFIG_TEMP"
  chmod 0644 "$STUDIO_CONFIG_TEMP"
  if [[ -f /etc/default/shodan-studio ]]; then
    cp -p -- /etc/default/shodan-studio /etc/default/shodan-studio.previous
  fi
  mv -f -- "$STUDIO_CONFIG_TEMP" /etc/default/shodan-studio
else
  printf 'Keeping existing /etc/default/shodan-studio configuration.\n'
fi

# Each release is separate; persistent job data is never copied or deleted here.
if [[ -L /opt/shodan-studio/current ]]; then
  STUDIO_OLD_RELEASE="$(readlink -- /opt/shodan-studio/current)"
  ln -sfn -- "$STUDIO_OLD_RELEASE" /opt/shodan-studio/previous
elif [[ -e /opt/shodan-studio/current ]]; then
  fail '/opt/shodan-studio/current exists but is not a symlink; inspect it before installing.'
fi
STUDIO_LINK_DIR="$(mktemp -d /opt/shodan-studio/.switch-XXXXXXXX)"
ln -s -- "$STUDIO_RELEASE" "$STUDIO_LINK_DIR/current"
mv -Tf -- "$STUDIO_LINK_DIR/current" /opt/shodan-studio/current
rmdir -- "$STUDIO_LINK_DIR"
install -m 0644 "$STUDIO_SOURCE/deploy/shodan-studio.service" /etc/systemd/system/shodan-studio.service
systemctl daemon-reload
if [[ "$STUDIO_START" == 1 ]]; then
  systemctl enable shodan-studio.service
  systemctl restart shodan-studio.service
fi

printf '\nInstalled: %s\n' "$STUDIO_RELEASE"
printf 'State preserved in: /var/lib/shodan-studio\n'
printf 'Status: sudo systemctl status shodan-studio --no-pager\n'
printf 'Logs:   sudo journalctl -u shodan-studio -n 50 --no-pager\n'
printf 'First setup token (after starting): sudo cat /var/lib/shodan-studio/setup-token.txt\n'
if [[ "$STUDIO_START" == 0 ]]; then
  printf 'Service was not started or enabled. Start with: sudo systemctl enable --now shodan-studio\n'
fi
