#!/usr/bin/env bash
# Optional headed browser dependency/account setup. Does not connect a VPN.
set -euo pipefail
if [[ "${1:-}" == --check ]]; then
  python3 -c "import ast,pathlib; [ast.parse(pathlib.Path(p).read_text()) for p in ('studio/browser_session.py','studio/browser_broker.py')]"
  echo 'Browser source syntax checked; no changes made.'
  exit 0
fi
[[ "$EUID" == 0 ]] || { echo 'Run as root.' >&2; exit 1; }
command -v chromium >/dev/null || { echo 'Install chromium xvfb xauth with apt first.' >&2; exit 1; }
command -v Xvfb >/dev/null
command -v xauth >/dev/null
if ! getent passwd shodan-browser >/dev/null; then
 useradd --system --user-group --no-create-home --home-dir /var/lib/shodan-studio-browser --shell /usr/sbin/nologin shodan-browser
fi
[[ "$(id -u shodan-browser)" != 0 && "$(id -u shodan-browser)" != "$(id -u shodan-studio)" ]]
[[ ! -L /var/lib/shodan-studio-browser ]]
install -d -o root -g shodan-browser -m 0710 /var/lib/shodan-studio-browser
echo 'Private browser account provisioned. No browser started.'
