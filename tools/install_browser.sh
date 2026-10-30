#!/usr/bin/env bash
# Optional headed browser dependency/account setup. Does not connect a VPN.
set -euo pipefail
STUDIO_BROWSER_SOURCE="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "$STUDIO_BROWSER_SOURCE"
[[ $# == 0 || $# == 1 && ( "$1" == --check || "$1" == --patchright ) ]] || { echo 'Usage: tools/install_browser.sh [--check|--patchright]' >&2; exit 2; }
if [[ "${1:-}" == --check ]]; then
  python3 -c "import ast,pathlib; [ast.parse(pathlib.Path('studio',p+'.py').read_text()) for p in ('browser_session','browser_broker','patchright_session','browser_recovery')]"
  echo 'Browser source syntax checked; no changes made.'
  exit 0
fi
[[ "$EUID" == 0 ]] || { echo 'Run as root.' >&2; exit 1; }
if [[ "${1:-}" != --patchright ]]; then
 command -v chromium >/dev/null || { echo 'Install chromium xvfb xauth with apt first.' >&2; exit 1; }
fi
command -v Xvfb >/dev/null
command -v xauth >/dev/null
if ! getent passwd shodan-browser >/dev/null; then
 useradd --system --user-group --no-create-home --home-dir /var/lib/shodan-studio-browser --shell /usr/sbin/nologin shodan-browser
fi
[[ "$(id -u shodan-browser)" != 0 && "$(id -u shodan-browser)" != "$(id -u shodan-studio)" ]]
[[ ! -L /var/lib/shodan-studio-browser ]]
[[ ! -L /var/lib/shodan-studio-enrichment-browser ]]
install -d -o root -g shodan-browser -m 0710 /var/lib/shodan-studio-browser /var/lib/shodan-studio-enrichment-browser
if [[ "${1:-}" == --patchright ]]; then
 STUDIO_BROWSER_RUNTIME=/opt/shodan-studio/browser-runtime
 [[ ! -L "$STUDIO_BROWSER_RUNTIME" ]]
 install -d -o root -g root -m 0755 "$STUDIO_BROWSER_RUNTIME"
 python3 -m venv "$STUDIO_BROWSER_RUNTIME/venv"
 "$STUDIO_BROWSER_RUNTIME/venv/bin/python3" -m pip install --disable-pip-version-check -r deploy/browser-requirements.txt
 PLAYWRIGHT_BROWSERS_PATH="$STUDIO_BROWSER_RUNTIME/browsers" "$STUDIO_BROWSER_RUNTIME/venv/bin/python3" -m patchright install chromium
 chown -R root:root "$STUDIO_BROWSER_RUNTIME"
 chmod -R go-w "$STUDIO_BROWSER_RUNTIME"
 echo 'Pinned Patchright runtime installed; select SHODAN_STUDIO_BROWSER_BACKEND=patchright in /etc/default/shodan-studio-browser.'
fi
echo 'Private browser account provisioned. No browser started.'
