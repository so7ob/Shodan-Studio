#!/usr/bin/env bash
# Install the fixed helper unit; never connect or alter the host network.
set -euo pipefail
STUDIO_VPN_SOURCE="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
STUDIO_VPN_CHECK=0
STUDIO_VPN_START=1
for STUDIO_VPN_ARG in "$@"; do
  case "$STUDIO_VPN_ARG" in
    --check) STUDIO_VPN_CHECK=1;;
    --no-start) STUDIO_VPN_START=0;;
    *) echo 'Usage: tools/install_vpn_helper.sh [--check] [--no-start]' >&2; exit 2;;
  esac
done
python3 - "$STUDIO_VPN_SOURCE" <<'PY'
import ast,pathlib,sys
root=pathlib.Path(sys.argv[1])
for name in ('vpn_helper','vpn_client','vpn_probe','vpn_config','vpn','vpn_schema'):
    ast.parse((root/'studio'/f'{name}.py').read_text(), feature_version=(3,11))
assert (root/'deploy/shodan-studio-vpn.service').is_file()
print('Helper source/unit syntax present. No network changes performed.')
PY
if [[ "$STUDIO_VPN_CHECK" == 1 ]]; then exit 0; fi
[[ "$EUID" == 0 ]] || { echo 'Run as root.' >&2; exit 1; }
[[ -f /opt/shodan-studio/current/studio/vpn_helper.py ]] || { echo 'Install the matching application release first.' >&2; exit 1; }
getent passwd shodan-studio >/dev/null
for STUDIO_VPN_PATH in /etc/shodan-studio /etc/shodan-studio/vpn /etc/netns /run/netns /run/amneziawg; do
  [[ ! -L "$STUDIO_VPN_PATH" ]] || { echo 'Refusing a symlinked helper path.' >&2; exit 1; }
done
install -d -o root -g root -m 0755 /etc/shodan-studio /etc/netns /run/netns /run/amneziawg
install -d -o root -g root -m 0700 /etc/shodan-studio/vpn /etc/shodan-studio/vpn/profiles
install -m 0644 "$STUDIO_VPN_SOURCE/deploy/shodan-studio-vpn.service" /etc/systemd/system/shodan-studio-vpn.service
systemctl daemon-reload
if [[ "$STUDIO_VPN_START" == 1 ]]; then systemctl enable --now shodan-studio-vpn.service; fi
printf 'VPN helper installed; no VPN profile was connected.\n'
