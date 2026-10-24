#!/usr/bin/env bash
# Shodan Studio: run from any working directory. No virtualenv or pip required.
set -euo pipefail
umask 077

STUDIO_ROOT="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
STUDIO_PYTHON="${SHODAN_STUDIO_PYTHON:-python3}"
if ! command -v -- "$STUDIO_PYTHON" >/dev/null 2>&1; then
  printf 'Python 3.10 or newer is required. On Debian 12: sudo apt install python3\n' >&2
  exit 1
fi
"$STUDIO_PYTHON" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else "Python 3.10 or newer is required")'
cd -- "$STUDIO_ROOT"
export PYTHONDONTWRITEBYTECODE=1
export PYTHONUNBUFFERED=1
exec "$STUDIO_PYTHON" -m studio.server "$@"
