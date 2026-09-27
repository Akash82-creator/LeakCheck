#!/usr/bin/env bash
# Starts LeakCheck and opens it in your browser (used by the Mac and Linux
# launchers). The first run sets up a private Python environment in .venv;
# that one step downloads dependencies. After that, nothing is downloaded.
set -euo pipefail
trap 'echo; echo "Something went wrong (see above)."; read -r -p "Press Enter to close." _ || true' ERR
cd "$(dirname "$0")/.."

PY=""
for c in python3.13 python3.12 python3.11 python3; do
  if command -v "$c" >/dev/null 2>&1 &&
     "$c" -c 'import sys; sys.exit(sys.version_info < (3, 11))' 2>/dev/null; then
    PY="$c"
    break
  fi
done
if [ -z "$PY" ]; then
  echo "LeakCheck needs Python 3.11 or newer. Install it from python.org, then run this again."
  read -r -p "Press Enter to close." _ || true
  exit 1
fi

# (Re)install only when requirements.txt changed since the last setup.
if ! cmp -s requirements.txt .venv/.leakcheck-installed 2>/dev/null; then
  echo "Setting up LeakCheck (first run only; needs internet)..."
  "$PY" -m venv .venv
  .venv/bin/python -m pip install --quiet --disable-pip-version-check -r requirements.txt
  cp requirements.txt .venv/.leakcheck-installed
fi

exec .venv/bin/python -m leakcheck open
