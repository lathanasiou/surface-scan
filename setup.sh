#!/usr/bin/env bash
# surface-scan — one-step setup.
# Creates a virtual environment in .venv and installs dependencies into it.
#
#   ./setup.sh
#
# Then, each time you use the tool:
#   source .venv/bin/activate
#   python scan.py --input records.csv
#   deactivate        # when finished
set -euo pipefail

# Find a Python 3 interpreter (macOS/Linux use python3; some setups use python).
if command -v python3 >/dev/null 2>&1; then
  PY=python3
elif command -v python >/dev/null 2>&1; then
  PY=python
else
  echo "ERROR: Python 3 was not found on your PATH." >&2
  echo "  macOS:  brew install python      (or download from python.org)" >&2
  echo "  Linux:  install python3 via your package manager" >&2
  exit 1
fi

echo "Using $($PY --version)"

# Require Python 3.10+
$PY - <<'PYEOF' || { echo "ERROR: Python 3.10 or newer is required." >&2; exit 1; }
import sys
raise SystemExit(0 if sys.version_info >= (3, 10) else 1)
PYEOF

echo "Creating virtual environment in .venv ..."
$PY -m venv .venv

# shellcheck disable=SC1091
source .venv/bin/activate

echo "Upgrading pip and installing dependencies ..."
python -m pip install --upgrade pip >/dev/null
python -m pip install -r requirements.txt

echo
echo "Done. To use surface-scan:"
echo "    source .venv/bin/activate"
echo "    python scan.py --input records.csv"
echo "    deactivate   # when finished"
