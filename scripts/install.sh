#!/usr/bin/env bash
#
# Quick local install helper for bgp-hijack-monitor.
# Sets up a virtualenv, installs the package, and copies the example config
# if one doesn't already exist.
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_DIR"

if ! command -v python3 >/dev/null 2>&1; then
    echo "python3 is required but was not found on PATH." >&2
    exit 1
fi

PY_VERSION="$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])')"
REQUIRED="3.10"
if [ "$(printf '%s\n' "$REQUIRED" "$PY_VERSION" | sort -V | head -n1)" != "$REQUIRED" ]; then
    echo "Python >= $REQUIRED is required (found $PY_VERSION)." >&2
    exit 1
fi

echo "==> Creating virtual environment in .venv"
python3 -m venv .venv
# shellcheck disable=SC1091
source .venv/bin/activate

echo "==> Installing bgp-hijack-monitor"
pip install --upgrade pip >/dev/null
pip install -e .

if [ ! -f config.yaml ]; then
    echo "==> Copying config/config.example.yaml -> config.yaml"
    cp config/config.example.yaml config.yaml
    echo "    Edit config.yaml with your org name and the prefixes/ASNs you own."
else
    echo "==> config.yaml already exists, leaving it untouched"
fi

cat <<'EOF'

Setup complete.

Next steps:
  source .venv/bin/activate
  bgp-hijack-monitor validate-config -c config.yaml
  bgp-hijack-monitor init-baseline   -c config.yaml
  bgp-hijack-monitor monitor         -c config.yaml

EOF
