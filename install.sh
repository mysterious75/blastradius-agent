#!/bin/bash
# BlastRadius Agent — one-command install (Linux/macOS).
set -e

echo "🔴 Installing BlastRadius Agent..."

# Check Python 3.11+
if ! command -v python3 >/dev/null 2>&1; then
  echo "Python 3.11+ required — install it first: https://www.python.org/downloads/"
  exit 1
fi
PY_MAJOR=$(python3 -c 'import sys; print(sys.version_info.major)')
PY_MINOR=$(python3 -c 'import sys; print(sys.version_info.minor)')
if [ "$PY_MAJOR" -lt 3 ] || { [ "$PY_MAJOR" -eq 3 ] && [ "$PY_MINOR" -lt 11 ]; }; then
  echo "Python 3.11+ required (found $(python3 --version))"
  exit 1
fi

# Install from PyPI, fall back to the git repo.
if ! pip install blastradius-agent 2>/dev/null; then
  echo "[*] PyPI install failed — installing from GitHub..."
  pip install git+https://github.com/mysterious75/blastradius-agent
fi

echo "✅ BlastRadius installed!"
echo "Run: python -m blastradius.cli.wizard"
