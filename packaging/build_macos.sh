#!/usr/bin/env bash
# Build the macOS .app bundle. Run on macOS with the project venv set up.
set -euo pipefail
cd "$(dirname "$0")/.."
PY="${PYTHON:-.venv/bin/python}"
"$PY" -m PyInstaller --noconfirm --clean packaging/securitysight.spec
echo
echo "Built: dist/securitysight.app"
echo "Run:   open dist/securitysight.app   (or: dist/securitysight.app/Contents/MacOS/securitysight --server)"
