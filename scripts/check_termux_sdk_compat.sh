#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if [[ "${PREFIX:-}" != *"/com.termux/files/usr" ]]; then
  echo "ERROR: run this script inside Termux (PREFIX should end in /com.termux/files/usr)." >&2
  exit 2
fi

PYTHON_BIN="${PYTHON_BIN:-python}"
if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
  echo "ERROR: Python executable not found: $PYTHON_BIN" >&2
  exit 2
fi

"$PYTHON_BIN" - <<'PY'
import platform
import sys

print(f"Termux candidate runtime: Python {platform.python_version()} ({platform.machine()})")
if sys.version_info < (3, 11):
    raise SystemExit("ERROR: this candidate stack requires Python 3.11 or newer.")
PY

if ! command -v rustc >/dev/null 2>&1 || ! command -v cargo >/dev/null 2>&1; then
  echo "NOTICE: rustc/cargo are not both installed. If no Android jiter wheel is available,"
  echo "        OpenAI SDK installation may need a source build. Termux setup: pkg install rust"
fi

TEMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/gh-ai-sdk-compat.XXXXXX")"
trap 'rm -rf "$TEMP_DIR"' EXIT
VENV_DIR="$TEMP_DIR/venv"
"$PYTHON_BIN" -m venv "$VENV_DIR"
VENV_PY="$VENV_DIR/bin/python"

"$VENV_PY" -m pip install --upgrade pip setuptools wheel
"$VENV_PY" -m pip install \
  "openai==3.46.0" \
  "httpx2>=2.15.1,<3" \
  "starlette[full]>=1.2,<2" \
  "pytest>=8" \
  "pytest-asyncio>=0.23" \
  "cachetools>=5"

"$VENV_PY" -m pip check
"$VENV_PY" - <<'PY'
import asyncio
import platform
import sys

import httpx2
import openai
import starlette
from openai import AsyncOpenAI, OpenAI

print(f"Python: {platform.python_version()} ({sys.platform}, {platform.machine()})")
print(f"OpenAI SDK: {openai.__version__}")
print(f"HTTPX2: {httpx2.__version__}")
print(f"Starlette: {starlette.__version__}")

with OpenAI(api_key="sk-termux-construction-check", timeout=5):
    pass

async def main() -> None:
    async with AsyncOpenAI(api_key="sk-termux-construction-check", timeout=5):
        pass

asyncio.run(main())
print("Default synchronous and asynchronous SDK clients constructed successfully.")
PY

PYTHONPATH="$ROOT_DIR" "$VENV_PY" -m pytest -q -o addopts="" \
  tests/test_openai_sdk_transport_compat.py

echo "Termux OpenAI SDK compatibility smoke test passed."
echo "This was an isolated temporary environment; the existing project dependencies were not changed."
