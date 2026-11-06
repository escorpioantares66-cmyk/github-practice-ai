#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if [[ "${PREFIX:-}" != *"/com.termux/files/usr" ]]; then
  echo "ERROR: run this script inside Termux (PREFIX should end in /com.termux/files/usr)." >&2
  exit 2
fi

PYTHON_BIN="${PYTHON_BIN:-python}"
command -v "$PYTHON_BIN" >/dev/null 2>&1 || {
  echo "ERROR: Python executable not found: $PYTHON_BIN" >&2
  exit 2
}

# This is an explicit authorization gate. The default path never installs
# candidate packages, even into a temporary virtual environment.
if [[ "${ALLOW_TERMUX_TEST_INSTALL:-}" != "1" ]]; then
  echo "STOP: runtime installation is disabled by default." >&2
  echo "After reviewing the staged wheels, explicitly authorize the isolated test with:" >&2
  echo "  ALLOW_TERMUX_TEST_INSTALL=1 WHEELHOUSE_DIR=/path/to/verified-wheelhouse bash scripts/check_termux_sdk_compat.sh" >&2
  exit 3
fi

PLATFORM="$("$PYTHON_BIN" -c 'import sysconfig; print(sysconfig.get_platform())')"
if [[ ! "$PLATFORM" =~ ^android-([0-9]+)-arm64_v8a$ ]]; then
  echo "ERROR: expected an Android aarch64 Python platform tag; got: $PLATFORM" >&2
  exit 2
fi
PYTHON_API_LEVEL="${BASH_REMATCH[1]}"
if [[ -n "${ANDROID_API_LEVEL:-}" && "$ANDROID_API_LEVEL" != "$PYTHON_API_LEVEL" ]]; then
  echo "ERROR: ANDROID_API_LEVEL=$ANDROID_API_LEVEL conflicts with Python platform $PLATFORM." >&2
  exit 2
fi
export ANDROID_API_LEVEL="$PYTHON_API_LEVEL"

WHEELHOUSE_DIR="${WHEELHOUSE_DIR:-}"
if [[ -z "$WHEELHOUSE_DIR" || ! -d "$WHEELHOUSE_DIR" ]]; then
  echo "ERROR: set WHEELHOUSE_DIR to the retained wheelhouse from build_termux_sdk_wheels.sh." >&2
  exit 2
fi

# Verify exact native package versions and wheel tags before creating the venv.
WHEELHOUSE_DIR="$WHEELHOUSE_DIR" ANDROID_API_LEVEL="$ANDROID_API_LEVEL" \
  "$PYTHON_BIN" - <<'PY'
from __future__ import annotations

import os
import re
import sys
import sysconfig
import zipfile
from email.parser import Parser
from pathlib import Path

wheelhouse = Path(os.environ["WHEELHOUSE_DIR"])
api_level = os.environ["ANDROID_API_LEVEL"]
platform = sysconfig.get_platform()
if platform != f"android-{api_level}-arm64_v8a":
    raise SystemExit(f"Python platform/API mismatch: {platform!r}, API {api_level}")

major, minor = sys.version_info[:2]
expected_tag = f"cp{major}{minor}-cp{major}{minor}-android_{api_level}_arm64_v8a"
expected = {"jiter": "0.18.0", "pydantic-core": "2.50.4"}
found: set[str] = set()

for wheel in wheelhouse.glob("*.whl"):
    with zipfile.ZipFile(wheel) as archive:
        metadata_names = [name for name in archive.namelist() if name.endswith(".dist-info/METADATA")]
        wheel_names = [name for name in archive.namelist() if name.endswith(".dist-info/WHEEL")]
        if len(metadata_names) != 1 or len(wheel_names) != 1:
            raise SystemExit(f"Unexpected wheel metadata layout: {wheel.name}")
        metadata = Parser().parsestr(archive.read(metadata_names[0]).decode())
        wheel_metadata = Parser().parsestr(archive.read(wheel_names[0]).decode())
        name = re.sub(r"[-_.]+", "-", metadata["Name"]).lower()
        if name not in expected:
            continue
        if metadata["Version"] != expected[name]:
            raise SystemExit(f"{name}: unexpected version {metadata['Version']}")
        tags = wheel_metadata.get_all("Tag", [])
        if tags != [expected_tag]:
            raise SystemExit(f"{wheel.name}: expected only {expected_tag}, got {tags}")
        if name in found:
            raise SystemExit(f"Duplicate wheel for {name}")
        found.add(name)
        print(f"Verified {wheel.name}: {expected_tag}")

if found != set(expected):
    raise SystemExit(f"Missing verified native wheels: {sorted(set(expected) - found)}")
print("Both exact native wheels are present and platform-tag verified.")
PY

TEMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/gh-ai-sdk-compat.XXXXXX")"
trap 'rm -rf "$TEMP_DIR"' EXIT
VENV_DIR="$TEMP_DIR/venv"
"$PYTHON_BIN" -m venv "$VENV_DIR"
VENV_PY="$VENV_DIR/bin/python"

"$VENV_PY" -m pip install --upgrade pip setuptools wheel
"$VENV_PY" -m pip install --no-cache-dir --find-links "$WHEELHOUSE_DIR" \
  "jiter==0.18.0" \
  "pydantic-core==2.50.4" \
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
import sysconfig
from importlib.metadata import version

import httpx2
import jiter
import openai
import pydantic_core
import starlette
from openai import AsyncOpenAI, OpenAI

print(f"Python: {platform.python_version()} ({sys.platform}, {platform.machine()})")
print(f"Python platform: {sysconfig.get_platform()}")
print(f"OpenAI SDK: {openai.__version__}")
print(f"jiter: {version('jiter')}")
print(f"pydantic-core: {pydantic_core.__version__}")
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
echo "Only the temporary virtual environment was modified; it is removed on exit."
echo "The verified wheelhouse was left untouched."
