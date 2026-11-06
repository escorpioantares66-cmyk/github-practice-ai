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

# Verify exact versions, interpreter platform tags, and the recorded SHA256
# manifest before creating a venv or installing any candidate package.
WHEELHOUSE_DIR="$WHEELHOUSE_DIR" ANDROID_API_LEVEL="$ANDROID_API_LEVEL" \
  "$PYTHON_BIN" - <<'PY'
from __future__ import annotations

import hashlib
import os
import re
import sys
import sysconfig
import zipfile
from email.parser import Parser
from pathlib import Path

wheelhouse = Path(os.environ["WHEELHOUSE_DIR"]).resolve()
api_level = os.environ["ANDROID_API_LEVEL"]
platform = sysconfig.get_platform()
if platform != f"android-{api_level}-arm64_v8a":
    raise SystemExit(f"Python platform/API mismatch: {platform!r}, API {api_level}")

major, minor = sys.version_info[:2]
expected_tag = f"cp{major}{minor}-cp{major}{minor}-android_{api_level}_arm64_v8a"
expected = {"jiter": "0.18.0", "pydantic-core": "2.50.4"}
found: dict[str, tuple[Path, str]] = {}

manifest_path = wheelhouse / "SHA256SUMS.txt"
if not manifest_path.is_file():
    raise SystemExit(f"Missing checksum manifest: {manifest_path}")

manifest: dict[str, str] = {}
for line in manifest_path.read_text(encoding="utf-8").splitlines():
    if not line.strip():
        continue
    try:
        digest, filename = line.split(maxsplit=1)
    except ValueError as exc:
        raise SystemExit(f"Malformed checksum line: {line!r}") from exc
    filename = filename.lstrip("*")
    if not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise SystemExit(f"Invalid SHA256 value for {filename!r}")
    if Path(filename).name != filename or filename in manifest:
        raise SystemExit(f"Unsafe or duplicate checksum filename: {filename!r}")
    manifest[filename] = digest

for wheel in sorted(wheelhouse.glob("*.whl")):
    with zipfile.ZipFile(wheel) as archive:
        metadata_names = [
            name for name in archive.namelist()
            if name.endswith(".dist-info/METADATA")
        ]
        wheel_names = [
            name for name in archive.namelist()
            if name.endswith(".dist-info/WHEEL")
        ]
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
        digest = hashlib.sha256(wheel.read_bytes()).hexdigest()
        found[name] = (wheel, digest)
        print(f"Verified {wheel.name}: {expected_tag}")
        print(f"  SHA256: {digest}")

if set(found) != set(expected):
    raise SystemExit(f"Missing verified native wheels: {sorted(set(expected) - found.keys())}")

expected_manifest = {
    wheel.name: digest for wheel, digest in found.values()
}
if manifest != expected_manifest:
    raise SystemExit(
        "SHA256SUMS.txt does not exactly match the verified native wheels. "
        f"Expected {expected_manifest}, found {manifest}"
    )

print("Both exact native wheels passed version, platform-tag, and SHA256 checks.")
PY

JITER_WHEEL="$(find "$WHEELHOUSE_DIR" -maxdepth 1 -type f -name 'jiter-0.18.0-*.whl' -print -quit)"
CORE_WHEEL="$(find "$WHEELHOUSE_DIR" -maxdepth 1 -type f -name 'pydantic_core-2.50.4-*.whl' -print -quit)"
if [[ -z "$JITER_WHEEL" || -z "$CORE_WHEEL" ]]; then
  echo "ERROR: verified native wheel paths could not be resolved." >&2
  exit 2
fi

TEMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/gh-ai-sdk-compat.XXXXXX")"
trap 'rm -rf "$TEMP_DIR"' EXIT
VENV_DIR="$TEMP_DIR/venv"
"$PYTHON_BIN" -m venv "$VENV_DIR"
VENV_PY="$VENV_DIR/bin/python"

"$VENV_PY" -m pip install --upgrade pip setuptools wheel

# Install only the previously verified native artifacts from local files.
# --no-index guarantees these two packages cannot be substituted by PyPI.
"$VENV_PY" -m pip install --no-index --no-deps "$JITER_WHEEL" "$CORE_WHEEL"

# Install the remaining candidate SDK stack while holding the native versions.
"$VENV_PY" -m pip install --no-cache-dir \
  "jiter==0.18.0" \
  "pydantic-core==2.50.4" \
  "openai==3.46.0" \
  "httpx2==2.16.0" \
  "starlette[full]>=1.2,<2" \
  "pytest>=8" \
  "pytest-asyncio>=0.23" \
  "cachetools>=5" \
  "cryptography>=44.0.0"

"$VENV_PY" -m pip check
"$VENV_PY" - <<'PY'
import asyncio
import platform
import sys
import sysconfig
from importlib.metadata import version

import httpx2
import openai
import pydantic_core
import starlette
from openai import AsyncOpenAI, OpenAI

assert version("jiter") == "0.18.0", version("jiter")
assert pydantic_core.__version__ == "2.50.4", pydantic_core.__version__

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

# Probe both real Termux trust sources with direct HTTPS. This uses no API key
# and explicitly bypasses proxy environment variables.
PYTHONPATH="$ROOT_DIR" "$VENV_PY" scripts/test_termux_sdk_live_tls.py

# Run loopback TLS rejection, proxy, timeout, and SDK connection-error tests.
PYTHONPATH="$ROOT_DIR" "$VENV_PY" -m pytest -q -o addopts="" \
  tests/test_sdk_transport_network_compat.py

# Retain the broader SDK/application integration checks.
PYTHONPATH="$ROOT_DIR" "$VENV_PY" -m pytest -q -o addopts="" \
  tests/test_openai_sdk_transport_compat.py

echo "Termux OpenAI SDK compatibility smoke test passed."
echo "Candidate packages were installed only in the temporary virtual environment; it is removed on exit."
echo "The Termux evidence report is retained in the working directory."
echo "The verified wheelhouse and global Termux environment were left untouched."
