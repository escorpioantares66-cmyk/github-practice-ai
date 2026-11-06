#!/usr/bin/env bash
set -Eeuo pipefail

# Build-only stage for PR #41. This script does not install either target
# package into the active Python environment or into a runtime venv.

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
command -v rustc >/dev/null 2>&1 || { echo "ERROR: rustc is required." >&2; exit 2; }
command -v cargo >/dev/null 2>&1 || { echo "ERROR: cargo is required." >&2; exit 2; }

PLATFORM="$("$PYTHON_BIN" -c 'import sysconfig; print(sysconfig.get_platform())')"
if [[ ! "$PLATFORM" =~ ^android-([0-9]+)-arm64_v8a$ ]]; then
  echo "ERROR: expected an Android aarch64 Python platform tag; got: $PLATFORM" >&2
  exit 2
fi
PYTHON_API_LEVEL="${BASH_REMATCH[1]}"

if [[ -n "${ANDROID_API_LEVEL:-}" && "$ANDROID_API_LEVEL" != "$PYTHON_API_LEVEL" ]]; then
  echo "ERROR: ANDROID_API_LEVEL=$ANDROID_API_LEVEL conflicts with Python platform $PLATFORM." >&2
  echo "Unset it or set it to $PYTHON_API_LEVEL; do not use the device API level as the wheel target." >&2
  exit 2
fi
export ANDROID_API_LEVEL="$PYTHON_API_LEVEL"

DEVICE_API_LEVEL="unavailable"
if command -v getprop >/dev/null 2>&1; then
  DEVICE_API_LEVEL="$(getprop ro.build.version.sdk 2>/dev/null || true)"
  DEVICE_API_LEVEL="${DEVICE_API_LEVEL:-unavailable}"
fi

WHEELHOUSE_DIR="${WHEELHOUSE_DIR:-$HOME/pr41-api24-wheelhouse}"
mkdir -p "$(dirname "$WHEELHOUSE_DIR")"
if [[ -e "$WHEELHOUSE_DIR" ]]; then
  echo "ERROR: refusing to reuse or overwrite existing wheelhouse: $WHEELHOUSE_DIR" >&2
  echo "Choose a new WHEELHOUSE_DIR or move the existing directory yourself." >&2
  exit 2
fi
mkdir -m 700 "$WHEELHOUSE_DIR"
export WHEELHOUSE_DIR

echo "Build-only PR #41 native dependency stage"
echo "Python: $("$PYTHON_BIN" --version 2>&1)"
echo "Python platform: $PLATFORM"
echo "Android device API: $DEVICE_API_LEVEL"
echo "Native wheel target: Android API $ANDROID_API_LEVEL"
echo "Rust: $(rustc --version)"
echo "Cargo: $(cargo --version)"
echo "Wheelhouse: $WHEELHOUSE_DIR"
echo "Pinned packages: jiter==0.18.0, pydantic-core==2.50.4"
echo "No target packages will be installed."

if git -C "$ROOT_DIR" rev-parse --verify HEAD >/dev/null 2>&1; then
  GIT_HEAD="$(git -C "$ROOT_DIR" rev-parse HEAD)"
else
  GIT_HEAD="unavailable"
fi

{
  echo "Repository commit: $GIT_HEAD"
  echo "Python: $("$PYTHON_BIN" --version 2>&1)"
  echo "Python platform: $PLATFORM"
  echo "Android device API: $DEVICE_API_LEVEL"
  echo "ANDROID_API_LEVEL: $ANDROID_API_LEVEL"
  echo "Rust: $(rustc --version)"
  echo "Cargo: $(cargo --version)"
  echo "Build command: pip wheel --no-deps --no-cache-dir --no-binary=jiter,pydantic-core"
  echo "Packages: jiter==0.18.0 pydantic-core==2.50.4"
} > "$WHEELHOUSE_DIR/BUILD-INFO.txt"

# --no-cache-dir prevents reuse of the previously cached API-33 wheels.
# pip wheel builds artifacts but does not install the target packages.
"$PYTHON_BIN" -m pip wheel --no-deps --no-cache-dir --no-binary=jiter,pydantic-core \
  --wheel-dir "$WHEELHOUSE_DIR" \
  "jiter==0.18.0" "pydantic-core==2.50.4" \
  2>&1 | tee "$WHEELHOUSE_DIR/build.log"

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

wheelhouse = Path(os.environ["WHEELHOUSE_DIR"])
api_level = os.environ["ANDROID_API_LEVEL"]
platform = sysconfig.get_platform()
match = re.fullmatch(r"android-(\d+)-arm64_v8a", platform)
if not match or match.group(1) != api_level:
    raise SystemExit(f"Python platform/API mismatch: {platform!r}, API {api_level}")

major, minor = sys.version_info[:2]
expected_tag = f"cp{major}{minor}-cp{major}{minor}-android_{api_level}_arm64_v8a"
expected = {"jiter": "0.18.0", "pydantic-core": "2.50.4"}
found: dict[str, Path] = {}

for wheel in sorted(wheelhouse.glob("*.whl")):
    with zipfile.ZipFile(wheel) as archive:
        metadata_names = [name for name in archive.namelist() if name.endswith(".dist-info/METADATA")]
        wheel_names = [name for name in archive.namelist() if name.endswith(".dist-info/WHEEL")]
        if len(metadata_names) != 1 or len(wheel_names) != 1:
            raise SystemExit(f"Unexpected wheel metadata layout: {wheel.name}")
        metadata = Parser().parsestr(archive.read(metadata_names[0]).decode())
        wheel_metadata = Parser().parsestr(archive.read(wheel_names[0]).decode())
        name = re.sub(r"[-_.]+", "-", metadata["Name"]).lower()
        version = metadata["Version"]
        tags = wheel_metadata.get_all("Tag", [])
        if name not in expected:
            continue
        if version != expected[name]:
            raise SystemExit(f"{name}: expected {expected[name]}, got {version}")
        if tags != [expected_tag]:
            raise SystemExit(f"{wheel.name}: expected only {expected_tag}, got {tags}")
        if name in found:
            raise SystemExit(f"Duplicate wheel for {name}")
        found[name] = wheel

if set(found) != set(expected):
    missing = sorted(set(expected) - set(found))
    raise SystemExit(f"Missing expected native wheels: {missing}")

lines = []
for name in sorted(found):
    wheel = found[name]
    digest = hashlib.sha256(wheel.read_bytes()).hexdigest()
    lines.append(f"{digest}  {wheel.name}")
    print(f"VERIFIED {name}=={expected[name]}")
    print(f"  wheel: {wheel.name}")
    print(f"  tag: {expected_tag}")
    print(f"  sha256: {digest}")

(wheelhouse / "SHA256SUMS.txt").write_text("\n".join(lines) + "\n")
(wheelhouse / "WHEEL-VERIFICATION.txt").write_text(
    f"Python platform: {platform}\n"
    f"Expected wheel tag: {expected_tag}\n"
    + "\n".join(lines)
    + "\n"
)
print("Both native wheels passed exact version, platform-tag, and SHA256 checks.")
print("BUILD ONLY: no target package was installed.")
PY

echo "Build and wheel verification completed."
echo "Artifacts and evidence retained at: $WHEELHOUSE_DIR"
echo "No SDK runtime installation or integration test was performed."
