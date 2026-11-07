#!/usr/bin/env bash
# Rebuild jiter 0.18.0 and pydantic-core 2.50.4 from immutable upstream commits.
# Writes only to a new wheelhouse; never modifies the historical wheelhouse.
set -Eeuo pipefail
umask 077

PYTHON_BIN="${PYTHON_BIN:-python}"
MATURIN_BIN="${MATURIN_BIN:-maturin}"
ORIGINAL_WHEELHOUSE_DIR="${ORIGINAL_WHEELHOUSE_DIR:-$HOME/pr41-api24-wheelhouse}"
OUTPUT_DIR="${SOURCE_PINNED_WHEELHOUSE_DIR:-$HOME/pr41-api24-source-pinned-wheelhouse}"
# The builder owns only a directory it creates itself. An explicit override
# must name a path that does not already exist; never recursively delete a
# caller-owned directory during EXIT cleanup.
BUILD_ROOT=""
BUILD_ROOT_OWNED=0
if [[ -n "${SOURCE_BUILD_ROOT:-}" ]]; then
  BUILD_ROOT="$SOURCE_BUILD_ROOT"
  if [[ -e "$BUILD_ROOT" || -L "$BUILD_ROOT" ]]; then
    echo "ERROR: refusing to use existing SOURCE_BUILD_ROOT: $BUILD_ROOT" >&2
    exit 2
  fi
  mkdir -m 700 -- "$BUILD_ROOT"
else
  BUILD_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/gh-ai-source-build.XXXXXX")"
fi
BUILD_ROOT_OWNED=1
KEEP_BUILD_ROOT="${KEEP_SOURCE_BUILD_ROOT:-0}"

cleanup() {
  if [[ "$BUILD_ROOT_OWNED" == "1" && -n "$BUILD_ROOT" && "$KEEP_BUILD_ROOT" != "1" ]]; then
    rm -rf -- "$BUILD_ROOT"
  elif [[ "$BUILD_ROOT_OWNED" == "1" && "$KEEP_BUILD_ROOT" == "1" ]]; then
    echo "Source/build checkout retained: $BUILD_ROOT"
  fi
}
trap cleanup EXIT

if [[ "${PREFIX:-}" != *"/com.termux/files/usr" ]]; then
  echo "ERROR: run this build only inside Termux (PREFIX must end in /com.termux/files/usr)." >&2
  exit 2
fi
PLATFORM="$("$PYTHON_BIN" -c 'import sysconfig; print(sysconfig.get_platform())')"
EXPECTED_ANDROID_API_LEVEL="${EXPECTED_ANDROID_API_LEVEL:-24}"
if [[ "$PLATFORM" != "android-${EXPECTED_ANDROID_API_LEVEL}-arm64_v8a" ]]; then
  echo "ERROR: expected Android API ${EXPECTED_ANDROID_API_LEVEL} aarch64 Python; got: $PLATFORM" >&2
  exit 2
fi
if [[ -n "${ANDROID_API_LEVEL:-}" && "$ANDROID_API_LEVEL" != "$EXPECTED_ANDROID_API_LEVEL" ]]; then
  echo "ERROR: ANDROID_API_LEVEL conflicts with Python platform." >&2
  exit 2
fi
export ANDROID_API_LEVEL="$EXPECTED_ANDROID_API_LEVEL"

for command_name in git rustc cargo sha256sum; do
  command -v "$command_name" >/dev/null 2>&1 || { echo "Missing required command: $command_name" >&2; exit 2; }
done
command -v "$PYTHON_BIN" >/dev/null 2>&1 || { echo "Missing Python: $PYTHON_BIN" >&2; exit 2; }
command -v "$MATURIN_BIN" >/dev/null 2>&1 || { echo "Missing maturin: $MATURIN_BIN" >&2; exit 2; }
[[ -d "$ORIGINAL_WHEELHOUSE_DIR" ]] || { echo "Original wheelhouse not found: $ORIGINAL_WHEELHOUSE_DIR" >&2; exit 2; }
[[ ! -e "$OUTPUT_DIR" ]] || { echo "Refusing to overwrite existing output: $OUTPUT_DIR" >&2; exit 2; }
mkdir -p "$BUILD_ROOT"
mkdir -p "$(dirname "$OUTPUT_DIR")"

# Snapshot every regular file in the original wheelhouse before any build work.
original_before="$BUILD_ROOT/original-wheelhouse.before"
(
  cd "$ORIGINAL_WHEELHOUSE_DIR"
  find . -type f -print0 | sort -z | xargs -0 -r sha256sum
) > "$original_before"

MATURIN_VERSION="$("$MATURIN_BIN" --version)"
[[ "$MATURIN_VERSION" == *"1.16.0"* ]] || {
  echo "Expected maturin 1.16.0 for a reproducible comparison; got: $MATURIN_VERSION" >&2
  exit 2
}

clone_at() {
  local url="$1" commit="$2" dest="$3" sparse_path="${4:-}"
  git clone --filter=blob:none --no-checkout --depth 1 "$url" "$dest"
  git -C "$dest" fetch --filter=blob:none --depth 1 origin "$commit"
  if [[ -n "$sparse_path" ]]; then
    git -C "$dest" sparse-checkout init --cone
    git -C "$dest" sparse-checkout set "$sparse_path"
  fi
  git -C "$dest" checkout --detach "$commit"
  [[ "$(git -C "$dest" rev-parse HEAD)" == "$commit" ]]
  [[ -z "$(git -C "$dest" status --porcelain)" ]]
}

JITER_COMMIT="fc2da0bd1fb699a6c4e9641e9e1c06fa6d5d93e8"
CORE_COMMIT="ea492e04654ab7f7a1f9287ea912419452ead4dd"
JITER_REPO="https://github.com/pydantic/jiter.git"
CORE_REPO="https://github.com/pydantic/pydantic.git"

clone_at "$JITER_REPO" "$JITER_COMMIT" "$BUILD_ROOT/jiter"
clone_at "$CORE_REPO" "$CORE_COMMIT" "$BUILD_ROOT/pydantic" "pydantic-core"

JITER_TREE="$(git -C "$BUILD_ROOT/jiter" rev-parse 'HEAD^{tree}')"
CORE_TREE="$(git -C "$BUILD_ROOT/pydantic" rev-parse 'HEAD^{tree}')"
[[ -f "$BUILD_ROOT/jiter/Cargo.lock" ]] || { echo "Pinned jiter source has no Cargo.lock" >&2; exit 2; }
[[ -f "$BUILD_ROOT/pydantic/pydantic-core/Cargo.lock" ]] || { echo "Pinned pydantic-core source has no Cargo.lock" >&2; exit 2; }
mkdir "$OUTPUT_DIR"

{
  echo "=== Source-pinned Termux native wheel build ==="
  echo "UTC timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "Python: $("$PYTHON_BIN" --version 2>&1)"
  echo "Python executable: $("$PYTHON_BIN" -c 'import sys; print(sys.executable)')"
  echo "Python platform: $("$PYTHON_BIN" -c 'import sysconfig; print(sysconfig.get_platform())')"
  echo "OpenSSL: $("$PYTHON_BIN" -c 'import ssl; print(ssl.OPENSSL_VERSION)')"
  echo "maturin: $MATURIN_VERSION"
  echo "rustc: $(rustc --version --verbose | tr '\n' ';')"
  echo "cargo: $(cargo --version)"
  echo "host: $(uname -a)"
  echo "ANDROID_API_LEVEL: ${ANDROID_API_LEVEL:-unset}"
  echo "RUSTFLAGS: ${RUSTFLAGS:-unset}"
  echo "CARGO_PROFILE_RELEASE_LTO: ${CARGO_PROFILE_RELEASE_LTO:-unset}"
  echo "jiter repository: $JITER_REPO"
  echo "jiter commit: $JITER_COMMIT"
  echo "jiter tree: $JITER_TREE"
  echo "jiter Cargo.lock SHA256: $(sha256sum "$BUILD_ROOT/jiter/Cargo.lock" | cut -d " " -f1)"
  echo "pydantic repository: $CORE_REPO"
  echo "pydantic commit: $CORE_COMMIT"
  echo "pydantic tree: $CORE_TREE"
  echo "pydantic-core Cargo.lock SHA256: $(sha256sum "$BUILD_ROOT/pydantic/pydantic-core/Cargo.lock" | cut -d " " -f1)"
  echo "pydantic-core package subdirectory: pydantic-core/"
  echo "pydantic-core publisher provenance: unavailable for PyPI 2.50.4; source commit is pinned here, but this is not an upstream publisher attestation."
} | tee "$OUTPUT_DIR/BUILD-EVIDENCE.txt"

# Cargo lockfiles are honored and locked mode rejects implicit dependency changes.
(
  cd "$BUILD_ROOT/jiter/crates/jiter-python"
  "$MATURIN_BIN" build --release --locked --interpreter "$PYTHON_BIN" --out "$OUTPUT_DIR"
)
(
  cd "$BUILD_ROOT/pydantic/pydantic-core"
  "$MATURIN_BIN" build --release --locked --interpreter "$PYTHON_BIN" --out "$OUTPUT_DIR"
)

# Validate exact package versions and this interpreter's Android API wheel tag.
WHEELHOUSE_DIR="$OUTPUT_DIR" "$PYTHON_BIN" - <<'PY'
from __future__ import annotations
import sys, sysconfig, zipfile
from email.parser import Parser
from pathlib import Path

root = Path(__import__("os").environ["WHEELHOUSE_DIR"])
platform = sysconfig.get_platform()
if not platform.startswith("android-") or not platform.endswith("-arm64_v8a"):
    raise SystemExit(f"Expected Android aarch64 Python, got {platform!r}")
api = platform.split("-")[1]
expected_tag = f"cp{sys.version_info.major}{sys.version_info.minor}-cp{sys.version_info.major}{sys.version_info.minor}-android_{api}_arm64_v8a"
expected = {"jiter": "0.18.0", "pydantic-core": "2.50.4"}
found = {}
for wheel in sorted(root.glob("*.whl")):
    with zipfile.ZipFile(wheel) as z:
        metadata = [n for n in z.namelist() if n.endswith(".dist-info/METADATA")]
        wheel_meta = [n for n in z.namelist() if n.endswith(".dist-info/WHEEL")]
        if len(metadata) != 1 or len(wheel_meta) != 1:
            raise SystemExit(f"Malformed wheel metadata: {wheel.name}")
        m = Parser().parsestr(z.read(metadata[0]).decode())
        w = Parser().parsestr(z.read(wheel_meta[0]).decode())
        name = m["Name"].lower().replace("_", "-")
        if name not in expected:
            raise SystemExit(f"Unexpected wheel in output: {wheel.name}")
        if m["Version"] != expected[name]:
            raise SystemExit(f"{name}: expected {expected[name]}, got {m['Version']}")
        if w.get_all("Tag", []) != [expected_tag]:
            raise SystemExit(f"{wheel.name}: expected {expected_tag}, got {w.get_all('Tag', [])}")
        if name in found:
            raise SystemExit(f"Duplicate wheel for {name}")
        found[name] = wheel.name
        print(f"Verified {wheel.name}: {expected_tag}")
if set(found) != set(expected):
    raise SystemExit(f"Missing wheel(s): {set(expected) - set(found)}")
PY

(
  cd "$OUTPUT_DIR"
  sha256sum ./*.whl > SHA256SUMS.txt
)

# Confirm the historical wheelhouse is byte-for-byte unchanged.
(
  cd "$ORIGINAL_WHEELHOUSE_DIR"
  find . -type f -print0 | sort -z | xargs -0 -r sha256sum
) > "$BUILD_ROOT/original-wheelhouse.after"
cmp "$original_before" "$BUILD_ROOT/original-wheelhouse.after"

echo "Source-pinned wheelhouse created: $OUTPUT_DIR"
echo "Original wheelhouse integrity: unchanged"
echo "Next: inspect BUILD-EVIDENCE.txt and SHA256SUMS.txt, then run the isolated validation script against this output."
