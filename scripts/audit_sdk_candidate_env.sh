#!/usr/bin/env bash
set -Eeuo pipefail

# Audit the already-installed SDK candidate without adding audit tooling to it.
# Run from the repository root, after installing the candidate test environment.
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

OUTPUT_DIR="${SDK_AUDIT_OUTPUT_DIR:-artifacts/sdk-3.46.0}"
mkdir -p "$OUTPUT_DIR"

python -m pip check
python -m pip freeze --all | LC_ALL=C sort > "$OUTPUT_DIR/pip-freeze.txt"

SITE_PACKAGES="$(python -c 'import sysconfig; print(sysconfig.get_paths()["purelib"])')"
python - "$OUTPUT_DIR/environment.txt" <<'PY'
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
import platform
import sys
import sysconfig

names = ("openai", "httpx2", "httpcore2", "anyio", "jiter", "pydantic", "typing-extensions")
lines = [
    f"python={platform.python_version()}",
    f"implementation={platform.python_implementation()}",
    f"platform={sys.platform}",
    f"machine={platform.machine()}",
    f"python_platform={sysconfig.get_platform()}",
]
for name in names:
    try:
        value = version(name)
    except PackageNotFoundError:
        value = "NOT_INSTALLED"
    lines.append(f"{name}={value}")
Path(sys.argv[1]).write_text("\n".join(lines) + "\n", encoding="utf-8")
PY

# pip-audit runs in its own disposable environment. --path scans the candidate
# site-packages without installing the scanner into or mutating that environment.
AUDIT_VENV="$(mktemp -d "${TMPDIR:-/tmp}/sdk-audit.XXXXXX")"
cleanup() { rm -rf "$AUDIT_VENV"; }
trap cleanup EXIT
python -m venv "$AUDIT_VENV"
"$AUDIT_VENV/bin/python" -m pip install --disable-pip-version-check "pip-audit==2.10.1"

set +e
"$AUDIT_VENV/bin/pip-audit" --path "$SITE_PACKAGES" \
  --progress-spinner=off --format=json > "$OUTPUT_DIR/pip-audit.json"
AUDIT_STATUS=$?
set -e
printf '%s\n' "$AUDIT_STATUS" > "$OUTPUT_DIR/pip-audit.exit-code"

if (( AUDIT_STATUS > 1 )); then
  echo "pip-audit failed to complete (exit $AUDIT_STATUS); inspect CI logs." >&2
  exit "$AUDIT_STATUS"
fi

echo "SDK candidate environment evidence written to $OUTPUT_DIR"
cat "$OUTPUT_DIR/environment.txt"
echo "pip-audit exit status: $AUDIT_STATUS (0=clean, 1=one or more findings)"
