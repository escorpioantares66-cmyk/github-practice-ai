#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if [[ "${ALLOW_TERMUX_TEST_INSTALL:-}" != "1" ]]; then
  echo "STOP: set ALLOW_TERMUX_TEST_INSTALL=1 only when explicitly authorizing this isolated run." >&2
  exit 3
fi
if [[ -z "${WHEELHOUSE_DIR:-}" || ! -d "$WHEELHOUSE_DIR" ]]; then
  echo "ERROR: WHEELHOUSE_DIR must point to the retained, verified native wheelhouse." >&2
  exit 2
fi

EVIDENCE_FILE="${TERMUX_EVIDENCE_FILE:-$ROOT_DIR/termux-sdk-3.46.0-termux-evidence.txt}"
LOG_FILE="$(mktemp "${TMPDIR:-/tmp}/termux-sdk-validation.XXXXXX.log")"
export TERMUX_EVIDENCE_FILE="$EVIDENCE_FILE"

finish() {
  status=$?
  trap - EXIT
  if [[ -f "$EVIDENCE_FILE" ]]; then
    {
      printf '\n=== Complete isolated validation transcript ===\n'
      cat "$LOG_FILE"
      printf '\nValidation process exit status: %s\n' "$status"
    } >> "$EVIDENCE_FILE"
  else
    {
      printf 'Termux SDK 3.46.0 validation transcript\n'
      cat "$LOG_FILE"
      printf '\nValidation process exit status: %s\n' "$status"
    } > "$EVIDENCE_FILE"
  fi
  rm -f "$LOG_FILE"
  exit "$status"
}
trap finish EXIT

echo "Starting isolated Termux validation; production Python is not modified."
echo "Evidence destination: $EVIDENCE_FILE"
bash scripts/check_termux_sdk_compat.sh 2>&1 | tee "$LOG_FILE"
