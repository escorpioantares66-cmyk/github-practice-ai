"""Read-only planning for 90-day approval and audit archival.

This module deliberately does not move, rewrite, or delete source evidence.
"""
from __future__ import annotations

import math
import time
from pathlib import Path
from typing import Any

from . import approval
from .secure_storage import read_private_text

RETENTION_DAYS = 90
RETENTION_SECONDS = RETENTION_DAYS * 24 * 60 * 60


def plan_retention(now: float | None = None) -> dict[str, Any]:
    """Report old, safe-to-archive evidence without changing any storage."""
    current = time.time() if now is None else now
    if (
        isinstance(current, bool)
        or not isinstance(current, (int, float))
        or not math.isfinite(current)
        or current <= 0
    ):
        raise ValueError("now must be a positive finite timestamp")

    cutoff = current - RETENTION_SECONDS
    eligible: list[str] = []
    excluded: dict[str, int] = {}
    approval_count = 0

    approval._ensure_dirs()
    for path in sorted(approval._approvals_dir.glob("*.json")):
        approval_count += 1
        reason = None
        if path.is_symlink():
            reason = "symlink"
        else:
            approval_id = path.stem
            try:
                record = approval._load_approval_record(path, approval_id)
            except (OSError, ValueError):
                reason = "corrupt_or_unreadable"
            else:
                created = float(record["created"])
                if created >= cutoff:
                    reason = "within_retention"
                elif created > current + approval.MAX_APPROVAL_CLOCK_SKEW_SECONDS:
                    reason = "future_dated"
                elif record.get("request_audit_status") != "written":
                    reason = "request_audit_incomplete"
                elif record["status"] == "pending":
                    # A pending record older than the 15-minute approval TTL
                    # is no longer executable, but still needs complete audit.
                    if not approval._approval_expired(created, current):
                        reason = "still_executable"
                elif record["status"] in {"approved", "denied"}:
                    if record.get("approval_audit_status") != "written":
                        reason = "transition_audit_incomplete"
                elif record["status"] == "consumed":
                    outcome = record.get("execution_outcome")
                    if (
                        record.get("approval_audit_status") != "written"
                        or not isinstance(outcome, dict)
                        or outcome.get("status") != "completed"
                        or outcome.get("audit_status") != "written"
                    ):
                        reason = "execution_recovery_required"
                else:
                    reason = "unsupported_state"

        if reason is None:
            eligible.append(path.stem)
        else:
            excluded[reason] = excluded.get(reason, 0) + 1

    # Verify the entire active chain before reporting any audit events as
    # eligible. Stage 1 only plans a verified archive snapshot; it never
    # extracts disconnected hash-chain fragments or truncates the source.
    audit_state = approval.verify_audit_log()
    audit_contents = read_private_text(approval._audit_file)
    old_audit_events = 0
    for raw_line in audit_contents.splitlines():
        if not raw_line:
            continue
        import json

        event = json.loads(raw_line)
        if float(event["time"]) < cutoff:
            old_audit_events += 1

    return {
        "mode": "dry_run",
        "retention_days": RETENTION_DAYS,
        "cutoff_timestamp": cutoff,
        "archive_destination": "private_local",
        "source_modified": False,
        "approval_records_scanned": approval_count,
        "approval_records_eligible": len(eligible),
        "eligible_approval_ids": eligible,
        "approval_records_excluded": excluded,
        "audit_log_verified": True,
        "audit_entries_scanned": audit_state["entries"],
        "audit_entries_older_than_cutoff": old_audit_events,
        "audit_head_sequence": audit_state["chained_entries"],
        "audit_head_hash": audit_state["head_hash"],
        "audit_archive_mode": "verified_snapshot_required",
    }
