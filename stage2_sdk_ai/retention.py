"""Read-only planning for 90-day approval and audit archival.

This module deliberately does not move, rewrite, or delete source evidence.
"""
from __future__ import annotations

import json
import math
import os
import stat
import time
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

    # Validate existing storage metadata without chmod, mkdir, or file creation.
    if approval._approvals_dir.is_symlink():
        raise approval.ApprovalStoreIntegrityError(
            "approval directory cannot be a symlink"
        )
    if approval._approvals_dir.exists():
        directory_info = approval._approvals_dir.lstat()
        if (
            not stat.S_ISDIR(directory_info.st_mode)
            or directory_info.st_uid != os.geteuid()
            or stat.S_IMODE(directory_info.st_mode) != 0o700
        ):
            raise approval.ApprovalStoreIntegrityError(
                "approval directory must be private and owned by the application user"
            )

    # A planner must not create missing storage directories or files.
    for path in sorted(approval._approvals_dir.glob("*.json")):
        approval_count += 1
        reason = None
        if path.is_symlink():
            reason = "symlink"
        else:
            file_info = path.lstat()
            if (
                not stat.S_ISREG(file_info.st_mode)
                or file_info.st_uid != os.geteuid()
                or file_info.st_nlink != 1
                or stat.S_IMODE(file_info.st_mode) != 0o600
            ):
                reason = "unsafe_file"
            approval_id = path.stem
            try:
                if reason is not None:
                    raise OSError("approval record is not a private regular file")
                record = approval._load_approval_record(path, approval_id)
            except (OSError, ValueError):
                reason = "corrupt_or_unreadable"
            else:
                created = float(record["created"])
                if created > current + approval.MAX_APPROVAL_CLOCK_SKEW_SECONDS:
                    reason = "future_dated"
                elif created >= cutoff:
                    reason = "within_retention"
                elif record.get("request_audit_status") != "written":
                    reason = "request_audit_incomplete"
                elif record["status"] == "pending":
                    # Expired pending requests cannot be executed, but their
                    # original request event must still be fully audited.
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

    # Validate the complete active chain without calling verify_audit_log(),
    # which opens a missing audit file with O_CREAT and would mutate storage.
    audit_path = approval._audit_file
    if audit_path.is_symlink():
        raise approval.AuditLogIntegrityError("audit log cannot be a symlink")
    if audit_path.exists():
        audit_info = audit_path.lstat()
        if (
            not stat.S_ISREG(audit_info.st_mode)
            or audit_info.st_uid != os.geteuid()
            or audit_info.st_nlink != 1
            or stat.S_IMODE(audit_info.st_mode) != 0o600
        ):
            raise approval.AuditLogIntegrityError(
                "audit log must be a private single-link regular file"
            )
        audit_contents = read_private_text(audit_path).encode("utf-8")
    else:
        audit_contents = b""
    sequence, head_hash, total, legacy_count, _ = approval._audit_chain_state(
        audit_contents
    )
    old_audit_events = 0
    for raw_line in audit_contents.splitlines():
        if not raw_line:
            continue
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
        "audit_entries_scanned": total,
        "audit_legacy_entries": legacy_count,
        "audit_entries_older_than_cutoff": old_audit_events,
        "audit_head_sequence": sequence,
        "audit_head_hash": head_hash,
        "audit_archive_mode": "verified_snapshot_required",
    }
