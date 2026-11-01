"""Private, copy-only archival for 90-day approval and audit evidence.

The default planner is read-only. Archiving is an explicit operation and never
removes or rewrites active source records.
"""
from __future__ import annotations

import base64
import fcntl
import hashlib
import json
import math
import os
import stat
import time
from contextlib import ExitStack
from pathlib import Path
from typing import Any

from . import approval
from .secure_storage import (
    ensure_private_directory,
    fsync_directory,
    open_private_file,
    write_text_atomically,
)

RETENTION_DAYS = 90
RETENTION_SECONDS = RETENTION_DAYS * 24 * 60 * 60
MAX_ARCHIVE_BYTES = 128 * 1024 * 1024
ARCHIVE_FORMAT_VERSION = 1


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _private_regular_file(path: Path, *, expected_mode: int = 0o600) -> os.stat_result:
    if path.is_symlink():
        raise approval.ApprovalStoreIntegrityError(
            "retention source cannot be a symlink"
        )
    info = path.lstat()
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.geteuid()
        or info.st_nlink != 1
        or stat.S_IMODE(info.st_mode) != expected_mode
    ):
        raise approval.ApprovalStoreIntegrityError(
            "retention source must be a private, single-link regular file"
        )
    return info


def _read_locked_file(path: Path, *, limit: int, exclusive: bool) -> bytes:
    _private_regular_file(path)
    fd = open_private_file(path, os.O_RDONLY)
    with os.fdopen(fd, "rb") as handle:
        fcntl.flock(
            handle.fileno(), fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH
        )
        try:
            contents = handle.read(limit + 1)
            if len(contents) > limit:
                raise approval.AuditLogIntegrityError(
                    "retention source exceeds its configured size limit"
                )
            return contents
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def _validate_now(now: float | None) -> float:
    current = time.time() if now is None else now
    if (
        isinstance(current, bool)
        or not isinstance(current, (int, float))
        or not math.isfinite(current)
        or current <= 0
    ):
        raise ValueError("now must be a positive finite timestamp")
    return float(current)


def plan_retention(now: float | None = None) -> dict[str, Any]:
    """Report old, safe-to-archive evidence without changing source storage."""
    current = _validate_now(now)
    cutoff = current - RETENTION_SECONDS
    eligible: list[str] = []
    excluded: dict[str, int] = {}
    approval_count = 0

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

    for path in sorted(approval._approvals_dir.glob("*.json")):
        approval_count += 1
        reason = None
        if path.is_symlink():
            reason = "symlink"
        else:
            try:
                _private_regular_file(path)
                record = approval._load_approval_record(path, path.stem)
            except (OSError, ValueError, approval.ApprovalStoreIntegrityError):
                reason = "corrupt_or_unreadable"
        if reason is None:
            created = float(record["created"])
            if created > current + approval.MAX_APPROVAL_CLOCK_SKEW_SECONDS:
                reason = "future_dated"
            elif created >= cutoff:
                reason = "within_retention"
            elif record.get("request_audit_status") != "written":
                reason = "request_audit_incomplete"
            elif record["status"] == "pending":
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

    audit_path = approval._audit_file
    if audit_path.is_symlink():
        raise approval.AuditLogIntegrityError("audit log cannot be a symlink")
    if audit_path.exists():
        audit_contents = _read_locked_file(
            audit_path, limit=approval.MAX_AUDIT_LOG_BYTES, exclusive=False
        )
    else:
        audit_contents = b""
    sequence, head_hash, total, legacy_count, _ = approval._audit_chain_state(
        audit_contents
    )
    old_audit_events = 0
    for raw_line in audit_contents.splitlines():
        if raw_line:
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
        "audit_archive_mode": "full_verified_snapshot",
    }


def _read_approval_snapshot(approval_id: str, cutoff: float, now: float) -> bytes:
    path = approval._approval_path(approval_id)
    if path is None:
        raise approval.ApprovalStoreIntegrityError("invalid approval ID in retention plan")
    _private_regular_file(path)
    raw = _read_locked_file(path, limit=MAX_ARCHIVE_BYTES, exclusive=False)
    record = json.loads(raw)
    validated = approval._load_approval_record(path, approval_id)
    if validated != record:
        raise approval.ApprovalStoreIntegrityError(
            "approval record changed while preparing archive"
        )
    created = float(record["created"])
    if created >= cutoff or created > now + approval.MAX_APPROVAL_CLOCK_SKEW_SECONDS:
        raise approval.ApprovalStoreIntegrityError(
            "approval record is no longer eligible for archival"
        )
    if record.get("request_audit_status") != "written":
        raise approval.ApprovalStoreIntegrityError("approval request audit is incomplete")
    if record["status"] == "pending":
        if not approval._approval_expired(created, now):
            raise approval.ApprovalStoreIntegrityError(
                "pending approval remains executable"
            )
    elif record["status"] in {"approved", "denied"}:
        if record.get("approval_audit_status") != "written":
            raise approval.ApprovalStoreIntegrityError(
                "approval transition audit is incomplete"
            )
    elif record["status"] == "consumed":
        outcome = record.get("execution_outcome")
        if (
            record.get("approval_audit_status") != "written"
            or not isinstance(outcome, dict)
            or outcome.get("status") != "completed"
            or outcome.get("audit_status") != "written"
        ):
            raise approval.ApprovalStoreIntegrityError(
                "consumed approval requires operator recovery"
            )
    else:
        raise approval.ApprovalStoreIntegrityError("unsupported approval state")
    return raw


def _decode_archive(archive_bytes: bytes) -> dict[str, Any]:
    if len(archive_bytes) > MAX_ARCHIVE_BYTES:
        raise ValueError("archive exceeds the configured size limit")
    try:
        envelope = json.loads(archive_bytes)
    except (UnicodeDecodeError, ValueError) as exc:
        raise ValueError("archive is not valid JSON") from exc
    if not isinstance(envelope, dict) or set(envelope) != {"manifest", "data"}:
        raise ValueError("archive envelope is malformed")
    manifest, data = envelope["manifest"], envelope["data"]
    if (
        not isinstance(manifest, dict)
        or manifest.get("format_version") != ARCHIVE_FORMAT_VERSION
        or not isinstance(manifest.get("archive_id"), str)
        or not isinstance(data, dict)
        or hashlib.sha256(_canonical_json(data)).hexdigest()
        != manifest.get("data_sha256")
    ):
        raise ValueError("archive manifest or data digest is invalid")
    if set(data) != {
        "cutoff_timestamp", "approval_records", "audit_log_base64",
        "audit_log_sha256", "audit_head_sequence", "audit_head_hash",
    }:
        raise ValueError("archive data schema is invalid")
    try:
        audit_bytes = base64.b64decode(data["audit_log_base64"], validate=True)
        records = data["approval_records"]
        if not isinstance(records, dict):
            raise ValueError
        for approval_id, item in records.items():
            if not isinstance(approval_id, str) or not isinstance(item, dict):
                raise ValueError
            raw = base64.b64decode(item["content_base64"], validate=True)
            if hashlib.sha256(raw).hexdigest() != item["sha256"]:
                raise ValueError
            parsed = json.loads(raw)
            if parsed.get("id") != approval_id:
                raise ValueError
        if hashlib.sha256(audit_bytes).hexdigest() != data["audit_log_sha256"]:
            raise ValueError
        sequence, head_hash, _, _, _ = approval._audit_chain_state(audit_bytes)
        if (
            sequence != data["audit_head_sequence"]
            or head_hash != data["audit_head_hash"]
        ):
            raise ValueError
    except (KeyError, TypeError, ValueError, approval.AuditLogIntegrityError) as exc:
        raise ValueError("archive payload integrity verification failed") from exc
    expected_archive_id = hashlib.sha256(
        _canonical_json({
            "cutoff_timestamp": data["cutoff_timestamp"],
            "data_sha256": manifest["data_sha256"],
        })
    ).hexdigest()
    if manifest["archive_id"] != expected_archive_id:
        raise ValueError("archive identifier does not match its contents")
    if (
        manifest.get("approval_record_count") != len(data["approval_records"])
        or manifest.get("audit_log_bytes") != len(audit_bytes)
        or manifest.get("retention_days") != RETENTION_DAYS
    ):
        raise ValueError("archive manifest metadata does not match its contents")
    return envelope


def verify_archive(path: Path) -> dict[str, Any]:
    """Verify archive privacy, manifest digests, approval payloads, and audit chain."""
    _private_regular_file(path)
    raw = _read_locked_file(path, limit=MAX_ARCHIVE_BYTES, exclusive=False)
    envelope = _decode_archive(raw)
    return {
        "valid": True,
        "archive_id": envelope["manifest"]["archive_id"],
        "approval_records": len(envelope["data"]["approval_records"]),
        "audit_log_sha256": envelope["data"]["audit_log_sha256"],
        "audit_head_sequence": envelope["data"]["audit_head_sequence"],
        "audit_head_hash": envelope["data"]["audit_head_hash"],
    }


def archive_retention(
    now: float | None = None, archive_dir: Path | None = None
) -> dict[str, Any]:
    """Create a verified private snapshot; never remove or rewrite source files."""
    current = _validate_now(now)
    initial_plan = plan_retention(current)
    approval_ids = initial_plan["eligible_approval_ids"]
    target_dir = archive_dir or (approval._approvals_dir.parent / "archive")

    with approval._locked_request_creation():
        with ExitStack() as locks:
            for approval_id in approval_ids:
                path = approval._approval_path(approval_id)
                if path is not None:
                    locks.enter_context(approval._locked_record(path))

            record_payloads: dict[str, bytes] = {}
            for approval_id in approval_ids:
                try:
                    record_payloads[approval_id] = _read_approval_snapshot(
                        approval_id, initial_plan["cutoff_timestamp"], current
                    )
                except (
                    OSError, ValueError, approval.ApprovalStoreIntegrityError
                ):
                    # A record that changed or became unsafe after planning is
                    # skipped, never force-copied.
                    continue

            audit_path = approval._audit_file
            if audit_path.exists():
                audit_bytes = _read_locked_file(
                    audit_path,
                    limit=approval.MAX_AUDIT_LOG_BYTES,
                    exclusive=True,
                )
            else:
                audit_bytes = b""
            sequence, head_hash, _, _, _ = approval._audit_chain_state(audit_bytes)

            records = {
                approval_id: {
                    "content_base64": base64.b64encode(raw).decode("ascii"),
                    "sha256": hashlib.sha256(raw).hexdigest(),
                }
                for approval_id, raw in sorted(record_payloads.items())
            }
            data = {
                "cutoff_timestamp": initial_plan["cutoff_timestamp"],
                "approval_records": records,
                "audit_log_base64": base64.b64encode(audit_bytes).decode("ascii"),
                "audit_log_sha256": hashlib.sha256(audit_bytes).hexdigest(),
                "audit_head_sequence": sequence,
                "audit_head_hash": head_hash,
            }
            data_bytes = _canonical_json(data)
            manifest_core = {
                "format_version": ARCHIVE_FORMAT_VERSION,
                "retention_days": RETENTION_DAYS,
                "created_at": current,
                "approval_record_count": len(records),
                "audit_log_bytes": len(audit_bytes),
                "data_sha256": hashlib.sha256(data_bytes).hexdigest(),
            }
            archive_id = hashlib.sha256(
                _canonical_json({
                    "cutoff_timestamp": initial_plan["cutoff_timestamp"],
                    "data_sha256": manifest_core["data_sha256"],
                })
            ).hexdigest()
            manifest = {**manifest_core, "archive_id": archive_id}
            archive_bytes = _canonical_json({"manifest": manifest, "data": data})
            if len(archive_bytes) > MAX_ARCHIVE_BYTES:
                raise ValueError("archive exceeds the configured 128 MiB limit")

            ensure_private_directory(target_dir)
            archive_path = target_dir / f"snapshot-{archive_id}.json"
            lock_path = target_dir / ".archive.lock"
            lock_fd = open_private_file(lock_path, os.O_RDWR | os.O_CREAT)
            with os.fdopen(lock_fd, "r+") as archive_lock:
                fcntl.flock(archive_lock.fileno(), fcntl.LOCK_EX)
                try:
                    if archive_path.exists() or archive_path.is_symlink():
                        existing = _read_locked_file(
                            archive_path, limit=MAX_ARCHIVE_BYTES, exclusive=False
                        )
                        verified = _decode_archive(existing)
                        if existing != archive_bytes:
                            # A retry may have a different created_at while the
                            # snapshot data and deterministic archive ID match.
                            if (
                                verified["manifest"].get("archive_id") != archive_id
                                or verified["manifest"].get("data_sha256")
                                != manifest["data_sha256"]
                            ):
                                raise approval.ApprovalStoreIntegrityError(
                                    "archive ID collision or conflicting archive content"
                                )
                        result = verify_archive(archive_path)
                        result["created"] = False
                    else:
                        write_text_atomically(
                            archive_path, archive_bytes.decode("utf-8"), target_dir
                        )
                        fsync_directory(target_dir)
                        result = verify_archive(archive_path)
                        result["created"] = True
                finally:
                    fcntl.flock(archive_lock.fileno(), fcntl.LOCK_UN)

    result.update({
        "archive_path": str(archive_path),
        "source_modified": False,
        "approval_records_copied": len(record_payloads),
        "audit_log_copied": True,
        "archive_bytes": len(archive_bytes),
    })
    return result
