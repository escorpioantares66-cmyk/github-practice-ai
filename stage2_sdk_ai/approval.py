from __future__ import annotations

import fcntl
import hashlib
import hmac
import json
import logging
import math
import os
import re
import secrets
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from . import auth
from .secure_storage import (
    ensure_private_directory,
    fsync_directory,
    open_private_file,
    read_private_text,
    write_text_atomically,
)

_approvals_dir = Path("approvals")
_audit_file = Path("logs/audit.jsonl")
logger = logging.getLogger(__name__)

# Pending/approved write requests are valid for 15 minutes from creation.
APPROVAL_TTL_SECONDS = 15 * 60
MAX_PENDING_APPROVALS_PER_REQUESTER = 10
MAX_APPROVAL_REQUESTS_PER_UTC_DAY = 100
# A persisted wall-clock timestamp this far ahead of the current clock is
# treated as invalid. This makes significant clock rollback fail closed.
MAX_APPROVAL_CLOCK_SKEW_SECONDS = 60


def _approval_expired(created: float, now: float | None = None) -> bool:
    """Fail closed on expiry and on a clock that moved behind record creation."""
    current_time = time.time() if now is None else now
    if created > current_time + MAX_APPROVAL_CLOCK_SKEW_SECONDS:
        return True
    return current_time - created > APPROVAL_TTL_SECONDS


class CorruptApprovalRecordError(ValueError):
    """An approval record is malformed or does not match its filename."""


class AuditLogIntegrityError(RuntimeError):
    """The append-only audit log contains an incomplete or invalid entry."""


class ApprovalAuditError(RuntimeError):
    """A request was stored but its audit state could not be confirmed."""

    def __init__(self, approval_id: str):
        super().__init__("approval_audit_incomplete")
        self.approval_id = approval_id


class ApprovalLimitError(RuntimeError):
    """A requester reached an approval creation quota."""

    def __init__(self, limit: str):
        super().__init__(limit)
        self.limit = limit


class ApprovalStoreIntegrityError(RuntimeError):
    """The approval store cannot be safely scanned for quota enforcement."""


def _ensure_dirs() -> None:
    ensure_private_directory(_approvals_dir)
    ensure_private_directory(_audit_file.parent)


def _approval_path(approval_id: str) -> Path | None:
    """Return a path only for a valid 128-bit approval ID."""
    if not isinstance(approval_id, str) or not re.fullmatch(
        r"[0-9a-f]{32}", approval_id
    ):
        return None
    return _approvals_dir / f"{approval_id}.json"


@contextmanager
def _locked_record(path: Path) -> Iterator[None]:
    """Serialize state transitions using an owner-only, no-follow lock file."""
    lock_path = path.with_suffix(path.suffix + ".lock")
    fd = open_private_file(lock_path, os.O_RDWR | os.O_CREAT)
    with os.fdopen(fd, "r+") as lock_file:
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)


@contextmanager
def _locked_request_creation() -> Iterator[None]:
    """Serialize requester quota checks across threads and worker processes."""
    lock_path = _approvals_dir / ".request.lock"
    fd = open_private_file(lock_path, os.O_RDWR | os.O_CREAT)
    with os.fdopen(fd, "r+") as lock_file:
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)


def _requester_usage(requester: str, now: float) -> tuple[int, int]:
    """Count active pending and all same-UTC-day requests for one identity."""
    day_start = int(now // 86_400) * 86_400
    day_end = day_start + 86_400
    pending = 0
    daily = 0
    for path in _approvals_dir.glob("*.json"):
        if path.is_symlink():
            raise ApprovalStoreIntegrityError(
                "approval store contains a symlink; operator review required"
            )
        try:
            record = _load_approval_record(path, path.stem)
        except (OSError, CorruptApprovalRecordError) as exc:
            raise ApprovalStoreIntegrityError(
                "approval store contains an unreadable record; operator review required"
            ) from exc
        if record["requester"] != requester:
            continue
        created = float(record["created"])
        if created > now + MAX_APPROVAL_CLOCK_SKEW_SECONDS:
            raise ApprovalStoreIntegrityError(
                "approval store contains a future-dated record; operator review required"
            )
        if day_start <= created < day_end:
            daily += 1
        if record["status"] == "pending" and not _approval_expired(created, now):
            pending += 1
    return pending, daily


def _write_record_atomically(path: Path, record: dict[str, Any]) -> None:
    """Replace a record atomically with mode 0600 and durable directory metadata."""
    write_text_atomically(
        path,
        json.dumps(record, indent=2),
        _approvals_dir,
    )


def request_approval(
    tool: str, args: dict[str, Any], requester: str = "agent"
) -> dict[str, Any]:
    """Create an approval owned by an authenticated requester identity."""
    if not isinstance(tool, str) or not tool.strip() or len(tool) > 120:
        raise ValueError("A valid approval tool name is required")
    if not isinstance(args, dict):
        raise ValueError("Approval arguments must be a dictionary")
    if not isinstance(requester, str) or not requester.strip() or len(requester) > 256:
        raise ValueError("A valid requester identity is required")
    try:
        json.dumps(args, allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise ValueError("Approval arguments must be finite JSON data") from exc
    _ensure_dirs()
    now = time.time()
    record = {
        "tool": tool,
        "args": args,
        "requester": requester,
        "status": "pending",
        "request_audit_status": "pending",
        "created": now,
    }
    with _locked_request_creation():
        pending_count, daily_count = _requester_usage(requester, now)
        if pending_count >= MAX_PENDING_APPROVALS_PER_REQUESTER:
            raise ApprovalLimitError("pending_approval_limit")
        if daily_count >= MAX_APPROVAL_REQUESTS_PER_UTC_DAY:
            raise ApprovalLimitError("daily_approval_limit")
        while True:
            approval_id = secrets.token_hex(16)
            path = _approval_path(approval_id)
            assert path is not None
            record["id"] = approval_id
            try:
                fd = open_private_file(
                    path, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                )
            except FileExistsError:
                continue
            # Reserve the random identifier without exposing a partially written
            # JSON record. The placeholder is fail-closed if the process crashes;
            # the complete record becomes visible in one atomic replacement.
            os.close(fd)
            try:
                _write_record_atomically(path, record)
            except Exception:
                try:
                    path.unlink(missing_ok=True)
                    fsync_directory(_approvals_dir)
                except OSError:
                    logger.exception(
                        "failed to clean incomplete approval reservation",
                        extra={"approval_id": approval_id},
                    )
                raise
            break
    # The request is not approvable until its audit append and durable
    # status marker both succeed. The initial pending marker fails closed.
    try:
        audit_record = dict(record)
        audit_record["request_audit_status"] = "written"
        log_audit("request", audit_record)
    except Exception as exc:
        record["request_audit_status"] = "failed"
        record["request_audit_error_type"] = type(exc).__name__[:120]
        try:
            _write_record_atomically(path, record)
        except Exception:
            pass
        raise ApprovalAuditError(approval_id) from exc

    record["request_audit_status"] = "written"
    try:
        _write_record_atomically(path, record)
    except Exception as exc:
        raise ApprovalAuditError(approval_id) from exc
    return record


def _load_approval_record(path: Path, approval_id: str) -> dict[str, Any]:
    """Load and validate a record before any state transition."""
    if _approval_path(approval_id) is None:
        raise CorruptApprovalRecordError("approval filename has an invalid ID")
    try:
        data = json.loads(read_private_text(path))
    except FileNotFoundError:
        raise
    except ValueError as exc:
        raise CorruptApprovalRecordError("approval record is malformed") from exc
    if not isinstance(data, dict) or data.get("id") != approval_id:
        raise CorruptApprovalRecordError("approval record identity mismatch")
    required = {
        "id",
        "tool",
        "args",
        "requester",
        "status",
        "request_audit_status",
        "created",
    }
    if not required.issubset(data):
        raise CorruptApprovalRecordError("approval record is missing required fields")
    if not isinstance(data["tool"], str) or not data["tool"]:
        raise CorruptApprovalRecordError("invalid approval tool")
    if (
        not isinstance(data["args"], dict)
        or not isinstance(data["requester"], str)
        or not data["requester"].strip()
    ):
        raise CorruptApprovalRecordError("invalid approval payload or requester")

    valid_statuses = {"pending", "approved", "denied", "consumed"}
    valid_audit_statuses = {"pending", "written", "failed"}
    if not isinstance(data["status"], str) or data["status"] not in valid_statuses:
        raise CorruptApprovalRecordError("invalid approval state")
    if (
        not isinstance(data["request_audit_status"], str)
        or data["request_audit_status"] not in valid_audit_statuses
    ):
        raise CorruptApprovalRecordError("invalid request audit state")

    created = data["created"]
    if (
        isinstance(created, bool)
        or not isinstance(created, (int, float))
        or not math.isfinite(created)
    ):
        raise CorruptApprovalRecordError("invalid approval creation time")

    approval_audit_status = data.get("approval_audit_status")
    if "approval_audit_status" in data and (
        not isinstance(approval_audit_status, str)
        or approval_audit_status not in valid_audit_statuses
    ):
        raise CorruptApprovalRecordError("invalid approval audit state")
    if (
        data["status"] in {"approved", "denied", "consumed"}
        and "approval_audit_status" not in data
    ):
        raise CorruptApprovalRecordError("missing approval audit state")
    if (
        data["status"] == "consumed"
        and data.get("approval_audit_status") != "written"
    ):
        raise CorruptApprovalRecordError("consumed approval has incomplete approval audit")

    for timestamp_field in ("approved_at", "denied_at", "consumed_at"):
        timestamp = data.get(timestamp_field)
        if timestamp is not None and (
            isinstance(timestamp, bool)
            or not isinstance(timestamp, (int, float))
            or not math.isfinite(timestamp)
        ):
            raise CorruptApprovalRecordError(
                f"invalid approval timestamp: {timestamp_field}"
            )

    for text_field in ("approver", "reason", "approval_audit_error_type"):
        value = data.get(text_field)
        if value is not None and not isinstance(value, str):
            raise CorruptApprovalRecordError(f"invalid approval field: {text_field}")

    execution_failure = data.get("execution_failure")
    if execution_failure is not None:
        if not isinstance(execution_failure, dict):
            raise CorruptApprovalRecordError("invalid execution failure metadata")
        failed_at = execution_failure.get("failed_at")
        if (
            isinstance(failed_at, bool)
            or not isinstance(failed_at, (int, float))
            or not math.isfinite(failed_at)
            or not isinstance(execution_failure.get("error_type"), str)
            or not isinstance(execution_failure.get("error_message"), str)
        ):
            raise CorruptApprovalRecordError("invalid execution failure metadata")
    execution = data.get("execution_outcome")
    if execution is not None:
        if not isinstance(execution, dict):
            raise CorruptApprovalRecordError("invalid execution outcome metadata")
        outcome_status = execution.get("status")
        started_at = execution.get("started_at")
        if (
            data["status"] != "consumed"
            or outcome_status not in {
                "started", "completed", "failed", "uncertain", "blocked"
            }
            or isinstance(started_at, bool)
            or not isinstance(started_at, (int, float))
            or not math.isfinite(started_at)
        ):
            raise CorruptApprovalRecordError("invalid execution outcome metadata")
        if outcome_status == "completed":
            completed_at = execution.get("completed_at")
            if (
                isinstance(completed_at, bool)
                or not isinstance(completed_at, (int, float))
                or not math.isfinite(completed_at)
                or execution.get("audit_status") not in {"pending", "written", "failed"}
            ):
                raise CorruptApprovalRecordError("invalid completed execution outcome")
        elif outcome_status != "started":
            finished_at = execution.get("finished_at")
            if (
                isinstance(finished_at, bool)
                or not isinstance(finished_at, (int, float))
                or not math.isfinite(finished_at)
                or execution.get("audit_status") not in {"pending", "written", "failed"}
                or not isinstance(execution.get("error_type"), str)
                or not isinstance(execution.get("error_message"), str)
            ):
                raise CorruptApprovalRecordError("invalid failed execution outcome")
    return data


def check_approval(approval_id: str) -> dict[str, Any]:
    _ensure_dirs()
    path = _approval_path(approval_id)
    if path is None:
        return {"status": "invalid_id", "id": approval_id}
    try:
        return _load_approval_record(path, approval_id)
    except FileNotFoundError:
        return {"status": "not_found", "id": approval_id}
    except CorruptApprovalRecordError:
        logger.exception(
    "approval record requires operator review",
    extra={"approval_id": approval_id},
        )
        return {"status": "corrupt_record", "id": approval_id}


def _transition(
    approval_id: str,
    target_status: str,
    approver_key: str,
    reason: str | None = None,
) -> dict[str, Any]:
    if not auth.verify_approver_key(approver_key):
        return {"status": "unauthorized", "id": approval_id}
    approver = auth.approver_identity(approver_key)
    _ensure_dirs()
    path = _approval_path(approval_id)
    if path is None:
        return {"status": "invalid_id", "id": approval_id}

    with _locked_record(path):
        try:
            data = _load_approval_record(path, approval_id)
        except FileNotFoundError:
            return {"status": "not_found", "id": approval_id}
        except CorruptApprovalRecordError:
            logger.exception(
    "approval record requires operator review",
    extra={"approval_id": approval_id},
            )
            return {"status": "corrupt_record", "id": approval_id}

        if data.get("status") != "pending":
            return {
                "status": "invalid_transition",
                "id": approval_id,
                "current_status": data.get("status"),
            }

        if _approval_expired(data["created"]):
            return {"status": "expired", "id": approval_id}

        # Distinct credentials are not sufficient if both roles resolve to
        # the same configured principal. Enforce separation of identities too.
        if data.get("requester") == approver:
            return {"status": "self_approval_denied", "id": approval_id}

        if data.get("request_audit_status") != "written":
            return {
                "status": "approval_audit_incomplete",
                "id": approval_id,
                "current_status": data.get("status"),
                "audit_phase": "request",
                "audit_status": data.get("request_audit_status", "missing"),
            }

        data["status"] = target_status
        data["approver"] = approver
        if target_status == "approved":
            data["approved_at"] = time.time()
            action = "approved"
        else:
            data["reason"] = reason or ""
            data["denied_at"] = time.time()
            action = "denied"

        # Commit the terminal transition first, but keep it non-executable
        # until its audit event is durably appended and the record is updated.
        data["approval_audit_status"] = "pending"
        _write_record_atomically(path, data)
        try:
            audit_record = dict(data)
            audit_record["approval_audit_status"] = "written"
            log_audit(action, audit_record)
        except Exception as exc:
            data["approval_audit_status"] = "failed"
            data["approval_audit_error_type"] = type(exc).__name__[:120]
            try:
                _write_record_atomically(path, data)
            except Exception:
                # "pending" remains fail-closed if the failure marker cannot
                # be persisted. Operators must inspect the audit and record.
                pass
            result = dict(data)
            result["status"] = "approval_audit_incomplete"
            result["approval_status"] = target_status
            return result

        data["approval_audit_status"] = "written"
        try:
            _write_record_atomically(path, data)
        except Exception as exc:
            # The audit event exists, but the record remains pending and
            # therefore cannot be consumed. Require operator reconciliation.
            result = dict(data)
            result["status"] = "approval_audit_incomplete"
            result["approval_status"] = target_status
            result["audit_error_type"] = type(exc).__name__[:120]
            return result
        return data


def approve(approval_id: str, approver_key: str) -> dict[str, Any]:
    """Approve a pending request using a configured approver credential."""
    return _transition(approval_id, "approved", approver_key)


def deny(
    approval_id: str, approver_key: str, reason: str = ""
) -> dict[str, Any]:
    """Deny a pending request using a configured approver credential."""
    return _transition(approval_id, "denied", approver_key, reason)


def record_execution_failure(
    approval_id: str, error_type: str, error_message: str,
    outcome_status: str = "failed",
) -> dict[str, Any]:
    """Record failed side effects without reopening a consumed approval.

    The approved payload remains in the private record for operator-led
    recovery. This function never changes status back to approved.
    """
    _ensure_dirs()
    path = _approval_path(approval_id)
    if path is None:
        return {"status": "invalid_id", "id": approval_id}

    with _locked_record(path):
        try:
            data = _load_approval_record(path, approval_id)
        except FileNotFoundError:
            return {"status": "not_found", "id": approval_id}
        except CorruptApprovalRecordError:
            logger.exception(
    "approval record requires operator review",
    extra={"approval_id": approval_id},
            )
            return {"status": "corrupt_record", "id": approval_id}

        if data.get("status") != "consumed":
            return {
                "status": "invalid_transition",
                "id": approval_id,
                "current_status": data.get("status"),
            }

        if outcome_status not in {"failed", "uncertain", "blocked"}:
            raise ValueError("Invalid execution outcome status")
        now = time.time()
        data["execution_failure"] = {
            "failed_at": now,
            "error_type": error_type[:120],
            "error_message": error_message[:1000],
        }
        previous = data.get("execution_outcome", {})
        started_at = previous.get("started_at", data.get("consumed_at", now))
        data["execution_outcome"] = {
            "status": outcome_status, "started_at": started_at,
            "finished_at": now, "audit_status": "pending",
            "error_type": error_type[:120], "error_message": error_message[:1000],
        }
        _write_record_atomically(path, data)
        audit_record = dict(data)
        audit_record["execution_outcome"] = dict(data["execution_outcome"])
        audit_record["execution_outcome"]["audit_status"] = "written"
        try:
            log_audit("execution_failed", audit_record)
        except Exception as exc:
            data["execution_outcome"]["audit_status"] = "failed"
            try:
                _write_record_atomically(path, data)
            except Exception:
                logger.exception("failed to persist execution audit failure marker",
                                 extra={"approval_id": approval_id})
            result = dict(data)
            result["audit_status"] = "failed"
            result["audit_error_type"] = type(exc).__name__[:120]
            return result
        data["execution_outcome"]["audit_status"] = "written"
        try:
            _write_record_atomically(path, data)
        except Exception as exc:
            result = dict(data)
            result["audit_status"] = "record_update_failed"
            result["audit_error_type"] = type(exc).__name__[:120]
            return result
        result = dict(data)
        result["audit_status"] = "written"
        return result


def record_execution_success(approval_id: str) -> dict[str, Any]:
    """Persist a completed side effect and append its audit event."""
    _ensure_dirs()
    path = _approval_path(approval_id)
    if path is None:
        return {"status": "invalid_id", "id": approval_id}
    with _locked_record(path):
        try:
            data = _load_approval_record(path, approval_id)
        except FileNotFoundError:
            return {"status": "not_found", "id": approval_id}
        except CorruptApprovalRecordError:
            return {"status": "corrupt_record", "id": approval_id}
        execution = data.get("execution_outcome")
        if (
            data.get("status") != "consumed"
            or data.get("approval_audit_status") != "written"
            or not isinstance(execution, dict)
            or execution.get("status") != "started"
        ):
            return {"status": "invalid_transition", "id": approval_id}
        data["execution_outcome"] = {
            "status": "completed", "started_at": execution["started_at"],
            "completed_at": time.time(), "audit_status": "pending",
        }
        try:
            _write_record_atomically(path, data)
        except Exception as exc:
            logger.error(
                "note write completed but execution outcome could not be persisted",
                exc_info=exc,
                extra={"approval_id": approval_id},
            )
            return {"status": "execution_outcome_recording_failed", "id": approval_id}
        audit_record = dict(data)
        audit_record["execution_outcome"] = dict(data["execution_outcome"])
        audit_record["execution_outcome"]["audit_status"] = "written"
        try:
            log_audit("execution_succeeded", audit_record)
        except Exception:
            data["execution_outcome"]["audit_status"] = "failed"
            try:
                _write_record_atomically(path, data)
            except Exception:
                logger.exception(
                    "failed to persist successful execution audit failure marker",
                    extra={"approval_id": approval_id},
                )
            return {"status": "execution_succeeded_audit_incomplete", "id": approval_id}
        data["execution_outcome"]["audit_status"] = "written"
        try:
            _write_record_atomically(path, data)
        except Exception as exc:
            logger.error("success audit exists but final outcome marker update failed",
                         exc_info=exc, extra={"approval_id": approval_id})
            return {"status": "execution_succeeded_audit_incomplete", "id": approval_id}
        return {"status": "completed", "id": approval_id}


def consume_approval_request(
    approval_id: str,
    tool: str,
    args: dict[str, Any] | None = None,
    requester: str | None = None,
) -> dict[str, Any]:
    """Atomically consume an approved operation and return its stored payload.

    When args is supplied, it must exactly match the approved arguments.
    Execution must provide the authenticated requester identity; ownership is
    checked under the same lock before the one-time consume transition.
    """
    _ensure_dirs()
    path = _approval_path(approval_id)
    if path is None:
        return {"status": "invalid_id", "id": approval_id}

    with _locked_record(path):
        try:
            data = _load_approval_record(path, approval_id)
        except FileNotFoundError:
            return {"status": "not_found", "id": approval_id}
        except CorruptApprovalRecordError:
            logger.exception(
    "approval record requires operator review",
    extra={"approval_id": approval_id},
            )
            return {"status": "corrupt_record", "id": approval_id}

        if data.get("status") == "pending":
            return {"status": "pending", "id": approval_id}
        if data.get("status") != "approved":
            return {
                "status": "invalid_transition",
                "id": approval_id,
                "current_status": data.get("status"),
            }

        if _approval_expired(data["created"]):
            return {"status": "expired", "id": approval_id}

        if data.get("approval_audit_status") != "written":
            return {
                "status": "approval_audit_incomplete",
                "id": approval_id,
                "current_status": data.get("status"),
                "audit_status": data.get("approval_audit_status", "missing"),
            }

        if not requester or data.get("requester") != requester:
            return {"status": "requester_mismatch", "id": approval_id}

        if data.get("tool") != tool or (
            args is not None and data.get("args") != args
        ):
            return {"status": "approval_mismatch", "id": approval_id}

        data["status"] = "consumed"
        data["consumed_at"] = time.time()
        data["execution_outcome"] = {
            "status": "started", "started_at": data["consumed_at"]
        }
        _write_record_atomically(path, data)
        # The state transition is durable before the audit append. If the
        # append fails, return the consumed record with an explicit marker so
        # callers fail closed and never perform the approved side effect.
        try:
            log_audit("consumed", data)
        except Exception as exc:
            result = dict(data)
            result["audit_status"] = "failed"
            result["audit_error_type"] = type(exc).__name__[:120]
            return result
        result = dict(data)
        result["audit_status"] = "written"
        return result


def consume_approval(
    approval_id: str,
    tool: str,
    args: dict[str, Any],
    requester: str | None = None,
) -> dict[str, Any]:
    """Consume an approval only for its owner and exact approved args."""
    return consume_approval_request(approval_id, tool, args, requester)


def _canonical_audit_entry(entry: dict[str, Any]) -> bytes:
    """Serialize an audit entry deterministically, excluding its own hash."""
    payload = {key: value for key, value in entry.items() if key != "hash"}
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _validate_audit_event(entry: Any, line_number: int) -> None:
    def invalid() -> None:
        raise AuditLogIntegrityError(
            f"audit log entry {line_number} has an invalid event schema"
        )

    if (
        not isinstance(entry, dict)
        or not isinstance(entry.get("action"), str)
        or entry.get("action") not in {
            "request", "approved", "denied", "consumed",
            "execution_failed", "execution_succeeded",
        }
        or isinstance(entry.get("time"), bool)
        or not isinstance(entry.get("time"), (int, float))
        or not math.isfinite(entry["time"])
        or not isinstance(entry.get("record"), dict)
    ):
        invalid()
    record = entry["record"]
    if (
        not isinstance(record.get("id"), str)
        or not re.fullmatch(r"[0-9a-f]{32}", record["id"])
        or not isinstance(record.get("tool"), str)
        or not record["tool"].strip()
        or len(record["tool"]) > 120
        or (
            not isinstance(record.get("args"), dict)
            and not (
                isinstance(record.get("args_sha256"), str)
                and re.fullmatch(r"[0-9a-f]{64}", record["args_sha256"])
            )
        )
        or ("args" in record and "args_sha256" in record)
        or not isinstance(record.get("requester"), str)
        or not record["requester"].strip()
        or len(record["requester"]) > 256
        or record.get("request_audit_status") != "written"
        or isinstance(record.get("created"), bool)
        or not isinstance(record.get("created"), (int, float))
        or not math.isfinite(record["created"])
    ):
        invalid()

    action = entry["action"]
    status = record.get("status")
    base_fields = {
        "id", "tool", "requester", "status",
        "request_audit_status", "created",
        "args" if "args" in record else "args_sha256",
    }
    action_fields = {
        "request": set(),
        "approved": {"approval_audit_status", "approver", "approved_at"},
        "denied": {
            "approval_audit_status", "approver", "denied_at", "reason",
        },
        "consumed": {
            "approval_audit_status", "approver", "approved_at", "consumed_at",
        },
        "execution_failed": {
            "approval_audit_status", "approver", "approved_at", "consumed_at",
            "execution_failure",
        },
        "execution_succeeded": {
            "approval_audit_status", "approver", "approved_at", "consumed_at",
            "execution_outcome",
        },
    }
    expected = base_fields | action_fields[action]
    allowed = {frozenset(expected)}
    if action in {"consumed", "execution_failed"}:
        allowed.add(frozenset(expected | {"execution_outcome"}))
    if frozenset(record) not in allowed:
        invalid()
    if action == "request":
        if status != "pending":
            invalid()
    elif action in {"approved", "denied"}:
        expected = "approved" if action == "approved" else "denied"
        timestamp = "approved_at" if action == "approved" else "denied_at"
        if (
            status != expected
            or record.get("approval_audit_status") != "written"
            or not isinstance(record.get("approver"), str)
            or not record["approver"].strip()
            or isinstance(record.get(timestamp), bool)
            or not isinstance(record.get(timestamp), (int, float))
            or not math.isfinite(record[timestamp])
        ):
            invalid()
        if action == "denied" and (
            not isinstance(record.get("reason"), str)
            or len(record["reason"]) > 2000
        ):
            invalid()
    elif action == "consumed":
        if (
            status != "consumed"
            or record.get("approval_audit_status") != "written"
            or not isinstance(record.get("approver"), str)
            or not record["approver"].strip()
            or isinstance(record.get("approved_at"), bool)
            or not isinstance(record.get("approved_at"), (int, float))
            or not math.isfinite(record["approved_at"])
            or isinstance(record.get("consumed_at"), bool)
            or not isinstance(record.get("consumed_at"), (int, float))
            or not math.isfinite(record["consumed_at"])
        ):
            invalid()
        if "execution_outcome" in record:
            outcome = record["execution_outcome"]
            if (
                not isinstance(outcome, dict)
                or outcome.get("status") != "started"
                or outcome.get("started_at") != record["consumed_at"]
            ):
                invalid()
    elif action == "execution_succeeded":
        outcome = record.get("execution_outcome")
        if (
            status != "consumed" or record.get("approval_audit_status") != "written"
            or not isinstance(outcome, dict) or outcome.get("status") != "completed"
            or outcome.get("audit_status") != "written"
            or isinstance(outcome.get("started_at"), bool)
            or not isinstance(outcome.get("started_at"), (int, float))
            or not math.isfinite(outcome["started_at"])
            or isinstance(outcome.get("completed_at"), bool)
            or not isinstance(outcome.get("completed_at"), (int, float))
            or not math.isfinite(outcome["completed_at"])
        ):
            invalid()
    else:
        failure = record.get("execution_failure")
        if (
            status != "consumed"
            or record.get("approval_audit_status") != "written"
            or not isinstance(record.get("approver"), str)
            or not record["approver"].strip()
            or isinstance(record.get("approved_at"), bool)
            or not isinstance(record.get("approved_at"), (int, float))
            or not math.isfinite(record["approved_at"])
            or isinstance(record.get("consumed_at"), bool)
            or not isinstance(record.get("consumed_at"), (int, float))
            or not math.isfinite(record["consumed_at"])
            or not isinstance(failure, dict)
            or isinstance(failure.get("failed_at"), bool)
            or not isinstance(failure.get("failed_at"), (int, float))
            or not math.isfinite(failure["failed_at"])
            or not isinstance(failure.get("error_type"), str)
            or not failure["error_type"].strip()
            or len(failure["error_type"]) > 120
            or not isinstance(failure.get("error_message"), str)
            or len(failure["error_message"]) > 1000
        ):
            invalid()
        if "execution_outcome" in record:
            outcome = record["execution_outcome"]
            if (
                not isinstance(outcome, dict)
                or outcome.get("status") not in {"failed", "uncertain", "blocked"}
                or outcome.get("audit_status") != "written"
                or not isinstance(outcome.get("error_type"), str)
                or not isinstance(outcome.get("error_message"), str)
            ):
                invalid()
    try:
        _canonical_audit_entry(entry)
    except (TypeError, ValueError, OverflowError) as exc:
        raise AuditLogIntegrityError(
            f"audit log entry {line_number} cannot be canonically serialized"
        ) from exc


def _validate_legacy_audit_event(entry: Any, line_number: int) -> None:
    if (
        not isinstance(entry, dict)
        or not isinstance(entry.get("action"), str)
        or entry.get("action") not in {
            "request", "approved", "denied", "consumed", "execution_failed",
            "execution_succeeded",
        }
        or isinstance(entry.get("time"), bool)
        or not isinstance(entry.get("time"), (int, float))
        or not math.isfinite(entry["time"])
        or not isinstance(entry.get("record"), dict)
    ):
        raise AuditLogIntegrityError(
            f"legacy audit entry {line_number} has an invalid schema"
        )


def _reject_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _audit_chain_state(contents: bytes) -> tuple[int, str, int, int, dict[int, str]]:
    """Validate legacy and chained entries; return seq, head hash, total count.

    Legacy JSONL entries are accepted as an immutable prefix. The first chained
    entry commits to the exact bytes of that prefix, so later edits to legacy
    history are detected. New entries use SHA-256 over canonical JSON.
    """
    if not contents:
        return 0, "0" * 64, 0, 0, {0: "0" * 64}
    if not contents.endswith(b"\n"):
        raise AuditLogIntegrityError(
            "audit log has an incomplete trailing entry; operator review required"
        )

    legacy_lines: list[bytes] = []
    sequence = 0
    previous_hash = "0" * 64
    total = 0
    legacy_count = 0
    chain_hashes: dict[int, str] = {0: "0" * 64}
    chain_started = False

    for line_number, raw_line in enumerate(
        contents.splitlines(keepends=True), start=1
    ):
        line = raw_line.rstrip(b"\r\n")
        try:
            entry = json.loads(line, object_pairs_hook=_reject_duplicate_json_keys)
        except ValueError as exc:
            raise AuditLogIntegrityError(
                f"audit log entry {line_number} is invalid; operator review required"
            ) from exc

        if isinstance(entry, dict) and set(entry) == {"action", "time", "record"}:
            if chain_started:
                raise AuditLogIntegrityError(
                    f"legacy entry {line_number} appears after the hash chain began"
                )
            _validate_legacy_audit_event(entry, line_number)
            legacy_lines.append(raw_line)
            legacy_count += 1
            total += 1
            continue

        expected_fields = {
            "action", "time", "record", "seq", "previous_hash", "hash"
        }
        if not isinstance(entry, dict) or set(entry) != expected_fields:
            raise AuditLogIntegrityError(
                f"audit log entry {line_number} has an invalid schema"
            )
        _validate_audit_event(entry, line_number)
        seq = entry.get("seq")
        if isinstance(seq, bool) or not isinstance(seq, int) or seq != sequence + 1:
            raise AuditLogIntegrityError(
                f"audit log sequence mismatch at entry {line_number}"
            )
        if not isinstance(entry.get("previous_hash"), str) or not re.fullmatch(
            r"[0-9a-f]{64}", entry["previous_hash"]
        ):
            raise AuditLogIntegrityError(
                f"audit log previous hash is invalid at entry {line_number}"
            )
        if not isinstance(entry.get("hash"), str) or not re.fullmatch(
            r"[0-9a-f]{64}", entry["hash"]
        ):
            raise AuditLogIntegrityError(
                f"audit log hash is invalid at entry {line_number}"
            )

        if not chain_started:
            expected_previous = (
                hashlib.sha256(
                    b"legacy-audit-prefix-v1\\0" + b"".join(legacy_lines)
                ).hexdigest()
                if legacy_lines else "0" * 64
            )
            chain_hashes[0] = expected_previous
        else:
            expected_previous = previous_hash
        if not hmac.compare_digest(entry["previous_hash"], expected_previous):
            raise AuditLogIntegrityError(
                f"audit log link mismatch at entry {line_number}"
            )
        calculated = hashlib.sha256(_canonical_audit_entry(entry)).hexdigest()
        if not hmac.compare_digest(entry["hash"], calculated):
            raise AuditLogIntegrityError(
                f"audit log hash mismatch at entry {line_number}"
            )
        sequence = seq
        previous_hash = entry["hash"]
        chain_hashes[sequence] = previous_hash
        chain_started = True
        total += 1

    if not chain_started and legacy_lines:
        previous_hash = hashlib.sha256(
            b"legacy-audit-prefix-v1\\0" + b"".join(legacy_lines)
        ).hexdigest()
    if not chain_started and legacy_lines:
        chain_hashes[0] = previous_hash
    return sequence, previous_hash, total, legacy_count, chain_hashes


def _validate_audit_bytes(contents: bytes) -> None:
    """Reject malformed, incomplete, reordered, or hash-mismatched history."""
    _audit_chain_state(contents)


MAX_AUDIT_LOG_BYTES = 64 * 1024 * 1024


def _audit_safe_record(record: dict[str, Any]) -> dict[str, Any]:
    """Replace potentially sensitive operation arguments with a stable digest."""
    safe_record = dict(record)
    args = safe_record.pop("args", None)
    if not isinstance(args, dict):
        raise AuditLogIntegrityError("audit record is missing operation arguments")
    try:
        canonical_args = json.dumps(
            args, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, OverflowError) as exc:
        raise AuditLogIntegrityError(
            "audit record arguments cannot be fingerprinted"
        ) from exc
    safe_record["args_sha256"] = hashlib.sha256(canonical_args).hexdigest()
    return safe_record


def log_audit(action: str, record: dict[str, Any]) -> None:
    """Append one durable JSONL event without storing operation payloads."""
    _ensure_dirs()
    entry = {
        "action": action,
        "time": time.time(),
        "record": _audit_safe_record(record),
    }
    fd = open_private_file(_audit_file, os.O_RDWR | os.O_CREAT)
    with os.fdopen(fd, "r+b") as audit_file:
        fcntl.flock(audit_file.fileno(), fcntl.LOCK_EX)
        try:
            audit_file.seek(0)
            existing = audit_file.read(MAX_AUDIT_LOG_BYTES + 1)
            if len(existing) > MAX_AUDIT_LOG_BYTES:
                raise AuditLogIntegrityError(
                    "audit log exceeds the configured 64 MiB validation limit; "
                    "archive through operator procedure"
                )
            sequence, previous_hash, _, _, _ = _audit_chain_state(existing)
            _validate_audit_event(entry, sequence + 1)
            entry["seq"] = sequence + 1
            entry["previous_hash"] = previous_hash
            entry["hash"] = hashlib.sha256(_canonical_audit_entry(entry)).hexdigest()
            encoded = (
                json.dumps(
                    entry,
                    separators=(",", ":"),
                    ensure_ascii=False,
                    allow_nan=False,
                )
                + "\n"
            ).encode("utf-8")
            audit_file.seek(0, os.SEEK_END)
            original_size = audit_file.tell()
            view = memoryview(encoded)
            try:
                while view:
                    written = os.write(audit_file.fileno(), view)
                    if written <= 0:
                        raise OSError("audit append made no forward progress")
                    view = view[written:]
                os.fsync(audit_file.fileno())
            except Exception:
                # Roll back a failed in-process append while still holding the
                # exclusive lock. A process crash may leave a tail fragment;
                # the next writer detects it and refuses to extend the log.
                try:
                    os.ftruncate(audit_file.fileno(), original_size)
                    os.fsync(audit_file.fileno())
                except OSError:
                    logger.exception(
                        "audit append rollback failed; operator review required"
                    )
                raise
        finally:
            fcntl.flock(audit_file.fileno(), fcntl.LOCK_UN)


def create_audit_checkpoint() -> dict[str, Any]:
    """Return a checkpoint for storage independently of this machine."""
    result = verify_audit_log()
    return {
        "version": 1,
        "sequence": result["chained_entries"],
        "legacy_entries": result["legacy_entries"],
        "head_hash": result["head_hash"],
        "created_at": time.time(),
    }


def verify_audit_log(
    expected_checkpoint: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Verify local history and, optionally, an independently retained head.

    An older checkpoint remains valid as the log grows. The verifier confirms
    the hash at the checkpoint sequence, detecting truncation past that point.
    """
    _ensure_dirs()
    fd = open_private_file(_audit_file, os.O_RDWR | os.O_CREAT)
    with os.fdopen(fd, "r+b") as audit_file:
        fcntl.flock(audit_file.fileno(), fcntl.LOCK_EX)
        try:
            contents = audit_file.read(MAX_AUDIT_LOG_BYTES + 1)
            if len(contents) > MAX_AUDIT_LOG_BYTES:
                raise AuditLogIntegrityError(
                    "audit log exceeds the configured 64 MiB validation limit"
                )
            sequence, head_hash, total, legacy_count, chain_hashes = (
                _audit_chain_state(contents)
            )
            result = {
                "valid": True,
                "entries": total,
                "legacy_entries": legacy_count,
                "chained_entries": sequence,
                "head_hash": head_hash,
            }
            if expected_checkpoint is not None:
                checkpoint = expected_checkpoint
                if (
                    not isinstance(checkpoint, dict)
                    or set(checkpoint) != {
                        "version", "sequence", "legacy_entries",
                        "head_hash", "created_at",
                    }
                    or isinstance(checkpoint.get("version"), bool)
                    or checkpoint.get("version") != 1
                    or isinstance(checkpoint.get("sequence"), bool)
                    or not isinstance(checkpoint.get("sequence"), int)
                    or checkpoint["sequence"] < 0
                    or isinstance(checkpoint.get("legacy_entries"), bool)
                    or not isinstance(checkpoint.get("legacy_entries"), int)
                    or checkpoint["legacy_entries"] < 0
                    or not isinstance(checkpoint.get("head_hash"), str)
                    or not re.fullmatch(r"[0-9a-f]{64}", checkpoint["head_hash"])
                    or isinstance(checkpoint.get("created_at"), bool)
                    or not isinstance(checkpoint.get("created_at"), (int, float))
                    or not math.isfinite(checkpoint["created_at"])
                    or checkpoint["created_at"] <= 0
                ):
                    raise AuditLogIntegrityError("audit checkpoint is malformed")
                checkpoint_seq = checkpoint["sequence"]
                if (
                    sequence < checkpoint_seq
                    or legacy_count != checkpoint["legacy_entries"]
                    or checkpoint_seq not in chain_hashes
                    or not hmac.compare_digest(
                        chain_hashes[checkpoint_seq], checkpoint["head_hash"]
                    )
                ):
                    raise AuditLogIntegrityError(
                        "audit log is truncated or diverges from the external checkpoint"
                    )
                result["checkpoint_verified"] = True
                result["checkpoint_sequence"] = checkpoint_seq
            return result
        finally:
            fcntl.flock(audit_file.fileno(), fcntl.LOCK_UN)


def list_execution_recovery() -> list[dict[str, Any]]:
    """List consumed executions needing inspection without exposing note content."""
    _ensure_dirs()
    recovery: list[dict[str, Any]] = []
    for path in _approvals_dir.glob("*.json"):
        if path.is_symlink():
            recovery.append({
                "approval_id": path.stem,
                "execution_status": "symlink_record",
                "execution_audit_status": None,
            })
            continue
        approval_id = path.stem
        try:
            data = _load_approval_record(path, approval_id)
        except (OSError, CorruptApprovalRecordError):
            logger.exception(
                "corrupt execution record requires operator review",
                extra={"approval_id": approval_id},
            )
            recovery.append({
                "approval_id": approval_id,
                "execution_status": "corrupt_record",
                "execution_audit_status": None,
            })
            continue
        if data.get("status") != "consumed":
            continue
        outcome = data.get("execution_outcome")
        outcome_status = outcome.get("status") if isinstance(outcome, dict) else "untracked"
        if outcome_status == "completed" and outcome.get("audit_status") == "written":
            continue
        args = data.get("args", {})
        recovery.append({
            "approval_id": approval_id, "tool": data.get("tool"),
            "requester": data.get("requester"),
            "path": args.get("path") if isinstance(args, dict) else None,
            "consumed_at": data.get("consumed_at"),
            "execution_status": outcome_status,
            "execution_audit_status": (
                outcome.get("audit_status") if isinstance(outcome, dict) else None
            ),
            "started_at": (
                outcome.get("started_at") if isinstance(outcome, dict) else None
            ),
            "finished_at": (
                outcome.get("completed_at", outcome.get("finished_at"))
                if isinstance(outcome, dict) else None
            ),
            "error_type": (
                outcome.get("error_type") if isinstance(outcome, dict) else None
            ),
            "error_message": (
                outcome.get("error_message") if isinstance(outcome, dict) else None
            ),
        })
    return sorted(recovery, key=lambda item: item.get("consumed_at") or 0)


def list_pending() -> list[dict[str, Any]]:
    """Return only valid, audited pending records; isolate corrupt files."""
    _ensure_dirs()
    pending = []
    for path in _approvals_dir.glob("*.json"):
        if path.is_symlink():
            continue
        approval_id = path.stem
        try:
            data = _load_approval_record(path, approval_id)
        except (
            OSError,
            CorruptApprovalRecordError,
        ):
            logger.exception(
                "skipping corrupt approval record; operator review required",
                extra={"approval_id": approval_id},
            )
            continue
        if (
            data["status"] == "pending"
            and data["request_audit_status"] == "written"
            and not _approval_expired(data["created"])
        ):
            pending.append(data)
    return pending
