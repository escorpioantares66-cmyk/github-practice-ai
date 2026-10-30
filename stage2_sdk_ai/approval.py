from __future__ import annotations

import fcntl
import json
import os
import re
import secrets
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from .secure_storage import (
    ensure_private_directory,
    open_private_file,
    read_private_text,
    write_text_atomically,
)

_approvals_dir = Path("approvals")
_audit_file = Path("logs/audit.jsonl")


def _ensure_dirs() -> None:
    ensure_private_directory(_approvals_dir)
    ensure_private_directory(_audit_file.parent)


def _approval_path(approval_id: str) -> Path | None:
    """Return a path only for valid legacy or new approval IDs."""
    if not isinstance(approval_id, str) or not re.fullmatch(
        r"(?:[0-9a-f]{8}|[0-9a-f]{32})", approval_id
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
    _ensure_dirs()
    record = {
        "tool": tool,
        "args": args,
        "requester": requester,
        "status": "pending",
        "created": time.time(),
    }
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
        with os.fdopen(fd, "w", encoding="utf-8") as approval_file:
            json.dump(record, approval_file, indent=2)
            approval_file.flush()
            os.fsync(approval_file.fileno())
        break
    log_audit("request", record)
    return record


def check_approval(approval_id: str) -> dict[str, Any]:
    _ensure_dirs()
    path = _approval_path(approval_id)
    if path is None:
        return {"status": "invalid_id", "id": approval_id}
    try:
        return json.loads(read_private_text(path))
    except FileNotFoundError:
        return {"status": "not_found", "id": approval_id}


def _transition(
    approval_id: str,
    target_status: str,
    approver: str,
    reason: str | None = None,
) -> dict[str, Any]:
    _ensure_dirs()
    path = _approval_path(approval_id)
    if path is None:
        return {"status": "invalid_id", "id": approval_id}

    with _locked_record(path):
        try:
            data = json.loads(read_private_text(path))
        except FileNotFoundError:
            return {"status": "not_found", "id": approval_id}

        if data.get("status") != "pending":
            return {
                "status": "invalid_transition",
                "id": approval_id,
                "current_status": data.get("status"),
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

        _write_record_atomically(path, data)
        log_audit(action, data)
        return data


def approve(approval_id: str, approver: str = "human") -> dict[str, Any]:
    return _transition(approval_id, "approved", approver)


def deny(
    approval_id: str, approver: str = "human", reason: str = ""
) -> dict[str, Any]:
    return _transition(approval_id, "denied", approver, reason)


def consume_approval_request(
    approval_id: str,
    tool: str,
    args: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Atomically consume an approved operation and return its stored payload.

    When args is supplied, it must exactly match the approved arguments.
    Omitting args is reserved for trusted server-side execution that loads
    the immutable approved payload from the record itself.
    """
    _ensure_dirs()
    path = _approval_path(approval_id)
    if path is None:
        return {"status": "invalid_id", "id": approval_id}

    with _locked_record(path):
        try:
            data = json.loads(read_private_text(path))
        except FileNotFoundError:
            return {"status": "not_found", "id": approval_id}

        if data.get("status") == "pending":
            return {"status": "pending", "id": approval_id}
        if data.get("status") != "approved":
            return {
                "status": "invalid_transition",
                "id": approval_id,
                "current_status": data.get("status"),
            }

        if data.get("tool") != tool or (
            args is not None and data.get("args") != args
        ):
            return {"status": "approval_mismatch", "id": approval_id}

        data["status"] = "consumed"
        data["consumed_at"] = time.time()
        _write_record_atomically(path, data)
        log_audit("consumed", data)
        return data


def consume_approval(
    approval_id: str, tool: str, args: dict[str, Any]
) -> dict[str, Any]:
    """Consume an approval only when the caller's exact args match."""
    return consume_approval_request(approval_id, tool, args)


def log_audit(action: str, record: dict[str, Any]) -> None:
    _ensure_dirs()
    entry = {"action": action, "time": time.time(), "record": record}
    fd = open_private_file(_audit_file, os.O_WRONLY | os.O_APPEND | os.O_CREAT)
    with os.fdopen(fd, "a", encoding="utf-8") as audit_file:
        fcntl.flock(audit_file.fileno(), fcntl.LOCK_EX)
        try:
            audit_file.write(json.dumps(entry) + "\\n")
            audit_file.flush()
            os.fsync(audit_file.fileno())
        finally:
            fcntl.flock(audit_file.fileno(), fcntl.LOCK_UN)


def list_pending() -> list[dict[str, Any]]:
    _ensure_dirs()
    pending = []
    for path in _approvals_dir.glob("*.json"):
        if path.is_symlink():
            continue
        data = json.loads(read_private_text(path))
        if data.get("status") == "pending":
            pending.append(data)
    return pending
