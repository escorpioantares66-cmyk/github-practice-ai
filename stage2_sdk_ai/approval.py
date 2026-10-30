from __future__ import annotations

import fcntl
import json
import os
import re
import secrets
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

_approvals_dir = Path("approvals")
_audit_file = Path("logs/audit.jsonl")


def _ensure_dirs() -> None:
    _approvals_dir.mkdir(parents=True, exist_ok=True)
    _audit_file.parent.mkdir(parents=True, exist_ok=True)


def _approval_path(approval_id: str) -> Path | None:
    """Return a path only for valid legacy or new approval IDs."""
    if not isinstance(approval_id, str) or not re.fullmatch(
        r"(?:[0-9a-f]{8}|[0-9a-f]{32})", approval_id
    ):
        return None
    return _approvals_dir / f"{approval_id}.json"


@contextmanager
def _locked_record(path: Path) -> Iterator[None]:
    """Serialize state transitions for one approval record across processes."""
    lock_path = path.with_suffix(path.suffix + ".lock")
    with lock_path.open("a+", encoding="utf-8") as lock_file:
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)


def _write_record_atomically(path: Path, record: dict[str, Any]) -> None:
    """Replace a record atomically so readers never observe partial JSON."""
    fd, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as temporary_file:
            json.dump(record, temporary_file, indent=2)
            temporary_file.flush()
            os.fsync(temporary_file.fileno())
        os.replace(temporary_name, path)
    finally:
        if os.path.exists(temporary_name):
            os.unlink(temporary_name)


def request_approval(
    tool: str, args: dict[str, Any], requester: str = "agent"
) -> dict[str, Any]:
    _ensure_dirs()
    approval_id = secrets.token_hex(16)
    record = {
        "id": approval_id,
        "tool": tool,
        "args": args,
        "requester": requester,
        "status": "pending",
        "created": time.time(),
    }
    path = _approval_path(approval_id)
    assert path is not None
    with path.open("x", encoding="utf-8") as approval_file:
        json.dump(record, approval_file, indent=2)
    log_audit("request", record)
    return record


def check_approval(approval_id: str) -> dict[str, Any]:
    _ensure_dirs()
    path = _approval_path(approval_id)
    if path is None:
        return {"status": "invalid_id", "id": approval_id}
    if not path.exists():
        return {"status": "not_found", "id": approval_id}
    return json.loads(path.read_text(encoding="utf-8"))


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
        if not path.exists():
            return {"status": "not_found", "id": approval_id}

        data = json.loads(path.read_text(encoding="utf-8"))
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



def consume_approval(
    approval_id: str, tool: str, args: dict[str, Any]
) -> dict[str, Any]:
    """Atomically consume an approval for one exact operation, once only."""
    _ensure_dirs()
    path = _approval_path(approval_id)
    if path is None:
        return {"status": "invalid_id", "id": approval_id}

    with _locked_record(path):
        if not path.exists():
            return {"status": "not_found", "id": approval_id}

        data = json.loads(path.read_text(encoding="utf-8"))
        if data.get("status") != "approved":
            return {
                "status": "invalid_transition",
                "id": approval_id,
                "current_status": data.get("status"),
            }

        if data.get("tool") != tool or data.get("args") != args:
            return {"status": "approval_mismatch", "id": approval_id}

        data["status"] = "consumed"
        data["consumed_at"] = time.time()
        _write_record_atomically(path, data)
        log_audit("consumed", data)
        return data


def log_audit(action: str, record: dict[str, Any]) -> None:
    _ensure_dirs()
    entry = {"action": action, "time": time.time(), "record": record}
    with _audit_file.open("a", encoding="utf-8") as audit_file:
        audit_file.write(json.dumps(entry) + "\n")


def list_pending() -> list[dict[str, Any]]:
    _ensure_dirs()
    pending = []
    for path in _approvals_dir.glob("*.json"):
        data = json.loads(path.read_text(encoding="utf-8"))
        if data.get("status") == "pending":
            pending.append(data)
    return pending
