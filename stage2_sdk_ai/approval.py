from __future__ import annotations

import json
import re
import time
import secrets
import uuid
from pathlib import Path
from typing import Any

_approvals_dir = Path("approvals")
_audit_file = Path("logs/audit.jsonl")

def _ensure_dirs() -> None:
    _approvals_dir.mkdir(exist_ok=True)
    _audit_file.parent.mkdir(exist_ok=True)


def _approval_path(approval_id: str) -> Path | None:
    """Return a path only for valid legacy or new approval IDs."""
    if not isinstance(approval_id, str) or not re.fullmatch(
        r"(?:[0-9a-f]{8}|[0-9a-f]{32})", approval_id
    ):
        return None
    return _approvals_dir / f"{approval_id}.json"


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
    (_approvals_dir / f"{approval_id}.json").write_text(
        json.dumps(record, indent=2), encoding="utf-8"
    )
    log_audit("request", record)
    return record


def check_approval(approval_id: str) -> dict[str, Any]:
    _ensure_dirs()
    path = _approval_path(approval_id)
    if path is None:
        return {"status": "invalid_id", "id": approval_id}
    if not path.exists():
        return {"status": "not_found", "id": approval_id}
    data = json.loads(path.read_text(encoding="utf-8"))
    return data

def approve(approval_id: str, approver: str = "human") -> dict[str, Any]:
    _ensure_dirs()
    path = _approval_path(approval_id)
    if path is None:
        return {"status": "invalid_id", "id": approval_id}
    if not path.exists():
        return {"status": "not_found", "id": approval_id}
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("status") != "pending":
        return {
            "status": "invalid_transition",
            "id": approval_id,
            "current_status": data.get("status"),
        }
    data["status"] = "approved"
    data["approver"] = approver
    data["approved_at"] = time.time()
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    log_audit("approved", data)
    return data

def deny(approval_id: str, approver: str = "human", reason: str = "") -> dict[str, Any]:
    _ensure_dirs()
    path = _approval_path(approval_id)
    if path is None:
        return {"status": "invalid_id", "id": approval_id}
    if not path.exists():
        return {"status": "not_found", "id": approval_id}
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("status") != "pending":
        return {
            "status": "invalid_transition",
            "id": approval_id,
            "current_status": data.get("status"),
        }
    data["status"] = "denied"
    data["approver"] = approver
    data["reason"] = reason
    data["denied_at"] = time.time()
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    log_audit("denied", data)
    return data

def log_audit(action: str, record: dict[str, Any]) -> None:
    _ensure_dirs()
    entry = {"action": action, "time": time.time(), "record": record}
    with _audit_file.open("a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")

def list_pending() -> list[dict[str, Any]]:
    _ensure_dirs()
    pending = []
    for p in _approvals_dir.glob("*.json"):
        data = json.loads(p.read_text(encoding="utf-8"))
        if data.get("status") == "pending":
            pending.append(data)
    return pending
