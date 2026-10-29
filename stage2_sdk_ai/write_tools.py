from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from .approval import approve, check_approval, request_approval

_notes_dir = Path("notes")
MAX_NOTE_CHARS = 5_000

def _is_mock() -> bool:
    key = os.getenv("OPENAI_API_KEY", "")
    return key.startswith("sk-test-mocked") or key == ""

def write_note(path: str, content: str, approval_id: str | None = None) -> dict[str, Any]:
    safe_path = _notes_dir / Path(path).name
    mock_mode = _is_mock()

    if len(content) > MAX_NOTE_CHARS:
        return {
            "tool": "write_note",
            "path": str(safe_path),
            "status": "rejected",
            "error": f"Content exceeds {MAX_NOTE_CHARS} characters",
            "is_mock": mock_mode,
        }

    if mock_mode:
        return {
            "tool": "write_note",
            "path": str(safe_path),
            "content": content[:100],
            "status": "needs_approval",
            "approval_id": "mock-123",
            "is_mock": True,
        }

    if approval_id is None:
        req = request_approval("write_note", {"path": str(safe_path), "content": content})
        return {
            "tool": "write_note",
            "path": str(safe_path),
            "status": "needs_approval",
            "approval_id": req["id"],
            "is_mock": False,
        }

    status = check_approval(approval_id)
    if status.get("status") != "approved":
        return {
            "tool": "write_note",
            "path": str(safe_path),
            "status": status.get("status", "not_found"),
            "approval_id": approval_id,
            "is_mock": False,
        }

    _notes_dir.mkdir(exist_ok=True)
    safe_path.write_text(content[:5000], encoding="utf-8")
    return {
        "tool": "write_note",
        "path": str(safe_path),
        "status": "written",
        "approval_id": approval_id,
        "is_mock": False,
    }

def approve_write(approval_id: str) -> dict[str, Any]:
    return approve(approval_id)
