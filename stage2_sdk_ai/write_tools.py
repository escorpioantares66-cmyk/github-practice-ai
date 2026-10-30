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


def canonical_note_path(path: str) -> Path:
    """Resolve note paths to the single filename location used by the writer."""
    filename = Path(path).name
    if filename in {"", ".", ".."}:
        raise ValueError("A note filename is required")
    return _notes_dir / filename


def write_note(
    path: str, content: str, approval_id: str | None = None
) -> dict[str, Any]:
    safe_path = canonical_note_path(path)
    mock_mode = _is_mock()

    if not isinstance(content, str) or len(content) > MAX_NOTE_CHARS:
        return {
            "tool": "write_note",
            "path": str(safe_path),
            "status": "rejected",
            "error": f"Content must be text no longer than {MAX_NOTE_CHARS} characters",
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
        request = request_approval(
            "write_note",
            {"path": str(safe_path), "content": content},
        )
        return {
            "tool": "write_note",
            "path": str(safe_path),
            "status": "needs_approval",
            "approval_id": request["id"],
            "is_mock": False,
        }

    approval_record = check_approval(approval_id)
    if approval_record.get("status") != "approved":
        return {
            "tool": "write_note",
            "path": str(safe_path),
            "status": approval_record.get("status", "not_found"),
            "approval_id": approval_id,
            "is_mock": False,
        }

    approved_args = approval_record.get("args")
    if (
        approval_record.get("tool") != "write_note"
        or not isinstance(approved_args, dict)
        or approved_args.get("path") != str(safe_path)
        or approved_args.get("content") != content
    ):
        return {
            "tool": "write_note",
            "path": str(safe_path),
            "status": "approval_mismatch",
            "approval_id": approval_id,
            "is_mock": False,
        }

    _notes_dir.mkdir(parents=True, exist_ok=True)
    safe_path.write_text(content, encoding="utf-8")
    return {
        "tool": "write_note",
        "path": str(safe_path),
        "status": "written",
        "approval_id": approval_id,
        "is_mock": False,
    }


def approve_write(approval_id: str) -> dict[str, Any]:
    return approve(approval_id)
