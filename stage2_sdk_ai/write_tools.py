from __future__ import annotations

import os
import tempfile
from pathlib import Path
from typing import Any

from .approval import approve, consume_approval, request_approval

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
        error = (
            "Content must be text"
            if not isinstance(content, str)
            else f"Content exceeds {MAX_NOTE_CHARS} characters"
        )
        return {
            "tool": "write_note",
            "path": str(safe_path),
            "status": "rejected",
            "error": error,
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

    consumed = consume_approval(
        approval_id,
        "write_note",
        {"path": str(safe_path), "content": content},
    )
    if consumed.get("status") != "consumed":
        return {
            "tool": "write_note",
            "path": str(safe_path),
            "status": consumed.get("status", "not_found"),
            "approval_id": approval_id,
            "is_mock": False,
        }

    _notes_dir.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(
        prefix=f".{safe_path.name}.", suffix=".tmp", dir=_notes_dir
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as temporary_file:
            temporary_file.write(content)
            temporary_file.flush()
            os.fsync(temporary_file.fileno())
        os.replace(temporary_name, safe_path)
    finally:
        if os.path.exists(temporary_name):
            os.unlink(temporary_name)

    return {
        "tool": "write_note",
        "path": str(safe_path),
        "status": "written",
        "approval_id": approval_id,
        "is_mock": False,
    }


def approve_write(approval_id: str) -> dict[str, Any]:
    return approve(approval_id)
