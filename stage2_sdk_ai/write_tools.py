from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from . import approval
from .approval import approve, consume_approval, consume_approval_request, request_approval
from .logging_setup import get_logger
from .secure_storage import ensure_private_directory, write_text_atomically

logger = get_logger(__name__)

_notes_dir = Path("notes")
MAX_NOTE_CHARS = 5_000


def _is_mock() -> bool:
    key = os.getenv("OPENAI_API_KEY", "")
    return key.startswith("sk-test-mocked") or key == ""


def canonical_note_path(path: str) -> Path:
    """Resolve note paths to the single filename location used by the writer."""
    if not isinstance(path, str) or not path.strip():
        raise ValueError("A note filename is required")
    filename = Path(path).name
    if filename in {"", ".", ".."}:
        raise ValueError("A note filename is required")
    return _notes_dir / filename


def _atomic_write_note(path: Path, content: str) -> None:
    """Write a note without following a destination symlink."""
    ensure_private_directory(_notes_dir)
    write_text_atomically(path, content, _notes_dir)


def _validate_note_payload(path: Any, content: Any) -> tuple[Path | None, str | None]:
    if not isinstance(content, str):
        return None, "Content must be text"
    if len(content) > MAX_NOTE_CHARS:
        return None, f"Content exceeds {MAX_NOTE_CHARS} characters"
    if not isinstance(path, str):
        return None, "Approved note path is not canonical"
    try:
        safe_path = canonical_note_path(path)
    except (TypeError, ValueError):
        return None, "A note filename is required"
    # The stored path must already be canonical. Do not silently reinterpret
    # an altered or legacy payload during execution.
    if str(safe_path) != path:
        return None, "Approved note path is not canonical"
    return safe_path, None


def _report_execution_failure(
    approval_id: str,
    path: Path,
    original_error: Exception,
    result_status: str = "execution_failed",
) -> dict[str, Any]:
    """Log the side-effect failure before attempting fallible recovery writes."""
    logger.error(
        "approved note write failed after approval was consumed",
        exc_info=original_error,
        extra={
            "approval_id": approval_id,
            "path": str(path),
            "approval_status": "consumed",
            "recovery": "operator_review_required",
            "failure_record_status": "pending",
        },
    )
    base = {
        "tool": "write_note",
        "path": str(path),
        "approval_id": approval_id,
        "is_mock": False,
    }
    try:
        record = approval.record_execution_failure(
            approval_id, type(original_error).__name__, str(original_error)
        )
    except Exception as reporting_error:
        logger.error(
            "failed to persist approved write failure metadata",
            exc_info=reporting_error,
            extra={
                "approval_id": approval_id,
                "path": str(path),
                "approval_status": "consumed",
                "recovery": "operator_review_required",
                "original_error_type": type(original_error).__name__,
            },
        )
        return {
            **base,
            "status": "execution_failure_recording_failed",
            "error": (
                "Write failed after approval consumption; failure metadata "
                "could not be confirmed; operator review required"
            ),
        }

    if record.get("status") != "consumed":
        logger.error(
            "approved write failure metadata was not recorded",
            extra={
                "approval_id": approval_id,
                "approval_status": record.get("status"),
                "recovery": "operator_review_required",
                "original_error_type": type(original_error).__name__,
            },
        )
        return {
            **base,
            "status": "execution_failure_recording_failed",
            "error": (
                "Write failed after approval consumption; approval record "
                "needs operator inspection"
            ),
        }

    if record.get("audit_status") == "failed":
        logger.error(
            "approved write failure metadata saved but audit append failed",
            extra={
                "approval_id": approval_id,
                "approval_status": "consumed",
                "recovery": "operator_review_required",
                "audit_error_type": record.get("audit_error_type"),
            },
        )
        return {
            **base,
            "status": "execution_failed_audit_incomplete",
            "error": (
                "Write failed; approval failure metadata was saved but audit "
                "logging failed; operator review required"
            ),
        }

    return {
        **base,
        "status": result_status,
        "error": "Approved operation stopped after consumption; operator review required",
    }


def write_note(
    path: str,
    content: str,
    approval_id: str | None = None,
    requester: str = "agent",
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
            requester=requester,
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
        requester=requester,
    )
    if consumed.get("status") != "consumed":
        return {
            "tool": "write_note",
            "path": str(safe_path),
            "status": consumed.get("status", "not_found"),
            "approval_id": approval_id,
            "is_mock": False,
        }

    if consumed.get("audit_status") == "failed":
        audit_error = RuntimeError(
            "consumed audit append failed: "
            + str(consumed.get("audit_error_type", "unknown error"))
        )
        return _report_execution_failure(
            approval_id, safe_path, audit_error,
            result_status="consumption_audit_incomplete",
        )

    try:
        _atomic_write_note(safe_path, content)
    except Exception as exc:
        return _report_execution_failure(approval_id, safe_path, exc)

    return {
        "tool": "write_note",
        "path": str(safe_path),
        "status": "written",
        "approval_id": approval_id,
        "is_mock": False,
    }


def execute_approved_write(
    approval_id: str, requester: str | None = None
) -> dict[str, Any]:
    """Execute only the exact payload persisted in a valid approved record.

    The caller cannot supply a path or content. The approval is consumed
    atomically before any filesystem side effect, so concurrent requests
    cannot both execute the same authorization.
    """
    consumed = consume_approval_request(
        approval_id, "write_note", requester=requester
    )
    if consumed.get("status") != "consumed":
        return {
            "tool": "write_note",
            "status": consumed.get("status", "not_found"),
            "approval_id": approval_id,
            "is_mock": False,
        }

    if consumed.get("audit_status") == "failed":
        audit_error = RuntimeError(
            "consumed audit append failed: "
            + str(consumed.get("audit_error_type", "unknown error"))
        )
        return _report_execution_failure(
            approval_id, safe_path, audit_error,
            result_status="consumption_audit_incomplete",
        )

    args = consumed.get("args")
    if not isinstance(args, dict):
        return {
            "tool": "write_note",
            "status": "invalid_approved_payload",
            "approval_id": approval_id,
            "is_mock": False,
        }

    safe_path, error = _validate_note_payload(args.get("path"), args.get("content"))
    if error or safe_path is None:
        validation_error = ValueError(error or "Invalid approved payload")
        return _report_execution_failure(
            approval_id,
            Path("<invalid-approved-path>"),
            validation_error,
            result_status="invalid_approved_payload_operator_review",
        )

    try:
        _atomic_write_note(safe_path, args["content"])
    except Exception as exc:
        # Never restore consumed authorization; secondary reporting failures
        # must not hide the original filesystem exception.
        return _report_execution_failure(approval_id, safe_path, exc)

    return {
        "tool": "write_note",
        "path": str(safe_path),
        "status": "written",
        "approval_id": approval_id,
        "is_mock": False,
    }


def approve_write(approval_id: str, approver_key: str) -> dict[str, Any]:
    """Approve a request only with a configured approver credential."""
    return approve(approval_id, approver_key=approver_key)
