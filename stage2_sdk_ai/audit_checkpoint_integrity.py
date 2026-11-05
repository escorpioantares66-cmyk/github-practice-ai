"""Explicit, non-enforcing verification of independent main/sandbox audit checkpoints.

This module never publishes checkpoints, changes audit storage, or enables
checkpoint enforcement. Callers must supply the trusted store identity out of
band; the identity embedded in an envelope is never trusted by itself.
"""
from __future__ import annotations

import json
import math
import re
import time
import uuid
from typing import Any

from . import approval, sandbox_approval

MAX_CHECKPOINT_BYTES = 16 * 1024
CHECKPOINT_FORMAT_VERSION = 1
MAIN_AUTHORITY = "main"
SANDBOX_AUTHORITY = "sandbox"
_AUTHORITIES = {MAIN_AUTHORITY, SANDBOX_AUTHORITY}
_STORE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_HASH_RE = re.compile(r"^[0-9a-f]{64}$")
_CHECKPOINT_ID_RE = re.compile(r"^[0-9a-f]{32}$")
_REQUIRED_FIELDS = {
    "format_version",
    "authority",
    "store_id",
    "sequence",
    "head_hash",
    "legacy_entries",
    "created_at",
    "checkpoint_id",
}


class AuditCheckpointIntegrityError(ValueError):
    """A checkpoint envelope is malformed or belongs to another audit store."""


def _validate_identity(authority: str, store_id: str) -> None:
    if authority not in _AUTHORITIES:
        raise AuditCheckpointIntegrityError("unknown audit checkpoint authority")
    if not isinstance(store_id, str) or not _STORE_ID_RE.fullmatch(store_id):
        raise AuditCheckpointIntegrityError("trusted audit store identity is invalid")


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise AuditCheckpointIntegrityError("checkpoint contains duplicate JSON keys")
        result[key] = value
    return result


def validate_checkpoint_envelope(
    checkpoint: Any,
    *,
    authority: str,
    store_id: str,
) -> dict[str, Any]:
    """Validate the exact envelope against caller-supplied trusted identity."""
    _validate_identity(authority, store_id)
    if not isinstance(checkpoint, dict) or set(checkpoint) != _REQUIRED_FIELDS:
        raise AuditCheckpointIntegrityError("checkpoint envelope has an invalid schema")

    version = checkpoint.get("format_version")
    sequence = checkpoint.get("sequence")
    legacy_entries = checkpoint.get("legacy_entries")
    created_at = checkpoint.get("created_at")
    if (
        isinstance(version, bool)
        or not isinstance(version, int)
        or version != CHECKPOINT_FORMAT_VERSION
        or checkpoint.get("authority") != authority
        or checkpoint.get("store_id") != store_id
        or isinstance(sequence, bool)
        or not isinstance(sequence, int)
        or sequence < 0
        or isinstance(legacy_entries, bool)
        or not isinstance(legacy_entries, int)
        or legacy_entries < 0
        or not isinstance(created_at, (int, float))
        or isinstance(created_at, bool)
        or not math.isfinite(created_at)
        or created_at <= 0
        or not isinstance(checkpoint.get("head_hash"), str)
        or not _HASH_RE.fullmatch(checkpoint["head_hash"])
        or not isinstance(checkpoint.get("checkpoint_id"), str)
        or not _CHECKPOINT_ID_RE.fullmatch(checkpoint["checkpoint_id"])
    ):
        raise AuditCheckpointIntegrityError("checkpoint envelope contains invalid fields")
    if authority == SANDBOX_AUTHORITY and legacy_entries != 0:
        raise AuditCheckpointIntegrityError(
            "sandbox checkpoint cannot contain legacy main-audit entries"
        )
    return dict(checkpoint)


def parse_checkpoint(
    payload: bytes | str,
    *,
    authority: str,
    store_id: str,
) -> dict[str, Any]:
    """Parse a bounded UTF-8 JSON envelope, rejecting duplicate keys."""
    _validate_identity(authority, store_id)
    if isinstance(payload, bytes):
        raw = payload
    elif isinstance(payload, str):
        raw = payload.encode("utf-8")
    else:
        raise AuditCheckpointIntegrityError("checkpoint payload must be bytes or text")
    if len(raw) > MAX_CHECKPOINT_BYTES:
        raise AuditCheckpointIntegrityError("checkpoint exceeds the size limit")
    try:
        parsed = json.loads(raw.decode("utf-8"), object_pairs_hook=_reject_duplicate_keys)
    except AuditCheckpointIntegrityError:
        raise
    except (UnicodeError, ValueError, TypeError) as exc:
        raise AuditCheckpointIntegrityError("checkpoint is not valid UTF-8 JSON") from exc
    return validate_checkpoint_envelope(
        parsed, authority=authority, store_id=store_id
    )


def serialize_checkpoint(
    checkpoint: dict[str, Any],
    *,
    authority: str,
    store_id: str,
) -> bytes:
    """Serialize a validated envelope without writing it to any storage."""
    envelope = validate_checkpoint_envelope(
        checkpoint, authority=authority, store_id=store_id
    )
    try:
        payload = (
            json.dumps(
                envelope,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            )
            + "\n"
        ).encode("utf-8")
    except (TypeError, ValueError, OverflowError) as exc:
        raise AuditCheckpointIntegrityError("checkpoint cannot be serialized") from exc
    if len(payload) > MAX_CHECKPOINT_BYTES:
        raise AuditCheckpointIntegrityError("checkpoint exceeds the size limit")
    return payload


def create_checkpoint_envelope(
    authority: str,
    store_id: str,
    *,
    created_at: float | None = None,
) -> dict[str, Any]:
    """Snapshot a verified authority head into a caller-identified envelope.

    This creates an in-memory object only. It does not publish or persist it.
    """
    _validate_identity(authority, store_id)
    timestamp = time.time() if created_at is None else created_at
    if (
        isinstance(timestamp, bool)
        or not isinstance(timestamp, (int, float))
        or not math.isfinite(timestamp)
        or timestamp <= 0
    ):
        raise AuditCheckpointIntegrityError("checkpoint timestamp is invalid")

    if authority == MAIN_AUTHORITY:
        snapshot = approval.create_audit_checkpoint()
        sequence = snapshot["sequence"]
        head_hash = snapshot["head_hash"]
        legacy_entries = snapshot["legacy_entries"]
    else:
        snapshot = sandbox_approval.verify_audit_log()
        sequence = snapshot["events"]
        head_hash = snapshot["last_hash"]
        legacy_entries = 0

    envelope = {
        "format_version": CHECKPOINT_FORMAT_VERSION,
        "authority": authority,
        "store_id": store_id,
        "sequence": sequence,
        "head_hash": head_hash,
        "legacy_entries": legacy_entries,
        "created_at": timestamp,
        "checkpoint_id": uuid.uuid4().hex,
    }
    return validate_checkpoint_envelope(
        envelope, authority=authority, store_id=store_id
    )


def verify_checkpoint(
    checkpoint: dict[str, Any] | bytes | str,
    *,
    authority: str,
    store_id: str,
) -> dict[str, Any]:
    """Compare an explicit checkpoint with the matching local audit authority.

    A successful result verifies history only through checkpoint_sequence.
    Events after that sequence are returned as an unanchored suffix; no
    freshness or maximum-suffix policy is imposed by this non-enforcing API.
    """
    if isinstance(checkpoint, (bytes, str)):
        envelope = parse_checkpoint(
            checkpoint, authority=authority, store_id=store_id
        )
    else:
        envelope = validate_checkpoint_envelope(
            checkpoint, authority=authority, store_id=store_id
        )

    checkpoint_sequence = envelope["sequence"]
    if authority == MAIN_AUTHORITY:
        result = approval.verify_audit_log(
            {
                "version": 1,
                "sequence": checkpoint_sequence,
                "legacy_entries": envelope["legacy_entries"],
                "head_hash": envelope["head_hash"],
                "created_at": envelope["created_at"],
            }
        )
        current_sequence = result["chained_entries"]
        suffix_name = "unanchored_suffix"
    else:
        result = sandbox_approval.verify_audit_log(
            {
                "sequence": checkpoint_sequence,
                "head_hash": envelope["head_hash"],
            }
        )
        current_sequence = result["events"]
        suffix_name = "unanchored_suffix"

    return {
        "valid": True,
        "checkpoint_verified": True,
        "authority": authority,
        "store_id": store_id,
        "checkpoint_id": envelope["checkpoint_id"],
        "checkpoint_sequence": checkpoint_sequence,
        "current_sequence": current_sequence,
        suffix_name: current_sequence - checkpoint_sequence,
    }
