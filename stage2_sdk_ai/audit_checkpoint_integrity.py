"""Explicit, non-enforcing verification of independent main/sandbox audit checkpoints.

This module never publishes checkpoints, changes audit storage, or enables
checkpoint enforcement. Callers must supply the trusted store identity out of
band; the identity embedded in an envelope is never trusted by itself.
"""
from __future__ import annotations

import json
import math
import re
import stat
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
    if not isinstance(authority, str) or authority not in _AUTHORITIES:
        raise AuditCheckpointIntegrityError("unknown audit checkpoint authority")
    if not isinstance(store_id, str) or not _STORE_ID_RE.fullmatch(store_id):
        raise AuditCheckpointIntegrityError("trusted audit store identity is invalid")

def _positive_finite_timestamp(value: Any) -> bool:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    try:
        return math.isfinite(value) and value > 0
    except (OverflowError, TypeError):
        return False

def _nonnegative_finite_number(value: Any) -> bool:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    try:
        return math.isfinite(value) and value >= 0
    except (OverflowError, TypeError):
        return False

def _require_existing_audit_file(path: Any) -> None:
    """Do not let snapshot creation initialize a missing audit history."""
    try:
        info = path.lstat()
    except OSError as exc:
        raise AuditCheckpointIntegrityError(
            "cannot checkpoint a missing or inaccessible audit log"
        ) from exc
    if not stat.S_ISREG(info.st_mode):
        raise AuditCheckpointIntegrityError(
            "cannot checkpoint a non-regular audit log path"
        )

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
        or not _positive_finite_timestamp(created_at)
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
        try:
            raw = payload.encode("utf-8")
        except UnicodeError as exc:
            raise AuditCheckpointIntegrityError(
                "checkpoint is not valid UTF-8 text"
            ) from exc
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
    if not _positive_finite_timestamp(timestamp):
        raise AuditCheckpointIntegrityError("checkpoint timestamp is invalid")

    if authority == MAIN_AUTHORITY:
        _require_existing_audit_file(approval._audit_file)
        snapshot = approval.create_audit_checkpoint()
        sequence = snapshot["sequence"]
        head_hash = snapshot["head_hash"]
        legacy_entries = snapshot["legacy_entries"]
    else:
        _require_existing_audit_file(
            sandbox_approval._store_dir() / "audit.jsonl"
        )
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

def _verify_checkpoint_set(
    checkpoints: list[dict[str, Any] | bytes | str],
    *,
    authority: str,
    store_id: str,
) -> list[dict[str, Any]]:
    """Verify multiple anchors against one locked audit-history snapshot."""
    if not checkpoints:
        raise AuditCheckpointIntegrityError("at least one checkpoint is required")
    envelopes = [
        parse_checkpoint(checkpoint, authority=authority, store_id=store_id)
        if isinstance(checkpoint, (bytes, str))
        else validate_checkpoint_envelope(
            checkpoint, authority=authority, store_id=store_id
        )
        for checkpoint in checkpoints
    ]

    if authority == MAIN_AUTHORITY:
        _require_existing_audit_file(approval._audit_file)
        expected = [
            {
                "version": 1,
                "sequence": envelope["sequence"],
                "legacy_entries": envelope["legacy_entries"],
                "head_hash": envelope["head_hash"],
                "created_at": envelope["created_at"],
            }
            for envelope in envelopes
        ]
        result = approval.verify_audit_log(expected_checkpoints=expected)
        current_sequence = result["chained_entries"]
    else:
        _require_existing_audit_file(
            sandbox_approval._store_dir() / "audit.jsonl"
        )
        expected = [
            {
                "sequence": envelope["sequence"],
                "head_hash": envelope["head_hash"],
            }
            for envelope in envelopes
        ]
        result = sandbox_approval.verify_audit_log(expected_checkpoints=expected)
        current_sequence = result["events"]

    return [
        {
            "valid": True,
            "checkpoint_verified": True,
            "authority": authority,
            "store_id": store_id,
            "checkpoint_id": envelope["checkpoint_id"],
            "checkpoint_sequence": envelope["sequence"],
            "current_sequence": current_sequence,
            "unanchored_suffix": current_sequence - envelope["sequence"],
        }
        for envelope in envelopes
    ]


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
    return _verify_checkpoint_set(
        [checkpoint], authority=authority, store_id=store_id
    )[0]

class AuditCheckpointPolicyError(AuditCheckpointIntegrityError):
    """A valid checkpoint fails the explicitly supplied freshness policy."""

class AuditCheckpointRollbackError(AuditCheckpointPolicyError):
    """A candidate checkpoint regresses behind the trusted operator floor."""

class AuditCheckpointRecoveryRequired(AuditCheckpointPolicyError):
    """Trusted checkpoint state is missing; automatic re-baselining is unsafe."""

_FLOOR_FIELDS = {
    "authority",
    "store_id",
    "sequence",
    "head_hash",
    "legacy_entries",
    "created_at",
    "checkpoint_id",
}

def validate_trusted_checkpoint_floor(
    floor: Any,
    *,
    authority: str,
    store_id: str,
) -> dict[str, Any]:
    """Validate the last operator-accepted checkpoint retained independently."""
    _validate_identity(authority, store_id)
    if not isinstance(floor, dict) or set(floor) != _FLOOR_FIELDS:
        raise AuditCheckpointIntegrityError(
            "trusted checkpoint floor has an invalid schema"
        )
    if (
        floor.get("authority") != authority
        or floor.get("store_id") != store_id
        or isinstance(floor.get("sequence"), bool)
        or not isinstance(floor.get("sequence"), int)
        or floor["sequence"] < 0
        or isinstance(floor.get("legacy_entries"), bool)
        or not isinstance(floor.get("legacy_entries"), int)
        or floor["legacy_entries"] < 0
        or not isinstance(floor.get("head_hash"), str)
        or not _HASH_RE.fullmatch(floor["head_hash"])
        or not _positive_finite_timestamp(floor.get("created_at"))
        or not isinstance(floor.get("checkpoint_id"), str)
        or not _CHECKPOINT_ID_RE.fullmatch(floor["checkpoint_id"])
    ):
        raise AuditCheckpointIntegrityError(
            "trusted checkpoint floor contains invalid fields"
        )
    if authority == SANDBOX_AUTHORITY:
        if floor["legacy_entries"] != 0:
            raise AuditCheckpointIntegrityError(
                "sandbox checkpoint floor cannot contain legacy main-audit entries"
            )
        if floor["sequence"] == 0 and floor["head_hash"] != "0" * 64:
            raise AuditCheckpointIntegrityError(
                "empty sandbox checkpoint floor has an invalid head hash"
            )
    return dict(floor)

def verify_checkpoint_with_policy(
    checkpoint: dict[str, Any] | bytes | str | None,
    *,
    authority: str,
    store_id: str,
    trusted_floor: dict[str, Any] | None,
    now: float,
    max_age_seconds: float,
    max_unanchored_suffix: int,
) -> dict[str, Any]:
    """Verify a checkpoint against audit history, freshness, and an operator floor.

    The caller must load trusted_floor from storage independent of the
    application-writable checkpoint. No floor or checkpoint is created,
    advanced, repaired, or persisted here. All policy limits are explicit
    inputs; this function deliberately chooses no production defaults.
    """
    _validate_identity(authority, store_id)
    if checkpoint is None or trusted_floor is None:
        raise AuditCheckpointRecoveryRequired(
            "trusted checkpoint state is missing; operator recovery is required"
        )
    if not _positive_finite_timestamp(now):
        raise AuditCheckpointPolicyError("policy evaluation time is invalid")
    if not _nonnegative_finite_number(max_age_seconds):
        raise AuditCheckpointPolicyError("maximum checkpoint age is invalid")
    if (
        isinstance(max_unanchored_suffix, bool)
        or not isinstance(max_unanchored_suffix, int)
        or max_unanchored_suffix < 0
    ):
        raise AuditCheckpointPolicyError(
            "maximum unanchored suffix must be a non-negative integer"
        )

    floor = validate_trusted_checkpoint_floor(
        trusted_floor, authority=authority, store_id=store_id
    )
    if isinstance(checkpoint, (bytes, str)):
        envelope = parse_checkpoint(
            checkpoint, authority=authority, store_id=store_id
        )
    else:
        envelope = validate_checkpoint_envelope(
            checkpoint, authority=authority, store_id=store_id
        )

    candidate_sequence = envelope["sequence"]
    floor_sequence = floor["sequence"]
    if candidate_sequence < floor_sequence:
        raise AuditCheckpointRollbackError(
            "checkpoint sequence regressed behind the trusted operator floor"
        )
    if (
        candidate_sequence == floor_sequence
        and envelope["head_hash"] != floor["head_hash"]
    ):
        raise AuditCheckpointRollbackError(
            "checkpoint conflicts with the trusted head at the same sequence"
        )
    if envelope["created_at"] < floor["created_at"]:
        raise AuditCheckpointRollbackError(
            "checkpoint publication time regressed behind the trusted floor"
        )
    if envelope["created_at"] > now:
        raise AuditCheckpointPolicyError(
            "checkpoint publication time is in the future"
        )

    # The floor is an actual historical anchor, not merely a well-formed
    # sequence/hash pair. Verify it against the audit history before trusting
    # a newer candidate; otherwise a validly rehashed fork after the floor
    # could be accepted because only the candidate would be checked.
    floor_envelope = {
        "format_version": CHECKPOINT_FORMAT_VERSION,
        "authority": floor["authority"],
        "store_id": floor["store_id"],
        "sequence": floor["sequence"],
        "head_hash": floor["head_hash"],
        "legacy_entries": floor["legacy_entries"],
        "created_at": floor["created_at"],
        "checkpoint_id": floor["checkpoint_id"],
    }
    floor_verification, verification = _verify_checkpoint_set(
        [floor_envelope, envelope], authority=authority, store_id=store_id
    )
    age_seconds = now - envelope["created_at"]
    if age_seconds > max_age_seconds:
        raise AuditCheckpointPolicyError("checkpoint is older than the permitted age")
    if verification["unanchored_suffix"] > max_unanchored_suffix:
        raise AuditCheckpointPolicyError(
            "unanchored audit suffix exceeds the permitted event limit"
        )

    return {
        **verification,
        "policy_accepted": True,
        "freshness_age_seconds": age_seconds,
        "max_age_seconds": max_age_seconds,
        "max_unanchored_suffix": max_unanchored_suffix,
        "trusted_floor_sequence": floor_sequence,
        "trusted_floor_verified": True,
        "trusted_floor_unanchored_suffix": floor_verification["unanchored_suffix"],
    }
