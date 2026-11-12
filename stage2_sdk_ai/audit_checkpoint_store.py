"""Read-only S3 retrieval and local export for independent audit checkpoints.

The application role should have s3:GetObject only. Checkpoint publication is
an operator-controlled action using separate AWS credentials.
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any

from . import approval
from .secure_storage import write_text_atomically

MAX_CHECKPOINT_BYTES = 16 * 1024


class AuditCheckpointStoreError(RuntimeError):
    """Raised when an external checkpoint cannot be safely retrieved."""


def export_audit_checkpoint(path: str | Path) -> dict[str, Any]:
    """Create a verified checkpoint and save it as an owner-only local file."""
    destination = Path(path)
    checkpoint = approval.create_audit_checkpoint()
    content = json.dumps(
        checkpoint, sort_keys=True, separators=(",", ":"), allow_nan=False
    )
    write_text_atomically(destination, content + "\n", destination.parent)
    return checkpoint


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def load_s3_checkpoint(
    s3_client: Any | None = None,
    *,
    bucket: str | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    """Fetch a bounded checkpoint from S3 using read-only application access."""
    bucket_name = bucket or os.getenv("AGENT_AUDIT_CHECKPOINT_S3_BUCKET", "")
    object_key = key or os.getenv(
        "AGENT_AUDIT_CHECKPOINT_S3_KEY", "audit-checkpoints/latest.json"
    )
    if not bucket_name or not object_key or object_key.startswith("/"):
        raise AuditCheckpointStoreError("S3 checkpoint bucket/key is not configured")

    if s3_client is None:
        try:
            import boto3
        except ImportError as exc:
            raise AuditCheckpointStoreError(
                "S3 checkpoint support requires the audit-s3 optional dependency"
            ) from exc
        region = os.getenv("AWS_REGION") or os.getenv("AWS_DEFAULT_REGION")
        s3_client = boto3.client("s3", region_name=region)

    try:
        response = s3_client.get_object(Bucket=bucket_name, Key=object_key)
        body = response["Body"]
        try:
            raw = body.read(MAX_CHECKPOINT_BYTES + 1)
        finally:
            close = getattr(body, "close", None)
            if callable(close):
                close()
        if len(raw) > MAX_CHECKPOINT_BYTES:
            raise AuditCheckpointStoreError("S3 checkpoint exceeds the size limit")
        checkpoint = json.loads(
            raw.decode("utf-8"), object_pairs_hook=_reject_duplicate_keys
        )
        # Reuse the audit verifier's strict schema and anchor checks.
        approval.verify_audit_log(checkpoint)
        return checkpoint
    except AuditCheckpointStoreError:
        raise
    except approval.AuditLogIntegrityError as exc:
        raise AuditCheckpointStoreError(
            "S3 checkpoint is malformed or does not match the local audit log"
        ) from exc
    except (KeyError, TypeError, ValueError, UnicodeError) as exc:
        raise AuditCheckpointStoreError("S3 checkpoint response is invalid") from exc
    except Exception as exc:
        # Do not expose SDK request details or credentials in application errors.
        raise AuditCheckpointStoreError("Unable to retrieve S3 audit checkpoint") from exc


def verify_audit_log_from_s3(s3_client: Any | None = None) -> dict[str, Any]:
    """Verify local audit history against the trusted checkpoint stored in S3."""
    checkpoint = load_s3_checkpoint(s3_client)
    return approval.verify_audit_log(checkpoint)

def _read_s3_checkpoint_payload(s3_client: Any, bucket: str, key: str) -> bytes:
    """Read one bounded checkpoint object without granting application write access."""
    try:
        response = s3_client.get_object(Bucket=bucket, Key=key)
        body = response["Body"]
        try:
            raw = body.read(MAX_CHECKPOINT_BYTES + 1)
        finally:
            close = getattr(body, "close", None)
            if callable(close):
                close()
    except Exception as exc:
        raise AuditCheckpointStoreError(
            "Unable to retrieve independent sandbox audit checkpoint"
        ) from exc
    if not isinstance(raw, bytes) or len(raw) > MAX_CHECKPOINT_BYTES:
        raise AuditCheckpointStoreError("Independent audit checkpoint is invalid or oversized")
    return raw


def verify_sandbox_audit_log_from_s3(
    s3_client: Any | None = None,
    *,
    bucket: str | None = None,
    checkpoint_key: str | None = None,
    trusted_floor_key: str | None = None,
    store_id: str | None = None,
    now: float | None = None,
    max_age_seconds: float | None = None,
    max_unanchored_suffix: int | None = None,
    reserve_unanchored_events: int = 0,
) -> dict[str, Any]:
    """Enforce the sandbox audit's independent S3 checkpoint and trusted floor.

    The application role is read-only. The candidate checkpoint and operator-
    accepted floor are separately retained S3 objects; this function never
    creates, advances, repairs, or replaces either object.
    """
    from . import audit_checkpoint_integrity as integrity

    bucket_name = bucket or os.getenv("AGENT_AUDIT_CHECKPOINT_S3_BUCKET", "").strip()
    candidate_key = checkpoint_key or os.getenv(
        "AGENT_SANDBOX_AUDIT_CHECKPOINT_S3_KEY",
        "audit-checkpoints/sandbox/latest.json",
    )
    floor_key = trusted_floor_key or os.getenv(
        "AGENT_SANDBOX_AUDIT_CHECKPOINT_FLOOR_S3_KEY",
        "audit-checkpoints/sandbox/trusted-floor.json",
    )
    trusted_store_id = store_id or os.getenv("AGENT_SANDBOX_AUDIT_STORE_ID", "").strip()
    raw_max_age = os.getenv("AGENT_SANDBOX_AUDIT_CHECKPOINT_MAX_AGE_SECONDS", "")
    raw_max_suffix = os.getenv("AGENT_SANDBOX_AUDIT_MAX_UNANCHORED_SUFFIX", "")

    if not bucket_name or not candidate_key or not floor_key or candidate_key == floor_key:
        raise AuditCheckpointStoreError("Independent sandbox checkpoint storage is not configured")
    if not trusted_store_id:
        raise AuditCheckpointStoreError("Sandbox audit store identity is not configured")
    if max_age_seconds is None:
        try:
            max_age_seconds = float(raw_max_age)
        except (TypeError, ValueError) as exc:
            raise AuditCheckpointStoreError(
                "Sandbox checkpoint maximum age policy is not configured"
            ) from exc
    if max_unanchored_suffix is None:
        try:
            if not raw_max_suffix or not raw_max_suffix.isascii() or not raw_max_suffix.isdecimal():
                raise ValueError("invalid suffix policy")
            max_unanchored_suffix = int(raw_max_suffix)
        except (TypeError, ValueError) as exc:
            raise AuditCheckpointStoreError(
                "Sandbox checkpoint maximum unanchored suffix policy is not configured"
            ) from exc

    if s3_client is None:
        try:
            import boto3
        except ImportError as exc:
            raise AuditCheckpointStoreError(
                "S3 checkpoint support requires the audit-s3 optional dependency"
            ) from exc
        region = os.getenv("AWS_REGION") or os.getenv("AWS_DEFAULT_REGION")
        s3_client = boto3.client("s3", region_name=region)

    try:
        candidate_raw = _read_s3_checkpoint_payload(
            s3_client, bucket_name, candidate_key
        )
        floor_raw = _read_s3_checkpoint_payload(s3_client, bucket_name, floor_key)
        candidate = integrity.parse_checkpoint(
            candidate_raw, authority=integrity.SANDBOX_AUTHORITY,
            store_id=trusted_store_id,
        )
        try:
            floor_value = json.loads(
                floor_raw.decode("utf-8"), object_pairs_hook=_reject_duplicate_keys
            )
        except (UnicodeError, ValueError, TypeError) as exc:
            raise AuditCheckpointStoreError(
                "Independent sandbox trusted floor is malformed"
            ) from exc
        floor = integrity.validate_trusted_checkpoint_floor(
            floor_value,
            authority=integrity.SANDBOX_AUTHORITY,
            store_id=trusted_store_id,
        )
        return integrity.verify_checkpoint_with_policy(
            candidate,
            authority=integrity.SANDBOX_AUTHORITY,
            store_id=trusted_store_id,
            trusted_floor=floor,
            now=time.time() if now is None else now,
            max_age_seconds=max_age_seconds,
            max_unanchored_suffix=max_unanchored_suffix,
            reserve_unanchored_events=reserve_unanchored_events,
        )
    except AuditCheckpointStoreError:
        raise
    except Exception as exc:
        raise AuditCheckpointStoreError(
            "Sandbox audit history does not match its independent trusted checkpoint"
        ) from exc


def create_sandbox_audit_checkpoint(store_id: str) -> dict[str, Any]:
    """Create an in-memory sandbox checkpoint for separate operator review/publication."""
    from .audit_checkpoint_integrity import SANDBOX_AUTHORITY, create_checkpoint_envelope

    return create_checkpoint_envelope(SANDBOX_AUTHORITY, store_id)
