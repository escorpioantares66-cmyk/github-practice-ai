"""Read-only S3 retrieval and local export for independent audit checkpoints.

The application role should have s3:GetObject only. Checkpoint publication is
an operator-controlled action using separate AWS credentials.
"""
from __future__ import annotations

import json
import os
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
        raw = body.read(MAX_CHECKPOINT_BYTES + 1)
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
