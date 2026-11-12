"""Non-secret deployment readiness checks for the API."""
from __future__ import annotations

import importlib.util
import os
from typing import Any

from stage2_sdk_ai.storage_paths import data_root

REQUIRED_APPROVAL_ENV = (
    "AGENT_API_KEYS",
    "AGENT_APPROVER_KEYS",
    "SANDBOX_APPROVAL_ACTIVE_KID",
    "SANDBOX_APPROVAL_SIGNING_PRIVATE_KEY",
    "SANDBOX_APPROVAL_VERIFY_KEYS",
    "SANDBOX_APPROVAL_ISSUER",
    "SANDBOX_APPROVAL_AUDIENCE",
    "SANDBOX_APPROVALS_DIR",
    "AGENT_AUDIT_CHECKPOINT_S3_BUCKET",
    "AGENT_SANDBOX_AUDIT_CHECKPOINT_S3_KEY",
    "AGENT_SANDBOX_AUDIT_CHECKPOINT_FLOOR_S3_KEY",
    "AGENT_SANDBOX_AUDIT_STORE_ID",
    "AGENT_SANDBOX_AUDIT_CHECKPOINT_MAX_AGE_SECONDS",
    "AGENT_SANDBOX_AUDIT_MAX_UNANCHORED_SUFFIX",
)


def persistent_storage_ready() -> bool:
    """Check that the configured persistent data root is safe and available."""
    raw_root = os.getenv("APP_DATA_DIR", "").strip()
    if not raw_root:
        return os.getenv("APP_REQUIRE_MOUNTED_DATA_DIR", "").lower() != "true"
    try:
        root = data_root()
    except (OSError, RuntimeError, ValueError):
        return False
    return (
        root.is_dir()
        and not root.is_symlink()
        and os.access(root, os.W_OK | os.X_OK)
    )


def readiness_report() -> dict[str, Any]:
    """Report missing deployment prerequisites without exposing secret values."""
    missing = [key for key in REQUIRED_APPROVAL_ENV if not os.getenv(key, "").strip()]
    if not (os.getenv("AWS_REGION") or os.getenv("AWS_DEFAULT_REGION")):
        missing.append("AWS_REGION")
    boto3_available = importlib.util.find_spec("boto3") is not None

    checks = {
        "persistent_data_directory": bool(os.getenv("APP_DATA_DIR", "").strip())
        and persistent_storage_ready(),
        "approval_configuration": not missing,
        "s3_client_dependency": boto3_available,
    }
    ready = all(checks.values())
    return {
        "status": "ready" if ready else "not_ready",
        "checks": checks,
        "missing_configuration": missing,
    }
