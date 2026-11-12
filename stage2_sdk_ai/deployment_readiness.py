"""Non-secret deployment readiness checks for the API."""
from __future__ import annotations

import importlib.util
import os
from pathlib import Path
from typing import Any

from stage2_sdk_ai import sandbox_approval
from stage2_sdk_ai.storage_paths import data_root

REQUIRED_APPROVAL_ENV = (
    "AGENT_API_KEYS",
    "AGENT_APPROVER_KEYS",
    "OPENAI_API_KEY",
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

def _path_is_within_data_root(raw_path: str) -> bool:
    """Require configured durable stores to resolve beneath the persistent root."""
    raw_root = os.getenv("APP_DATA_DIR", "").strip()
    if not raw_root or not raw_path.strip():
        return False
    try:
        root = Path(raw_root).expanduser().resolve(strict=True)
        target = Path(raw_path).expanduser()
        if not target.is_absolute():
            return False
        resolved = target.resolve(strict=False)
    except (OSError, RuntimeError, ValueError):
        return False
    return resolved != root and root in resolved.parents

def sandbox_checkpoint_enforcement_ready() -> bool:
    """Exercise the production checkpoint verifier; never infer enforcement from config."""
    verifier = getattr(
        sandbox_approval, "_verify_independent_audit_checkpoint", None
    )
    if not callable(verifier):
        return False
    try:
        result = verifier()
    except Exception:
        # Do not leak SDK, bucket, object-key, or credential details to /readyz.
        return False
    return (
        isinstance(result, dict)
        and result.get("valid") is True
        and result.get("policy_accepted") is True
        and result.get("trusted_floor_verified") is True
    )

def readiness_report() -> dict[str, Any]:
    """Report deployment prerequisites without exposing secret values."""
    missing = [key for key in REQUIRED_APPROVAL_ENV if not os.getenv(key, "").strip()]
    if not (os.getenv("AWS_REGION") or os.getenv("AWS_DEFAULT_REGION")):
        missing.append("AWS_REGION")
    boto3_available = importlib.util.find_spec("boto3") is not None

    checks = {
        "persistent_data_directory": bool(os.getenv("APP_DATA_DIR", "").strip())
        and persistent_storage_ready(),
        "approval_configuration": not missing,
        "sandbox_store_within_persistent_data": _path_is_within_data_root(
            os.getenv("SANDBOX_APPROVALS_DIR", "")
        ),
        "quota_database_within_persistent_data": _path_is_within_data_root(
            os.getenv("AGENT_QUOTA_DB_PATH", "")
        ),
        "s3_client_dependency": boto3_available,
        "sandbox_checkpoint_enforcement": sandbox_checkpoint_enforcement_ready(),
    }
    ready = all(checks.values())
    return {
        "status": "ready" if ready else "not_ready",
        "checks": checks,
        "missing_configuration": missing,
    }
