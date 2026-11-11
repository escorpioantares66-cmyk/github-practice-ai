from __future__ import annotations

import hashlib
import hmac
import os
import re
import threading
from collections import defaultdict

from stage2_sdk_ai import quota_store

_rate: dict[str, list[float]] = defaultdict(list)
_MAX_PER_MIN = 10
_rate_lock = threading.Lock()


def _parse_key_config(
    env_name: str,
    legacy_prefix: str,
    *,
    require_identity: bool = False,
    minimum_secret_length: int = 0,
) -> list[tuple[str, str]]:
    """Parse identity=secret pairs, rejecting the entire config if ambiguous.

    Legacy bare secrets remain supported with deterministic fingerprint
    identities. Empty entries, malformed pairs, duplicate identities, and
    duplicate secrets fail closed instead of silently changing access policy.
    """
    raw = os.getenv(env_name, "").strip()
    if not raw:
        return []

    configured: list[tuple[str, str]] = []
    identities: set[str] = set()
    secrets: set[str] = set()
    for raw_item in raw.split(","):
        item = raw_item.strip()
        if not item:
            return []
        if "=" in item:
            identity, secret = item.split("=", 1)
            identity, secret = identity.strip(), secret.strip()
            if not identity or not secret:
                return []
        else:
            if require_identity:
                return []
            secret = item
            identity = legacy_prefix + hashlib.sha256(
                secret.encode("utf-8")
            ).hexdigest()[:12]

        # Approval credentials are provisioned as high-entropy secrets.
        # Keep the legacy requester parser compatible, but require explicit
        # identities and at least 32 ASCII characters for approval principals.
        if (
            not secret.isascii()
            or len(secret) < minimum_secret_length
            or (
                require_identity
                and not re.fullmatch(
                    r"[A-Za-z0-9][A-Za-z0-9._:@-]{0,127}", identity
                )
            )
        ):
            return []
        if identity in identities or secret in secrets:
            return []
        identities.add(identity)
        secrets.add(secret)
        configured.append((identity, secret))
    return configured


def _configured_requester_keys() -> list[tuple[str, str]]:
    """Return validated requester identity/secret pairs."""
    return _parse_key_config("AGENT_API_KEYS", "requester-")


def _configured_approval_requester_keys() -> list[tuple[str, str]]:
    """Return requester credentials with explicit principal identities only."""
    return _parse_key_config(
        "AGENT_API_KEYS",
        "requester-",
        require_identity=True,
        minimum_secret_length=32,
    )

def _allowed_keys() -> list[str]:
    """Return explicitly configured API secrets; missing configuration fails closed."""
    return [secret for _, secret in _configured_requester_keys()]


def check_auth(api_key: str | None) -> dict[str, object]:
    if not isinstance(api_key, str) or not api_key:
        return {"is_ok": False, "reason": "missing api key"}
    if not api_key.isascii():
        return {"is_ok": False, "reason": "invalid key"}
    allowed = _allowed_keys()
    if not any(hmac.compare_digest(api_key, key) for key in allowed):
        return {"is_ok": False, "reason": "invalid key"}
    if any(
        hmac.compare_digest(api_key, secret)
        for _, secret in _configured_approver_keys()
    ):
        return {"is_ok": False, "reason": "credential roles must be separate"}
    return {"is_ok": True, "reason": "ok"}


def requester_identity(api_key: str | None) -> str | None:
    """Resolve a valid API secret to its stable, non-secret requester identity."""
    if not isinstance(api_key, str) or not api_key or not api_key.isascii():
        return None
    for identity, secret in _configured_requester_keys():
        if hmac.compare_digest(api_key, secret):
            return identity
    return None


def check_rate(api_key: str, role: str = "api") -> dict[str, object]:
    """Enforce a durable sliding-window limit shared by local worker processes."""
    try:
        allowed = quota_store.check_rate_limit(
            api_key, role, _MAX_PER_MIN, window_seconds=60
        )
    except Exception:
        return {"is_ok": False, "reason": "rate limit storage unavailable"}
    if not allowed:
        return {"is_ok": False, "reason": f"rate limit {_MAX_PER_MIN}/min"}
    return {"is_ok": True, "reason": "ok"}


def reset_rate() -> None:
    with _rate_lock:
        _rate.clear()
    quota_store.reset_rate_limits()


def verify_api_key(api_key: str | None) -> bool:
    return check_auth(api_key).get("is_ok", False)


def check_rate_limit(api_key: str, role: str = "api") -> bool:
    return check_rate(api_key, role=role).get("is_ok", False)

def _configured_approver_keys() -> list[tuple[str, str]]:
    """Return approver credentials with explicit principal identities only."""
    return _parse_key_config(
        "AGENT_APPROVER_KEYS",
        "approver-",
        require_identity=True,
        minimum_secret_length=32,
    )


def verify_approver_key(approver_key: str | None) -> bool:
    """Accept approver credentials only when both roles have named principals."""
    if (
        not isinstance(approver_key, str)
        or not approver_key
        or not approver_key.isascii()
    ):
        return False

    requester_keys = _configured_approval_requester_keys()
    approver_keys = _configured_approver_keys()
    # Without explicit identities on both sides, self-approval cannot be
    # reliably detected. Keep approval decisions disabled until configured.
    if not requester_keys or not approver_keys:
        return False
    if any(
        hmac.compare_digest(approver_key, secret)
        for _, secret in requester_keys
    ):
        return False
    return any(
        hmac.compare_digest(approver_key, secret)
        for _, secret in approver_keys
    )


def approver_identity(approver_key: str) -> str:
    """Resolve a valid approver secret to its stable configured identity."""
    if (
        not isinstance(approver_key, str)
        or not approver_key
        or not approver_key.isascii()
    ):
        raise ValueError("Approver identity is not configured")
    if not _configured_approval_requester_keys():
        raise ValueError("Requester identities must be explicitly configured")
    for identity, secret in _configured_approver_keys():
        if hmac.compare_digest(approver_key, secret):
            return identity
    raise ValueError("Approver identity is not configured")


def approval_requester_identity(api_key: str | None) -> str | None:
    """Resolve only an explicitly named requester for approval workflows."""
    if not isinstance(api_key, str) or not api_key or not api_key.isascii():
        return None
    for identity, secret in _configured_approval_requester_keys():
        if hmac.compare_digest(api_key, secret):
            return identity
    return None


def requester_rate_limit_identity(api_key: str | None) -> str | None:
    """Use the configured requester identity, not its rotating secret, for limits."""
    return requester_identity(api_key)


def check_requester_rate_limit(api_key: str | None) -> bool:
    """Apply the requester rate limit to its stable configured identity."""
    identity = requester_rate_limit_identity(api_key)
    return bool(identity and check_rate_limit(identity))
