from __future__ import annotations

import hashlib
import hmac
import os
import threading
import time
from collections import defaultdict

_rate: dict[str, list[float]] = defaultdict(list)
_MAX_PER_MIN = 10
_rate_lock = threading.Lock()


def _parse_key_config(env_name: str, legacy_prefix: str) -> list[tuple[str, str]]:
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
            secret = item
            identity = legacy_prefix + hashlib.sha256(
                secret.encode("utf-8")
            ).hexdigest()[:12]

        if identity in identities or secret in secrets:
            return []
        identities.add(identity)
        secrets.add(secret)
        configured.append((identity, secret))
    return configured


def _configured_requester_keys() -> list[tuple[str, str]]:
    """Return validated requester identity/secret pairs."""
    return _parse_key_config("AGENT_API_KEYS", "requester-")

def _allowed_keys() -> list[str]:
    """Return explicitly configured API secrets; missing configuration fails closed."""
    return [secret for _, secret in _configured_requester_keys()]


def check_auth(api_key: str | None) -> dict[str, object]:
    allowed = _allowed_keys()
    if not api_key:
        return {"is_ok": False, "reason": "missing api key"}
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
    if not api_key:
        return None
    for identity, secret in _configured_requester_keys():
        if hmac.compare_digest(api_key, secret):
            return identity
    return None


def check_rate(api_key: str) -> dict[str, object]:
    """Atomically enforce a per-process sliding-window limit."""
    now = time.monotonic()
    with _rate_lock:
        window = [t for t in _rate[api_key] if now - t < 60]
        _rate[api_key] = window
        if len(window) >= _MAX_PER_MIN:
            return {"is_ok": False, "reason": f"rate limit {_MAX_PER_MIN}/min"}
        window.append(now)
        return {"is_ok": True, "reason": "ok"}


def reset_rate() -> None:
    with _rate_lock:
        _rate.clear()


def verify_api_key(api_key: str | None) -> bool:
    return check_auth(api_key).get("is_ok", False)


def check_rate_limit(api_key: str) -> bool:
    return check_rate(api_key).get("is_ok", False)

def _configured_approver_keys() -> list[tuple[str, str]]:
    """Return validated approver identity/secret pairs."""
    return _parse_key_config("AGENT_APPROVER_KEYS", "approver-")


def verify_approver_key(approver_key: str | None) -> bool:
    """Accept only approver credentials not shared with requester access."""
    if not approver_key:
        return False
    if any(
        hmac.compare_digest(approver_key, secret)
        for secret in _allowed_keys()
    ):
        return False
    return any(
        hmac.compare_digest(approver_key, secret)
        for _, secret in _configured_approver_keys()
    )


def approver_identity(approver_key: str) -> str:
    """Resolve a valid approver secret to its stable configured identity."""
    for identity, secret in _configured_approver_keys():
        if hmac.compare_digest(approver_key, secret):
            return identity
    raise ValueError("Approver identity is not configured")


def requester_rate_limit_identity(api_key: str | None) -> str | None:
    """Use the configured requester identity, not its rotating secret, for limits."""
    return requester_identity(api_key)


def check_requester_rate_limit(api_key: str | None) -> bool:
    """Apply the requester rate limit to its stable configured identity."""
    identity = requester_rate_limit_identity(api_key)
    return bool(identity and check_rate_limit(identity))
