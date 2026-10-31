from __future__ import annotations

import hashlib
import hmac
import os
import time
from collections import defaultdict

_rate: dict[str, list[float]] = defaultdict(list)
_MAX_PER_MIN = 10


def _configured_requester_keys() -> list[tuple[str, str]]:
    """Return (identity, secret) pairs from AGENT_API_KEYS.

    Preferred syntax is identity=secret, comma-separated. Legacy bare
    secrets remain accepted and receive a deterministic fingerprint identity.
    Keep an identity label stable when rotating its secret.
    """
    raw = os.getenv("AGENT_API_KEYS", "").strip()
    configured: list[tuple[str, str]] = []
    for item in raw.split(","):
        item = item.strip()
        if not item:
            continue
        if "=" in item:
            identity, secret = item.split("=", 1)
            identity, secret = identity.strip(), secret.strip()
            if not identity or not secret:
                continue
        else:
            secret = item
            identity = "requester-" + hashlib.sha256(
                secret.encode("utf-8")
            ).hexdigest()[:12]
        configured.append((identity, secret))
    return configured


def _allowed_keys() -> list[str]:
    """Return explicitly configured API secrets; missing configuration fails closed."""
    return [secret for _, secret in _configured_requester_keys()]


def check_auth(api_key: str | None) -> dict[str, object]:
    allowed = _allowed_keys()
    if not api_key:
        return {"is_ok": False, "reason": "missing api key"}
    if not any(hmac.compare_digest(api_key, key) for key in allowed):
        return {"is_ok": False, "reason": "invalid key"}
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
    now = time.time()
    window = [t for t in _rate[api_key] if now - t < 60]
    _rate[api_key] = window
    if len(window) >= _MAX_PER_MIN:
        return {"is_ok": False, "reason": f"rate limit {_MAX_PER_MIN}/min"}
    _rate[api_key].append(now)
    return {"is_ok": True, "reason": "ok"}


def reset_rate() -> None:
    _rate.clear()


def verify_api_key(api_key: str | None) -> bool:
    return check_auth(api_key).get("is_ok", False)


def check_rate_limit(api_key: str) -> bool:
    return check_rate(api_key).get("is_ok", False)

def verify_approver_key(approver_key: str | None) -> bool:
    """Accept only explicitly configured approval credentials."""
    if not approver_key:
        return False

    raw = os.getenv("AGENT_APPROVER_KEYS", "").strip()
    if not raw:
        return False

    allowed = [key.strip() for key in raw.split(",") if key.strip()]
    return any(
        hmac.compare_digest(approver_key, key)
        for key in allowed
    )



def approver_identity(approver_key: str) -> str:
    """Return a non-secret stable audit/rate-limit identifier for a valid key."""
    fingerprint = hashlib.sha256(approver_key.encode("utf-8")).hexdigest()[:12]
    return f"approver-{fingerprint}"
