from __future__ import annotations

import hmac
import os
import time
from collections import defaultdict


_rate: dict[str, list[float]] = defaultdict(list)
_MAX_PER_MIN = 10


def _allowed_keys() -> list[str]:
    """Return explicitly configured API keys.

    API authentication must not depend on AI mock mode or the presence
    of OPENAI_API_KEY. Missing AGENT_API_KEYS fails closed.
    """
    raw = os.getenv("AGENT_API_KEYS", "").strip()
    if not raw:
        return []
    return [key.strip() for key in raw.split(",") if key.strip()]


def check_auth(api_key: str | None) -> dict[str, object]:
    allowed = _allowed_keys()
    if not api_key:
        return {"is_ok": False, "reason": "missing api key"}
    if api_key not in allowed:
        return {"is_ok": False, "reason": "invalid key"}
    return {"is_ok": True, "reason": "ok"}


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
