from __future__ import annotations

import os
import time
from collections import defaultdict

from .tools import _is_mock

_rate: dict[str, list[float]] = defaultdict(list)
_MAX_PER_MIN = 10


def _allowed_keys() -> list[str]:
    """Return the list of valid API keys.

    In mock/CI mode (no OPENAI_API_KEY set) we fall back to the well-known
    test key so the test suite works without any environment setup.

    In production mode (real OPENAI_API_KEY present) we require
    AGENT_API_KEYS to be explicitly configured.  If it is missing or empty
    we return an empty list, which means *every* request is rejected -- a
    fail-closed posture that prevents a stale default from becoming an
    unauthenticated back-door.
    """
    raw = os.getenv("AGENT_API_KEYS", "").strip()
    if raw:
        return [k.strip() for k in raw.split(",") if k.strip()]
    if _is_mock():
        return ["test-key-123"]
    # Production with no AGENT_API_KEYS configured: fail closed.
    return []


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
