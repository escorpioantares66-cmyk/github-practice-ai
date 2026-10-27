from __future__ import annotations

import os
import time
from collections import defaultdict

_rate: dict[str, list[float]] = defaultdict(list)
_MAX_PER_MIN = 10

def check_auth(api_key: str | None) -> dict[str, object]:
    allowed = os.getenv("AGENT_API_KEYS", "test-key-123").split(",")
    allowed = [k.strip() for k in allowed if k.strip()]
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
