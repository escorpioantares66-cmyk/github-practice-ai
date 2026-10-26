from __future__ import annotations

import time
from collections import defaultdict

_cost: dict[str, float] = defaultdict(float)
_last_reset: float = time.time()
_DAILY_LIMIT = 1.0
_PRICE_PER_1K = 0.001

def _maybe_reset() -> None:
    global _last_reset
    now = time.time()
    if now - _last_reset > 86400:
        _cost.clear()
        _last_reset = now

def estimate_cost(text: str) -> float:
    tokens = len(text.split()) * 1.3
    return (tokens / 1000.0) * _PRICE_PER_1K

def check_cost(api_key: str, text: str) -> dict[str, object]:
    _maybe_reset()
    c = estimate_cost(text)
    total = _cost[api_key] + c
    if total > _DAILY_LIMIT:
        return {"is_ok": False, "reason": f"daily limit ${ _DAILY_LIMIT}", "cost": total}
    return {"is_ok": True, "reason": "ok", "cost": total}

def add_cost(api_key: str, text: str) -> float:
    _maybe_reset()
    c = estimate_cost(text)
    _cost[api_key] += c
    return _cost[api_key]

def reset_cost() -> None:
    _cost.clear()
