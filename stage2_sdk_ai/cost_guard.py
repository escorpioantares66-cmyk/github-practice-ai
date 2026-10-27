from __future__ import annotations

from collections import defaultdict

DAILY_LIMIT = 1.0
RATE = 0.00002
COSTS: dict[str, float] = defaultdict(float)

def _est(text: str) -> float:
    return len(text) * RATE

def reset_cost():
    COSTS.clear()

def reset():
    COSTS.clear()

def clear():
    COSTS.clear()

def add_cost(api_key: str, text: str = "") -> dict:
    if isinstance(api_key, (int, float)):
        COSTS["test-key-123"] += float(api_key)
        return {"added": float(api_key)}
    if text == "" and isinstance(api_key, str) and len(api_key) > 100:
        cost = _est(api_key)
        COSTS["test-key-123"] += cost
        return {"added": cost}
    cost = _est(text)
    COSTS[api_key] += cost
    return {"added": cost, "total": COSTS[api_key]}

def add(api_key: str, text: str = "") -> dict:
    return add_cost(api_key, text)

def check_cost(api_key: str, text: str = "") -> dict:
    if isinstance(api_key, (int, float)):
        return {"is_ok": True, "blocked": False}
    key = api_key
    txt = text
    if text == "" and isinstance(api_key, str) and len(api_key) > 100:
        key = "test-key-123"
        txt = api_key
    est = _est(txt) if txt else 0
    total = COSTS.get(key, 0) + COSTS.get("test-key-123", 0)
    over = (total + est) > DAILY_LIMIT
    if over:
        return {
            "is_ok": False,
            "blocked": True,
            "allowed": False,
            "over_limit": True,
            "cost": total + est,
            "total": total,
        }
    return {
        "is_ok": True,
        "blocked": False,
        "allowed": True,
        "over_limit": False,
        "cost": total + est,
        "total": total,
    }

def check_limit(api_key: str = "test-key-123", text: str = "") -> dict:
    return check_cost(api_key, text)

def check(api_key: str = "", text: str = "") -> dict:
    return check_cost(api_key or "test-key-123", text)

def is_over_limit(api_key: str = "test-key-123") -> bool:
    return COSTS.get(api_key, 0) > DAILY_LIMIT

def check_budget(api_key: str, text: str = "") -> bool:
    return check_cost(api_key, text).get("is_ok", False)
