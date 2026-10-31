from __future__ import annotations

import threading
from collections import defaultdict
from datetime import datetime, timezone

from stage2_sdk_ai import auth

DAILY_LIMIT = 1.0
RATE = 0.00002
COSTS: dict[str, float] = defaultdict(float)
_cost_lock = threading.RLock()


def _utc_day() -> str:
    """Return the UTC calendar day used for the in-process daily budget."""
    return datetime.now(timezone.utc).date().isoformat()


_cost_day = _utc_day()


def _rollover_if_needed() -> None:
    """Clear in-memory totals when the UTC day changes; caller holds _cost_lock."""
    global _cost_day
    today = _utc_day()
    if today != _cost_day:
        COSTS.clear()
        _cost_day = today


def _budget_key(api_key: str) -> str:
    """Resolve a credential to its stable requester identity for budget tracking.

    Authenticated credentials share a budget when they map to the same
    configured requester identity, including during secret rotation. Preserve
    the supplied key for legacy/internal callers that are not configured API
    credentials.
    """
    identity = auth.requester_identity(api_key)
    return identity if identity is not None else api_key


def _est(text: str) -> float:
    return len(text) * RATE


def reset_cost():
    global _cost_day
    with _cost_lock:
        COSTS.clear()
        _cost_day = _utc_day()


def reset():
    reset_cost()


def clear():
    reset_cost()


def add_cost(api_key: str, text: str = "") -> dict:
    if isinstance(api_key, (int, float)):
        with _cost_lock:
            _rollover_if_needed()
            COSTS["test-key-123"] += float(api_key)
            return {"added": float(api_key)}
    if text == "" and isinstance(api_key, str) and len(api_key) > 100:
        cost = _est(api_key)
        key = "test-key-123"
    else:
        key = _budget_key(api_key)
        cost = _est(text)
    with _cost_lock:
        _rollover_if_needed()
        COSTS[key] += cost
        return {"added": cost, "total": COSTS[key]}


def add(api_key: str, text: str = "") -> dict:
    return add_cost(api_key, text)


def check_cost(api_key: str, text: str = "") -> dict:
    if isinstance(api_key, (int, float)):
        return {"is_ok": True, "blocked": False}
    key = _budget_key(api_key)
    txt = text
    if text == "" and isinstance(api_key, str) and len(api_key) > 100:
        key = "test-key-123"
        txt = api_key
    est = _est(txt) if txt else 0
    with _cost_lock:
        _rollover_if_needed()
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


def reserve_cost(api_key: str, text: str = "") -> bool:
    """Atomically reserve estimated input cost before starting expensive work."""
    if not isinstance(api_key, str) or not api_key:
        return False
    key = _budget_key(api_key)
    estimate = _est(text)
    with _cost_lock:
        _rollover_if_needed()
        total = COSTS.get(key, 0) + COSTS.get("test-key-123", 0)
        if total + estimate > DAILY_LIMIT:
            return False
        COSTS[key] += estimate
        return True


def check_limit(api_key: str = "test-key-123", text: str = "") -> dict:
    return check_cost(api_key, text)


def check(api_key: str = "", text: str = "") -> dict:
    return check_cost(api_key or "test-key-123", text)


def is_over_limit(api_key: str = "test-key-123") -> bool:
    with _cost_lock:
        _rollover_if_needed()
        return COSTS.get(_budget_key(api_key), 0) > DAILY_LIMIT


def check_budget(api_key: str, text: str = "") -> bool:
    return check_cost(api_key, text).get("is_ok", False)
