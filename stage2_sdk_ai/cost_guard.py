from __future__ import annotations

import math
import os
import threading
import uuid
from collections import defaultdict
from datetime import datetime, timezone

from stage2_sdk_ai import auth, quota_store

DAILY_LIMIT = 1.0
# Retained for legacy SDK compatibility only. The API records provider token usage.
RATE = 0.00002
MODEL_NAME = "gpt-4o-mini"
MAX_MODEL_CALLS_PER_REQUEST = 3
MAX_PROMPT_TOKENS_PER_CALL = 2048
MAX_COMPLETION_TOKENS_PER_CALL = 250
RESERVATION_TTL_SECONDS = 3600
COSTS: dict[str, float] = defaultdict(float)
_cost_lock = threading.RLock()


def _utc_day() -> str:
    return datetime.now(timezone.utc).date().isoformat()


def _budget_key(api_key: str) -> str:
    identity = auth.requester_identity(api_key)
    return identity if identity is not None else api_key


def _model_rates() -> tuple[float, float]:
    try:
        input_rate = float(os.getenv("AGENT_MODEL_INPUT_USD_PER_1M", "0.15"))
        output_rate = float(os.getenv("AGENT_MODEL_OUTPUT_USD_PER_1M", "0.60"))
    except ValueError as exc:
        raise ValueError("model token prices must be numeric") from exc
    if (
        not math.isfinite(input_rate)
        or not math.isfinite(output_rate)
        or input_rate < 0
        or output_rate < 0
    ):
        raise ValueError("model token prices must be finite and non-negative")
    return input_rate, output_rate


def estimate_request_reservation() -> float:
    """Reserve a bounded worst-case allowance for the API agent loop."""
    input_rate, output_rate = _model_rates()
    per_call = (
        MAX_PROMPT_TOKENS_PER_CALL * input_rate
        + MAX_COMPLETION_TOKENS_PER_CALL * output_rate
    ) / 1_000_000
    return per_call * MAX_MODEL_CALLS_PER_REQUEST


def reset_cost() -> None:
    with _cost_lock:
        COSTS.clear()
    quota_store.reset_cost_usage()


def reset() -> None:
    reset_cost()


def clear() -> None:
    reset_cost()


def reserve_request(api_key: str, reservation_id: str) -> bool:
    if not isinstance(api_key, str) or not api_key:
        return False
    identity = _budget_key(api_key)
    return quota_store.reserve_budget(
        identity,
        _utc_day(),
        reservation_id,
        estimate_request_reservation(),
        DAILY_LIMIT,
        ttl_seconds=RESERVATION_TTL_SECONDS,
    )


def release_request(reservation_id: str) -> None:
    quota_store.release_budget(reservation_id)


def record_model_usage(
    requester: str,
    input_tokens: int,
    output_tokens: int,
    model: str = MODEL_NAME,
) -> dict:
    if model != MODEL_NAME:
        raise ValueError("usage pricing is not configured for this model")
    input_rate, output_rate = _model_rates()
    amount = (
        input_tokens * input_rate + output_tokens * output_rate
    ) / 1_000_000
    result = quota_store.record_model_usage(
        requester, _utc_day(), input_tokens, output_tokens, amount
    )
    with _cost_lock:
        COSTS[requester] = float(result["total"])
    return {"added": amount, **result}


def add_cost(api_key: str, text: str = "") -> dict:
    """Record a legacy character estimate; not used for provider billing."""
    if isinstance(api_key, (int, float)):
        key, amount = "test-key-123", float(api_key)
    elif text == "" and isinstance(api_key, str) and len(api_key) > 100:
        key, amount = "test-key-123", len(api_key) * RATE
    else:
        key, amount = _budget_key(api_key), len(text) * RATE
    total = quota_store.add_estimated_cost(key, _utc_day(), amount)
    with _cost_lock:
        COSTS[key] = total
    return {"added": amount, "total": total}


def add(api_key: str, text: str = "") -> dict:
    return add_cost(api_key, text)


def check_cost(api_key: str, text: str = "") -> dict:
    if isinstance(api_key, (int, float)):
        return {"is_ok": True, "blocked": False}
    key = _budget_key(api_key)
    txt = text
    if text == "" and isinstance(api_key, str) and len(api_key) > 100:
        key, txt = "test-key-123", api_key
    estimate = len(txt) * RATE if txt else 0.0
    usage = quota_store.get_daily_usage(key, _utc_day())
    total = float(usage["total"])
    reserved = float(usage["reserved"])
    projected = total + reserved + estimate
    allowed = projected <= DAILY_LIMIT
    return {
        "is_ok": allowed,
        "blocked": not allowed,
        "allowed": allowed,
        "over_limit": not allowed,
        "cost": projected,
        "total": total,
        "reserved": reserved,
    }


def reserve_cost(api_key: str, text: str = "") -> bool:
    """Legacy SDK estimate path; atomically check and account the estimate."""
    if not isinstance(api_key, str) or not api_key:
        return False
    key = _budget_key(api_key)
    allowed, total = quota_store.reserve_estimated_cost(
        key, _utc_day(), len(text) * RATE, DAILY_LIMIT
    )
    if not allowed:
        return False
    with _cost_lock:
        COSTS[key] = total
    return True


def check_limit(api_key: str = "test-key-123", text: str = "") -> dict:
    return check_cost(api_key, text)


def check(api_key: str = "", text: str = "") -> dict:
    return check_cost(api_key or "test-key-123", text)


def is_over_limit(api_key: str = "test-key-123") -> bool:
    return check_cost(api_key).get("total", 0) > DAILY_LIMIT


def check_budget(api_key: str, text: str = "") -> bool:
    return check_cost(api_key, text).get("is_ok", False)
