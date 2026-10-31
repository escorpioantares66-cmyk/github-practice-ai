from concurrent.futures import ThreadPoolExecutor

import pytest

from stage2_sdk_ai import cost_guard


def test_daily_budget_rolls_over_at_utc_day_boundary(monkeypatch):
    day = ["2026-10-30"]
    monkeypatch.setattr(cost_guard, "_utc_day", lambda: day[0])
    cost_guard.reset_cost()
    cost_guard.add_cost("requester-a", "x" * 1000)
    assert cost_guard.COSTS["requester-a"] == pytest.approx(0.02)

    day[0] = "2026-10-31"
    result = cost_guard.check_cost("requester-a")
    assert result["total"] == 0
    assert "requester-a" not in cost_guard.COSTS
    cost_guard.reset_cost()


def test_cost_reservations_are_atomic_under_concurrency(monkeypatch):
    cost_guard.reset_cost()
    monkeypatch.setattr(cost_guard, "DAILY_LIMIT", 1.0)
    monkeypatch.setattr(cost_guard, "RATE", 0.1)

    def reserve():
        return cost_guard.reserve_cost("same-requester", "x" * 6)

    with ThreadPoolExecutor(max_workers=32) as pool:
        results = list(pool.map(lambda _: reserve(), range(100)))

    assert sum(results) == 1
    assert cost_guard.COSTS["same-requester"] == pytest.approx(0.6)
    cost_guard.reset_cost()


def test_cost_reservation_survives_requester_secret_rotation(monkeypatch):
    cost_guard.reset_cost()
    monkeypatch.setattr(cost_guard, "DAILY_LIMIT", 1.0)
    monkeypatch.setenv("AGENT_API_KEYS", "automation=old-secret")
    assert cost_guard.reserve_cost("old-secret", "x" * 30000)

    monkeypatch.setenv("AGENT_API_KEYS", "automation=new-secret")
    assert cost_guard.reserve_cost("new-secret", "x" * 30000) is False
    assert cost_guard.COSTS["automation"] == pytest.approx(0.6)
    cost_guard.reset_cost()
