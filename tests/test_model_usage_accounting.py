import pytest

from stage2_sdk_ai import cost_guard, quota_store
from stage2_sdk_ai.agent_loop import UsageAccountingError, _real_llm_pick_tool


def test_model_usage_is_priced_from_provider_token_counts(monkeypatch, tmp_path):
    monkeypatch.setenv("AGENT_QUOTA_DB_PATH", str(tmp_path / "quota.sqlite3"))
    monkeypatch.setenv("AGENT_MODEL_INPUT_USD_PER_1M", "0.15")
    monkeypatch.setenv("AGENT_MODEL_OUTPUT_USD_PER_1M", "0.60")
    result = cost_guard.record_model_usage("requester-a", 1000, 500)
    assert result["added"] == pytest.approx(0.00045)
    usage = quota_store.get_daily_usage("requester-a", cost_guard._utc_day())
    assert usage["input_tokens"] == 1000
    assert usage["output_tokens"] == 500


def test_invalid_model_pricing_fails_closed(monkeypatch):
    monkeypatch.setenv("AGENT_MODEL_INPUT_USD_PER_1M", "nan")
    with pytest.raises(ValueError):
        cost_guard.estimate_request_reservation()


def test_missing_provider_usage_stops_model_call(monkeypatch):
    import sys
    import types

    fake = types.ModuleType("openai")

    class Completions:
        def create(self, **kwargs):
            choice = types.SimpleNamespace(
                message=types.SimpleNamespace(content='{"tool":"final","args":{"answer":"ok"}}')
            )
            return types.SimpleNamespace(choices=[choice], usage=None)

    class Client:
        def __init__(self, api_key=None):
            self.chat = types.SimpleNamespace(completions=Completions())

    fake.OpenAI = Client
    monkeypatch.setitem(sys.modules, "openai", fake)
    monkeypatch.setenv("OPENAI_API_KEY", "sk-live-test")
    with pytest.raises(UsageAccountingError):
        _real_llm_pick_tool("hello", [], requester="requester-a")



def test_usage_is_charged_to_reservation_day_across_utc_midnight(monkeypatch, tmp_path):
    monkeypatch.setenv("AGENT_QUOTA_DB_PATH", str(tmp_path / "quota.sqlite3"))
    day = ["2026-10-31"]
    monkeypatch.setattr(cost_guard, "_utc_day", lambda: day[0])
    reservation_id = "utc-boundary-reservation"
    assert cost_guard.reserve_request("requester-a", reservation_id)

    day[0] = "2026-11-01"
    cost_guard.record_model_usage(
        "requester-a", 1000, 500, reservation_id=reservation_id
    )
    old_day = quota_store.get_daily_usage("requester-a", "2026-10-31")
    new_day = quota_store.get_daily_usage("requester-a", "2026-11-01")
    assert old_day["input_tokens"] == 1000
    assert old_day["output_tokens"] == 500
    assert new_day["input_tokens"] == 0
    cost_guard.release_request(reservation_id)
