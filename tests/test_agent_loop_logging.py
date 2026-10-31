"""Step C regression tests: agent_loop.py's 3 fallback paths used to be
silent print() calls -- invisible to any log aggregator. They now go
through the same structured logger as the rest of the app. These tests
confirm each path actually emits a structured warning with useful
context, not just that it falls back to the mock (test_agent_loop_real_mode.py
already covers the fallback behavior itself).
"""
import logging

from stage2_sdk_ai.agent_loop import _real_llm_pick_tool
from tests.test_agent_loop_real_mode import _install_fake_openai


def test_missing_api_key_logs_structured_warning(monkeypatch, caplog):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    with caplog.at_level(logging.WARNING, logger="stage2_sdk_ai.agent_loop"):
        _real_llm_pick_tool("hi", [], requester="test-requester")
    assert len(caplog.records) == 1
    record = caplog.records[0]
    assert "OPENAI_API_KEY" in record.message
    assert record.event == "llm_fallback"
    assert record.reason == "missing_api_key"


def test_openai_not_installed_logs_structured_warning(monkeypatch, caplog):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-real-not-mocked")
    monkeypatch.delitem(__import__("sys").modules, "openai", raising=False)
    import builtins

    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "openai":
            raise ImportError("simulated: openai not installed")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)

    with caplog.at_level(logging.WARNING, logger="stage2_sdk_ai.agent_loop"):
        _real_llm_pick_tool("hi", [], requester="test-requester")
    assert len(caplog.records) == 1
    record = caplog.records[0]
    assert record.event == "llm_fallback"
    assert record.reason == "import_error"


def test_api_exception_logs_structured_warning_with_traceback(monkeypatch, caplog):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-real-not-mocked")
    _install_fake_openai(monkeypatch, raise_exc=RuntimeError("simulated API failure"))

    with caplog.at_level(logging.WARNING, logger="stage2_sdk_ai.agent_loop"):
        _real_llm_pick_tool("hi", [], requester="test-requester")
    assert len(caplog.records) == 1
    record = caplog.records[0]
    assert record.event == "llm_fallback"
    assert record.reason == "request_failed"
    assert record.exception_type == "RuntimeError"
    assert record.exc_info is not None
