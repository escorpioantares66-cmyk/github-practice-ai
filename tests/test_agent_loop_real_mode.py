"""Coverage for agent_loop.py's real-LLM code path (lines ~22-70, 79, 95-96).

These never run in the normal test suite because every other test uses
OPENAI_API_KEY=sk-test-mocked, which keeps _is_mock() True. Here we force
real mode and simulate the `openai` package with a fake module installed
into sys.modules, so we exercise the real request/response/error-handling
logic without installing openai or making a network call.
"""
import sys
import types

import stage2_sdk_ai.agent_loop as agent_loop_mod
from stage2_sdk_ai.agent_loop import _real_llm_pick_tool


def _install_fake_openai(monkeypatch, content=None, raise_exc=None):
    """Put a minimal fake `openai` module in sys.modules so that
    `from openai import OpenAI` inside _real_llm_pick_tool succeeds and
    returns a response we control."""
    fake_module = types.ModuleType("openai")

    class FakeCompletions:
        def create(self, **kwargs):
            if raise_exc:
                raise raise_exc
            msg = types.SimpleNamespace(content=content)
            choice = types.SimpleNamespace(message=msg)
            usage = types.SimpleNamespace(prompt_tokens=120, completion_tokens=40)
            return types.SimpleNamespace(choices=[choice], usage=usage)

    class FakeChat:
        def __init__(self):
            self.completions = FakeCompletions()

    class FakeOpenAI:
        def __init__(self, api_key=None):
            self.api_key = api_key
            self.chat = FakeChat()

    fake_module.OpenAI = FakeOpenAI
    monkeypatch.setitem(sys.modules, "openai", fake_module)


def test_missing_api_key_falls_back_to_mock(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    result = _real_llm_pick_tool("hi", [], requester="test-requester")
    assert result["tool"] in ("search", "read_note", "final")


def test_happy_path_returns_parsed_tool_call(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-real-not-mocked")
    _install_fake_openai(monkeypatch, content='{"tool": "final", "args": {"answer": "ok"}}')
    result = _real_llm_pick_tool("hi", [], requester="test-requester")
    assert result == {"tool": "final", "args": {"answer": "ok"}}


def test_unparseable_response_falls_back_to_mock(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-real-not-mocked")
    _install_fake_openai(monkeypatch, content="not json at all")
    result = _real_llm_pick_tool("hi", [], requester="test-requester")
    assert result["tool"] in ("search", "read_note", "final")


def test_args_not_a_dict_falls_back_to_mock(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-real-not-mocked")
    _install_fake_openai(monkeypatch, content='{"tool": "final", "args": "oops-a-string"}')
    result = _real_llm_pick_tool("hi", [], requester="test-requester")
    assert result["tool"] in ("search", "read_note", "final")


def test_api_exception_falls_back_to_mock(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-real-not-mocked")
    _install_fake_openai(monkeypatch, raise_exc=RuntimeError("simulated API failure"))
    result = _real_llm_pick_tool("hi", [], requester="test-requester")
    assert result["tool"] in ("search", "read_note", "final")


def test_openai_not_installed_falls_back_to_mock(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-real-not-mocked")
    monkeypatch.delitem(sys.modules, "openai", raising=False)
    import builtins

    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "openai":
            raise ImportError("simulated: openai not installed")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    result = _real_llm_pick_tool("hi", [], requester="test-requester")
    assert result["tool"] in ("search", "read_note", "final")


def test_run_agent_real_mode_takes_else_branch_to_final(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-real-not-mocked")
    monkeypatch.setattr(agent_loop_mod, "_is_mock", lambda: False)
    monkeypatch.setattr(
        agent_loop_mod,
        "_real_llm_pick_tool",
        lambda query, history, requester=None: {"tool": "final", "args": {"answer": "done"}},
    )
    result = agent_loop_mod.run_agent("hi")
    assert result["answer"] == "done"


def test_run_agent_real_mode_unknown_tool_fails_closed(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-real-not-mocked")
    monkeypatch.setattr(agent_loop_mod, "_is_mock", lambda: False)
    monkeypatch.setattr(
        agent_loop_mod,
        "_real_llm_pick_tool",
        lambda query, history, requester=None: {"tool": "no_such_tool", "args": {}},
    )
    result = agent_loop_mod.run_agent("hi", max_steps=2)
    assert result["answer"] == "I could not safely process that request."
    assert result["steps"] == []
