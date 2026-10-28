"""Step D regression tests: auth.py must be fail-closed in production.

The old default was os.getenv("AGENT_API_KEYS", "test-key-123"), which
means a production deployment with no AGENT_API_KEYS env-var would silently
accept "test-key-123" as a valid key -- a hardcoded back-door.

These tests verify:
  1. Mock/CI mode (no OPENAI_API_KEY) still accepts "test-key-123" so the
     existing test suite keeps working without any env setup.
  2. Production mode (OPENAI_API_KEY set) with no AGENT_API_KEYS configured
     rejects every key -- fail closed.
  3. Production mode with AGENT_API_KEYS configured accepts only those keys.
"""
import pytest

from stage2_sdk_ai.auth import check_auth, _allowed_keys


def test_mock_mode_accepts_test_key(monkeypatch):
    """CI: no OPENAI_API_KEY → fall back to test-key-123 so tests pass."""
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("AGENT_API_KEYS", raising=False)
    assert check_auth("test-key-123")["is_ok"] is True


def test_production_mode_no_agent_keys_fails_closed(monkeypatch):
    """Production: OPENAI_API_KEY set but AGENT_API_KEYS missing → reject all."""
    monkeypatch.setenv("OPENAI_API_KEY", "sk-real-key")
    monkeypatch.delenv("AGENT_API_KEYS", raising=False)
    result = check_auth("test-key-123")
    assert result["is_ok"] is False, (
        "Fail-closed violated: test-key-123 must not be accepted in production "
        "when AGENT_API_KEYS is not configured."
    )


def test_production_mode_explicit_keys_accepted(monkeypatch):
    """Production: explicit AGENT_API_KEYS → only those keys accepted."""
    monkeypatch.setenv("OPENAI_API_KEY", "sk-real-key")
    monkeypatch.setenv("AGENT_API_KEYS", "prod-key-aaa,prod-key-bbb")
    assert check_auth("prod-key-aaa")["is_ok"] is True
    assert check_auth("prod-key-bbb")["is_ok"] is True
    assert check_auth("test-key-123")["is_ok"] is False


def test_production_mode_explicit_keys_rejects_unknown(monkeypatch):
    """Production: unknown key is rejected even when AGENT_API_KEYS is set."""
    monkeypatch.setenv("OPENAI_API_KEY", "sk-real-key")
    monkeypatch.setenv("AGENT_API_KEYS", "prod-key-aaa")
    assert check_auth("not-a-real-key")["is_ok"] is False


def test_allowed_keys_empty_in_production_without_config(monkeypatch):
    """_allowed_keys() returns [] in production with no AGENT_API_KEYS."""
    monkeypatch.setenv("OPENAI_API_KEY", "sk-real-key")
    monkeypatch.delenv("AGENT_API_KEYS", raising=False)
    assert _allowed_keys() == []
