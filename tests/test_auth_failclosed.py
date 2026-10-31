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
from concurrent.futures import ThreadPoolExecutor

from stage2_sdk_ai import auth
from stage2_sdk_ai.auth import _allowed_keys, check_auth


def test_explicit_test_key_is_accepted(monkeypatch):
    """A test key is accepted only when explicitly configured."""
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.setenv("AGENT_API_KEYS", "test-key-123")
    assert check_auth("test-key-123")["is_ok"] is True


def test_missing_keys_fails_closed_without_openai_key(monkeypatch):
    """A missing OpenAI key must not enable a default API credential."""
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("AGENT_API_KEYS", raising=False)
    assert check_auth("test-key-123")["is_ok"] is False
    assert _allowed_keys() == []


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


def test_requester_rate_limit_uses_stable_identity_across_secret_rotation(monkeypatch):

    auth.reset_rate()
    monkeypatch.setenv("AGENT_API_KEYS", "automation=old-secret")
    assert auth.requester_identity("old-secret") == "automation"
    for _ in range(auth._MAX_PER_MIN):
        assert auth.check_requester_rate_limit("old-secret") is True

    monkeypatch.setenv("AGENT_API_KEYS", "automation=new-secret")
    assert auth.requester_identity("new-secret") == "automation"
    assert auth.check_requester_rate_limit("new-secret") is False
    auth.reset_rate()


def test_different_requester_identities_have_independent_rate_limits(monkeypatch):

    auth.reset_rate()
    monkeypatch.setenv(
        "AGENT_API_KEYS", "automation-a=secret-a,automation-b=secret-b"
    )
    for _ in range(auth._MAX_PER_MIN):
        assert auth.check_requester_rate_limit("secret-a") is True
    assert auth.check_requester_rate_limit("secret-a") is False
    assert auth.check_requester_rate_limit("secret-b") is True
    auth.reset_rate()


def test_approver_rate_limit_uses_stable_identity_across_secret_rotation(monkeypatch):

    auth.reset_rate()
    monkeypatch.setenv("AGENT_APPROVER_KEYS", "reviewer=old-approver-secret")
    assert auth.verify_approver_key("old-approver-secret")
    identity = auth.approver_identity("old-approver-secret")
    assert identity == "reviewer"
    for _ in range(auth._MAX_PER_MIN):
        assert auth.check_rate_limit(identity, role="approver")

    monkeypatch.setenv("AGENT_APPROVER_KEYS", "reviewer=new-approver-secret")
    assert auth.verify_approver_key("new-approver-secret")
    assert auth.approver_identity("new-approver-secret") == identity
    assert not auth.check_rate_limit(identity, role="approver")
    # Requester and approver identities occupy separate durable rate buckets.
    assert auth.check_rate_limit(identity, role="api")
    auth.reset_rate()


def test_rate_limit_is_atomic_under_concurrent_requests(monkeypatch):
    auth.reset_rate()
    monkeypatch.setattr(auth, "_MAX_PER_MIN", 10)
    with ThreadPoolExecutor(max_workers=32) as pool:
        results = list(pool.map(auth.check_rate_limit, ["parallel-worker"] * 100))
    assert sum(results) == 10
    auth.reset_rate()


def test_malformed_requester_key_config_fails_closed_as_a_whole(monkeypatch):
    monkeypatch.setenv("AGENT_API_KEYS", "automation=secret-a,,backup=secret-b")
    assert _allowed_keys() == []
    assert check_auth("secret-a")["is_ok"] is False
    assert auth.requester_identity("secret-a") is None


def test_duplicate_requester_identity_fails_closed(monkeypatch):
    monkeypatch.setenv("AGENT_API_KEYS", "automation=secret-a,automation=secret-b")
    assert _allowed_keys() == []
    assert check_auth("secret-a")["is_ok"] is False
    assert check_auth("secret-b")["is_ok"] is False


def test_duplicate_requester_secret_across_identities_fails_closed(monkeypatch):
    monkeypatch.setenv("AGENT_API_KEYS", "automation-a=shared-secret,automation-b=shared-secret")
    assert _allowed_keys() == []
    assert check_auth("shared-secret")["is_ok"] is False


def test_empty_identity_or_secret_fails_closed(monkeypatch):
    for config in ("=secret", "automation=", "automation=   "):
        monkeypatch.setenv("AGENT_API_KEYS", config)
        assert _allowed_keys() == []
        assert check_auth("secret")["is_ok"] is False


def test_legacy_bare_secrets_keep_deterministic_identities(monkeypatch):
    monkeypatch.setenv("AGENT_API_KEYS", "legacy-secret-a,legacy-secret-b")
    first = auth.requester_identity("legacy-secret-a")
    assert first is not None
    assert first.startswith("requester-")
    assert auth.requester_identity("legacy-secret-a") == first
    assert auth.requester_identity("legacy-secret-b") != first


def test_malformed_approver_config_fails_closed(monkeypatch):
    monkeypatch.setenv("AGENT_APPROVER_KEYS", "reviewer=secret-a,reviewer=secret-b")
    assert auth.verify_approver_key("secret-a") is False
    assert auth.verify_approver_key("secret-b") is False


def test_requester_and_approver_credentials_must_be_distinct(monkeypatch):
    monkeypatch.setenv("AGENT_API_KEYS", "automation=shared-secret")
    monkeypatch.setenv("AGENT_APPROVER_KEYS", "reviewer=shared-secret")
    assert auth.verify_api_key("shared-secret") is False
    assert auth.verify_approver_key("shared-secret") is False


def test_distinct_requester_and_approver_credentials_are_accepted(monkeypatch):
    monkeypatch.setenv("AGENT_API_KEYS", "automation=requester-secret")
    monkeypatch.setenv("AGENT_APPROVER_KEYS", "reviewer=approver-secret")
    assert auth.verify_api_key("requester-secret") is True
    assert auth.verify_approver_key("approver-secret") is True


def test_rate_limit_uses_persisted_wall_clock(monkeypatch, tmp_path):
    from stage2_sdk_ai import quota_store

    monkeypatch.setenv("AGENT_QUOTA_DB_PATH", str(tmp_path / "quota.sqlite3"))
    auth.reset_rate()
    clock = [100.0]
    monkeypatch.setattr(quota_store.time, "time", lambda: clock[0])

    for _ in range(auth._MAX_PER_MIN):
        assert auth.check_rate_limit("wall-clock-worker")
    assert not auth.check_rate_limit("wall-clock-worker")

    clock[0] += 61.0
    assert auth.check_rate_limit("wall-clock-worker")
    auth.reset_rate()
