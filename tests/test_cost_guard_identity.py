from stage2_sdk_ai import cost_guard


def test_cost_budget_is_shared_across_secret_rotation(monkeypatch):
    cost_guard.reset_cost()
    monkeypatch.setenv("AGENT_API_KEYS", "automation=old-secret")

    cost_guard.add_cost("old-secret", "x" * 30000)
    assert cost_guard.COSTS["automation"] == 0.6
    assert cost_guard.check_budget("old-secret", "x" * 25000) is False

    monkeypatch.setenv("AGENT_API_KEYS", "automation=new-secret")
    assert cost_guard.check_cost("new-secret")["total"] == 0.6
    assert cost_guard.check_budget("new-secret", "x" * 25000) is False
    cost_guard.reset_cost()


def test_different_requester_identities_have_independent_cost_budgets(monkeypatch):
    cost_guard.reset_cost()
    monkeypatch.setenv(
        "AGENT_API_KEYS",
        "automation-a=secret-a,automation-b=secret-b",
    )

    cost_guard.add_cost("secret-a", "x" * 30000)
    assert cost_guard.check_cost("secret-a")["total"] == 0.6
    assert cost_guard.check_cost("secret-b")["total"] == 0
    assert cost_guard.check_budget("secret-b", "x" * 25000) is True
    cost_guard.reset_cost()


def test_unknown_key_does_not_resolve_to_configured_identity(monkeypatch):
    cost_guard.reset_cost()
    monkeypatch.setenv("AGENT_API_KEYS", "automation=known-secret")

    cost_guard.add_cost("unknown-secret", "x" * 30000)
    assert cost_guard.COSTS["unknown-secret"] == 0.6
    assert "automation" not in cost_guard.COSTS
    cost_guard.reset_cost()
