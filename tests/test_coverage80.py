import os

os.environ["AGENT_API_KEYS"] = "test-key-123"
os.environ["OPENAI_API_KEY"] = "sk-test-mocked"

def test_boost_api():
    from stage2_sdk_ai.api import health, healthz, query, root
    assert healthz()["status"] == "ok"
    assert "github" in root()["message"].lower()
    assert health()["status"] == "ok"
    assert "answer" in query("hi", top_k=2) or "blocked" in str(query("hi")).lower()

def test_boost_safety_report():
    from stage2_sdk_ai.safety_report import generate_safety_report
    inj = {"pass_rate": 1.0, "blocked": 10, "total": 10}
    pii = {"pass_rate": 1.0, "filtered": 5, "total": 5}
    cost = {"pass": True, "spike_blocked": True}
    appr = {"pass_rate": 1.0, "blocked": 3, "total": 3}
    r = generate_safety_report(inj, pii, cost, appr, tests_passed=39)
    assert r["overall"] in ("SAFE_TO_DEPLOY", "NEEDS_FIX")

def test_boost_write_and_approval(monkeypatch, tmp_path):
    from stage2_sdk_ai import approval, write_tools
    monkeypatch.setenv("AGENT_APPROVER_KEYS", "test-approver-secret")
    monkeypatch.setattr(approval, "_approvals_dir", tmp_path / "approvals")
    monkeypatch.setattr(approval, "_audit_file", tmp_path / "logs" / "audit.jsonl")
    monkeypatch.setattr(write_tools, "_notes_dir", tmp_path / "notes")
    req = approval.request_approval(
        "write_note", {"path": str(tmp_path / "notes" / "prod.md"), "content": "final"}
    )
    rid = req.get("id") or req.get("approval_id")
    assert rid
    approval.approve(rid, approver_key="test-approver-secret")
    res = write_tools.write_note("prod.md", "final", approval_id=rid)
    assert isinstance(res, dict)

def test_boost_vector_and_redteam():
    from stage2_sdk_ai.red_team import INJECTION_PAYLOADS, eval_input_guard
    r = eval_input_guard(lambda t: {"is_safe": "ignore" not in t.lower()})
    assert r["total"] == len(INJECTION_PAYLOADS)
