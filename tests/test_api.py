"""End-to-end tests for the real FastAPI app in stage2_sdk_ai/api.py.

Unlike tests/test_rag_phase3.py (which calls query_compat() in-process and
never touches auth, HTTP status codes, or the dependency chain), these use
fastapi.testclient.TestClient to drive real requests through the app --
including the X-API-Key header, auth failures, rate limiting, request-id
tracing, and unhandled-exception handling.
"""
import os

os.environ.setdefault("OPENAI_API_KEY", "sk-test-mocked")
os.environ.setdefault("CI", "true")

import pytest
from fastapi.testclient import TestClient

from stage2_sdk_ai import auth
from stage2_sdk_ai.api import app

VALID_KEY = "test-key-123"


@pytest.fixture(autouse=True)
def _reset_auth_state(monkeypatch):
    monkeypatch.setenv("AGENT_API_KEYS", VALID_KEY)
    auth.reset_rate()
    yield
    auth.reset_rate()


@pytest.fixture
def client(monkeypatch, tmp_path):
    from stage2_sdk_ai import approval, tools, write_tools

    monkeypatch.setattr(write_tools, "_notes_dir", tmp_path / "notes")
    monkeypatch.setattr(tools, "_notes_dir", tmp_path / "notes")
    monkeypatch.setattr(approval, "_approvals_dir", tmp_path / "approvals")
    monkeypatch.setattr(
        approval, "_audit_file", tmp_path / "logs" / "audit.jsonl"
    )
    return TestClient(app)


def test_healthz(client):
    resp = client.get("/healthz")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_root(client):
    resp = client.get("/")
    assert resp.status_code == 200
    assert "message" in resp.json()


def test_query_without_api_key_is_401(client):
    resp = client.post("/query", json={"query": "hello"})
    assert resp.status_code == 401


def test_query_with_wrong_api_key_is_401(client):
    resp = client.post(
        "/query", json={"query": "hello"}, headers={"X-API-Key": "totally-wrong"}
    )
    assert resp.status_code == 401


def test_query_with_valid_api_key_succeeds(client):
    resp = client.post(
        "/query", json={"query": "laundry hours"}, headers={"X-API-Key": VALID_KEY}
    )
    assert resp.status_code == 200
    body = resp.json()
    assert "answer" in body
    assert "sources" in body


def test_query_rate_limit_enforced(client):
    # auth._MAX_PER_MIN is 10; the 11th request in the window should 429.
    for _ in range(10):
        resp = client.post(
            "/query", json={"query": "hi"}, headers={"X-API-Key": VALID_KEY}
        )
        assert resp.status_code == 200
    resp = client.post(
        "/query", json={"query": "hi"}, headers={"X-API-Key": VALID_KEY}
    )
    assert resp.status_code == 429


def test_write_requires_approval(client):
    resp = client.post(
        "/write",
        json={"path": "notes/test.md", "content": "hello"},
        headers={"X-API-Key": VALID_KEY},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body.get("needs_approval") is True
    assert body.get("approval_id") or body.get("id")


def test_write_without_api_key_is_401(client):
    resp = client.post("/write", json={"path": "x.md", "content": "y"})
    assert resp.status_code == 401


def test_oversized_write_body_is_rejected_before_json_validation(client):
    from stage2_sdk_ai.api import MAX_REQUEST_BODY_BYTES

    response = client.post(
        "/write",
        content=b'{"path":"large.md","content":"' + b"x" * MAX_REQUEST_BODY_BYTES + b'"}',
        headers={"X-API-Key": VALID_KEY, "Content-Type": "application/json"},
    )
    assert response.status_code == 413
    assert response.json()["detail"] == "Request body too large"


def test_oversized_deny_body_is_rejected_before_json_validation(client, monkeypatch):
    from stage2_sdk_ai.api import MAX_REQUEST_BODY_BYTES

    # The early middleware auth gate requires this test key to be configured.
    monkeypatch.setenv("AGENT_APPROVER_KEYS", "any")
    response = client.post(
        "/deny",
        content=(
            b'{"approval_id":"' + b"d" * 32 + b'","reason":"'
            + b"x" * MAX_REQUEST_BODY_BYTES
            + b'"}'
        ),
        headers={"X-Approver-Key": "any", "Content-Type": "application/json"},
    )
    assert response.status_code == 413
    assert response.json()["detail"] == "Request body too large"


def test_every_response_carries_a_request_id_header(client):
    resp = client.get("/healthz")
    assert resp.status_code == 200
    assert "x-request-id" in resp.headers
    assert len(resp.headers["x-request-id"]) > 0


def test_unhandled_exception_returns_clean_json_not_a_traceback(client, monkeypatch):
    """Before the Step B exception handler existed, this exact scenario --
    an unexpected exception inside /query -- would have 500'd with a raw
    stack trace leaked to the caller. Now it returns clean JSON with a
    request_id the operator can grep for in the logs."""
    import stage2_sdk_ai.api as api_mod

    def _boom(*args, **kwargs):
        raise RuntimeError("simulated unexpected failure")

    monkeypatch.setattr(api_mod, "run_agent", _boom)
    resp = client.post(
        "/query", json={"query": "hi"}, headers={"X-API-Key": VALID_KEY}
    )
    assert resp.status_code == 500
    body = resp.json()
    assert body["error"] == "internal_error"
    assert "request_id" in body and body["request_id"]
    assert "Traceback" not in resp.text
    assert "RuntimeError" not in resp.text
    assert "x-request-id" in resp.headers
    assert resp.headers["x-request-id"] == body["request_id"]


def test_approve_without_approver_key_is_forbidden(client):
    resp = client.post("/approve?approval_id=" + "d" * 32)
    assert resp.status_code == 403


def test_normal_api_key_cannot_approve(client):
    resp = client.post(
        "/approve?approval_id=" + "d" * 32,
        headers={"X-API-Key": VALID_KEY},
    )
    assert resp.status_code == 403


def test_wrong_approver_key_is_forbidden(client, monkeypatch):
    monkeypatch.setenv("AGENT_APPROVER_KEYS", "correct-approver-secret")

    resp = client.post(
        "/approve?approval_id=" + "d" * 32,
        headers={"X-Approver-Key": "wrong-approver-secret"},
    )
    assert resp.status_code == 403


def test_valid_approver_key_can_approve(client, monkeypatch, tmp_path):
    from stage2_sdk_ai import approval

    monkeypatch.setenv("AGENT_APPROVER_KEYS", "correct-approver-secret")
    monkeypatch.setattr(approval, "_approvals_dir", tmp_path / "approvals")
    monkeypatch.setattr(
        approval, "_audit_file", tmp_path / "logs" / "audit.jsonl"
    )

    request = approval.request_approval(
        "write_note", {"path": "notes/security-test.md"}
    )

    resp = client.post(
        f"/approve?approval_id={request['id']}",
        headers={"X-Approver-Key": "correct-approver-secret"},
    )

    assert resp.status_code == 200
    assert resp.json()["status"] == "approved"
    assert resp.json()["approver"].startswith("approver-")


def test_write_rejects_empty_note_path(client):
    resp = client.post(
        "/write",
        json={"path": "", "content": "hello"},
        headers={"X-API-Key": VALID_KEY},
    )
    assert resp.status_code == 422



def test_complete_approved_write_lifecycle(client, monkeypatch, tmp_path):
    import hashlib
    from pathlib import Path

    from stage2_sdk_ai import auth

    monkeypatch.setenv("AGENT_APPROVER_KEYS", "correct-approver-secret")

    requested = client.post(
        "/write",
        json={"path": "reports/approved.md", "content": "approved body"},
        headers={"X-API-Key": VALID_KEY},
    )
    assert requested.status_code == 200
    approval_id = requested.json()["approval_id"]

    approved = client.post(
        f"/approve?approval_id={approval_id}",
        headers={"X-Approver-Key": "correct-approver-secret"},
    )
    assert approved.status_code == 200
    assert approved.json()["status"] == "approved"

    tampered = client.post(
        "/write/execute",
        json={
            "approval_id": approval_id,
            "path": "reports/attacker.md",
            "content": "attacker-controlled replacement",
        },
        headers={"X-API-Key": VALID_KEY},
    )
    assert tampered.status_code == 422
    executed = client.post(
        "/write/execute",
        json={"approval_id": approval_id},
        headers={"X-API-Key": VALID_KEY},
    )
    assert executed.status_code == 200
    body = executed.json()
    assert body["status"] == "written"
    owner_dir = hashlib.sha256(
        auth.requester_identity(VALID_KEY).encode("utf-8")
    ).hexdigest()
    assert body["path"] == str(tmp_path / "notes" / owner_dir / "approved.md")
    assert Path(body["path"]).read_text(encoding="utf-8") == "approved body"
    assert not (tmp_path / "notes" / owner_dir / "attacker.md").exists()

    replay = client.post(
        "/write/execute",
        json={"approval_id": approval_id},
        headers={"X-API-Key": VALID_KEY},
    )
    assert replay.status_code == 409


def test_execute_requires_normal_api_authentication(client, monkeypatch):
    monkeypatch.setenv("AGENT_APPROVER_KEYS", "correct-approver-secret")
    request = client.post(
        "/write/execute",
        json={"approval_id": "d" * 32},
    )
    assert request.status_code == 401


def test_execute_pending_approval_conflicts(client, monkeypatch):
    requested = client.post(
        "/write",
        json={"path": "pending.md", "content": "not yet approved"},
        headers={"X-API-Key": VALID_KEY},
    )
    approval_id = requested.json()["approval_id"]

    response = client.post(
        "/write/execute",
        json={"approval_id": approval_id},
        headers={"X-API-Key": VALID_KEY},
    )
    assert response.status_code == 409


def test_approve_unknown_id_returns_not_found(client, monkeypatch):
    monkeypatch.setenv("AGENT_APPROVER_KEYS", "correct-approver-secret")
    response = client.post(
        "/approve?approval_id=" + "d" * 32,
        headers={"X-Approver-Key": "correct-approver-secret"},
    )
    assert response.status_code == 404


def test_concurrent_execute_has_exactly_one_winner(client, monkeypatch, tmp_path):
    from concurrent.futures import ThreadPoolExecutor

    monkeypatch.setenv("AGENT_APPROVER_KEYS", "correct-approver-secret")
    requested = client.post(
        "/write",
        json={"path": "race.md", "content": "one authorized write"},
        headers={"X-API-Key": VALID_KEY},
    )
    approval_id = requested.json()["approval_id"]
    approved = client.post(
        f"/approve?approval_id={approval_id}",
        headers={"X-Approver-Key": "correct-approver-secret"},
    )
    assert approved.status_code == 200

    def execute():
        return client.post(
            "/write/execute",
            json={"approval_id": approval_id},
            headers={"X-API-Key": VALID_KEY},
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        responses = list(pool.map(lambda _: execute(), range(2)))

    assert sorted(response.status_code for response in responses) == [200, 409]
    import hashlib
    from stage2_sdk_ai import auth

    owner_dir = hashlib.sha256(
        auth.requester_identity(VALID_KEY).encode("utf-8")
    ).hexdigest()
    assert (
        tmp_path / "notes" / owner_dir / "race.md"
    ).read_text(encoding="utf-8") == "one authorized write"



def test_approver_can_deny_and_denied_request_cannot_execute(client, monkeypatch):
    monkeypatch.setenv("AGENT_APPROVER_KEYS", "correct-approver-secret")
    requested = client.post(
        "/write",
        json={"path": "denied.md", "content": "must never be written"},
        headers={"X-API-Key": VALID_KEY},
    )
    approval_id = requested.json()["approval_id"]

    denied = client.post(
        "/deny",
        json={"approval_id": approval_id, "reason": "Not authorized for release"},
        headers={"X-Approver-Key": "correct-approver-secret"},
    )
    assert denied.status_code == 200
    assert denied.json()["status"] == "denied"

    executed = client.post(
        "/write/execute",
        json={"approval_id": approval_id},
        headers={"X-API-Key": VALID_KEY},
    )
    assert executed.status_code == 409


def test_deny_requires_separate_approver_credential(client):
    requested = client.post(
        "/write",
        json={"path": "protected.md", "content": "protected"},
        headers={"X-API-Key": VALID_KEY},
    )
    approval_id = requested.json()["approval_id"]

    denied = client.post(
        "/deny",
        json={"approval_id": approval_id, "reason": "attempt"},
        headers={"X-API-Key": VALID_KEY},
    )
    assert denied.status_code == 403
    wrong_key = client.post(
        "/deny", json={"approval_id": approval_id, "reason": "attempt"},
        headers={"X-Approver-Key": "wrong-approver-secret"},
    )
    assert wrong_key.status_code == 403


def test_approval_state_transitions_are_terminal_at_api_boundary(client, monkeypatch):
    monkeypatch.setenv("AGENT_APPROVER_KEYS", "correct-approver-secret")
    first = client.post(
        "/write", json={"path": "terminal-approved.md", "content": "approved"},
        headers={"X-API-Key": VALID_KEY},
    )
    approved_id = first.json()["approval_id"]
    assert client.post(
        f"/approve?approval_id={approved_id}",
        headers={"X-Approver-Key": "correct-approver-secret"},
    ).status_code == 200
    assert client.post(
        f"/approve?approval_id={approved_id}",
        headers={"X-Approver-Key": "correct-approver-secret"},
    ).status_code == 409
    assert client.post(
        "/deny", json={"approval_id": approved_id},
        headers={"X-Approver-Key": "correct-approver-secret"},
    ).status_code == 409
    second = client.post(
        "/write", json={"path": "terminal-denied.md", "content": "denied"},
        headers={"X-API-Key": VALID_KEY},
    )
    denied_id = second.json()["approval_id"]
    assert client.post(
        "/deny", json={"approval_id": denied_id, "reason": "rejected"},
        headers={"X-Approver-Key": "correct-approver-secret"},
    ).status_code == 200
    assert client.post(
        f"/approve?approval_id={denied_id}",
        headers={"X-Approver-Key": "correct-approver-secret"},
    ).status_code == 409
    assert client.post(
        "/deny", json={"approval_id": denied_id, "reason": "repeat"},
        headers={"X-Approver-Key": "correct-approver-secret"},
    ).status_code == 409


def test_deny_rejects_oversized_reason(client, monkeypatch):
    monkeypatch.setenv("AGENT_APPROVER_KEYS", "correct-approver-secret")
    requested = client.post(
        "/write",
        json={"path": "reason.md", "content": "content"},
        headers={"X-API-Key": VALID_KEY},
    )
    approval_id = requested.json()["approval_id"]

    denied = client.post(
        "/deny",
        json={"approval_id": approval_id, "reason": "x" * 501},
        headers={"X-Approver-Key": "correct-approver-secret"},
    )
    assert denied.status_code == 422
    assert client.post(
        "/write/execute",
        json={"approval_id": approval_id},
        headers={"X-API-Key": VALID_KEY},
    ).status_code == 409



def test_approval_is_owned_by_requester_and_wrong_user_does_not_consume(
    client, monkeypatch, tmp_path
):
    from pathlib import Path

    from stage2_sdk_ai import approval

    monkeypatch.setenv(
        "AGENT_API_KEYS",
        "requester-a=secret-a,requester-b=secret-b",
    )
    monkeypatch.setenv("AGENT_APPROVER_KEYS", "separate-approver-secret")

    requested = client.post(
        "/write",
        json={"path": "owner-bound.md", "content": "owner-only"},
        headers={"X-API-Key": "secret-a"},
    )
    assert requested.status_code == 200
    approval_id = requested.json()["approval_id"]
    stored = approval.check_approval(approval_id)
    assert stored["requester"] == "requester-a"
    assert "secret-a" not in str(stored)

    approved = client.post(
        f"/approve?approval_id={approval_id}",
        headers={"X-Approver-Key": "separate-approver-secret"},
    )
    assert approved.status_code == 200

    wrong_owner = client.post(
        "/write/execute",
        json={"approval_id": approval_id},
        headers={"X-API-Key": "secret-b"},
    )
    assert wrong_owner.status_code == 403
    assert approval.check_approval(approval_id)["status"] == "approved"
    owner_dir = hashlib.sha256(b"requester-a").hexdigest()
    assert not (tmp_path / "notes" / owner_dir / "owner-bound.md").exists()

    rightful_owner = client.post(
        "/write/execute",
        json={"approval_id": approval_id},
        headers={"X-API-Key": "secret-a"},
    )
    assert rightful_owner.status_code == 200
    assert rightful_owner.json()["status"] == "written"
    owner_dir = hashlib.sha256(b"requester-a").hexdigest()
    assert Path(rightful_owner.json()["path"]).read_text(
        encoding="utf-8"
    ) == "owner-only"
    assert rightful_owner.json()["path"] == str(
        tmp_path / "notes" / owner_dir / "owner-bound.md"
    )

    replay = client.post(
        "/write/execute",
        json={"approval_id": approval_id},
        headers={"X-API-Key": "secret-a"},
    )
    assert replay.status_code == 409


def test_requester_identity_survives_secret_rotation(monkeypatch):
    from stage2_sdk_ai.auth import requester_identity

    monkeypatch.setenv("AGENT_API_KEYS", "automation=old-secret")
    assert requester_identity("old-secret") == "automation"

    monkeypatch.setenv("AGENT_API_KEYS", "automation=new-secret")
    assert requester_identity("new-secret") == "automation"
    assert requester_identity("old-secret") is None


def test_approval_audit_failure_is_http_500_and_execution_is_blocked(
    client, monkeypatch, tmp_path
):
    from stage2_sdk_ai import approval

    monkeypatch.setenv("AGENT_APPROVER_KEYS", "correct-approver-secret")
    real_log_audit = approval.log_audit

    def fail_approval_audit(action, record):
        if action == "approved":
            raise OSError("approval audit unavailable")
        return real_log_audit(action, record)

    monkeypatch.setattr(approval, "log_audit", fail_approval_audit)
    requested = client.post(
        "/write",
        json={"path": "approval-audit-api.md", "content": "must not execute"},
        headers={"X-API-Key": VALID_KEY},
    )
    assert requested.status_code == 200
    approval_id = requested.json()["approval_id"]

    approved = client.post(
        f"/approve?approval_id={approval_id}",
        headers={"X-Approver-Key": "correct-approver-secret"},
    )
    assert approved.status_code == 500
    assert approved.json()["detail"]["error"] == "approval_audit_incomplete"

    executed = client.post(
        "/write/execute",
        json={"approval_id": approval_id},
        headers={"X-API-Key": VALID_KEY},
    )
    assert executed.status_code == 500
    assert executed.json()["detail"]["error"] == "approval_audit_incomplete"
    assert not (tmp_path / "notes" / "approval-audit-api.md").exists()


def test_request_audit_failure_returns_http_500_and_cannot_be_approved(
    client, monkeypatch
):
    from stage2_sdk_ai import approval

    monkeypatch.setenv("AGENT_APPROVER_KEYS", "correct-approver-secret")

    def fail_request_audit(action, record):
        if action == "request":
            raise OSError("request audit unavailable")
        raise AssertionError("unexpected audit action")

    monkeypatch.setattr(approval, "log_audit", fail_request_audit)
    requested = client.post(
        "/write",
        json={"path": "request-audit-failure.md", "content": "never execute"},
        headers={"X-API-Key": VALID_KEY},
    )
    assert requested.status_code == 500
    detail = requested.json()["detail"]
    assert detail["error"] == "approval_audit_incomplete"
    approval_id = detail["approval_id"]
    assert approval.check_approval(approval_id)["request_audit_status"] == "failed"

    approved = client.post(
        f"/approve?approval_id={approval_id}",
        headers={"X-Approver-Key": "correct-approver-secret"},
    )
    assert approved.status_code == 500
    assert approved.json()["detail"]["error"] == "approval_audit_incomplete"


def test_query_redacts_pii_from_answer_and_sources(client, monkeypatch):
    import stage2_sdk_ai.api as api_mod

    def return_pii(*args, **kwargs):
        return {
            "answer": "Contact alice@example.com or call 555-123-4567.",
            "sources": [
                {"text": "Customer email alice@example.com"},
                {"metadata": {"contact": "555-123-4567"}},
            ],
        }

    monkeypatch.setattr(api_mod, "run_agent", return_pii)
    response = client.post(
        "/query",
        json={"query": "contact details"},
        headers={"X-API-Key": VALID_KEY},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["filtered"] is True
    assert "alice@example.com" not in body["answer"]
    assert "555-123-4567" not in body["answer"]
    assert "alice@example.com" not in response.text
    assert "555-123-4567" not in response.text
    assert "[REDACTED:EMAIL]" in response.text


def test_query_rejects_unbounded_top_k_and_invalid_query(client):
    oversized_top_k = client.post(
        "/query",
        json={"query": "hello", "top_k": 51},
        headers={"X-API-Key": VALID_KEY},
    )
    assert oversized_top_k.status_code == 422

    empty_query = client.post(
        "/query",
        json={"query": ""},
        headers={"X-API-Key": VALID_KEY},
    )
    assert empty_query.status_code == 422


def test_query_fails_closed_when_input_guard_returns_malformed_result(
    client, monkeypatch
):
    import stage2_sdk_ai.api as api_mod

    monkeypatch.setattr(api_mod.input_guard, "check_input", lambda _query: {})
    monkeypatch.setattr(
        api_mod,
        "run_agent",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("agent must not run when guard result is malformed")
        ),
    )
    response = client.post(
        "/query",
        json={"query": "hello"},
        headers={"X-API-Key": VALID_KEY},
    )
    assert response.status_code == 200
    assert response.json()["blocked"] is True


def test_query_compatibility_function_redacts_pii(monkeypatch):
    import stage2_sdk_ai.api as api_mod

    monkeypatch.setattr(
        api_mod,
        "run_agent",
        lambda *_args, **_kwargs: {
            "answer": "Contact alice@example.com",
            "sources": [{"text": "Call 0712 345 678"}],
        },
    )
    result = api_mod.query_compat("hello")
    assert "alice@example.com" not in result["answer"]
    assert "0712 345 678" not in str(result["sources"])
    assert result["filtered"] is True



def test_unauthenticated_oversized_write_is_rejected_before_body_limit(client):
    from stage2_sdk_ai.api import MAX_REQUEST_BODY_BYTES

    response = client.post(
        "/write",
        content=b"x" * (MAX_REQUEST_BODY_BYTES + 1),
        headers={"content-type": "application/json"},
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid API key"
    assert response.headers.get("x-request-id")


def test_unauthorized_oversized_deny_is_rejected_before_body_limit(client):
    from stage2_sdk_ai.api import MAX_REQUEST_BODY_BYTES

    response = client.post(
        "/deny",
        content=b"x" * (MAX_REQUEST_BODY_BYTES + 1),
        headers={"content-type": "application/json"},
    )
    assert response.status_code == 403
    assert response.json()["detail"] == "Invalid or missing approver credentials"
    assert response.headers.get("x-request-id")
