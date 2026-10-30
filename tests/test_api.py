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
def client():
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
    resp = client.post("/approve?approval_id=deadbeef")
    assert resp.status_code == 403


def test_normal_api_key_cannot_approve(client):
    resp = client.post(
        "/approve?approval_id=deadbeef",
        headers={"X-API-Key": VALID_KEY},
    )
    assert resp.status_code == 403


def test_wrong_approver_key_is_forbidden(client, monkeypatch):
    monkeypatch.setenv("AGENT_APPROVER_KEYS", "correct-approver-secret")

    resp = client.post(
        "/approve?approval_id=deadbeef",
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
    assert resp.json()["approver"] == "authenticated_approver"


def test_write_rejects_empty_note_path(client):
    resp = client.post(
        "/write",
        json={"path": "", "content": "hello"},
        headers={"X-API-Key": VALID_KEY},
    )
    assert resp.status_code == 422
