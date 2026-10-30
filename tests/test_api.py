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
    from stage2_sdk_ai import approval, write_tools

    monkeypatch.setattr(write_tools, "_notes_dir", tmp_path / "notes")
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



def test_complete_approved_write_lifecycle(client, monkeypatch, tmp_path):
    from pathlib import Path

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

    executed = client.post(
        "/write/execute",
        json={
            "approval_id": approval_id,
            "path": "reports/attacker.md",
            "content": "attacker-controlled replacement",
        },
        headers={"X-API-Key": VALID_KEY},
    )
    assert executed.status_code == 200
    body = executed.json()
    assert body["status"] == "written"
    assert body["path"] == str(tmp_path / "notes" / "approved.md")
    assert Path(body["path"]).read_text(encoding="utf-8") == "approved body"
    assert not (tmp_path / "notes" / "attacker.md").exists()

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
        json={"approval_id": "deadbeef"},
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
        "/approve?approval_id=deadbeef",
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
    assert (tmp_path / "notes" / "race.md").read_text(encoding="utf-8") == "one authorized write"
