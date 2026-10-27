"""End-to-end tests for the real FastAPI app in stage2_sdk_ai/api.py.

Unlike tests/test_rag_phase3.py (which calls query_compat() in-process and
never touches auth, HTTP status codes, or the dependency chain), these use
fastapi.testclient.TestClient to drive real requests through the app --
including the X-API-Key header, auth failures, and rate limiting. This is
the test that should have existed before api.py shipped: it would have
caught auth.verify_api_key/check_rate_limit not existing immediately.
"""
import os

os.environ.setdefault("OPENAI_API_KEY", "sk-test-mocked")
os.environ.setdefault("CI", "true")

import pytest
from fastapi.testclient import TestClient

from stage2_sdk_ai import auth
from stage2_sdk_ai import cost_guard
from stage2_sdk_ai.api import app

VALID_KEY = "test-key-123"


@pytest.fixture(autouse=True)
def _reset_auth_state(monkeypatch):
    monkeypatch.setenv("AGENT_API_KEYS", VALID_KEY)
    auth.reset_rate()
    cost_guard.reset_cost()
    yield
    auth.reset_rate()
    cost_guard.reset_cost()


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
