from pathlib import Path

import pytest

from stage2_sdk_ai import approval, write_tools
from stage2_sdk_ai.approval import list_pending, request_approval
from stage2_sdk_ai.write_tools import write_note

APPROVER_KEY = "test-approver-secret"


@pytest.fixture(autouse=True)
def isolated_storage(monkeypatch, tmp_path):
    monkeypatch.setattr(approval, "_approvals_dir", tmp_path / "approvals")
    monkeypatch.setattr(approval, "_audit_file", tmp_path / "logs" / "audit.jsonl")
    monkeypatch.setattr(write_tools, "_notes_dir", tmp_path / "notes")
    monkeypatch.setenv("AGENT_APPROVER_KEYS", APPROVER_KEY)
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-mocked")


def test_request_and_approve():
    req = request_approval("write_note", {"path": "test.md", "content": "hi"})
    assert req["status"] == "pending"
    assert len(list_pending()) == 1
    assert approval.approve(req["id"], approver_key=APPROVER_KEY)["status"] == "approved"


def test_write_needs_approval_then_writes():
    req = request_approval("write_note", {"path": "a.md", "content": "hello"})
    assert write_note("a.md", "hello", approval_id=req["id"])["status"] == "needs_approval"
    assert "approval_id" in write_note("b.md", "mock content")


def test_deny_flow():
    req = request_approval("write_note", {"path": "b.md", "content": "bad"})
    denied = approval.deny(req["id"], approver_key=APPROVER_KEY, reason="not allowed")
    assert denied["status"] == "denied"


def test_audit_log_exists():
    req = request_approval("write_note", {"path": "c.md", "content": "c"})
    approval.approve(req["id"], approver_key=APPROVER_KEY)
    assert approval._audit_file.exists()
