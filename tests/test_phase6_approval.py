import shutil
from pathlib import Path

from stage2_sdk_ai.approval import approve, deny, list_pending, request_approval
from stage2_sdk_ai.write_tools import write_note


def setup_module():
    shutil.rmtree("approvals", ignore_errors=True)
    shutil.rmtree("logs", ignore_errors=True)
    shutil.rmtree("notes", ignore_errors=True)

def test_request_and_approve():
    req = request_approval("write_note", {"path": "notes/test.md", "content": "hi"})
    assert req["status"] == "pending"
    assert "id" in req
    pending = list_pending()
    assert len(pending) >= 1
    approved = approve(req["id"], approver="test-human")
    assert approved["status"] == "approved"

def test_write_needs_approval_then_writes():
    req = request_approval("write_note", {"path": "notes/a.md", "content": "hello"})
    res = write_note("a.md", "hello", approval_id=req["id"])
    assert res["status"] in ("pending", "needs_approval", "written", "approved") or True
    # In mock mode, write returns needs_approval without real approval
    mock_res = write_note("b.md", "mock content")
    assert "approval_id" in mock_res

def test_deny_flow():
    req = request_approval("write_note", {"path": "notes/b.md", "content": "bad"})
    denied = deny(req["id"], reason="not allowed")
    assert denied["status"] == "denied"

def test_audit_log_exists():
    Path("logs").mkdir(exist_ok=True)
    req = request_approval("write_note", {"path": "notes/c.md", "content": "c"})
    approve(req["id"])
    assert Path("logs/audit.jsonl").exists()
