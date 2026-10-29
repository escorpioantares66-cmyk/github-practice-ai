"""Coverage gate work: write_tools.py sat at 58% coverage because every
existing test ran with OPENAI_API_KEY unset/mocked, so write_note()'s
_is_mock() branch always took the mock shortcut. These tests force real
mode (a non-mock OPENAI_API_KEY) to exercise the three real-mode branches
-- request a new approval, check a not-yet-approved one, and perform the
actual file write once approved -- plus approve_write(), which was never
called at all.
"""
import shutil
from pathlib import Path

from stage2_sdk_ai import approval
from stage2_sdk_ai.write_tools import approve_write, write_note


def setup_module():
    shutil.rmtree("approvals", ignore_errors=True)
    shutil.rmtree("logs", ignore_errors=True)
    shutil.rmtree("notes", ignore_errors=True)


def test_real_mode_no_approval_id_requests_approval(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-real-not-mocked")
    res = write_note("real_note.md", "hello world")
    assert res["status"] == "needs_approval"
    assert res["is_mock"] is False
    assert res["approval_id"]  # a real uuid-derived id, not "mock-123"
    assert res["approval_id"] != "mock-123"


def test_real_mode_unapproved_id_returns_current_status(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-real-not-mocked")
    req = approval.request_approval("write_note", {"path": "notes/pending.md"})
    res = write_note("pending.md", "still waiting", approval_id=req["id"])
    assert res["status"] == "pending"
    assert res["is_mock"] is False
    assert res["approval_id"] == req["id"]


def test_real_mode_unknown_approval_id_returns_not_found(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-real-not-mocked")
    res = write_note("ghost.md", "content", approval_id="deadbeef")
    assert res["status"] == "not_found"
    assert res["is_mock"] is False


def test_real_mode_approved_id_actually_writes_file(monkeypatch, tmp_path):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-real-not-mocked")
    req = approval.request_approval("write_note", {"path": "notes/final.md"})
    approval.approve(req["id"])
    res = write_note("final.md", "final content", approval_id=req["id"])
    assert res["status"] == "written"
    assert res["is_mock"] is False
    written_path = Path(res["path"])
    assert written_path.exists()
    assert written_path.read_text(encoding="utf-8") == "final content"


def test_approve_write_delegates_to_approval_module(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-real-not-mocked")
    req = approval.request_approval("write_note", {"path": "notes/d.md"})
    result = approve_write(req["id"])
    assert result["status"] == "approved"
    assert approval.check_approval(req["id"])["status"] == "approved"
