"""Regression tests for strict requester isolation in direct SDK note operations."""
import hashlib

import pytest

from stage2_sdk_ai import approval, tools, write_tools


@pytest.fixture
def isolated_storage(monkeypatch, tmp_path):
    notes = tmp_path / "notes"
    monkeypatch.setattr(tools, "_notes_dir", notes)
    monkeypatch.setattr(write_tools, "_notes_dir", notes)
    monkeypatch.setattr(approval, "_approvals_dir", tmp_path / "approvals")
    monkeypatch.setattr(approval, "_audit_file", tmp_path / "logs" / "audit.jsonl")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-real-not-mocked")
    monkeypatch.setenv("AGENT_APPROVER_KEYS", "separate-approver-secret")
    return tmp_path


def test_read_note_requires_requester_and_never_reads_legacy_shared_path(
    isolated_storage,
):
    shared = isolated_storage / "notes" / "private.md"
    shared.parent.mkdir(parents=True)
    shared.write_text("legacy shared secret", encoding="utf-8")

    result = tools.read_note("private.md")

    assert result["error"] == "A valid requester identity is required"
    assert result["content"] == ""
    assert str(shared) not in result["path"]


def test_read_note_isolated_between_requesters(isolated_storage):
    requester_a = "tenant-a"
    requester_b = "tenant-b"
    owner_dir = isolated_storage / "notes" / hashlib.sha256(
        requester_a.encode("utf-8")
    ).hexdigest()
    owner_dir.mkdir(parents=True)
    (owner_dir / "private.md").write_text("tenant A data", encoding="utf-8")

    own = tools.read_note("private.md", requester=requester_a)
    other = tools.read_note("private.md", requester=requester_b)

    assert own["content"] == "tenant A data"
    assert other["content"] == ""
    assert other["error"] == "not found"


def test_write_note_rejects_missing_requester_without_creating_shared_storage(
    isolated_storage,
):
    result = write_tools.write_note("private.md", "must not be stored")

    assert result["status"] == "rejected"
    assert "requester identity" in result["error"]
    assert not (isolated_storage / "notes").exists()
    assert not (isolated_storage / "approvals").exists()


def test_canonical_note_path_requires_requester(isolated_storage):
    with pytest.raises(ValueError, match="requester identity"):
        write_tools.canonical_note_path("private.md")


def test_approved_write_cannot_cross_requester_boundary(isolated_storage):
    requester_a = "tenant-a"
    request = write_tools.write_note(
        "private.md", "tenant A content", requester=requester_a
    )
    assert request["status"] == "needs_approval"
    approval.approve(
        request["approval_id"], approver_key="separate-approver-secret"
    )

    wrong_owner = write_tools.write_note(
        "private.md",
        "tenant A content",
        approval_id=request["approval_id"],
        requester="tenant-b",
    )
    assert wrong_owner["status"] == "requester_mismatch"

    rightful_owner = write_tools.write_note(
        "private.md",
        "tenant A content",
        approval_id=request["approval_id"],
        requester=requester_a,
    )
    assert rightful_owner["status"] == "written"
    assert (isolated_storage / "notes" / hashlib.sha256(
        requester_a.encode("utf-8")
    ).hexdigest() / "private.md").read_text(encoding="utf-8") == "tenant A content"


def test_execute_approved_write_requires_requester_before_consumption(
    isolated_storage,
):
    request = write_tools.write_note(
        "private.md", "tenant A content", requester="tenant-a"
    )
    approval.approve(
        request["approval_id"], approver_key="separate-approver-secret"
    )

    result = write_tools.execute_approved_write(request["approval_id"])

    assert result["status"] == "rejected"
    assert approval.check_approval(request["approval_id"])["status"] == "approved"
