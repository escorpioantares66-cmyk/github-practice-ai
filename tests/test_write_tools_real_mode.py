"""Real-mode write tests use isolated temporary storage for every test."""
from pathlib import Path

from stage2_sdk_ai import approval, write_tools


def configure_paths(monkeypatch, tmp_path):
    monkeypatch.setattr(approval, "_approvals_dir", tmp_path / "approvals")
    monkeypatch.setattr(
        approval, "_audit_file", tmp_path / "logs" / "audit.jsonl"
    )
    monkeypatch.setattr(write_tools, "_notes_dir", tmp_path / "notes")


def test_real_mode_no_approval_id_requests_bound_approval(
    monkeypatch, tmp_path
):
    configure_paths(monkeypatch, tmp_path)
    monkeypatch.setenv("OPENAI_API_KEY", "sk-real-not-mocked")

    result = write_tools.write_note("real_note.md", "hello world")

    assert result["status"] == "needs_approval"
    assert result["is_mock"] is False
    record = approval.check_approval(result["approval_id"])
    assert record["tool"] == "write_note"
    assert record["args"] == {
        "path": str(tmp_path / "notes" / "real_note.md"),
        "content": "hello world",
    }


def test_real_mode_unapproved_id_returns_pending(monkeypatch, tmp_path):
    configure_paths(monkeypatch, tmp_path)
    monkeypatch.setenv("OPENAI_API_KEY", "sk-real-not-mocked")
    request = approval.request_approval(
        "write_note",
        {
            "path": str(tmp_path / "notes" / "pending.md"),
            "content": "still waiting",
        },
    )

    result = write_tools.write_note(
        "pending.md", "still waiting", approval_id=request["id"]
    )

    assert result["status"] == "pending"
    assert result["is_mock"] is False
    assert result["approval_id"] == request["id"]


def test_real_mode_unknown_approval_id_returns_not_found(
    monkeypatch, tmp_path
):
    configure_paths(monkeypatch, tmp_path)
    monkeypatch.setenv("OPENAI_API_KEY", "sk-real-not-mocked")

    result = write_tools.write_note(
        "ghost.md", "content", approval_id="deadbeef"
    )

    assert result["status"] == "not_found"
    assert result["is_mock"] is False


def test_real_mode_approved_id_writes_only_approved_content(
    monkeypatch, tmp_path
):
    configure_paths(monkeypatch, tmp_path)
    monkeypatch.setenv("OPENAI_API_KEY", "sk-real-not-mocked")
    request = write_tools.write_note("final.md", "final content")
    approval.approve(request["approval_id"])

    result = write_tools.write_note(
        "final.md", "final content", approval_id=request["approval_id"]
    )

    assert result["status"] == "written"
    assert result["is_mock"] is False
    written_path = Path(result["path"])
    assert written_path.exists()
    assert written_path.read_text(encoding="utf-8") == "final content"


def test_approved_id_cannot_be_reused_for_different_content(
    monkeypatch, tmp_path
):
    configure_paths(monkeypatch, tmp_path)
    monkeypatch.setenv("OPENAI_API_KEY", "sk-real-not-mocked")
    request = write_tools.write_note("safe.md", "approved text")
    approval.approve(request["approval_id"])

    result = write_tools.write_note(
        "safe.md", "replacement text", approval_id=request["approval_id"]
    )

    assert result["status"] == "approval_mismatch"
    assert not (tmp_path / "notes" / "safe.md").exists()


def test_approved_id_cannot_be_reused_for_different_path(
    monkeypatch, tmp_path
):
    configure_paths(monkeypatch, tmp_path)
    monkeypatch.setenv("OPENAI_API_KEY", "sk-real-not-mocked")
    request = write_tools.write_note("approved.md", "approved text")
    approval.approve(request["approval_id"])

    result = write_tools.write_note(
        "other.md", "approved text", approval_id=request["approval_id"]
    )

    assert result["status"] == "approval_mismatch"
    assert not (tmp_path / "notes" / "other.md").exists()


def test_approve_write_delegates_to_approval_module(monkeypatch, tmp_path):
    configure_paths(monkeypatch, tmp_path)
    monkeypatch.setenv("OPENAI_API_KEY", "sk-real-not-mocked")
    request = write_tools.write_note("delegated.md", "approved content")

    result = write_tools.approve_write(request["approval_id"])

    assert result["status"] == "approved"
    assert approval.check_approval(request["approval_id"])["status"] == "approved"


def test_oversized_content_is_rejected(monkeypatch, tmp_path):
    configure_paths(monkeypatch, tmp_path)
    monkeypatch.setenv("OPENAI_API_KEY", "sk-real-not-mocked")

    result = write_tools.write_note("large.md", "x" * 5001)

    assert result["status"] == "rejected"
    assert not (tmp_path / "notes").exists()


def test_approval_cannot_be_replayed_after_successful_write(
    monkeypatch, tmp_path
):
    configure_paths(monkeypatch, tmp_path)
    monkeypatch.setenv("OPENAI_API_KEY", "sk-real-not-mocked")
    request = write_tools.write_note("once.md", "one-time content")
    approval.approve(request["approval_id"])

    first = write_tools.write_note(
        "once.md", "one-time content", approval_id=request["approval_id"]
    )
    second = write_tools.write_note(
        "once.md", "one-time content", approval_id=request["approval_id"]
    )

    assert first["status"] == "written"
    assert second["status"] == "invalid_transition"
    assert approval.check_approval(request["approval_id"])["status"] == "consumed"


def test_atomic_write_replaces_symlink_without_modifying_target(
    monkeypatch, tmp_path
):
    configure_paths(monkeypatch, tmp_path)
    monkeypatch.setenv("OPENAI_API_KEY", "sk-real-not-mocked")
    notes_dir = tmp_path / "notes"
    notes_dir.mkdir()
    outside_file = tmp_path / "outside.txt"
    outside_file.write_text("do not change", encoding="utf-8")
    (notes_dir / "linked.md").symlink_to(outside_file)

    request = write_tools.write_note("linked.md", "approved note")
    approval.approve(request["approval_id"])
    result = write_tools.write_note(
        "linked.md", "approved note", approval_id=request["approval_id"]
    )

    assert result["status"] == "written"
    assert outside_file.read_text(encoding="utf-8") == "do not change"
    assert not (notes_dir / "linked.md").is_symlink()
    assert (notes_dir / "linked.md").read_text(encoding="utf-8") == "approved note"
