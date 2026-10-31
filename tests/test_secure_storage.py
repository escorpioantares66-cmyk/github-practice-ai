import hashlib
import json
import os
import stat

import pytest

from stage2_sdk_ai import approval, write_tools
from stage2_sdk_ai import tools as read_tools
from stage2_sdk_ai.secure_storage import UnsafeStoragePathError


def test_approval_and_audit_storage_are_owner_only(monkeypatch, tmp_path):
    monkeypatch.setattr(approval, "_approvals_dir", tmp_path / "approvals")
    monkeypatch.setattr(approval, "_audit_file", tmp_path / "logs" / "audit.jsonl")

    record = approval.request_approval("write_note", {"path": "notes/a.md"})

    assert stat.S_IMODE((tmp_path / "approvals").stat().st_mode) == 0o700
    assert stat.S_IMODE((tmp_path / "logs").stat().st_mode) == 0o700
    assert stat.S_IMODE((tmp_path / "approvals" / f"{record['id']}.json").stat().st_mode) == 0o600
    assert stat.S_IMODE((tmp_path / "logs" / "audit.jsonl").stat().st_mode) == 0o600


def test_approval_directory_symlink_is_rejected(monkeypatch, tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    link = tmp_path / "approvals"
    link.symlink_to(outside, target_is_directory=True)
    monkeypatch.setattr(approval, "_approvals_dir", link)
    monkeypatch.setattr(approval, "_audit_file", tmp_path / "logs" / "audit.jsonl")

    with pytest.raises(UnsafeStoragePathError):
        approval.request_approval("write_note", {"path": "notes/a.md"})

    assert list(outside.iterdir()) == []


def test_audit_file_symlink_is_rejected(monkeypatch, tmp_path):
    monkeypatch.setattr(approval, "_approvals_dir", tmp_path / "approvals")
    logs = tmp_path / "logs"
    logs.mkdir()
    outside = tmp_path / "outside.jsonl"
    outside.write_text("do not append", encoding="utf-8")
    (logs / "audit.jsonl").symlink_to(outside)

    monkeypatch.setattr(approval, "_audit_file", logs / "audit.jsonl")
    with pytest.raises(OSError):
        approval.log_audit("test", {"status": "safe"})

    assert outside.read_text(encoding="utf-8") == "do not append"


def test_approval_record_symlink_is_never_read_or_overwritten(monkeypatch, tmp_path):
    monkeypatch.setattr(approval, "_approvals_dir", tmp_path / "approvals")
    monkeypatch.setattr(approval, "_audit_file", tmp_path / "logs" / "audit.jsonl")
    approval._ensure_dirs()
    outside = tmp_path / "outside.json"
    outside.write_text(json.dumps({"status": "pending"}), encoding="utf-8")
    approval_id = "a" * 32
    (tmp_path / "approvals" / f"{approval_id}.json").symlink_to(outside)

    with pytest.raises(OSError):
        approval.check_approval(approval_id)
    assert json.loads(outside.read_text(encoding="utf-8")) == {"status": "pending"}


def test_notes_directory_symlink_is_rejected(monkeypatch, tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    link = tmp_path / "notes"
    link.symlink_to(outside, target_is_directory=True)
    monkeypatch.setattr(write_tools, "_notes_dir", link)
    monkeypatch.setenv("OPENAI_API_KEY", "sk-real-not-mocked")

    with pytest.raises(UnsafeStoragePathError):
        write_tools._atomic_write_note(link / "note.md", "must not escape")
    assert list(outside.iterdir()) == []


def test_note_file_is_owner_only_and_symlink_target_is_not_followed(monkeypatch, tmp_path):
    notes = tmp_path / "notes"
    monkeypatch.setattr(write_tools, "_notes_dir", notes)
    outside = tmp_path / "outside.txt"
    outside.write_text("original", encoding="utf-8")
    notes.mkdir(mode=0o700)
    destination = notes / "linked.md"
    destination.symlink_to(outside)

    write_tools._atomic_write_note(destination, "new note")

    assert outside.read_text(encoding="utf-8") == "original"
    assert not destination.is_symlink()
    assert destination.read_text(encoding="utf-8") == "new note"
    assert stat.S_IMODE(destination.stat().st_mode) == 0o600
    assert stat.S_IMODE(notes.stat().st_mode) == 0o700



def test_filesystem_root_is_never_used_as_private_storage():
    from pathlib import Path

    from stage2_sdk_ai.secure_storage import ensure_private_directory

    with pytest.raises(UnsafeStoragePathError, match="filesystem root"):
        ensure_private_directory(Path("/"))


def test_read_note_rejects_symlink_to_external_file(monkeypatch, tmp_path):
    notes = tmp_path / "notes"
    owner_notes = notes / hashlib.sha256(b"test-requester").hexdigest()
    owner_notes.mkdir(parents=True, mode=0o700)
    outside = tmp_path / "private.txt"
    outside.write_text("sensitive external content", encoding="utf-8")
    (owner_notes / "linked.md").symlink_to(outside)
    monkeypatch.setattr(read_tools, "_notes_dir", notes)
    monkeypatch.setenv("OPENAI_API_KEY", "sk-real-not-mocked")

    with pytest.raises(OSError):
        read_tools.read_note("linked.md", requester="test-requester")

    assert outside.read_text(encoding="utf-8") == "sensitive external content"


def test_read_note_rejects_symlinked_notes_directory(monkeypatch, tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "note.md").write_text("external", encoding="utf-8")
    notes_link = tmp_path / "notes"
    notes_link.symlink_to(outside, target_is_directory=True)
    monkeypatch.setattr(read_tools, "_notes_dir", notes_link)
    monkeypatch.setenv("OPENAI_API_KEY", "sk-real-not-mocked")

    with pytest.raises(UnsafeStoragePathError):
        read_tools.read_note("note.md", requester="test-requester")



def test_private_directory_must_be_owned_by_effective_user(monkeypatch, tmp_path):
    from stage2_sdk_ai import secure_storage

    current_uid = os.geteuid()
    monkeypatch.setattr(secure_storage.os, "geteuid", lambda: current_uid + 1)
    with pytest.raises(UnsafeStoragePathError, match="owned by the application user"):
        secure_storage.ensure_private_directory(tmp_path / "private")


def test_private_file_must_be_owned_by_effective_user(monkeypatch, tmp_path):
    from stage2_sdk_ai import secure_storage

    private_dir = tmp_path / "private"
    secure_storage.ensure_private_directory(private_dir)
    target = private_dir / "record.json"
    target.write_text("{}", encoding="utf-8")
    current_uid = os.geteuid()
    monkeypatch.setattr(secure_storage.os, "geteuid", lambda: current_uid + 1)

    with pytest.raises(UnsafeStoragePathError, match="owned by the application user"):
        secure_storage.open_private_file(target, os.O_RDONLY)


def test_fifo_is_rejected_without_blocking(tmp_path):
    from stage2_sdk_ai.secure_storage import open_private_file

    private_dir = tmp_path / "private"
    private_dir.mkdir(mode=0o700)
    fifo = private_dir / "pipe"
    os.mkfifo(fifo)

    with pytest.raises(UnsafeStoragePathError, match="not a regular file"):
        open_private_file(fifo, os.O_RDONLY)


def test_hard_linked_private_file_is_rejected(tmp_path):
    from stage2_sdk_ai.secure_storage import open_private_file

    private_dir = tmp_path / "private"
    private_dir.mkdir(mode=0o700)
    stored = private_dir / "record.json"
    stored.write_text("sensitive", encoding="utf-8")
    os.link(stored, tmp_path / "outside-link")

    with pytest.raises(UnsafeStoragePathError, match="additional hard links"):
        open_private_file(stored, os.O_RDONLY)
