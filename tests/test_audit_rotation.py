import json

import pytest

from stage2_sdk_ai import approval, audit_rotation


def _setup(monkeypatch, tmp_path):
    monkeypatch.setattr(approval, "_approvals_dir", tmp_path / "approvals")
    monkeypatch.setattr(
        approval, "_audit_file", tmp_path / "logs" / "audit.jsonl"
    )
    approval._ensure_dirs()
    first = approval.request_approval("write_note", {"path": "first.md"})
    return first


def test_copy_only_rotation_preserves_active_audit_bytes(monkeypatch, tmp_path):
    _setup(monkeypatch, tmp_path)
    audit_path = approval._audit_file
    before = audit_path.read_bytes()

    result = audit_rotation.rotate_audit_log()

    assert result["status"] == "archived_copy"
    assert result["truncated"] is False
    assert result["source_modified"] is False
    assert audit_path.read_bytes() == before
    assert audit_rotation.verify_archive_segment(result["archive_path"])["valid"] is True


def test_truncation_requires_fresh_checkpoint_and_preserves_chain(
    monkeypatch, tmp_path
):
    _setup(monkeypatch, tmp_path)
    checkpoint = approval.create_audit_checkpoint()
    result = audit_rotation.rotate_audit_log(
        truncate=True, expected_checkpoint=checkpoint
    )

    assert result["status"] == "rotated"
    assert result["truncated"] is True
    assert approval._audit_file.read_bytes() == b""
    verified = approval.verify_audit_log(checkpoint)
    assert verified["valid"] is True
    assert verified["entries"] == 1
    assert verified["chained_entries"] == 1

    approval.request_approval("write_note", {"path": "after.md"})
    verified = approval.verify_audit_log(checkpoint)
    assert verified["entries"] == 2
    assert verified["chained_entries"] == 2
    assert verified["archived_segments"] == 1


def test_multiple_rotations_preserve_sequence_and_segment_links(
    monkeypatch, tmp_path
):
    _setup(monkeypatch, tmp_path)
    first_checkpoint = approval.create_audit_checkpoint()
    audit_rotation.rotate_audit_log(
        truncate=True, expected_checkpoint=first_checkpoint
    )

    approval.request_approval("write_note", {"path": "second.md"})
    second_checkpoint = approval.create_audit_checkpoint()
    audit_rotation.rotate_audit_log(
        truncate=True, expected_checkpoint=second_checkpoint
    )

    result = approval.verify_audit_log(first_checkpoint)
    assert result["valid"] is True
    assert result["entries"] == 2
    assert result["chained_entries"] == 2
    assert result["archived_segments"] == 2
    assert approval.verify_audit_log(second_checkpoint)["checkpoint_verified"] is True


def test_stale_checkpoint_cannot_authorize_truncation(monkeypatch, tmp_path):
    _setup(monkeypatch, tmp_path)
    checkpoint = approval.create_audit_checkpoint()
    approval.request_approval("write_note", {"path": "later.md"})
    before = approval._audit_file.read_bytes()

    with pytest.raises(approval.AuditLogIntegrityError, match="exact active"):
        audit_rotation.rotate_audit_log(
            truncate=True, expected_checkpoint=checkpoint
        )

    assert approval._audit_file.read_bytes() == before
    assert not approval._audit_file.with_name("audit.rotation.json").exists()


def test_truncation_requires_explicit_opt_in(monkeypatch, tmp_path):
    _setup(monkeypatch, tmp_path)
    before = approval._audit_file.read_bytes()

    with pytest.raises(ValueError, match="independently retained checkpoint"):
        audit_rotation.rotate_audit_log(truncate=True)

    assert approval._audit_file.read_bytes() == before


def test_interrupted_rotation_blocks_appends_until_explicit_recovery(
    monkeypatch, tmp_path
):
    _setup(monkeypatch, tmp_path)
    checkpoint = approval.create_audit_checkpoint()
    original_ftruncate = audit_rotation.os.ftruncate

    def fail_truncate(fd, size):
        raise OSError("simulated crash before truncation")

    with monkeypatch.context() as patch:
        patch.setattr(audit_rotation.os, "ftruncate", fail_truncate)
        with pytest.raises(OSError, match="simulated crash"):
            audit_rotation.rotate_audit_log(
                truncate=True, expected_checkpoint=checkpoint
            )

    with pytest.raises(approval.AuditLogIntegrityError, match="recovery is pending"):
        approval.verify_audit_log()
    pending = audit_rotation.recover_audit_rotation()
    assert pending["status"] == "verified_pending_truncation"
    assert approval._audit_file.read_bytes()

    recovered = audit_rotation.recover_audit_rotation(allow_truncate=True)
    assert recovered["status"] == "recovered_and_rotated"
    assert approval._audit_file.read_bytes() == b""
    assert approval.verify_audit_log(checkpoint)["valid"] is True
    assert audit_rotation.os.ftruncate is original_ftruncate


def test_recovery_cleans_journal_after_truncation_was_completed(
    monkeypatch, tmp_path
):
    _setup(monkeypatch, tmp_path)
    checkpoint = approval.create_audit_checkpoint()

    def fail_cleanup(_path):
        raise OSError("simulated crash after truncation")

    monkeypatch.setattr(audit_rotation, "_clear_journal", fail_cleanup)
    with pytest.raises(OSError, match="after truncation"):
        audit_rotation.rotate_audit_log(
            truncate=True, expected_checkpoint=checkpoint
        )
    assert approval._audit_file.read_bytes() == b""

    monkeypatch.setattr(
        audit_rotation, "_clear_journal",
        lambda path: audit_rotation.Path(path).unlink(),
    )
    recovered = audit_rotation.recover_audit_rotation()
    assert recovered["status"] == "recovered_complete"
    assert not approval._audit_file.with_name("audit.rotation.json").exists()
    assert approval.verify_audit_log(checkpoint)["valid"] is True


def test_tampered_archived_segment_fails_closed(monkeypatch, tmp_path):
    _setup(monkeypatch, tmp_path)
    checkpoint = approval.create_audit_checkpoint()
    result = audit_rotation.rotate_audit_log(
        truncate=True, expected_checkpoint=checkpoint
    )
    archive_path = audit_rotation.Path(result["archive_path"])
    raw = json.loads(archive_path.read_text(encoding="utf-8"))
    raw["manifest"]["end_sequence"] += 1
    archive_path.write_text(json.dumps(raw), encoding="utf-8")

    with pytest.raises(approval.AuditLogIntegrityError, match="segment"):
        approval.verify_audit_log()


def test_missing_active_segment_fails_closed(monkeypatch, tmp_path):
    _setup(monkeypatch, tmp_path)
    checkpoint = approval.create_audit_checkpoint()
    audit_rotation.rotate_audit_log(
        truncate=True, expected_checkpoint=checkpoint
    )
    approval._audit_file.unlink()

    with pytest.raises(approval.AuditLogIntegrityError, match="active audit segment"):
        approval.verify_audit_log()


def test_unexpected_active_bytes_block_recovery(monkeypatch, tmp_path):
    _setup(monkeypatch, tmp_path)
    checkpoint = approval.create_audit_checkpoint()
    original_ftruncate = audit_rotation.os.ftruncate

    def fail_truncate(fd, size):
        raise OSError("simulated interruption")

    with monkeypatch.context() as patch:
        patch.setattr(audit_rotation.os, "ftruncate", fail_truncate)
        with pytest.raises(OSError):
            audit_rotation.rotate_audit_log(
                truncate=True, expected_checkpoint=checkpoint
            )

    approval._audit_file.write_bytes(b"tampered\n")
    with pytest.raises(approval.AuditLogIntegrityError, match="differs"):
        audit_rotation.recover_audit_rotation(allow_truncate=True)
    assert audit_rotation.os.ftruncate is original_ftruncate


def test_checkpoint_history_survives_segmented_verification(
    monkeypatch, tmp_path
):
    _setup(monkeypatch, tmp_path)
    checkpoint = approval.create_audit_checkpoint()
    audit_rotation.rotate_audit_log(
        truncate=True, expected_checkpoint=checkpoint
    )

    tampered_checkpoint = dict(checkpoint)
    tampered_checkpoint["head_hash"] = "f" * 64
    with pytest.raises(approval.AuditLogIntegrityError, match="checkpoint"):
        approval.verify_audit_log(tampered_checkpoint)


def test_rotation_does_not_recreate_missing_active_log(monkeypatch, tmp_path):
    _setup(monkeypatch, tmp_path)
    checkpoint = approval.create_audit_checkpoint()
    audit_rotation.rotate_audit_log(
        truncate=True, expected_checkpoint=checkpoint
    )
    approval._audit_file.unlink()

    with pytest.raises(approval.AuditLogIntegrityError, match="active audit log is missing"):
        audit_rotation.rotate_audit_log()
    assert not approval._audit_file.exists()


def test_recovery_does_not_recreate_missing_active_log(monkeypatch, tmp_path):
    _setup(monkeypatch, tmp_path)
    checkpoint = approval.create_audit_checkpoint()
    original_ftruncate = audit_rotation.os.ftruncate

    def fail_truncate(fd, size):
        raise OSError("simulated interruption")

    with monkeypatch.context() as patch:
        patch.setattr(audit_rotation.os, "ftruncate", fail_truncate)
        with pytest.raises(OSError):
            audit_rotation.rotate_audit_log(
                truncate=True, expected_checkpoint=checkpoint
            )

    approval._audit_file.unlink()
    with pytest.raises(approval.AuditLogIntegrityError, match="active audit log is missing"):
        audit_rotation.recover_audit_rotation(allow_truncate=True)
    assert not approval._audit_file.exists()
    assert audit_rotation.os.ftruncate is original_ftruncate


def test_archive_segment_chain_verification_includes_predecessors(
    monkeypatch, tmp_path
):
    _setup(monkeypatch, tmp_path)
    first_checkpoint = approval.create_audit_checkpoint()
    first = audit_rotation.rotate_audit_log(
        truncate=True, expected_checkpoint=first_checkpoint
    )

    approval.request_approval("write_note", {"path": "second.md"})
    second_checkpoint = approval.create_audit_checkpoint()
    second = audit_rotation.rotate_audit_log(
        truncate=True, expected_checkpoint=second_checkpoint
    )

    verified = audit_rotation.verify_archive_segment(
        audit_rotation.Path(second["archive_path"])
    )
    assert verified["valid"] is True
    assert verified["segments"] == 2
    assert verified["sequence"] == second_checkpoint["sequence"]
    assert audit_rotation.verify_archive_segment(
        audit_rotation.Path(first["archive_path"])
    )["segments"] == 1


def test_missing_rotation_anchor_is_detected_after_destructive_rotation(
    monkeypatch, tmp_path
):
    _setup(monkeypatch, tmp_path)
    checkpoint = approval.create_audit_checkpoint()
    audit_rotation.rotate_audit_log(
        truncate=True, expected_checkpoint=checkpoint
    )
    anchor_path = approval._audit_file.with_name("audit.anchor.json")
    state_path = approval._audit_file.with_name("audit.rotation-state.json")
    assert anchor_path.exists()
    assert state_path.exists()
    anchor_path.unlink()

    with pytest.raises(approval.AuditLogIntegrityError, match="anchor is missing"):
        approval.verify_audit_log()


def test_rotation_state_marker_tampering_fails_closed(monkeypatch, tmp_path):
    _setup(monkeypatch, tmp_path)
    checkpoint = approval.create_audit_checkpoint()
    audit_rotation.rotate_audit_log(
        truncate=True, expected_checkpoint=checkpoint
    )
    state_path = approval._audit_file.with_name("audit.rotation-state.json")
    state = json.loads(state_path.read_text(encoding="utf-8"))
    state["head_hash"] = "f" * 64
    state_path.write_text(json.dumps(state), encoding="utf-8")

    with pytest.raises(approval.AuditLogIntegrityError, match="does not match"):
        approval.verify_audit_log()
