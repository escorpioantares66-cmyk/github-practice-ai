import json

import pytest

from stage2_sdk_ai import approval
from stage2_sdk_ai.retention import (
    RETENTION_SECONDS,
    archive_retention,
    plan_retention,
    verify_archive,
)
from stage2_sdk_ai.secure_storage import UnsafeStoragePathError


def _create_old_request(monkeypatch, tmp_path, created):
    monkeypatch.setattr(approval, "_approvals_dir", tmp_path / "approvals")
    monkeypatch.setattr(approval, "_audit_file", tmp_path / "logs" / "audit.jsonl")
    monkeypatch.setattr(approval.time, "time", lambda: created)
    return approval.request_approval("write_note", {"path": "notes/old.md"})


def test_retention_planner_uses_strict_90_day_boundary(monkeypatch, tmp_path):
    now = 1_800_000_000.0
    old = _create_old_request(monkeypatch, tmp_path, now - RETENTION_SECONDS - 1)
    monkeypatch.setattr(approval.time, "time", lambda: now)
    approval.request_approval("write_note", {"path": "notes/boundary.md"})
    result = plan_retention(now=now)

    assert result["retention_days"] == 90
    assert result["approval_records_eligible"] == 1
    assert result["eligible_approval_ids"] == [old["id"]]
    assert result["approval_records_excluded"]["within_retention"] == 1
    assert result["source_modified"] is False


def test_retention_planner_does_not_modify_source_bytes(monkeypatch, tmp_path):
    now = 1_800_000_000.0
    _create_old_request(monkeypatch, tmp_path, now - RETENTION_SECONDS - 10)
    approvals = {
        path.name: path.read_bytes()
        for path in (tmp_path / "approvals").glob("*.json")
    }
    audit_before = (tmp_path / "logs" / "audit.jsonl").read_bytes()

    plan_retention(now=now)

    assert {
        path.name: path.read_bytes()
        for path in (tmp_path / "approvals").glob("*.json")
    } == approvals
    assert (tmp_path / "logs" / "audit.jsonl").read_bytes() == audit_before


def test_retention_planner_excludes_incomplete_audit_records(monkeypatch, tmp_path):
    now = 1_800_000_000.0
    record = _create_old_request(monkeypatch, tmp_path, now - RETENTION_SECONDS - 1)
    path = tmp_path / "approvals" / f"{record['id']}.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    data["request_audit_status"] = "failed"
    path.write_text(json.dumps(data), encoding="utf-8")

    result = plan_retention(now=now)

    assert result["approval_records_eligible"] == 0
    assert result["approval_records_excluded"]["request_audit_incomplete"] == 1


def test_retention_planner_excludes_symlinked_approval_records(monkeypatch, tmp_path):
    monkeypatch.setattr(approval, "_approvals_dir", tmp_path / "approvals")
    monkeypatch.setattr(approval, "_audit_file", tmp_path / "logs" / "audit.jsonl")
    approval._ensure_dirs()
    outside = tmp_path / "outside.json"
    outside.write_text("{}", encoding="utf-8")
    (tmp_path / "approvals" / f"{'a' * 32}.json").symlink_to(outside)

    result = plan_retention(now=1_800_000_000.0)

    assert result["approval_records_eligible"] == 0
    assert result["approval_records_excluded"]["symlink"] == 1
    assert outside.read_text(encoding="utf-8") == "{}"


def test_retention_planner_fails_closed_on_corrupt_audit_log(monkeypatch, tmp_path):
    monkeypatch.setattr(approval, "_approvals_dir", tmp_path / "approvals")
    audit = tmp_path / "logs" / "audit.jsonl"
    audit.parent.mkdir(mode=0o700)
    audit.write_text('{"broken":true}\n', encoding="utf-8")
    audit.chmod(0o600)
    monkeypatch.setattr(approval, "_audit_file", audit)

    with pytest.raises(approval.AuditLogIntegrityError):
        plan_retention(now=1_800_000_000.0)


def test_retention_planner_does_not_create_missing_storage(monkeypatch, tmp_path):
    approvals = tmp_path / "missing-approvals"
    audit = tmp_path / "missing-logs" / "audit.jsonl"
    monkeypatch.setattr(approval, "_approvals_dir", approvals)
    monkeypatch.setattr(approval, "_audit_file", audit)

    result = plan_retention(now=1_800_000_000.0)

    assert result["approval_records_scanned"] == 0
    assert result["audit_entries_scanned"] == 0
    assert not approvals.exists()
    assert not audit.parent.exists()



def test_archive_retention_copies_and_verifies_without_removing_sources(
    monkeypatch, tmp_path
):
    now = 1_800_000_000.0
    record = _create_old_request(
        monkeypatch, tmp_path, now - RETENTION_SECONDS - 10
    )
    approval_path = tmp_path / "approvals" / f"{record['id']}.json"
    approval_before = approval_path.read_bytes()
    audit_path = tmp_path / "logs" / "audit.jsonl"
    audit_before = audit_path.read_bytes()
    archive_dir = tmp_path / "archive"

    result = archive_retention(now=now, archive_dir=archive_dir)

    assert result["created"] is True
    assert result["valid"] is True
    assert result["approval_records_copied"] == 1
    assert result["source_modified"] is False
    assert approval_path.read_bytes() == approval_before
    assert audit_path.read_bytes() == audit_before
    assert approval_path.exists()
    assert audit_path.exists()
    assert verify_archive(archive_dir / f"snapshot-{result['archive_id']}.json")[
        "valid"
    ] is True


def test_archive_retention_is_idempotent(monkeypatch, tmp_path):
    now = 1_800_000_000.0
    _create_old_request(monkeypatch, tmp_path, now - RETENTION_SECONDS - 10)
    archive_dir = tmp_path / "archive"

    first = archive_retention(now=now, archive_dir=archive_dir)
    second = archive_retention(now=now, archive_dir=archive_dir)

    assert first["created"] is True
    assert second["created"] is False
    assert first["archive_id"] == second["archive_id"]
    assert second["valid"] is True


def test_archive_verification_detects_tampering(monkeypatch, tmp_path):
    now = 1_800_000_000.0
    _create_old_request(monkeypatch, tmp_path, now - RETENTION_SECONDS - 10)
    archive_dir = tmp_path / "archive"
    result = archive_retention(now=now, archive_dir=archive_dir)
    archive_path = archive_dir / f"snapshot-{result['archive_id']}.json"
    archive_path.write_bytes(archive_path.read_bytes() + b" ")

    with pytest.raises(ValueError, match="archive"):
        verify_archive(archive_path)


def test_archive_rejects_symlink_destination(monkeypatch, tmp_path):
    now = 1_800_000_000.0
    _create_old_request(monkeypatch, tmp_path, now - RETENTION_SECONDS - 10)
    archive_dir = tmp_path / "archive"
    outside = tmp_path / "outside"
    outside.mkdir()
    archive_dir.symlink_to(outside, target_is_directory=True)

    with pytest.raises(UnsafeStoragePathError):
        archive_retention(now=now, archive_dir=archive_dir)

    assert list(outside.iterdir()) == []
