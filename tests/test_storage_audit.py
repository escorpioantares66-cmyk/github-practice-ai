import json
import sys

from stage2_sdk_ai import approval, write_tools
from stage2_sdk_ai.cli import main
from stage2_sdk_ai.storage_audit import inspect_storage_path, run_storage_audit


def _private_dir(path):
    path.mkdir(parents=True, mode=0o700, exist_ok=True)
    path.chmod(0o700)
    return path


def _private_file(path, content=b"data"):
    _private_dir(path.parent)
    path.write_bytes(content)
    path.chmod(0o600)
    return path


def _configure_paths(monkeypatch, tmp_path):
    approvals = tmp_path / "approvals"
    logs = tmp_path / "logs"
    notes = tmp_path / "notes"
    monkeypatch.setattr(approval, "_approvals_dir", approvals)
    monkeypatch.setattr(approval, "_audit_file", logs / "audit.jsonl")
    monkeypatch.setattr(write_tools, "_notes_dir", notes)
    monkeypatch.setattr(
        "stage2_sdk_ai.storage_audit.VECTOR_STORE_DEFAULT_PATH",
        tmp_path / "vector",
    )
    quota_path = tmp_path / ".agent_state" / "quotas.sqlite3"
    monkeypatch.setenv("AGENT_QUOTA_DB_PATH", str(quota_path))
    return approvals, logs, notes, quota_path


def test_storage_audit_reports_growth_areas_and_retention_without_exposing_ids(
    monkeypatch, tmp_path
):
    approvals, logs, notes, quota_path = _configure_paths(monkeypatch, tmp_path)
    old_created = 1_700_000_000.0
    now = old_created + (90 * 24 * 60 * 60) + 10
    monkeypatch.setattr(approval.time, "time", lambda: old_created)
    request = approval.request_approval("write_note", {"path": "old.md"})
    approval_id = request["id"]
    monkeypatch.setattr(approval.time, "time", lambda: now)

    _private_file(notes / "owner" / "note.md", b"private note")
    _private_file(quota_path, b"sqlite-placeholder")
    _private_file(quota_path.with_name(quota_path.name + "-wal"), b"wal")
    _private_file(tmp_path / "vector" / "store.json", b"{}")

    approval_files_before = {
        path.name: path.read_bytes() for path in approvals.iterdir() if path.is_file()
    }
    audit_before = (logs / "audit.jsonl").read_bytes()
    note_before = (notes / "owner" / "note.md").read_bytes()
    quota_before = quota_path.read_bytes()
    wal_before = quota_path.with_name(quota_path.name + "-wal").read_bytes()

    result = run_storage_audit(now=now)

    assert result["mode"] == "read_only"
    assert result["source_modified"] is False
    assert result["storage_mutations_performed"] == 0
    assert result["areas"]["approvals"]["approval_json_records"] == 1
    assert result["areas"]["approvals"]["lock_files"] >= 1
    assert result["areas"]["notes"]["regular_files"] == 1
    assert result["areas"]["quota_database"]["total_bytes"] == (
        len(b"sqlite-placeholder") + len(b"wal")
    )
    assert result["areas"]["quota_database"]["database_contents_inspected"] is False
    assert result["retention"]["status"] == "verified"
    assert result["retention"]["eligible_approval_records"] == 1
    assert approval_id not in json.dumps(result)
    assert "private note" not in json.dumps(result)

    assert {
        path.name: path.read_bytes() for path in approvals.iterdir() if path.is_file()
    } == approval_files_before
    assert (logs / "audit.jsonl").read_bytes() == audit_before
    assert (notes / "owner" / "note.md").read_bytes() == note_before
    assert quota_path.read_bytes() == quota_before
    assert quota_path.with_name(quota_path.name + "-wal").read_bytes() == wal_before


def test_storage_audit_does_not_create_missing_storage(monkeypatch, tmp_path):
    approvals, logs, notes, quota_path = _configure_paths(monkeypatch, tmp_path)

    result = run_storage_audit(now=1_800_000_000.0)

    assert result["retention"]["status"] == "verified"
    assert result["areas"]["approvals"]["status"] == "missing"
    assert result["areas"]["audit"]["status"] == "missing"
    assert result["areas"]["notes"]["status"] == "missing"
    assert result["areas"]["quota_database"]["files"]["database"]["status"] == "missing"
    assert not approvals.exists()
    assert not logs.exists()
    assert not notes.exists()
    assert not quota_path.parent.exists()


def test_storage_audit_does_not_follow_symlink_roots(tmp_path):
    outside = _private_dir(tmp_path / "outside")
    protected = _private_file(outside / "keep.txt", b"must stay private")
    link = tmp_path / "linked-storage"
    link.symlink_to(outside, target_is_directory=True)

    result = inspect_storage_path(link)

    assert result["status"] == "symlink"
    assert result["symlinks"] == 1
    assert result["regular_files"] == 0
    assert protected.read_bytes() == b"must stay private"


def test_storage_audit_marks_unexpected_permissions(tmp_path):
    directory = _private_dir(tmp_path / "store")
    file_path = _private_file(directory / "record.json", b"{}")
    file_path.chmod(0o644)

    result = inspect_storage_path(directory)

    assert result["regular_files"] == 1
    assert result["unsafe_permissions"] == 1


def test_storage_audit_respects_scan_limits(monkeypatch, tmp_path):
    directory = _private_dir(tmp_path / "many")
    _private_file(directory / "one.json")
    _private_file(directory / "two.json")
    result = inspect_storage_path(directory, max_entries=1)

    assert result["entries_examined"] == 1
    assert result["truncated"] is True


def test_storage_audit_reports_retention_verification_failure(monkeypatch, tmp_path):
    _configure_paths(monkeypatch, tmp_path)

    def fail_retention(now=None):
        raise approval.AuditLogIntegrityError("test")

    monkeypatch.setattr("stage2_sdk_ai.storage_audit.plan_retention", fail_retention)

    result = run_storage_audit(now=1_800_000_000.0)

    assert result["retention"]["status"] == "unavailable"
    assert result["retention"]["error_type"] == "AuditLogIntegrityError"
    assert any(
        item["code"] == "retention_or_audit_verification_failed"
        for item in result["findings"]
    )


def test_storage_audit_cli_prints_json(monkeypatch, capsys):
    expected = {"mode": "read_only", "source_modified": False}
    monkeypatch.setattr(
        "stage2_sdk_ai.storage_audit.run_storage_audit",
        lambda: expected,
    )
    monkeypatch.setattr(sys, "argv", ["gh-ai", "--storage-audit"])

    main()

    assert json.loads(capsys.readouterr().out) == expected


def test_storage_audit_detects_quota_database_symlink_without_following(
    monkeypatch, tmp_path
):
    _, _, _, quota_path = _configure_paths(monkeypatch, tmp_path)
    outside = _private_file(tmp_path / "outside.sqlite3", b"do not inspect")
    _private_dir(quota_path.parent)
    quota_path.symlink_to(outside)

    result = run_storage_audit(now=1_800_000_000.0)

    assert result["areas"]["quota_database"]["files"]["database"]["status"] == "symlink"
    assert any(item["code"] == "quota_database_symlink" for item in result["findings"])
    assert outside.read_bytes() == b"do not inspect"


def test_storage_audit_rejects_symlinked_parent_path(tmp_path):
    outside = _private_dir(tmp_path / "outside")
    _private_file(outside / "inside.json", b"outside")
    link = tmp_path / "parent-link"
    link.symlink_to(outside, target_is_directory=True)

    result = inspect_storage_path(link / "inside.json")

    assert result["status"] == "symlink"
    assert result["symlinks"] == 1
    assert result["regular_files"] == 0
