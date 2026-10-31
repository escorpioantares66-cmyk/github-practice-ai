"""Approved write failures remain consumed and are operator-recoverable."""
import json

from stage2_sdk_ai import approval, write_tools


def test_failed_write_records_operator_recovery_context_without_replay(
    monkeypatch, tmp_path, caplog
):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-real-not-mocked")
    monkeypatch.setenv("AGENT_APPROVER_KEYS", "test-approver-secret")
    monkeypatch.setattr(approval, "_approvals_dir", tmp_path / "approvals")
    monkeypatch.setattr(
        approval, "_audit_file", tmp_path / "logs" / "audit.jsonl"
    )
    monkeypatch.setattr(write_tools, "_notes_dir", tmp_path / "notes")

    request = write_tools.write_note("recover-me.md", "approved payload")
    approval_id = request["approval_id"]
    approval.approve(approval_id, approver_key="test-approver-secret")

    def fail_write(*args, **kwargs):
        raise OSError("simulated disk failure")

    monkeypatch.setattr(write_tools, "_atomic_write_note", fail_write)
    result = write_tools.execute_approved_write(
        approval_id, requester="agent"
    )

    assert result["status"] == "execution_failed"
    assert result["approval_id"] == approval_id
    record = approval.check_approval(approval_id)
    assert record["status"] == "consumed"
    assert record["args"]["content"] == "approved payload"
    assert record["execution_failure"]["error_type"] == "OSError"
    assert "simulated disk failure" in record["execution_failure"]["error_message"]
    assert any(
        getattr(record, "recovery", None) == "operator_review_required"
        for record in caplog.records
    )

    audit = [
        json.loads(line)
        for line in (tmp_path / "logs" / "audit.jsonl").read_text().splitlines()
    ]
    assert any(
        entry["action"] == "execution_failed"
        and entry["record"]["id"] == approval_id
        for entry in audit
    )

    replay = write_tools.execute_approved_write(
        approval_id, requester="agent"
    )
    assert replay["status"] == "invalid_transition"


def _approved_request(monkeypatch, tmp_path):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-real-not-mocked")
    monkeypatch.setenv("AGENT_APPROVER_KEYS", "test-approver-secret")
    monkeypatch.setattr(approval, "_approvals_dir", tmp_path / "approvals")
    monkeypatch.setattr(approval, "_audit_file", tmp_path / "logs" / "audit.jsonl")
    monkeypatch.setattr(write_tools, "_notes_dir", tmp_path / "notes")
    request = write_tools.write_note("fault-case.md", "approved payload")
    approval.approve(request["approval_id"], approver_key="test-approver-secret")
    return request["approval_id"]


def test_failure_metadata_write_error_does_not_hide_original_or_enable_replay(
    monkeypatch, tmp_path, caplog
):
    approval_id = _approved_request(monkeypatch, tmp_path)
    monkeypatch.setattr(
        write_tools, "_atomic_write_note",
        lambda *args, **kwargs: (_ for _ in ()).throw(OSError("disk full")),
    )
    real_write_record = approval._write_record_atomically

    def fail_only_failure_metadata(path, record):
        if "execution_failure" in record:
            raise OSError("approval store read-only")
        return real_write_record(path, record)

    monkeypatch.setattr(approval, "_write_record_atomically", fail_only_failure_metadata)

    result = write_tools.execute_approved_write(approval_id, requester="agent")

    assert result["status"] == "execution_failure_recording_failed"
    assert approval.check_approval(approval_id)["status"] == "consumed"
    assert any("approved note write failed" in r.message for r in caplog.records)
    assert write_tools.execute_approved_write(approval_id, requester="agent")["status"] == "invalid_transition"


def test_audit_append_failure_is_distinguished_from_record_failure(
    monkeypatch, tmp_path
):
    approval_id = _approved_request(monkeypatch, tmp_path)
    monkeypatch.setattr(
        write_tools, "_atomic_write_note",
        lambda *args, **kwargs: (_ for _ in ()).throw(OSError("disk full")),
    )
    real_log_audit = approval.log_audit

    def fail_execution_audit(action, record):
        if action == "execution_failed":
            raise OSError("audit volume unavailable")
        return real_log_audit(action, record)

    monkeypatch.setattr(approval, "log_audit", fail_execution_audit)
    result = write_tools.execute_approved_write(approval_id, requester="agent")

    assert result["status"] == "execution_failed_audit_incomplete"
    record = approval.check_approval(approval_id)
    assert record["status"] == "consumed"
    assert record["execution_failure"]["error_type"] == "OSError"
    assert not any(
        json.loads(line)["action"] == "execution_failed"
        for line in (tmp_path / "logs" / "audit.jsonl").read_text().splitlines()
    )


def test_directory_fsync_failure_after_replace_requires_destination_inspection(
    monkeypatch, tmp_path
):
    from stage2_sdk_ai import secure_storage

    approval_id = _approved_request(monkeypatch, tmp_path)
    notes_dir = tmp_path / "notes"
    notes_dir.mkdir(parents=True, exist_ok=True)
    destination = notes_dir / "fault-case.md"
    destination.write_text("old contents", encoding="utf-8")
    real_fsync_directory = secure_storage.fsync_directory

    def fail_notes_directory(path):
        if path == notes_dir:
            raise OSError("directory fsync failed after replace")
        return real_fsync_directory(path)

    monkeypatch.setattr(secure_storage, "fsync_directory", fail_notes_directory)
    result = write_tools.execute_approved_write(approval_id, requester="agent")

    assert result["status"] == "execution_failed"
    assert destination.read_text(encoding="utf-8") == "approved payload"
    assert approval.check_approval(approval_id)["status"] == "consumed"
