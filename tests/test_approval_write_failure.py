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
    replay = write_tools.execute_approved_write(approval_id, requester="agent")
    assert replay["status"] == "invalid_transition"


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


def test_consumed_audit_failure_prevents_write_and_records_recovery(
    monkeypatch, tmp_path
):
    approval_id = _approved_request(monkeypatch, tmp_path)
    real_log_audit = approval.log_audit

    def fail_consumed_audit(action, record):
        if action == "consumed":
            raise OSError("consumed audit volume unavailable")
        return real_log_audit(action, record)

    monkeypatch.setattr(approval, "log_audit", fail_consumed_audit)
    result = write_tools.execute_approved_write(approval_id, requester="agent")

    assert result["status"] == "consumption_audit_incomplete"
    assert not (tmp_path / "notes" / "fault-case.md").exists()
    record = approval.check_approval(approval_id)
    assert record["status"] == "consumed"
    assert record["execution_failure"]["error_type"] == "RuntimeError"
    assert "consumed audit append failed" in record["execution_failure"]["error_message"]
    replay = write_tools.execute_approved_write(approval_id, requester="agent")
    assert replay["status"] == "invalid_transition"


def test_invalid_approved_payload_is_recorded_for_operator_review(
    monkeypatch, tmp_path
):
    approval_id = _approved_request(monkeypatch, tmp_path)
    record = approval.check_approval(approval_id)
    record["args"]["path"] = "../outside.md"
    approval._write_record_atomically(approval._approval_path(approval_id), record)

    result = write_tools.execute_approved_write(approval_id, requester="agent")

    assert result["status"] == "invalid_approved_payload_operator_review"
    persisted = approval.check_approval(approval_id)
    assert persisted["status"] == "consumed"
    assert persisted["execution_failure"]["error_type"] == "ValueError"
    assert "not canonical" in persisted["execution_failure"]["error_message"]
    assert not (tmp_path / "outside.md").exists()
    replay = write_tools.execute_approved_write(approval_id, requester="agent")
    assert replay["status"] == "invalid_transition"


def test_approval_audit_failure_blocks_execution_and_preserves_consumed_safety(
    monkeypatch, tmp_path
):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-real-not-mocked")
    monkeypatch.setenv("AGENT_APPROVER_KEYS", "test-approver-secret")
    monkeypatch.setattr(approval, "_approvals_dir", tmp_path / "approvals")
    monkeypatch.setattr(
        approval, "_audit_file", tmp_path / "logs" / "audit.jsonl"
    )
    monkeypatch.setattr(write_tools, "_notes_dir", tmp_path / "notes")

    request = write_tools.write_note("approval-audit.md", "must not be written")
    approval_id = request["approval_id"]
    real_log_audit = approval.log_audit

    def fail_approval_audit(action, record):
        if action == "approved":
            raise OSError("approval audit volume unavailable")
        return real_log_audit(action, record)

    monkeypatch.setattr(approval, "log_audit", fail_approval_audit)
    approved = approval.approve(
        approval_id, approver_key="test-approver-secret"
    )

    assert approved["status"] == "approval_audit_incomplete"
    assert approved["approval_status"] == "approved"
    record = approval.check_approval(approval_id)
    assert record["status"] == "approved"
    assert record["approval_audit_status"] == "failed"
    assert record["approval_audit_error_type"] == "OSError"

    execution = write_tools.execute_approved_write(
        approval_id, requester="agent"
    )
    assert execution["status"] == "approval_audit_incomplete"
    assert not (tmp_path / "notes" / "approval-audit.md").exists()
    assert approval.check_approval(approval_id)["status"] == "approved"


def test_approval_audit_record_update_failure_leaves_approval_unexecutable(
    monkeypatch, tmp_path
):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-real-not-mocked")
    monkeypatch.setenv("AGENT_APPROVER_KEYS", "test-approver-secret")
    monkeypatch.setattr(approval, "_approvals_dir", tmp_path / "approvals")
    monkeypatch.setattr(
        approval, "_audit_file", tmp_path / "logs" / "audit.jsonl"
    )
    monkeypatch.setattr(write_tools, "_notes_dir", tmp_path / "notes")

    request = write_tools.write_note("approval-audit-persist.md", "payload")
    approval_id = request["approval_id"]
    real_write = approval._write_record_atomically
    calls = 0

    def fail_second_record_write(path, record):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("approval record update unavailable")
        return real_write(path, record)

    monkeypatch.setattr(approval, "_write_record_atomically", fail_second_record_write)
    approved = approval.approve(
        approval_id, approver_key="test-approver-secret"
    )

    assert approved["status"] == "approval_audit_incomplete"
    assert approved["approval_status"] == "approved"
    assert approval.check_approval(approval_id)["approval_audit_status"] == "pending"
    assert any(
        json.loads(line)["action"] == "approved"
        for line in (tmp_path / "logs" / "audit.jsonl").read_text().splitlines()
    )

    execution = write_tools.execute_approved_write(
        approval_id, requester="agent"
    )
    assert execution["status"] == "approval_audit_incomplete"
    assert not (tmp_path / "notes" / "approval-audit-persist.md").exists()


def test_denial_audit_failure_keeps_denial_terminal_and_reports_incomplete_audit(
    monkeypatch, tmp_path
):
    monkeypatch.setenv("AGENT_APPROVER_KEYS", "test-approver-secret")
    monkeypatch.setattr(approval, "_approvals_dir", tmp_path / "approvals")
    monkeypatch.setattr(
        approval, "_audit_file", tmp_path / "logs" / "audit.jsonl"
    )
    request = approval.request_approval(
        "write_note", {"path": "denied-audit.md", "content": "never write"}
    )
    real_log_audit = approval.log_audit

    def fail_denial_audit(action, record):
        if action == "denied":
            raise OSError("denial audit volume unavailable")
        return real_log_audit(action, record)

    monkeypatch.setattr(approval, "log_audit", fail_denial_audit)
    denied = approval.deny(
        request["id"],
        approver_key="test-approver-secret",
        reason="not authorized",
    )

    assert denied["status"] == "approval_audit_incomplete"
    assert denied["approval_status"] == "denied"
    record = approval.check_approval(request["id"])
    assert record["status"] == "denied"
    assert record["approval_audit_status"] == "failed"
    assert approval.approve(
        request["id"], approver_key="test-approver-secret"
    )["status"] == "invalid_transition"


def test_request_audit_append_failure_leaves_request_unapprovable(
    monkeypatch, tmp_path
):
    monkeypatch.setenv("AGENT_APPROVER_KEYS", "test-approver-secret")
    monkeypatch.setattr(approval, "_approvals_dir", tmp_path / "approvals")
    monkeypatch.setattr(approval, "_audit_file", tmp_path / "logs" / "audit.jsonl")

    def fail_request_audit(action, record):
        if action == "request":
            raise OSError("request audit unavailable")
        raise AssertionError("unexpected audit action")

    monkeypatch.setattr(approval, "log_audit", fail_request_audit)
    try:
        approval.request_approval("write_note", {"path": "unaudited.md", "content": "blocked"})
    except approval.ApprovalAuditError as exc:
        approval_id = exc.approval_id
    else:
        raise AssertionError("request audit failure must be reported")

    stored = approval.check_approval(approval_id)
    assert stored["status"] == "pending"
    assert stored["request_audit_status"] == "failed"
    assert stored["request_audit_error_type"] == "OSError"
    assert approval.approve(approval_id, approver_key="test-approver-secret")["status"] == "approval_audit_incomplete"
    assert approval.check_approval(approval_id)["status"] == "pending"


def test_request_audit_status_persistence_failure_leaves_request_unapprovable(
    monkeypatch, tmp_path
):
    monkeypatch.setenv("AGENT_APPROVER_KEYS", "test-approver-secret")
    monkeypatch.setattr(approval, "_approvals_dir", tmp_path / "approvals")
    monkeypatch.setattr(approval, "_audit_file", tmp_path / "logs" / "audit.jsonl")
    real_write = approval._write_record_atomically

    def fail_request_audit_marker(path, record):
        if record.get("request_audit_status") == "written":
            raise OSError("approval record update unavailable")
        return real_write(path, record)

    monkeypatch.setattr(approval, "_write_record_atomically", fail_request_audit_marker)
    try:
        approval.request_approval("write_note", {"path": "audit-marker.md", "content": "blocked"})
    except approval.ApprovalAuditError as exc:
        approval_id = exc.approval_id
    else:
        raise AssertionError("audit marker persistence failure must be reported")

    stored = approval.check_approval(approval_id)
    assert stored["status"] == "pending"
    assert stored["request_audit_status"] == "pending"
    audit_lines = (tmp_path / "logs" / "audit.jsonl").read_text().splitlines()
    assert any(json.loads(line)["action"] == "request" for line in audit_lines)
    assert approval.approve(approval_id, approver_key="test-approver-secret")["status"] == "approval_audit_incomplete"
