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
    assert "operator_review_required" in caplog.text

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
