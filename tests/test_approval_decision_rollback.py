"""Rollback-resistant approval and denial decision regression tests."""


import pytest

from stage2_sdk_ai import approval


APPROVER_KEY = "test-approver-secret"


@pytest.fixture
def approval_environment(monkeypatch, tmp_path):
    monkeypatch.setenv("AGENT_API_KEYS", "agent=requester-secret")
    monkeypatch.setenv("AGENT_APPROVER_KEYS", f"operator={APPROVER_KEY}")
    monkeypatch.setattr(approval, "_approvals_dir", tmp_path / "approvals")
    monkeypatch.setattr(
        approval, "_audit_file", tmp_path / "logs" / "audit.jsonl"
    )
    return tmp_path


@pytest.mark.parametrize(
    ("original_decision", "retry_decision", "expected_prior"),
    [
        ("denied", "approve", "denied"),
        ("approved", "deny", "approved"),
    ],
)
@pytest.mark.parametrize(
    "rotate_audit", [False, True], ids=["active-log", "rotated-log"]
)
def test_restored_pending_snapshot_cannot_reverse_recorded_decision(
    approval_environment,
    original_decision,
    retry_decision,
    expected_prior,
    rotate_audit,
):
    from stage2_sdk_ai import audit_rotation

    request = approval.request_approval(
        "write_note", {"path": "decision-rollback.md", "content": "payload"}
    )
    approval_id = request["id"]
    record_path = approval._approval_path(approval_id)
    pending_snapshot = record_path.read_bytes()

    if original_decision == "denied":
        decision = approval.deny(
            approval_id, APPROVER_KEY, reason="not authorized"
        )
    else:
        decision = approval.approve(approval_id, APPROVER_KEY)
    assert decision["status"] == original_decision

    if rotate_audit:
        checkpoint = approval.create_audit_checkpoint()
        rotated = audit_rotation.rotate_audit_log(
            truncate=True, expected_checkpoint=checkpoint
        )
        assert rotated["status"] == "rotated"

    # Simulate restoring a pre-decision record while retaining verified
    # active/archived audit evidence.
    record_path.write_bytes(pending_snapshot)
    assert approval.check_approval(approval_id)["status"] == "pending"

    if retry_decision == "approve":
        retry = approval.approve(approval_id, APPROVER_KEY)
    else:
        retry = approval.deny(
            approval_id, APPROVER_KEY, reason="attempted reversal"
        )

    assert retry["status"] == "invalid_transition"
    assert retry["prior_decision"] == expected_prior
    assert record_path.read_bytes() == pending_snapshot
    assert approval.verify_audit_log()["valid"] is True


def test_decision_transition_fails_closed_when_audit_history_is_unavailable(
    approval_environment,
):
    request = approval.request_approval(
        "write_note", {"path": "audit-unavailable.md", "content": "payload"}
    )
    approval_id = request["id"]
    record_path = approval._approval_path(approval_id)
    before = record_path.read_bytes()
    audit_path = approval._audit_file

    # Corrupt the existing request event so decision history cannot be trusted.
    corrupted_audit = '{"action":"request","broken":true}' + chr(10)
    audit_path.write_text(corrupted_audit, encoding="utf-8")

    result = approval.approve(approval_id, APPROVER_KEY)

    assert result["status"] == "approval_audit_incomplete"
    assert result["audit_phase"] == "decision_history"
    assert result["audit_status"] == "unavailable"
    assert record_path.read_bytes() == before
    assert audit_path.read_text(encoding="utf-8") == corrupted_audit
