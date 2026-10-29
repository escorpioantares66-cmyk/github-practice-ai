from stage2_sdk_ai import approval


def setup_approval_dirs(monkeypatch, tmp_path):
    monkeypatch.setattr(approval, "_approvals_dir", tmp_path / "approvals")
    monkeypatch.setattr(
        approval, "_audit_file", tmp_path / "logs" / "audit.jsonl"
    )


def test_malformed_ids_are_rejected(monkeypatch, tmp_path):
    setup_approval_dirs(monkeypatch, tmp_path)

    for operation in (
        approval.check_approval,
        approval.approve,
        approval.deny,
    ):
        result = operation("../audit")
        assert result["status"] == "invalid_id"

    assert not (tmp_path / "logs" / "audit.json").exists()


def test_approved_request_cannot_be_denied_again(monkeypatch, tmp_path):
    setup_approval_dirs(monkeypatch, tmp_path)
    request = approval.request_approval("write_note", {"path": "a.md"})

    result = approval.approve(request["id"])
    assert result["status"] == "approved"

    repeated = approval.deny(request["id"], reason="late denial")
    assert repeated["status"] == "invalid_transition"
    assert repeated["current_status"] == "approved"
    assert approval.check_approval(request["id"])["status"] == "approved"


def test_denied_request_cannot_be_approved(monkeypatch, tmp_path):
    setup_approval_dirs(monkeypatch, tmp_path)
    request = approval.request_approval("write_note", {"path": "a.md"})

    result = approval.deny(request["id"], reason="not permitted")
    assert result["status"] == "denied"

    repeated = approval.approve(request["id"])
    assert repeated["status"] == "invalid_transition"
    assert repeated["current_status"] == "denied"
    assert approval.check_approval(request["id"])["status"] == "denied"


def test_unknown_well_formed_id_remains_not_found(monkeypatch, tmp_path):
    setup_approval_dirs(monkeypatch, tmp_path)

    result = approval.check_approval("deadbeef")
    assert result["status"] == "not_found"
