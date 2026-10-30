import json

from stage2_sdk_ai import approval

APPROVER_KEY = "test-approver-secret"


def setup_approval_dirs(monkeypatch, tmp_path):
    monkeypatch.setenv("AGENT_APPROVER_KEYS", APPROVER_KEY)
    monkeypatch.setattr(approval, "_approvals_dir", tmp_path / "approvals")
    monkeypatch.setattr(
        approval, "_audit_file", tmp_path / "logs" / "audit.jsonl"
    )


def test_malformed_ids_are_rejected(monkeypatch, tmp_path):
    setup_approval_dirs(monkeypatch, tmp_path)

    for operation in (
        approval.check_approval,
        lambda value: approval.approve(value, approver_key=APPROVER_KEY),
        lambda value: approval.deny(value, approver_key=APPROVER_KEY),
    ):
        result = operation("../audit")
        assert result["status"] == "invalid_id"

    assert not (tmp_path / "logs" / "audit.json").exists()


def test_approved_request_cannot_be_denied_again(monkeypatch, tmp_path):
    setup_approval_dirs(monkeypatch, tmp_path)
    request = approval.request_approval("write_note", {"path": "a.md"})

    result = approval.approve(request["id"], approver_key=APPROVER_KEY)
    assert result["status"] == "approved"

    repeated = approval.deny(request["id"], approver_key=APPROVER_KEY, reason="late denial")
    assert repeated["status"] == "invalid_transition"
    assert repeated["current_status"] == "approved"
    assert approval.check_approval(request["id"])["status"] == "approved"


def test_denied_request_cannot_be_approved(monkeypatch, tmp_path):
    setup_approval_dirs(monkeypatch, tmp_path)
    request = approval.request_approval("write_note", {"path": "a.md"})

    result = approval.deny(request["id"], approver_key=APPROVER_KEY, reason="not permitted")
    assert result["status"] == "denied"

    repeated = approval.approve(request["id"], approver_key=APPROVER_KEY)
    assert repeated["status"] == "invalid_transition"
    assert repeated["current_status"] == "denied"
    assert approval.check_approval(request["id"])["status"] == "denied"


def test_unknown_well_formed_id_remains_not_found(monkeypatch, tmp_path):
    setup_approval_dirs(monkeypatch, tmp_path)

    result = approval.check_approval("d" * 32)
    assert result["status"] == "not_found"


def test_new_approval_ids_are_32_hex_characters(monkeypatch, tmp_path):
    setup_approval_dirs(monkeypatch, tmp_path)

    request = approval.request_approval("write_note", {"path": "a.md"})
    approval_id = request["id"]

    assert len(approval_id) == 32
    assert all(char in "0123456789abcdef" for char in approval_id)


def test_legacy_8_character_approval_ids_are_rejected(monkeypatch, tmp_path):
    setup_approval_dirs(monkeypatch, tmp_path)
    approvals_dir = tmp_path / "approvals"
    approvals_dir.mkdir(parents=True, exist_ok=True)
    legacy_id = "deadbeef"
    legacy_path = approvals_dir / f"{legacy_id}.json"
    legacy_path.write_text(json.dumps({"id": legacy_id, "status": "pending"}), encoding="utf-8")
    assert approval.check_approval(legacy_id)["status"] == "invalid_id"
    assert approval.approve(legacy_id, approver_key=APPROVER_KEY)["status"] == "invalid_id"
    assert json.loads(legacy_path.read_text(encoding="utf-8"))["status"] == "pending"


def test_direct_approval_calls_reject_unconfigured_keys(monkeypatch, tmp_path):
    setup_approval_dirs(monkeypatch, tmp_path)
    request = approval.request_approval("write_note", {"path": "a.md"})
    result = approval.approve(request["id"], approver_key="attacker-controlled-key")
    assert result["status"] == "unauthorized"
    assert approval.check_approval(request["id"])["status"] == "pending"



def test_concurrent_approve_and_deny_have_one_winner(monkeypatch, tmp_path):
    from concurrent.futures import ThreadPoolExecutor

    setup_approval_dirs(monkeypatch, tmp_path)
    request = approval.request_approval("write_note", {"path": "a.md"})

    with ThreadPoolExecutor(max_workers=2) as executor:
        approve_future = executor.submit(
            approval.approve, request["id"], approver_key=APPROVER_KEY
        )
        deny_future = executor.submit(
            approval.deny, request["id"],
            approver_key=APPROVER_KEY, reason="concurrent denial"
        )
        results = [approve_future.result(), deny_future.result()]

    statuses = sorted(result["status"] for result in results)
    assert statuses in (
        ["approved", "invalid_transition"],
        ["denied", "invalid_transition"],
    )
    final_record = approval.check_approval(request["id"])
    assert final_record["status"] in {"approved", "denied"}
    assert sum(result["status"] == "invalid_transition" for result in results) == 1
