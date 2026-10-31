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


def test_malformed_approval_field_types_are_isolated(monkeypatch, tmp_path):
    setup_approval_dirs(monkeypatch, tmp_path)
    approval._ensure_dirs()
    approvals_dir = tmp_path / "approvals"

    malformed_values = [
        ("status", []),
        ("status", {}),
        ("request_audit_status", None),
        ("request_audit_status", []),
        ("approval_audit_status", []),
        ("created", "not-a-timestamp"),
        ("created", True),
        ("created", float("inf")),
    ]
    for index, (field, value) in enumerate(malformed_values):
        approval_id = f"{index:032x}"
        record = {
            "id": approval_id,
            "tool": "write_note",
            "args": {"path": "a.md"},
            "requester": "requester-1",
            "status": "pending",
            "request_audit_status": "written",
            "created": 1.0,
        }
        record[field] = value
        (approvals_dir / f"{approval_id}.json").write_text(
            json.dumps(record), encoding="utf-8"
        )

        assert approval.check_approval(approval_id)["status"] == "corrupt_record"
        assert approval.approve(
            approval_id, approver_key=APPROVER_KEY
        )["status"] == "corrupt_record"

    assert approval.list_pending() == []


def test_pending_scan_uses_complete_record_validation(monkeypatch, tmp_path):
    setup_approval_dirs(monkeypatch, tmp_path)
    valid = approval.request_approval("write_note", {"path": "valid.md"})
    approvals_dir = tmp_path / "approvals"
    malformed_id = "f" * 32
    malformed = {
        "id": malformed_id,
        "tool": "write_note",
        "args": {"path": "bad.md"},
        "requester": "requester-1",
        "status": "pending",
        "request_audit_status": [],
        "created": 1.0,
    }
    (approvals_dir / f"{malformed_id}.json").write_text(
        json.dumps(malformed), encoding="utf-8"
    )

    pending = approval.list_pending()
    assert [record["id"] for record in pending] == [valid["id"]]

    invalid_filename = approvals_dir / "legacy.json"
    invalid_filename.write_text(
        json.dumps({
            "id": "legacy",
            "tool": "write_note",
            "args": {"path": "legacy.md"},
            "requester": "requester-1",
            "status": "pending",
            "request_audit_status": "written",
            "created": 1.0,
        }),
        encoding="utf-8",
    )
    assert [record["id"] for record in approval.list_pending()] == [valid["id"]]
