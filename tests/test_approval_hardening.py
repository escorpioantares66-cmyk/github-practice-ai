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


def test_audit_hash_chain_verifies_and_detects_entry_tampering(monkeypatch, tmp_path):
    setup_approval_dirs(monkeypatch, tmp_path)
    first = approval.request_approval("write_note", {"path": "one.md"})
    second = approval.request_approval("write_note", {"path": "two.md"})

    audit_path = tmp_path / "logs" / "audit.jsonl"
    entries = [json.loads(line) for line in audit_path.read_text(encoding="utf-8").splitlines()]
    assert [entry["seq"] for entry in entries] == [1, 2]
    assert entries[0]["previous_hash"] == "0" * 64
    assert entries[1]["previous_hash"] == entries[0]["hash"]
    assert approval.verify_audit_log()["valid"] is True

    entries[0]["record"]["tool"] = "tampered_tool"
    audit_path.write_text(
        "".join(json.dumps(entry, separators=(",", ":")) + chr(10) for entry in entries),
        encoding="utf-8",
    )
    try:
        approval.verify_audit_log()
    except approval.AuditLogIntegrityError:
        pass
    else:
        raise AssertionError("tampered audit entry was accepted")

    assert first["id"] != second["id"]


def test_audit_hash_chain_detects_deleted_or_reordered_entries(monkeypatch, tmp_path):
    setup_approval_dirs(monkeypatch, tmp_path)
    approval.request_approval("write_note", {"path": "one.md"})
    approval.request_approval("write_note", {"path": "two.md"})
    audit_path = tmp_path / "logs" / "audit.jsonl"
    lines = audit_path.read_text(encoding="utf-8").splitlines(keepends=True)

    audit_path.write_text(lines[1], encoding="utf-8")
    try:
        approval.verify_audit_log()
    except approval.AuditLogIntegrityError:
        pass
    else:
        raise AssertionError("deleted audit history was accepted")

    audit_path.write_text("".join(reversed(lines)), encoding="utf-8")
    try:
        approval.verify_audit_log()
    except approval.AuditLogIntegrityError:
        pass
    else:
        raise AssertionError("reordered audit history was accepted")


def test_audit_hash_chain_anchors_legacy_prefix(monkeypatch, tmp_path):
    setup_approval_dirs(monkeypatch, tmp_path)
    approval._ensure_dirs()
    audit_path = tmp_path / "logs" / "audit.jsonl"
    legacy = {
        "action": "request",
        "time": 1.0,
        "record": {"id": "a" * 32, "tool": "write_note"},
    }
    audit_path.write_text(json.dumps(legacy, separators=(",", ":")) + chr(10), encoding="utf-8")

    approval.log_audit("request", {"id": "b" * 32, "tool": "write_note"})
    assert approval.verify_audit_log()["entries"] == 2

    legacy["record"]["tool"] = "changed"
    chained = json.loads(audit_path.read_text(encoding="utf-8").splitlines()[1])
    audit_path.write_text(
        json.dumps(legacy, separators=(",", ":")) + chr(10)
        + json.dumps(chained, separators=(",", ":")) + chr(10),
        encoding="utf-8",
    )
    try:
        approval.verify_audit_log()
    except approval.AuditLogIntegrityError:
        pass
    else:
        raise AssertionError("modified legacy prefix was accepted")
