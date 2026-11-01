import hashlib
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
    entries = [
        json.loads(line)
        for line in audit_path.read_text(encoding="utf-8").splitlines()
    ]
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


def test_audit_append_refuses_to_cross_validation_limit(monkeypatch, tmp_path):
    setup_approval_dirs(monkeypatch, tmp_path)
    first = approval.request_approval("write_note", {"path": "first.md"})
    audit_path = tmp_path / "logs" / "audit.jsonl"
    original_audit = audit_path.read_bytes()

    # Leave room for only one extra byte: the next valid event must be rejected
    # before any bytes are appended, otherwise verification becomes impossible.
    monkeypatch.setattr(
        approval, "MAX_AUDIT_LOG_BYTES", len(original_audit) + 1
    )
    try:
        approval.request_approval("write_note", {"path": "second.md"})
    except approval.ApprovalAuditError as exc:
        second_id = exc.approval_id
    else:
        raise AssertionError("audit append crossed the configured size limit")

    assert audit_path.read_bytes() == original_audit
    assert approval.verify_audit_log()["valid"] is True
    assert approval.check_approval(second_id)["request_audit_status"] == "failed"
    assert approval.check_approval(first["id"])["request_audit_status"] == "written"


def test_audit_hash_chain_anchors_legacy_prefix(monkeypatch, tmp_path):
    setup_approval_dirs(monkeypatch, tmp_path)
    approval._ensure_dirs()
    audit_path = tmp_path / "logs" / "audit.jsonl"
    legacy = {
        "action": "request",
        "time": 1.0,
        "record": {"id": "a" * 32, "tool": "write_note"},
    }
    audit_path.write_text(
        json.dumps(legacy, separators=(",", ":")) + chr(10),
        encoding="utf-8",
    )

    approval.request_approval("write_note", {"path": "two.md"})
    assert approval.verify_audit_log()["entries"] == 2

    legacy["record"]["tool"] = "changed"
    chained = json.loads(audit_path.read_text(encoding="utf-8").splitlines()[1])
    audit_path.write_text(
        json.dumps(legacy, separators=(",", ":"))
        + chr(10)
        + json.dumps(chained, separators=(",", ":"))
        + chr(10),
        encoding="utf-8",
    )
    try:
        approval.verify_audit_log()
    except approval.AuditLogIntegrityError:
        pass
    else:
        raise AssertionError("modified legacy prefix was accepted")


def test_audit_hash_chain_rejects_duplicate_json_keys(monkeypatch, tmp_path):
    setup_approval_dirs(monkeypatch, tmp_path)
    approval._ensure_dirs()
    audit_path = tmp_path / "logs" / "audit.jsonl"
    audit_path.write_text(
        '{"action":"request","action":"denied","time":1.0,'
        '"record":{"id":"' + "c" * 32 + '"}}' + chr(10),
        encoding="utf-8",
    )
    try:
        approval.verify_audit_log()
    except approval.AuditLogIntegrityError:
        pass
    else:
        raise AssertionError("duplicate JSON keys were accepted")



def _process_append_audit_event(index):
    approval.request_approval(
        "write_note", {"path": f"process-{index}.md"},
        requester=f"process-requester-{index}",
    )
    return index


def _process_limited_approval_request(index):
    try:
        approval.request_approval(
            "write_note", {"path": f"limited-{index}.md"},
            requester="shared-requester",
        )
    except approval.ApprovalLimitError as exc:
        return exc.limit
    return "created"


def test_audit_writes_are_serialized_across_processes(monkeypatch, tmp_path):
    import multiprocessing

    setup_approval_dirs(monkeypatch, tmp_path)
    context = multiprocessing.get_context("fork")
    with context.Pool(processes=4) as pool:
        results = pool.map(_process_append_audit_event, range(12))

    assert sorted(results) == list(range(12))
    verified = approval.verify_audit_log()
    assert verified["valid"] is True
    assert verified["entries"] == 12
    assert verified["chained_entries"] == 12
    entries = [
        json.loads(line)
        for line in (tmp_path / "logs" / "audit.jsonl").read_text(
            encoding="utf-8"
        ).splitlines()
    ]
    assert [entry["seq"] for entry in entries] == list(range(1, 13))


def test_external_checkpoint_detects_suffix_truncation(monkeypatch, tmp_path):
    setup_approval_dirs(monkeypatch, tmp_path)
    for index in range(3):
        approval.request_approval("write_note", {"path": f"{index}.md"})
    checkpoint = approval.create_audit_checkpoint()

    approval.request_approval("write_note", {"path": "later.md"})
    assert approval.verify_audit_log(checkpoint)["checkpoint_verified"] is True

    audit_path = tmp_path / "logs" / "audit.jsonl"
    lines = audit_path.read_text(encoding="utf-8").splitlines(keepends=True)
    audit_path.write_text("".join(lines[:2]), encoding="utf-8")
    try:
        approval.verify_audit_log(checkpoint)
    except approval.AuditLogIntegrityError:
        pass
    else:
        raise AssertionError("truncation before external checkpoint was accepted")

    audit_path.write_text("", encoding="utf-8")
    try:
        approval.verify_audit_log(checkpoint)
    except approval.AuditLogIntegrityError:
        pass
    else:
        raise AssertionError("empty log was accepted against external checkpoint")


def test_checkpoint_rejects_modified_checkpoint_and_supports_legacy_migration(
    monkeypatch, tmp_path
):
    setup_approval_dirs(monkeypatch, tmp_path)
    approval._ensure_dirs()
    audit_path = tmp_path / "logs" / "audit.jsonl"
    legacy = {
        "action": "request",
        "time": 1.0,
        "record": {"id": "a" * 32, "tool": "write_note"},
    }
    audit_path.write_text(
        json.dumps(legacy, separators=(",", ":")) + chr(10),
        encoding="utf-8",
    )

    checkpoint = approval.create_audit_checkpoint()
    assert checkpoint["sequence"] == 0
    assert checkpoint["legacy_entries"] == 1
    approval.request_approval("write_note", {"path": "after-migration.md"})
    assert approval.verify_audit_log(checkpoint)["checkpoint_verified"] is True

    changed = dict(checkpoint)
    changed["head_hash"] = "f" * 64
    try:
        approval.verify_audit_log(changed)
    except approval.AuditLogIntegrityError:
        pass
    else:
        raise AssertionError("modified external checkpoint was accepted")

    lines = audit_path.read_text(encoding="utf-8").splitlines(keepends=True)
    legacy["record"]["tool"] = "rewritten"
    audit_path.write_text(
        json.dumps(legacy, separators=(",", ":")) + chr(10) + lines[1],
        encoding="utf-8",
    )
    try:
        approval.verify_audit_log(checkpoint)
    except approval.AuditLogIntegrityError:
        pass
    else:
        raise AssertionError("modified migrated legacy prefix was accepted")


def test_audit_event_validation_rejects_inconsistent_state(monkeypatch, tmp_path):
    setup_approval_dirs(monkeypatch, tmp_path)
    record = {
        "id": "d" * 32,
        "tool": "write_note",
        "args": {"path": "bad.md"},
        "requester": "requester-1",
        "status": "approved",
        "request_audit_status": "written",
        "approval_audit_status": "written",
        "approver": "operator-1",
        "approved_at": 1.0,
        "created": 1.0,
    }
    try:
        approval.log_audit("request", record)
    except approval.AuditLogIntegrityError:
        pass
    else:
        raise AssertionError("request event with approved state was accepted")


def test_audit_event_validation_rejects_nested_non_finite_values(
    monkeypatch, tmp_path
):
    setup_approval_dirs(monkeypatch, tmp_path)
    record = {
        "id": "e" * 32,
        "tool": "write_note",
        "args": {"value": float("nan")},
        "requester": "requester-1",
        "status": "pending",
        "request_audit_status": "written",
        "created": 1.0,
    }
    try:
        approval.log_audit("request", record)
    except approval.AuditLogIntegrityError:
        pass
    else:
        raise AssertionError("nested non-finite JSON value was accepted")


def test_audit_event_validation_rejects_incomplete_consumption_metadata(
    monkeypatch, tmp_path
):
    setup_approval_dirs(monkeypatch, tmp_path)
    record = {
        "id": "f" * 32,
        "tool": "write_note",
        "args": {"path": "bad.md"},
        "requester": "requester-1",
        "status": "consumed",
        "request_audit_status": "written",
        "approval_audit_status": "written",
        "approver": "",
        "approved_at": 1.0,
        "consumed_at": 2.0,
        "created": 1.0,
    }
    try:
        approval.log_audit("consumed", record)
    except approval.AuditLogIntegrityError:
        pass
    else:
        raise AssertionError("consumed event with empty approver was accepted")


def test_audit_event_validation_rejects_incomplete_execution_failure_metadata(
    monkeypatch, tmp_path
):
    setup_approval_dirs(monkeypatch, tmp_path)
    record = {
        "id": "1" * 32,
        "tool": "write_note",
        "args": {"path": "bad.md"},
        "requester": "requester-1",
        "status": "consumed",
        "request_audit_status": "written",
        "approval_audit_status": "written",
        "approver": "operator-1",
        "approved_at": 1.0,
        "consumed_at": 2.0,
        "execution_failure": {
            "failed_at": 3.0,
            "error_type": "OSError",
            "error_message": "write failed",
        },
        "created": 1.0,
    }
    record["approved_at"] = float("nan")
    try:
        approval.log_audit("execution_failed", record)
    except approval.AuditLogIntegrityError:
        pass
    else:
        raise AssertionError("execution failure with invalid approval time was accepted")


def test_request_approval_rejects_invalid_payload_before_writing(
    monkeypatch, tmp_path
):
    setup_approval_dirs(monkeypatch, tmp_path)
    invalid_requests = [
        ("", {"path": "x.md"}, "requester"),
        (" " * 121, {"path": "x.md"}, "requester"),
        ("write_note", [], "requester"),
        ("write_note", {"value": float("nan")}, "requester"),
        ("write_note", {"value": object()}, "requester"),
        ("write_note", {"path": "x.md"}, ""),
        ("write_note", {"path": "x.md"}, "r" * 257),
    ]

    for tool, args, requester in invalid_requests:
        try:
            approval.request_approval(tool, args, requester=requester)
        except ValueError:
            pass
        else:
            raise AssertionError("invalid approval request was accepted")

    approvals_dir = tmp_path / "approvals"
    assert not approvals_dir.exists()
    assert not (tmp_path / "logs" / "audit.jsonl").exists()


def test_request_approval_accepts_valid_json_payload_and_logs_it(
    monkeypatch, tmp_path
):
    setup_approval_dirs(monkeypatch, tmp_path)
    request = approval.request_approval(
        "write_note", {"path": "safe.md", "content": "hello"},
        requester="agent-1",
    )

    assert request["request_audit_status"] == "written"
    assert approval.check_approval(request["id"])["args"] == {
        "path": "safe.md", "content": "hello"
    }
    audit_record = json.loads(
        (tmp_path / "logs" / "audit.jsonl").read_text(encoding="utf-8").splitlines()[0]
    )["record"]
    assert "args" not in audit_record
    assert audit_record["args_sha256"] == hashlib.sha256(
        json.dumps(
            {"path": "safe.md", "content": "hello"},
            sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        ).encode("utf-8")
    ).hexdigest()
    assert "hello" not in (tmp_path / "logs" / "audit.jsonl").read_text(
        encoding="utf-8"
    )


def test_pending_approval_limit_is_released_after_decision(monkeypatch, tmp_path):
    setup_approval_dirs(monkeypatch, tmp_path)
    monkeypatch.setattr(approval, "MAX_PENDING_APPROVALS_PER_REQUESTER", 2)
    monkeypatch.setattr(approval, "MAX_APPROVAL_REQUESTS_PER_UTC_DAY", 20)
    monkeypatch.setenv("AGENT_APPROVER_KEYS", APPROVER_KEY)
    first = approval.request_approval("write_note", {"path": "one.md"}, "same")
    approval.request_approval("write_note", {"path": "two.md"}, "same")
    try:
        approval.request_approval("write_note", {"path": "three.md"}, "same")
    except approval.ApprovalLimitError as exc:
        assert exc.limit == "pending_approval_limit"
    else:
        raise AssertionError("pending request limit was bypassed")

    assert approval.approve(first["id"], APPROVER_KEY)["status"] == "approved"
    third = approval.request_approval("write_note", {"path": "three.md"}, "same")
    assert third["status"] == "pending"


def test_daily_approval_limit_counts_decided_requests(monkeypatch, tmp_path):
    setup_approval_dirs(monkeypatch, tmp_path)
    monkeypatch.setattr(approval, "MAX_PENDING_APPROVALS_PER_REQUESTER", 20)
    monkeypatch.setattr(approval, "MAX_APPROVAL_REQUESTS_PER_UTC_DAY", 2)
    approval.request_approval("write_note", {"path": "one.md"}, "same")
    approval.request_approval("write_note", {"path": "two.md"}, "same")
    try:
        approval.request_approval("write_note", {"path": "three.md"}, "same")
    except approval.ApprovalLimitError as exc:
        assert exc.limit == "daily_approval_limit"
    else:
        raise AssertionError("daily approval limit was bypassed")


def test_pending_limit_cannot_be_bypassed_by_concurrent_processes(
    monkeypatch, tmp_path
):
    import multiprocessing

    setup_approval_dirs(monkeypatch, tmp_path)
    monkeypatch.setattr(approval, "MAX_PENDING_APPROVALS_PER_REQUESTER", 5)
    monkeypatch.setattr(approval, "MAX_APPROVAL_REQUESTS_PER_UTC_DAY", 100)
    context = multiprocessing.get_context("fork")
    with context.Pool(processes=8) as pool:
        results = pool.map(_process_limited_approval_request, range(20))

    assert results.count("created") == 5
    assert results.count("pending_approval_limit") == 15
    assert len(approval.list_pending()) == 5
