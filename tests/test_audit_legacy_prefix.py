import hashlib
import json

import pytest

from stage2_sdk_ai import approval


def _legacy_event(number):
    return {
        "action": "request",
        "time": float(number),
        "record": {"id": f"legacy-{number}"},
    }


def _jsonl(entry):
    return json.dumps(entry, separators=(",", ":")).encode() + b"\n"


def _first_chained_event(legacy_prefix):
    record = {
        "id": "a" * 32,
        "tool": "write_note",
        "args": {"path": "note.md", "content": "safe"},
        "requester": "agent",
        "status": "pending",
        "request_audit_status": "written",
        "created": 123.0,
    }
    entry = {
        "action": "request",
        "time": 123.0,
        "record": record,
        "seq": 1,
        "previous_hash": (
            hashlib.sha256(
                b"legacy-audit-prefix-v1\0" + legacy_prefix
            ).hexdigest()
            if legacy_prefix else "0" * 64
        ),
    }
    entry["hash"] = hashlib.sha256(
        approval._canonical_audit_entry(entry)
    ).hexdigest()
    return entry


def test_audit_chain_accepts_multiple_legacy_prefix_entries():
    contents = _jsonl(_legacy_event(1)) + _jsonl(_legacy_event(2))

    sequence, head_hash, total, legacy_count, _ = (
        approval._audit_chain_state(contents)
    )

    assert sequence == 0
    assert head_hash == hashlib.sha256(
        b"legacy-audit-prefix-v1\0" + contents
    ).hexdigest()
    assert total == 2
    assert legacy_count == 2


def test_audit_chain_accepts_legacy_prefix_then_hash_chained_entry():
    legacy_prefix = _jsonl(_legacy_event(1))
    chained = _first_chained_event(legacy_prefix)

    sequence, _, total, legacy_count, _ = approval._audit_chain_state(
        legacy_prefix + _jsonl(chained)
    )

    assert sequence == 1
    assert total == 2
    assert legacy_count == 1


def test_audit_chain_rejects_legacy_entry_after_hash_chain_started():
    legacy_prefix = _jsonl(_legacy_event(1))
    chained = _first_chained_event(legacy_prefix)
    contents = legacy_prefix + _jsonl(chained) + _jsonl(_legacy_event(2))

    with pytest.raises(
        approval.AuditLogIntegrityError,
        match="legacy entry 3 appears after the hash chain began",
    ):
        approval._audit_chain_state(contents)


def test_audit_chain_rejects_invalid_legacy_event_schema():
    invalid = {"action": "unknown", "time": 1.0, "record": {}}

    with pytest.raises(
        approval.AuditLogIntegrityError,
        match="legacy audit entry 1 has an invalid schema",
    ):
        approval._audit_chain_state(_jsonl(invalid))
