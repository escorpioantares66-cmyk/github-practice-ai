import hashlib
import json

import pytest

from stage2_sdk_ai import approval, audit_checkpoint_integrity, sandbox_approval

MAIN_STORE_ID = "main-store-test-001"
SANDBOX_STORE_ID = "sandbox-store-test-001"

@pytest.fixture
def main_audit(monkeypatch, tmp_path):
    monkeypatch.setattr(approval, "_approvals_dir", tmp_path / "approvals")
    monkeypatch.setattr(approval, "_audit_file", tmp_path / "logs" / "audit.jsonl")
    approval._ensure_dirs()
    approval.request_approval("write_note", {"path": "first.md"})

@pytest.fixture
def sandbox_audit(monkeypatch, tmp_path):
    monkeypatch.setenv("SANDBOX_APPROVALS_DIR", str(tmp_path / "sandbox-approvals"))
    sandbox_approval._append_audit(
        "a" * 32, "request_created", "automation", {}, 123.0
    )

def test_main_checkpoint_creation_refuses_missing_audit_file(monkeypatch, tmp_path):
    monkeypatch.setattr(approval, "_approvals_dir", tmp_path / "approvals")
    missing_log = tmp_path / "logs" / "audit.jsonl"
    monkeypatch.setattr(approval, "_audit_file", missing_log)

    with pytest.raises(audit_checkpoint_integrity.AuditCheckpointIntegrityError):
        audit_checkpoint_integrity.create_checkpoint_envelope(
            audit_checkpoint_integrity.MAIN_AUTHORITY, MAIN_STORE_ID
        )
    assert not missing_log.exists()
    assert not missing_log.parent.exists()

def test_sandbox_checkpoint_creation_refuses_missing_audit_file(monkeypatch, tmp_path):
    missing_store = tmp_path / "sandbox-approvals"
    monkeypatch.setenv("SANDBOX_APPROVALS_DIR", str(missing_store))

    with pytest.raises(audit_checkpoint_integrity.AuditCheckpointIntegrityError):
        audit_checkpoint_integrity.create_checkpoint_envelope(
            audit_checkpoint_integrity.SANDBOX_AUTHORITY, SANDBOX_STORE_ID
        )
    assert not missing_store.exists()

def test_main_checkpoint_verifies_exact_head_and_reports_later_suffix(main_audit):
    checkpoint = audit_checkpoint_integrity.create_checkpoint_envelope(
        audit_checkpoint_integrity.MAIN_AUTHORITY, MAIN_STORE_ID, created_at=123.0
    )

    exact = audit_checkpoint_integrity.verify_checkpoint(
        checkpoint,
        authority=audit_checkpoint_integrity.MAIN_AUTHORITY,
        store_id=MAIN_STORE_ID,
    )
    assert exact["valid"] is True
    assert exact["checkpoint_verified"] is True
    assert exact["unanchored_suffix"] == 0

    approval.request_approval("write_note", {"path": "later.md"})
    later = audit_checkpoint_integrity.verify_checkpoint(
        checkpoint,
        authority=audit_checkpoint_integrity.MAIN_AUTHORITY,
        store_id=MAIN_STORE_ID,
    )
    assert later["valid"] is True
    assert later["checkpoint_sequence"] < later["current_sequence"]
    assert later["unanchored_suffix"] == 1

def test_main_checkpoint_detects_rehashed_history_rewrite(main_audit):
    checkpoint = audit_checkpoint_integrity.create_checkpoint_envelope(
        audit_checkpoint_integrity.MAIN_AUTHORITY, MAIN_STORE_ID
    )
    path = approval._audit_file
    entry = json.loads(path.read_text(encoding="utf-8"))
    entry["record"]["tool"] = "rewritten_tool"
    entry["hash"] = hashlib.sha256(
        approval._canonical_audit_entry(entry)
    ).hexdigest()
    path.write_text(
        json.dumps(entry, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )

    # The rewritten history is internally valid; only the independent anchor
    # can detect that its checkpointed head has changed.
    assert approval.verify_audit_log()["valid"] is True
    with pytest.raises(approval.AuditLogIntegrityError):
        audit_checkpoint_integrity.verify_checkpoint(
            checkpoint,
            authority=audit_checkpoint_integrity.MAIN_AUTHORITY,
            store_id=MAIN_STORE_ID,
        )

def test_main_checkpoint_rejects_truncation_before_anchor(main_audit):
    checkpoint = audit_checkpoint_integrity.create_checkpoint_envelope(
        audit_checkpoint_integrity.MAIN_AUTHORITY, MAIN_STORE_ID
    )
    approval._audit_file.write_bytes(b"")

    with pytest.raises(approval.AuditLogIntegrityError):
        audit_checkpoint_integrity.verify_checkpoint(
            checkpoint,
            authority=audit_checkpoint_integrity.MAIN_AUTHORITY,
            store_id=MAIN_STORE_ID,
        )

def test_sandbox_checkpoint_verifies_exact_head_and_reports_later_suffix(sandbox_audit):
    checkpoint = audit_checkpoint_integrity.create_checkpoint_envelope(
        audit_checkpoint_integrity.SANDBOX_AUTHORITY,
        SANDBOX_STORE_ID,
        created_at=123.0,
    )
    exact = audit_checkpoint_integrity.verify_checkpoint(
        checkpoint,
        authority=audit_checkpoint_integrity.SANDBOX_AUTHORITY,
        store_id=SANDBOX_STORE_ID,
    )
    assert exact["valid"] is True
    assert exact["unanchored_suffix"] == 0

    sandbox_approval._append_audit(
        "b" * 32, "request_created", "automation", {}, 124.0
    )
    later = audit_checkpoint_integrity.verify_checkpoint(
        checkpoint,
        authority=audit_checkpoint_integrity.SANDBOX_AUTHORITY,
        store_id=SANDBOX_STORE_ID,
    )
    assert later["valid"] is True
    assert later["checkpoint_sequence"] < later["current_sequence"]
    assert later["unanchored_suffix"] == 1

def test_sandbox_checkpoint_detects_rehashed_history_rewrite(sandbox_audit):
    checkpoint = audit_checkpoint_integrity.create_checkpoint_envelope(
        audit_checkpoint_integrity.SANDBOX_AUTHORITY, SANDBOX_STORE_ID
    )
    path = sandbox_approval._store_dir() / "audit.jsonl"
    entry = json.loads(path.read_text(encoding="utf-8"))
    entry["actor"] = "intruder"
    entry_without_hash = {key: value for key, value in entry.items() if key != "hash"}
    entry["hash"] = hashlib.sha256(
        sandbox_approval._canonical(entry_without_hash)
    ).hexdigest()
    path.write_text(
        json.dumps(entry, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )

    # The local chain still verifies after re-hashing, but no longer matches
    # the independently retained checkpoint.
    assert sandbox_approval.verify_audit_log()["valid"] is True
    with pytest.raises(sandbox_approval.SandboxApprovalError):
        audit_checkpoint_integrity.verify_checkpoint(
            checkpoint,
            authority=audit_checkpoint_integrity.SANDBOX_AUTHORITY,
            store_id=SANDBOX_STORE_ID,
        )

def test_sandbox_checkpoint_rejects_truncation_before_anchor(sandbox_audit):
    checkpoint = audit_checkpoint_integrity.create_checkpoint_envelope(
        audit_checkpoint_integrity.SANDBOX_AUTHORITY, SANDBOX_STORE_ID
    )
    path = sandbox_approval._store_dir() / "audit.jsonl"
    path.write_bytes(b"")

    with pytest.raises(sandbox_approval.SandboxApprovalError):
        audit_checkpoint_integrity.verify_checkpoint(
            checkpoint,
            authority=audit_checkpoint_integrity.SANDBOX_AUTHORITY,
            store_id=SANDBOX_STORE_ID,
        )

def test_main_checkpoint_cannot_be_used_for_sandbox(sandbox_audit):
    checkpoint = {
        "format_version": 1,
        "authority": "main",
        "store_id": MAIN_STORE_ID,
        "sequence": 0,
        "head_hash": "0" * 64,
        "legacy_entries": 0,
        "created_at": 123.0,
        "checkpoint_id": "1" * 32,
    }
    with pytest.raises(audit_checkpoint_integrity.AuditCheckpointIntegrityError):
        audit_checkpoint_integrity.verify_checkpoint(
            checkpoint,
            authority=audit_checkpoint_integrity.SANDBOX_AUTHORITY,
            store_id=SANDBOX_STORE_ID,
        )

@pytest.mark.parametrize(
    "change",
    [
        {"format_version": True},
        {"sequence": True},
        {"legacy_entries": True},
        {"head_hash": "A" * 64},
        {"created_at": float("nan")},
        {"checkpoint_id": "not-an-id"},
        {"unexpected": "field"},
    ],
)
def test_envelope_rejects_invalid_fields(main_audit, change):
    checkpoint = audit_checkpoint_integrity.create_checkpoint_envelope(
        audit_checkpoint_integrity.MAIN_AUTHORITY, MAIN_STORE_ID
    )
    checkpoint.update(change)
    with pytest.raises(audit_checkpoint_integrity.AuditCheckpointIntegrityError):
        audit_checkpoint_integrity.validate_checkpoint_envelope(
            checkpoint,
            authority=audit_checkpoint_integrity.MAIN_AUTHORITY,
            store_id=MAIN_STORE_ID,
        )

def test_sandbox_envelope_rejects_main_legacy_prefix_count(sandbox_audit):
    checkpoint = {
        "format_version": 1,
        "authority": "sandbox",
        "store_id": SANDBOX_STORE_ID,
        "sequence": 1,
        "head_hash": "a" * 64,
        "legacy_entries": 1,
        "created_at": 123.0,
        "checkpoint_id": "1" * 32,
    }
    with pytest.raises(audit_checkpoint_integrity.AuditCheckpointIntegrityError):
        audit_checkpoint_integrity.validate_checkpoint_envelope(
            checkpoint,
            authority=audit_checkpoint_integrity.SANDBOX_AUTHORITY,
            store_id=SANDBOX_STORE_ID,
        )

def test_envelope_rejects_wrong_authority_and_store_id(main_audit):
    checkpoint = audit_checkpoint_integrity.create_checkpoint_envelope(
        audit_checkpoint_integrity.MAIN_AUTHORITY, MAIN_STORE_ID
    )
    with pytest.raises(audit_checkpoint_integrity.AuditCheckpointIntegrityError):
        audit_checkpoint_integrity.validate_checkpoint_envelope(
            checkpoint,
            authority=audit_checkpoint_integrity.SANDBOX_AUTHORITY,
            store_id=SANDBOX_STORE_ID,
        )
    with pytest.raises(audit_checkpoint_integrity.AuditCheckpointIntegrityError):
        audit_checkpoint_integrity.validate_checkpoint_envelope(
            checkpoint,
            authority=audit_checkpoint_integrity.MAIN_AUTHORITY,
            store_id="another-store",
        )

def test_parser_rejects_duplicate_keys_and_oversized_payload():
    duplicate = (
        b'{"format_version":1,"format_version":1,"authority":"main",'
        b'"store_id":"' + MAIN_STORE_ID.encode() + b'","sequence":0,'
        b'"head_hash":"' + b"0" * 64 + b'","legacy_entries":0,'
        b'"created_at":123.0,"checkpoint_id":"' + b"1" * 32 + b'"}'
    )
    with pytest.raises(audit_checkpoint_integrity.AuditCheckpointIntegrityError):
        audit_checkpoint_integrity.parse_checkpoint(
            duplicate,
            authority=audit_checkpoint_integrity.MAIN_AUTHORITY,
            store_id=MAIN_STORE_ID,
        )
    with pytest.raises(audit_checkpoint_integrity.AuditCheckpointIntegrityError):
        audit_checkpoint_integrity.parse_checkpoint(
            b"x" * (audit_checkpoint_integrity.MAX_CHECKPOINT_BYTES + 1),
            authority=audit_checkpoint_integrity.MAIN_AUTHORITY,
            store_id=MAIN_STORE_ID,
        )

def test_serialized_checkpoint_is_canonical_and_round_trips(main_audit):
    checkpoint = audit_checkpoint_integrity.create_checkpoint_envelope(
        audit_checkpoint_integrity.MAIN_AUTHORITY, MAIN_STORE_ID
    )
    encoded = audit_checkpoint_integrity.serialize_checkpoint(
        checkpoint,
        authority=audit_checkpoint_integrity.MAIN_AUTHORITY,
        store_id=MAIN_STORE_ID,
    )
    parsed = audit_checkpoint_integrity.parse_checkpoint(
        encoded,
        authority=audit_checkpoint_integrity.MAIN_AUTHORITY,
        store_id=MAIN_STORE_ID,
    )
    assert parsed == checkpoint
    assert encoded.endswith(b"\n")

def _trusted_floor(checkpoint):
    return {
        "authority": checkpoint["authority"],
        "store_id": checkpoint["store_id"],
        "sequence": checkpoint["sequence"],
        "head_hash": checkpoint["head_hash"],
        "legacy_entries": checkpoint["legacy_entries"],
        "created_at": checkpoint["created_at"],
        "checkpoint_id": checkpoint["checkpoint_id"],
    }

def test_main_checkpoint_freshness_accepts_age_boundary_and_rejects_stale(main_audit):
    checkpoint = audit_checkpoint_integrity.create_checkpoint_envelope(
        audit_checkpoint_integrity.MAIN_AUTHORITY, MAIN_STORE_ID, created_at=100.0
    )
    floor = _trusted_floor(checkpoint)

    accepted = audit_checkpoint_integrity.verify_checkpoint_with_policy(
        checkpoint,
        authority=audit_checkpoint_integrity.MAIN_AUTHORITY,
        store_id=MAIN_STORE_ID,
        trusted_floor=floor,
        now=110.0,
        max_age_seconds=10.0,
        max_unanchored_suffix=0,
    )
    assert accepted["policy_accepted"] is True
    assert accepted["freshness_age_seconds"] == 10.0

    with pytest.raises(audit_checkpoint_integrity.AuditCheckpointPolicyError):
        audit_checkpoint_integrity.verify_checkpoint_with_policy(
            checkpoint,
            authority=audit_checkpoint_integrity.MAIN_AUTHORITY,
            store_id=MAIN_STORE_ID,
            trusted_floor=floor,
            now=110.001,
            max_age_seconds=10.0,
            max_unanchored_suffix=0,
        )

def test_main_checkpoint_rejects_suffix_over_policy_limit(main_audit):
    checkpoint = audit_checkpoint_integrity.create_checkpoint_envelope(
        audit_checkpoint_integrity.MAIN_AUTHORITY, MAIN_STORE_ID, created_at=100.0
    )
    floor = _trusted_floor(checkpoint)
    approval.request_approval("write_note", {"path": "later.md"})

    with pytest.raises(audit_checkpoint_integrity.AuditCheckpointPolicyError):
        audit_checkpoint_integrity.verify_checkpoint_with_policy(
            checkpoint,
            authority=audit_checkpoint_integrity.MAIN_AUTHORITY,
            store_id=MAIN_STORE_ID,
            trusted_floor=floor,
            now=101.0,
            max_age_seconds=10.0,
            max_unanchored_suffix=0,
        )

    accepted = audit_checkpoint_integrity.verify_checkpoint_with_policy(
        checkpoint,
        authority=audit_checkpoint_integrity.MAIN_AUTHORITY,
        store_id=MAIN_STORE_ID,
        trusted_floor=floor,
        now=101.0,
        max_age_seconds=10.0,
        max_unanchored_suffix=1,
    )
    assert accepted["unanchored_suffix"] == 1

def test_main_checkpoint_rejects_restored_older_checkpoint(main_audit):
    older = audit_checkpoint_integrity.create_checkpoint_envelope(
        audit_checkpoint_integrity.MAIN_AUTHORITY, MAIN_STORE_ID, created_at=100.0
    )
    approval.request_approval("write_note", {"path": "newer.md"})
    newer = audit_checkpoint_integrity.create_checkpoint_envelope(
        audit_checkpoint_integrity.MAIN_AUTHORITY, MAIN_STORE_ID, created_at=101.0
    )

    with pytest.raises(audit_checkpoint_integrity.AuditCheckpointRollbackError):
        audit_checkpoint_integrity.verify_checkpoint_with_policy(
            older,
            authority=audit_checkpoint_integrity.MAIN_AUTHORITY,
            store_id=MAIN_STORE_ID,
            trusted_floor=_trusted_floor(newer),
            now=102.0,
            max_age_seconds=100.0,
            max_unanchored_suffix=10,
        )

def test_main_checkpoint_rejects_same_head_with_older_publication_time(main_audit):
    trusted = audit_checkpoint_integrity.create_checkpoint_envelope(
        audit_checkpoint_integrity.MAIN_AUTHORITY, MAIN_STORE_ID, created_at=101.0
    )
    older_publication = dict(trusted)
    older_publication["created_at"] = 100.0

    with pytest.raises(audit_checkpoint_integrity.AuditCheckpointRollbackError):
        audit_checkpoint_integrity.verify_checkpoint_with_policy(
            older_publication,
            authority=audit_checkpoint_integrity.MAIN_AUTHORITY,
            store_id=MAIN_STORE_ID,
            trusted_floor=_trusted_floor(trusted),
            now=102.0,
            max_age_seconds=100.0,
            max_unanchored_suffix=0,
        )

def test_main_checkpoint_rejects_future_publication_timestamp(main_audit):
    checkpoint = audit_checkpoint_integrity.create_checkpoint_envelope(
        audit_checkpoint_integrity.MAIN_AUTHORITY, MAIN_STORE_ID, created_at=200.0
    )

    with pytest.raises(audit_checkpoint_integrity.AuditCheckpointPolicyError):
        audit_checkpoint_integrity.verify_checkpoint_with_policy(
            checkpoint,
            authority=audit_checkpoint_integrity.MAIN_AUTHORITY,
            store_id=MAIN_STORE_ID,
            trusted_floor=_trusted_floor(checkpoint),
            now=199.0,
            max_age_seconds=100.0,
            max_unanchored_suffix=0,
        )

def test_missing_checkpoint_or_trusted_floor_requires_operator_recovery(main_audit):
    checkpoint = audit_checkpoint_integrity.create_checkpoint_envelope(
        audit_checkpoint_integrity.MAIN_AUTHORITY, MAIN_STORE_ID, created_at=100.0
    )
    floor = _trusted_floor(checkpoint)

    for candidate, trusted in ((None, floor), (checkpoint, None)):
        with pytest.raises(
            audit_checkpoint_integrity.AuditCheckpointRecoveryRequired
        ):
            audit_checkpoint_integrity.verify_checkpoint_with_policy(
                candidate,
                authority=audit_checkpoint_integrity.MAIN_AUTHORITY,
                store_id=MAIN_STORE_ID,
                trusted_floor=trusted,
                now=101.0,
                max_age_seconds=10.0,
                max_unanchored_suffix=0,
            )

def test_policy_rejects_invalid_limits_and_wrong_floor_identity(main_audit):
    checkpoint = audit_checkpoint_integrity.create_checkpoint_envelope(
        audit_checkpoint_integrity.MAIN_AUTHORITY, MAIN_STORE_ID, created_at=100.0
    )
    floor = _trusted_floor(checkpoint)

    with pytest.raises(audit_checkpoint_integrity.AuditCheckpointPolicyError):
        audit_checkpoint_integrity.verify_checkpoint_with_policy(
            checkpoint,
            authority=audit_checkpoint_integrity.MAIN_AUTHORITY,
            store_id=MAIN_STORE_ID,
            trusted_floor=floor,
            now=101.0,
            max_age_seconds=True,
            max_unanchored_suffix=0,
        )
    with pytest.raises(audit_checkpoint_integrity.AuditCheckpointPolicyError):
        audit_checkpoint_integrity.verify_checkpoint_with_policy(
            checkpoint,
            authority=audit_checkpoint_integrity.MAIN_AUTHORITY,
            store_id=MAIN_STORE_ID,
            trusted_floor=floor,
            now=101.0,
            max_age_seconds=10.0,
            max_unanchored_suffix=True,
        )

    wrong_floor = dict(floor, store_id="different-store")
    with pytest.raises(audit_checkpoint_integrity.AuditCheckpointIntegrityError):
        audit_checkpoint_integrity.verify_checkpoint_with_policy(
            checkpoint,
            authority=audit_checkpoint_integrity.MAIN_AUTHORITY,
            store_id=MAIN_STORE_ID,
            trusted_floor=wrong_floor,
            now=101.0,
            max_age_seconds=10.0,
            max_unanchored_suffix=0,
        )

def test_sandbox_checkpoint_freshness_and_suffix_policy(sandbox_audit):
    checkpoint = audit_checkpoint_integrity.create_checkpoint_envelope(
        audit_checkpoint_integrity.SANDBOX_AUTHORITY,
        SANDBOX_STORE_ID,
        created_at=100.0,
    )
    floor = _trusted_floor(checkpoint)
    sandbox_approval._append_audit(
        "b" * 32, "request_created", "automation", {}, 124.0
    )

    accepted = audit_checkpoint_integrity.verify_checkpoint_with_policy(
        checkpoint,
        authority=audit_checkpoint_integrity.SANDBOX_AUTHORITY,
        store_id=SANDBOX_STORE_ID,
        trusted_floor=floor,
        now=110.0,
        max_age_seconds=10.0,
        max_unanchored_suffix=1,
    )
    assert accepted["policy_accepted"] is True
    assert accepted["unanchored_suffix"] == 1

    with pytest.raises(audit_checkpoint_integrity.AuditCheckpointPolicyError):
        audit_checkpoint_integrity.verify_checkpoint_with_policy(
            checkpoint,
            authority=audit_checkpoint_integrity.SANDBOX_AUTHORITY,
            store_id=SANDBOX_STORE_ID,
            trusted_floor=floor,
            now=110.0,
            max_age_seconds=10.0,
            max_unanchored_suffix=0,
        )
    with pytest.raises(audit_checkpoint_integrity.AuditCheckpointPolicyError):
        audit_checkpoint_integrity.verify_checkpoint_with_policy(
            checkpoint,
            authority=audit_checkpoint_integrity.SANDBOX_AUTHORITY,
            store_id=SANDBOX_STORE_ID,
            trusted_floor=floor,
            now=110.001,
            max_age_seconds=10.0,
            max_unanchored_suffix=1,
        )

def test_sandbox_checkpoint_rejects_rollback_to_older_checkpoint(sandbox_audit):
    older = audit_checkpoint_integrity.create_checkpoint_envelope(
        audit_checkpoint_integrity.SANDBOX_AUTHORITY,
        SANDBOX_STORE_ID,
        created_at=100.0,
    )
    sandbox_approval._append_audit(
        "b" * 32, "request_created", "automation", {}, 124.0
    )
    newer = audit_checkpoint_integrity.create_checkpoint_envelope(
        audit_checkpoint_integrity.SANDBOX_AUTHORITY,
        SANDBOX_STORE_ID,
        created_at=101.0,
    )

    with pytest.raises(audit_checkpoint_integrity.AuditCheckpointRollbackError):
        audit_checkpoint_integrity.verify_checkpoint_with_policy(
            older,
            authority=audit_checkpoint_integrity.SANDBOX_AUTHORITY,
            store_id=SANDBOX_STORE_ID,
            trusted_floor=_trusted_floor(newer),
            now=102.0,
            max_age_seconds=100.0,
            max_unanchored_suffix=10,
        )

def test_main_checkpoint_verification_refuses_missing_audit_log(monkeypatch, tmp_path):
    monkeypatch.setattr(approval, "_approvals_dir", tmp_path / "approvals")
    audit_path = tmp_path / "logs" / "audit.jsonl"
    monkeypatch.setattr(approval, "_audit_file", audit_path)
    approval._ensure_dirs()
    audit_path.write_bytes(b"")
    checkpoint = audit_checkpoint_integrity.create_checkpoint_envelope(
        audit_checkpoint_integrity.MAIN_AUTHORITY,
        MAIN_STORE_ID,
        created_at=100.0,
    )
    audit_path.unlink()

    with pytest.raises(audit_checkpoint_integrity.AuditCheckpointIntegrityError):
        audit_checkpoint_integrity.verify_checkpoint(
            checkpoint,
            authority=audit_checkpoint_integrity.MAIN_AUTHORITY,
            store_id=MAIN_STORE_ID,
        )
    assert not audit_path.exists()

def test_sandbox_checkpoint_verification_refuses_missing_audit_log(
    monkeypatch, tmp_path
):
    store = tmp_path / "sandbox-approvals"
    monkeypatch.setenv("SANDBOX_APPROVALS_DIR", str(store))
    sandbox_approval._ensure_store()
    audit_path = store / "audit.jsonl"
    audit_path.write_bytes(b"")
    audit_path.chmod(0o600)
    checkpoint = audit_checkpoint_integrity.create_checkpoint_envelope(
        audit_checkpoint_integrity.SANDBOX_AUTHORITY,
        SANDBOX_STORE_ID,
        created_at=100.0,
    )
    audit_path.unlink()

    with pytest.raises(audit_checkpoint_integrity.AuditCheckpointIntegrityError):
        audit_checkpoint_integrity.verify_checkpoint(
            checkpoint,
            authority=audit_checkpoint_integrity.SANDBOX_AUTHORITY,
            store_id=SANDBOX_STORE_ID,
        )
    assert not audit_path.exists()

def test_checkpoint_rejects_same_sequence_conflicting_trusted_head(main_audit):
    trusted = audit_checkpoint_integrity.create_checkpoint_envelope(
        audit_checkpoint_integrity.MAIN_AUTHORITY, MAIN_STORE_ID, created_at=101.0
    )
    conflict = dict(trusted, head_hash="f" * 64)

    with pytest.raises(audit_checkpoint_integrity.AuditCheckpointRollbackError):
        audit_checkpoint_integrity.verify_checkpoint_with_policy(
            conflict,
            authority=audit_checkpoint_integrity.MAIN_AUTHORITY,
            store_id=MAIN_STORE_ID,
            trusted_floor=_trusted_floor(trusted),
            now=102.0,
            max_age_seconds=100.0,
            max_unanchored_suffix=0,
        )


def test_main_policy_rejects_rehashed_history_after_trusted_floor(main_audit):
    trusted = audit_checkpoint_integrity.create_checkpoint_envelope(
        audit_checkpoint_integrity.MAIN_AUTHORITY, MAIN_STORE_ID, created_at=100.0
    )
    approval.request_approval("write_note", {"path": "after-floor.md"})

    entries = [
        json.loads(line)
        for line in approval._audit_file.read_text(encoding="utf-8").splitlines()
    ]
    entries[0]["record"]["tool"] = "rewritten_after_trusted_floor"
    previous_hash = "0" * 64
    for entry in entries:
        entry["previous_hash"] = previous_hash
        entry["hash"] = hashlib.sha256(
            approval._canonical_audit_entry(entry)
        ).hexdigest()
        previous_hash = entry["hash"]
    approval._audit_file.write_text(
        "".join(
            json.dumps(entry, sort_keys=True, separators=(",", ":")) + "\\n"
            for entry in entries
        ),
        encoding="utf-8",
    )

    # The rewritten chain is internally consistent and the newer candidate
    # matches it. Only checking the independently retained floor catches
    # that this history no longer contains the operator-trusted prefix.
    assert approval.verify_audit_log()["valid"] is True
    candidate = audit_checkpoint_integrity.create_checkpoint_envelope(
        audit_checkpoint_integrity.MAIN_AUTHORITY, MAIN_STORE_ID, created_at=101.0
    )
    with pytest.raises(approval.AuditLogIntegrityError):
        audit_checkpoint_integrity.verify_checkpoint_with_policy(
            candidate,
            authority=audit_checkpoint_integrity.MAIN_AUTHORITY,
            store_id=MAIN_STORE_ID,
            trusted_floor=_trusted_floor(trusted),
            now=102.0,
            max_age_seconds=100.0,
            max_unanchored_suffix=0,
        )


def test_sandbox_policy_rejects_rehashed_history_after_trusted_floor(sandbox_audit):
    trusted = audit_checkpoint_integrity.create_checkpoint_envelope(
        audit_checkpoint_integrity.SANDBOX_AUTHORITY,
        SANDBOX_STORE_ID,
        created_at=100.0,
    )
    sandbox_approval._append_audit(
        "b" * 32, "request_created", "automation", {}, 124.0
    )

    entries = sandbox_approval._read_audit_entries()
    entries[0]["actor"] = "rewritten_after_trusted_floor"
    previous_hash = "0" * 64
    rewritten = []
    for entry in entries:
        value = dict(entry)
        value.pop("hash", None)
        value["previous_hash"] = previous_hash
        digest = hashlib.sha256(
            sandbox_approval._canonical(value)
        ).hexdigest()
        value["hash"] = digest
        previous_hash = digest
        rewritten.append(value)
    audit_path = sandbox_approval._store_dir() / "audit.jsonl"
    audit_path.write_text(
        "".join(
            json.dumps(entry, sort_keys=True, separators=(",", ":")) + "\\n"
            for entry in rewritten
        ),
        encoding="utf-8",
    )

    # The new local chain and candidate are internally valid. The retained
    # floor must still match its original sequence/hash in that history.
    assert sandbox_approval.verify_audit_log()["valid"] is True
    candidate = audit_checkpoint_integrity.create_checkpoint_envelope(
        audit_checkpoint_integrity.SANDBOX_AUTHORITY,
        SANDBOX_STORE_ID,
        created_at=101.0,
    )
    with pytest.raises(sandbox_approval.SandboxApprovalError):
        audit_checkpoint_integrity.verify_checkpoint_with_policy(
            candidate,
            authority=audit_checkpoint_integrity.SANDBOX_AUTHORITY,
            store_id=SANDBOX_STORE_ID,
            trusted_floor=_trusted_floor(trusted),
            now=102.0,
            max_age_seconds=100.0,
            max_unanchored_suffix=0,
        )
