"""Security and recovery tests for the external sandbox approval authority."""
import json
import uuid

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from stage2_sdk_ai import auth, sandbox_approval
from stage2_sdk_ai.api import app

REQUESTER_KEY = "sandbox-requester-secret"
APPROVER_KEY = "sandbox-approver-secret"
ISSUER = "github-practice-ai"
AUDIENCE = "second-brain"


def _key_pair():
    private = Ed25519PrivateKey.generate()
    private_pem = private.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode("ascii")
    public_pem = private.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    return private_pem, public_pem


def _configure_keys(monkeypatch, active_kid="key-1"):
    private_pem, public_pem = _key_pair()
    monkeypatch.setenv("SANDBOX_APPROVAL_ACTIVE_KID", active_kid)
    monkeypatch.setenv("SANDBOX_APPROVAL_SIGNING_PRIVATE_KEY", private_pem)
    monkeypatch.setenv(
        "SANDBOX_APPROVAL_VERIFY_KEYS",
        json.dumps({active_kid: public_pem}),
    )
    return private_pem, public_pem


@pytest.fixture
def authority(monkeypatch, tmp_path):
    monkeypatch.setenv("SANDBOX_APPROVALS_DIR", str(tmp_path / "sandbox-approvals"))
    monkeypatch.setenv("SANDBOX_APPROVAL_ISSUER", ISSUER)
    monkeypatch.setenv("SANDBOX_APPROVAL_AUDIENCE", AUDIENCE)
    monkeypatch.setenv("AGENT_API_KEYS", f"automation={REQUESTER_KEY}")
    monkeypatch.setenv("AGENT_APPROVER_KEYS", f"reviewer={APPROVER_KEY}")
    _configure_keys(monkeypatch)
    monkeypatch.setattr(auth, "check_rate_limit", lambda *_args, **_kwargs: True)
    return tmp_path


@pytest.fixture
def scope():
    return {
        "repository": "owner/second-brain",
        "sandbox_id": "sbx-0123456789abcdef",
        "base_sha": "a" * 40,
        "head_sha": "b" * 40,
        "diff_sha256": "c" * 64,
        "action": "prepare_pull_request",
    }


def _create(authority, scope, requester="automation"):
    return sandbox_approval.create_request(
        scope,
        requester=requester,
        issuer=ISSUER,
        audience=AUDIENCE,
    )


def _approve(created):
    return sandbox_approval.decide(
        created["approval_id"], approver_key=APPROVER_KEY, decision="approved"
    )


def test_signed_decision_is_bound_to_expected_issuer_audience_and_scope(
    authority, scope
):
    created = _create(authority, scope)
    result = _approve(created)
    receipt = result["receipt"]

    assert result["status"] == "approved"
    assert receipt["alg"] == "Ed25519"
    assert receipt["claims"]["scope"] == scope
    assert receipt["claims"]["requester"] == "automation"
    assert receipt["claims"]["approver"] == "reviewer"
    assert sandbox_approval.verify_receipt(
        receipt, expected_issuer=ISSUER, expected_audience=AUDIENCE
    )
    assert not sandbox_approval.verify_receipt(
        receipt, expected_issuer="another-authority", expected_audience=AUDIENCE
    )
    assert not sandbox_approval.verify_receipt(
        receipt, expected_issuer=ISSUER, expected_audience="another-client"
    )


def test_tampered_signed_decision_is_rejected(authority, scope):
    receipt = _approve(_create(authority, scope))["receipt"]
    tampered = json.loads(json.dumps(receipt))
    tampered["claims"]["scope"]["head_sha"] = "d" * 40

    assert not sandbox_approval.verify_receipt(
        tampered, expected_issuer=ISSUER, expected_audience=AUDIENCE
    )


def test_unknown_key_id_is_rejected(authority, scope):
    receipt = _approve(_create(authority, scope))["receipt"]
    receipt["kid"] = "unknown-key"

    assert not sandbox_approval.verify_receipt(
        receipt, expected_issuer=ISSUER, expected_audience=AUDIENCE
    )


def test_key_rotation_keeps_old_receipts_verifiable_during_overlap(
    authority, scope, monkeypatch
):
    receipt = _approve(_create(authority, scope))["receipt"]
    old_public = json.loads(
        __import__("os").environ["SANDBOX_APPROVAL_VERIFY_KEYS"]
    )["key-1"]
    new_private, new_public = _key_pair()
    monkeypatch.setenv("SANDBOX_APPROVAL_ACTIVE_KID", "key-2")
    monkeypatch.setenv("SANDBOX_APPROVAL_SIGNING_PRIVATE_KEY", new_private)
    monkeypatch.setenv(
        "SANDBOX_APPROVAL_VERIFY_KEYS",
        json.dumps({"key-1": old_public, "key-2": new_public}),
    )

    assert sandbox_approval.verify_receipt(
        receipt, expected_issuer=ISSUER, expected_audience=AUDIENCE
    )
    monkeypatch.setenv(
        "SANDBOX_APPROVAL_VERIFY_KEYS", json.dumps({"key-2": new_public})
    )
    assert not sandbox_approval.verify_receipt(
        receipt, expected_issuer=ISSUER, expected_audience=AUDIENCE
    )


def test_missing_or_mismatched_signing_configuration_fails_closed(
    authority, scope, monkeypatch
):
    monkeypatch.delenv("SANDBOX_APPROVAL_SIGNING_PRIVATE_KEY")
    with pytest.raises(sandbox_approval.SandboxApprovalConfigurationError):
        _create(authority, scope)

    private_pem, _ = _key_pair()
    monkeypatch.setenv("SANDBOX_APPROVAL_SIGNING_PRIVATE_KEY", private_pem)
    with pytest.raises(sandbox_approval.SandboxApprovalConfigurationError):
        _create(authority, scope)


def test_request_scope_rejects_extra_fields_and_wrong_action(authority, scope):
    extra = dict(scope, requester="agent")
    with pytest.raises(sandbox_approval.SandboxApprovalError):
        _create(authority, extra)
    wrong_action = dict(scope, action="merge")
    with pytest.raises(sandbox_approval.SandboxApprovalError):
        _create(authority, wrong_action)


def test_self_approval_and_duplicate_decision_are_rejected(
    authority, scope, monkeypatch
):
    created = _create(authority, scope)
    monkeypatch.setenv("AGENT_APPROVER_KEYS", "automation=self-approver-secret")
    with pytest.raises(sandbox_approval.SandboxApprovalForbidden):
        sandbox_approval.decide(
            created["approval_id"],
            approver_key="self-approver-secret",
            decision="approved",
        )
    monkeypatch.setenv("AGENT_APPROVER_KEYS", f"reviewer={APPROVER_KEY}")
    _approve(created)
    with pytest.raises(sandbox_approval.SandboxApprovalConflict):
        _approve(created)


def test_decision_service_rejects_asserted_identity_without_credential(
    authority, scope
):
    created = _create(authority, scope)
    with pytest.raises(sandbox_approval.SandboxApprovalForbidden):
        sandbox_approval.decide(
            created["approval_id"], approver_key="reviewer", decision="approved"
        )
    assert sandbox_approval.inspect(
        created["approval_id"], requester="automation"
    )["status"] == "pending"


def test_scope_mismatch_cannot_consume_approval(authority, scope):
    created = _create(authority, scope)
    nonce = _approve(created)["receipt"]["claims"]["nonce"]
    changed = dict(scope, head_sha="d" * 40)

    with pytest.raises(sandbox_approval.SandboxApprovalConflict):
        sandbox_approval.consume(
            created["approval_id"],
            requester="automation",
            request_id=str(uuid.uuid4()),
            nonce=nonce,
            scope=changed,
        )


def test_one_time_consumption_allows_only_identical_idempotent_retry(authority, scope):
    created = _create(authority, scope)
    nonce = _approve(created)["receipt"]["claims"]["nonce"]
    request_id = str(uuid.uuid4())
    first = sandbox_approval.consume(
        created["approval_id"],
        requester="automation",
        request_id=request_id,
        nonce=nonce,
        scope=scope,
    )
    retry = sandbox_approval.consume(
        created["approval_id"],
        requester="automation",
        request_id=request_id,
        nonce=nonce,
        scope=scope,
    )

    assert first == retry
    assert first["status"] == "consumed"
    with pytest.raises(sandbox_approval.SandboxApprovalConflict):
        sandbox_approval.consume(
            created["approval_id"],
            requester="automation",
            request_id=str(uuid.uuid4()),
            nonce=nonce,
            scope=scope,
        )


def test_same_idempotency_key_with_changed_scope_is_rejected(authority, scope):
    created = _create(authority, scope)
    nonce = _approve(created)["receipt"]["claims"]["nonce"]
    request_id = str(uuid.uuid4())
    sandbox_approval.consume(
        created["approval_id"],
        requester="automation",
        request_id=request_id,
        nonce=nonce,
        scope=scope,
    )
    changed = dict(scope, diff_sha256="e" * 64)

    with pytest.raises(sandbox_approval.SandboxApprovalConflict):
        sandbox_approval.consume(
            created["approval_id"],
            requester="automation",
            request_id=request_id,
            nonce=nonce,
            scope=changed,
        )


def test_consumption_state_survives_reopen_and_is_inspectable(authority, scope):
    created = _create(authority, scope)
    nonce = _approve(created)["receipt"]["claims"]["nonce"]
    request_id = str(uuid.uuid4())
    sandbox_approval.consume(
        created["approval_id"],
        requester="automation",
        request_id=request_id,
        nonce=nonce,
        scope=scope,
    )

    state = sandbox_approval.inspect(
        created["approval_id"], requester="automation"
    )
    assert state["status"] == "consumed"
    assert state["consumption"]["request_id"] == request_id
    assert state["consumption"]["outcome"]["status"] == "consumed"


def test_requester_cannot_inspect_another_principals_approval(authority, scope):
    created = _create(authority, scope)
    with pytest.raises(sandbox_approval.SandboxApprovalForbidden):
        sandbox_approval.inspect(created["approval_id"], requester="intruder")


def test_denial_is_terminal_and_never_produces_signed_approval(authority, scope):
    created = _create(authority, scope)
    result = sandbox_approval.decide(
        created["approval_id"], approver_key=APPROVER_KEY, decision="denied"
    )

    assert result["status"] == "denied"
    assert result["receipt"] is None
    with pytest.raises(sandbox_approval.SandboxApprovalConflict):
        sandbox_approval.get_decision(
            created["approval_id"], requester="automation"
        )


def test_http_api_authenticates_requester_and_approver(authority, scope):
    client = TestClient(app)
    body = {"scope": scope}
    denied = client.post("/v1/sandbox/approvals", json=body)
    assert denied.status_code == 401

    created = client.post(
        "/v1/sandbox/approvals",
        json=body,
        headers={"X-API-Key": "wrong"},
    )
    assert created.status_code == 401

    created = client.post(
        "/v1/sandbox/approvals",
        json=body,
        headers={"X-API-Key": REQUESTER_KEY},
    )
    assert created.status_code == 200
    approval_id = created.json()["approval_id"]

    unauthorized = client.post(
        f"/v1/sandbox/approvals/{approval_id}/approve",
        headers={"X-Approver-Key": "wrong"},
    )
    assert unauthorized.status_code == 403

    approved = client.post(
        f"/v1/sandbox/approvals/{approval_id}/approve",
        headers={"X-Approver-Key": APPROVER_KEY},
    )
    assert approved.status_code == 200
    receipt = client.get(
        f"/v1/sandbox/approvals/{approval_id}/decision",
        headers={"X-API-Key": REQUESTER_KEY},
    )
    assert receipt.status_code == 200
    assert receipt.json()["claims"]["scope"] == scope


def test_http_api_rejects_self_approval(authority, scope, monkeypatch):
    monkeypatch.setenv("AGENT_APPROVER_KEYS", f"automation={APPROVER_KEY}")
    client = TestClient(app)
    created = client.post(
        "/v1/sandbox/approvals",
        json={"scope": scope},
        headers={"X-API-Key": REQUESTER_KEY},
    )
    approval_id = created.json()["approval_id"]
    response = client.post(
        f"/v1/sandbox/approvals/{approval_id}/approve",
        headers={"X-Approver-Key": APPROVER_KEY},
    )
    assert response.status_code == 403


def test_http_consume_is_idempotent_and_scope_bound(authority, scope):
    client = TestClient(app)
    headers = {"X-API-Key": REQUESTER_KEY}
    created = client.post(
        "/v1/sandbox/approvals", json={"scope": scope}, headers=headers
    ).json()
    approval_id = created["approval_id"]
    assert client.post(
        f"/v1/sandbox/approvals/{approval_id}/approve",
        headers={"X-Approver-Key": APPROVER_KEY},
    ).status_code == 200
    decision = client.get(
        f"/v1/sandbox/approvals/{approval_id}/decision", headers=headers
    ).json()

    request_id = str(uuid.uuid4())
    payload = {
        "request_id": request_id,
        "nonce": decision["claims"]["nonce"],
        "scope": scope,
    }
    first = client.post(
        f"/v1/sandbox/approvals/{approval_id}/consume",
        json=payload,
        headers=headers,
    )
    retry = client.post(
        f"/v1/sandbox/approvals/{approval_id}/consume",
        json=payload,
        headers=headers,
    )
    assert first.status_code == 200
    assert retry.status_code == 200
    assert first.json() == retry.json()

    replay = client.post(
        f"/v1/sandbox/approvals/{approval_id}/consume",
        json={
            "request_id": str(uuid.uuid4()),
            "nonce": decision["claims"]["nonce"],
            "scope": scope,
        },
        headers=headers,
    )
    assert replay.status_code == 409


def test_concurrent_consumption_has_exactly_one_distinct_request_winner(
    authority, scope
):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier

    created = _create(authority, scope)
    nonce = _approve(created)["receipt"]["claims"]["nonce"]
    barrier = Barrier(2)

    def attempt(request_id):
        barrier.wait(timeout=5)
        try:
            return sandbox_approval.consume(
                created["approval_id"],
                requester="automation",
                request_id=request_id,
                nonce=nonce,
                scope=scope,
            )
        except sandbox_approval.SandboxApprovalConflict:
            return {"status": "replayed"}

    request_ids = [str(uuid.uuid4()), str(uuid.uuid4())]
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(attempt, request_ids))

    assert sorted(result["status"] for result in results) == [
        "consumed",
        "replayed",
    ]
    assert sandbox_approval.inspect(
        created["approval_id"], requester="automation"
    )["status"] == "consumed"


def test_wrong_nonce_cannot_consume_approval(authority, scope):
    created = _create(authority, scope)
    _approve(created)
    with pytest.raises(sandbox_approval.SandboxApprovalConflict):
        sandbox_approval.consume(
            created["approval_id"],
            requester="automation",
            request_id=str(uuid.uuid4()),
            nonce="f" * 64,
            scope=scope,
        )


def test_audit_chain_records_request_decision_and_consumption(authority, scope):
    created = _create(authority, scope)
    nonce = _approve(created)["receipt"]["claims"]["nonce"]
    sandbox_approval.consume(
        created["approval_id"],
        requester="automation",
        request_id=str(uuid.uuid4()),
        nonce=nonce,
        scope=scope,
    )

    result = sandbox_approval.verify_audit_log()
    assert result["valid"] is True
    assert result["events"] == 3


def test_corrupt_audit_history_blocks_inspection_and_new_requests(
    authority, scope
):
    created = _create(authority, scope)
    audit_path = authority / "sandbox-approvals" / "audit.jsonl"
    entries = audit_path.read_text(encoding="utf-8").splitlines()
    entry = json.loads(entries[0])
    entry["actor"] = "tampered"
    entries[0] = json.dumps(entry, sort_keys=True, separators=(",", ":"))
    audit_path.write_text("\n".join(entries) + "\n", encoding="utf-8")

    with pytest.raises(sandbox_approval.SandboxApprovalError):
        sandbox_approval.inspect(created["approval_id"], requester="automation")
    with pytest.raises(sandbox_approval.SandboxApprovalError):
        _create(authority, dict(scope, sandbox_id="another-sandbox"))


def test_legacy_unnamed_requester_key_cannot_create_sandbox_approval(
    authority, scope, monkeypatch
):
    monkeypatch.setenv("AGENT_API_KEYS", REQUESTER_KEY)
    client = TestClient(app)
    response = client.post(
        "/v1/sandbox/approvals",
        json={"scope": scope},
        headers={"X-API-Key": REQUESTER_KEY},
    )
    assert response.status_code == 401


def test_signed_receipt_expires(authority, scope):
    receipt = _approve(_create(authority, scope))["receipt"]
    assert not sandbox_approval.verify_receipt(
        receipt,
        expected_issuer=ISSUER,
        expected_audience=AUDIENCE,
        now=receipt["claims"]["exp"] + 1,
    )


def test_audit_failure_after_consumption_never_reopens_approval(
    authority, scope, monkeypatch
):
    created = _create(authority, scope)
    nonce = _approve(created)["receipt"]["claims"]["nonce"]
    request_id = str(uuid.uuid4())

    def fail_audit(*_args, **_kwargs):
        raise OSError("simulated audit fsync failure")

    monkeypatch.setattr(sandbox_approval, "_append_audit", fail_audit)
    with pytest.raises(OSError):
        sandbox_approval.consume(
            created["approval_id"],
            requester="automation",
            request_id=request_id,
            nonce=nonce,
            scope=scope,
        )

    state = sandbox_approval.inspect(
        created["approval_id"], requester="automation"
    )
    assert state["status"] == "consumed"
    assert state["audit_status"] == "failed"
    with pytest.raises(sandbox_approval.SandboxApprovalError):
        sandbox_approval.consume(
            created["approval_id"],
            requester="automation",
            request_id=request_id,
            nonce=nonce,
            scope=scope,
        )
    with pytest.raises(sandbox_approval.SandboxApprovalError):
        sandbox_approval.consume(
            created["approval_id"],
            requester="automation",
            request_id=str(uuid.uuid4()),
            nonce=nonce,
            scope=scope,
        )


def test_audit_history_prevents_replay_after_approval_record_rollback(
    authority, scope
):
    created = _create(authority, scope)
    nonce = _approve(created)["receipt"]["claims"]["nonce"]
    request_id = str(uuid.uuid4())
    original = sandbox_approval.consume(
        created["approval_id"],
        requester="automation",
        request_id=request_id,
        nonce=nonce,
        scope=scope,
    )

    record_path = (
        authority / "sandbox-approvals" / f"{created['approval_id']}.json"
    )
    record = json.loads(record_path.read_text(encoding="utf-8"))
    record["status"] = "approved"
    record["decision"] = "approved"
    record["audit_status"] = "written"
    record["consumption"] = None
    record_path.write_text(json.dumps(record), encoding="utf-8")

    recovered = sandbox_approval.consume(
        created["approval_id"],
        requester="automation",
        request_id=request_id,
        nonce=nonce,
        scope=scope,
    )
    assert recovered == original
    assert sandbox_approval.inspect(
        created["approval_id"], requester="automation"
    )["status"] == "consumed"

    with pytest.raises(sandbox_approval.SandboxApprovalConflict):
        sandbox_approval.consume(
            created["approval_id"],
            requester="automation",
            request_id=str(uuid.uuid4()),
            nonce=nonce,
            scope=scope,
        )


def test_audit_history_prevents_second_approval_after_record_rollback(
    authority, scope, monkeypatch
):
    created = _create(authority, scope)
    _approve(created)
    record_path = (
        authority / "sandbox-approvals" / f"{created['approval_id']}.json"
    )
    record = json.loads(record_path.read_text(encoding="utf-8"))
    record["status"] = "pending"
    record["decision"] = "pending"
    record["approver"] = None
    record["receipt"] = None
    record["audit_status"] = "written"
    record_path.write_text(json.dumps(record), encoding="utf-8")
    inspected = sandbox_approval.inspect(
        created["approval_id"], requester="automation"
    )
    assert inspected["status"] == "pending"
    assert [event["action"] for event in inspected["audit_history"]] == [
        "request_created", "approved"
    ]

    with pytest.raises(sandbox_approval.SandboxApprovalConflict):
        monkeypatch.setenv(
            "AGENT_APPROVER_KEYS",
            f"reviewer={APPROVER_KEY},second-reviewer=second-approver-secret",
        )
        sandbox_approval.decide(
            created["approval_id"],
            approver_key="second-approver-secret",
            decision="approved",
        )


def test_duplicate_generated_approval_id_does_not_overwrite_existing(
    authority, scope, monkeypatch
):
    first = _create(authority, scope)
    first_path = (
        authority / "sandbox-approvals" / f"{first['approval_id']}.json"
    )
    original = first_path.read_bytes()
    candidates = iter([first["approval_id"], "b" * 32])
    real_token_hex = sandbox_approval.secrets.token_hex

    def deterministic_token_hex(size):
        if size == 16:
            return next(candidates)
        return real_token_hex(size)

    monkeypatch.setattr(
        sandbox_approval.secrets, "token_hex", deterministic_token_hex
    )
    second = _create(authority, dict(scope, sandbox_id="other-sandbox"))

    assert second["approval_id"] == "b" * 32
    assert first_path.read_bytes() == original


def test_http_deny_is_terminal_and_has_no_decision_receipt(authority, scope):
    client = TestClient(app)
    headers = {"X-API-Key": REQUESTER_KEY}
    created = client.post(
        "/v1/sandbox/approvals", json={"scope": scope}, headers=headers
    ).json()
    approval_id = created["approval_id"]
    denied = client.post(
        f"/v1/sandbox/approvals/{approval_id}/deny",
        headers={"X-Approver-Key": APPROVER_KEY},
    )
    assert denied.status_code == 200
    assert denied.json()["status"] == "denied"
    evidence = client.get(
        f"/v1/sandbox/approvals/{approval_id}/decision", headers=headers
    )
    assert evidence.status_code == 409


def test_http_api_fails_closed_when_signing_configuration_is_missing(
    authority, scope, monkeypatch
):
    monkeypatch.delenv("SANDBOX_APPROVAL_SIGNING_PRIVATE_KEY")
    response = TestClient(app).post(
        "/v1/sandbox/approvals",
        json={"scope": scope},
        headers={"X-API-Key": REQUESTER_KEY},
    )
    assert response.status_code == 503


def test_http_api_applies_requester_rate_limit(authority, scope, monkeypatch):
    monkeypatch.setattr(auth, "check_rate_limit", lambda *_args, **_kwargs: False)
    response = TestClient(app).post(
        "/v1/sandbox/approvals",
        json={"scope": scope},
        headers={"X-API-Key": REQUESTER_KEY},
    )
    assert response.status_code == 429


def test_http_api_rejects_extra_scope_fields(authority, scope):
    invalid_scope = dict(scope, extra="not-allowed")
    response = TestClient(app).post(
        "/v1/sandbox/approvals",
        json={"scope": invalid_scope},
        headers={"X-API-Key": REQUESTER_KEY},
    )
    assert response.status_code == 422


def test_missing_crypto_library_disables_only_sandbox_authority(
    authority, scope, monkeypatch
):
    import builtins

    original_import = builtins.__import__

    def without_crypto(name, *args, **kwargs):
        if name == "cryptography" or name.startswith("cryptography."):
            raise ImportError("simulated missing optional signing dependency")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", without_crypto)
    with pytest.raises(sandbox_approval.SandboxApprovalConfigurationError):
        _create(authority, scope)
