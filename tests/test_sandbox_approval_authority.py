"""Security and recovery tests for the external sandbox approval authority."""
import base64
import errno
import hashlib
import io
import json
import os
import subprocess
import sys
import types
import uuid
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from stage2_sdk_ai import (
    audit_checkpoint_integrity,
    audit_checkpoint_store,
    auth,
    sandbox_approval,
)
from stage2_sdk_ai.api import app

REQUESTER_KEY = "sandbox-requester-secret-for-tests-00000000000000000001"
APPROVER_KEY = "sandbox-approver-secret-for-tests-00000000000000000002"
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
    store_dir = tmp_path / "sandbox-approvals"
    store_dir.mkdir(mode=0o700)
    os.chmod(store_dir, 0o700)
    audit_path = store_dir / "audit.jsonl"
    audit_path.touch(mode=0o600)
    os.chmod(audit_path, 0o600)
    monkeypatch.setenv("SANDBOX_APPROVALS_DIR", str(store_dir))
    monkeypatch.setenv("SANDBOX_APPROVAL_ISSUER", ISSUER)
    monkeypatch.setenv("SANDBOX_APPROVAL_AUDIENCE", AUDIENCE)
    monkeypatch.setenv("AGENT_API_KEYS", f"automation={REQUESTER_KEY}")
    monkeypatch.setenv("AGENT_APPROVER_KEYS", f"reviewer={APPROVER_KEY}")
    monkeypatch.setenv("AGENT_AUDIT_CHECKPOINT_S3_BUCKET", "synthetic-audit-bucket")
    monkeypatch.setenv(
        "AGENT_SANDBOX_AUDIT_CHECKPOINT_S3_KEY",
        "audit-checkpoints/sandbox/latest.json",
    )
    monkeypatch.setenv(
        "AGENT_SANDBOX_AUDIT_CHECKPOINT_FLOOR_S3_KEY",
        "audit-checkpoints/sandbox/trusted-floor.json",
    )
    monkeypatch.setenv("AGENT_SANDBOX_AUDIT_STORE_ID", "sandbox-contract-test-store")
    monkeypatch.setenv("AGENT_SANDBOX_AUDIT_CHECKPOINT_MAX_AGE_SECONDS", "86400")
    monkeypatch.setenv("AGENT_SANDBOX_AUDIT_MAX_UNANCHORED_SUFFIX", "1000")
    _configure_keys(monkeypatch)

    envelope = audit_checkpoint_integrity.create_checkpoint_envelope(
        audit_checkpoint_integrity.SANDBOX_AUTHORITY,
        "sandbox-contract-test-store",
    )
    candidate_key = "audit-checkpoints/sandbox/latest.json"
    candidate_version_id = "synthetic-candidate-version-1"
    floor_fields = {
        "authority", "store_id", "sequence", "head_hash",
        "legacy_entries", "created_at", "checkpoint_id",
    }
    floor = {key: envelope[key] for key in floor_fields}
    floor.update({
        "candidate_version_id": candidate_version_id,
        "candidate_checkpoint_id": envelope["checkpoint_id"],
        "candidate_sequence": envelope["sequence"],
        "candidate_head_hash": envelope["head_hash"],
        "candidate_created_at": envelope["created_at"],
    })

    class FakeS3:
        def __init__(self):
            self.objects = {
                candidate_key: json.dumps(envelope).encode("utf-8"),
                "audit-checkpoints/sandbox/trusted-floor.json": json.dumps(floor).encode("utf-8"),
            }
            candidate_payload = self.objects[candidate_key]
            self.version_ids = {candidate_key: candidate_version_id}
            self.version_objects = {
                candidate_key: {candidate_version_id: candidate_payload}
            }
            self.unavailable = False

        def get_object(self, *, Bucket, Key, VersionId=None):
            if self.unavailable or Bucket != "synthetic-audit-bucket" or Key not in self.objects:
                raise OSError("synthetic checkpoint store unavailable")
            if VersionId is not None:
                payload = self.version_objects.get(Key, {}).get(VersionId)
                if payload is None:
                    raise OSError("synthetic S3 object version is unavailable")
                actual_version = VersionId
            else:
                payload = self.objects[Key]
                actual_version = self.version_ids.get(Key)
            return {"Body": io.BytesIO(payload), "VersionId": actual_version}

    fake_s3 = FakeS3()
    monkeypatch.setitem(
        sys.modules, "boto3", types.SimpleNamespace(client=lambda *_args, **_kwargs: fake_s3)
    )
    monkeypatch.setattr(auth, "check_rate_limit", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(sandbox_approval, "_test_checkpoint_store", fake_s3, raising=False)
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



def test_sandbox_approval_credentials_require_named_minimum_length_principals(
    authority, monkeypatch
):
    monkeypatch.setenv("AGENT_API_KEYS", "automation=short-requester")
    monkeypatch.setenv("AGENT_APPROVER_KEYS", "reviewer=short-approver")
    assert auth.sandbox_requester_identity("short-requester") is None
    assert not auth.verify_sandbox_approver_key("short-approver")

    requester_secret = "r" * 40
    approver_secret = "a" * 40
    monkeypatch.setenv("AGENT_API_KEYS", f"automation={requester_secret}")
    monkeypatch.setenv("AGENT_APPROVER_KEYS", f"reviewer={approver_secret}")
    assert auth.sandbox_requester_identity(requester_secret) == "automation"
    assert auth.verify_sandbox_approver_key(approver_secret)
    assert auth.sandbox_approver_identity(approver_secret) == "reviewer"

    # A secret duplicated across roles disables both approval principals.
    monkeypatch.setenv("AGENT_APPROVER_KEYS", f"reviewer={requester_secret}")
    assert not auth.verify_api_key(requester_secret)
    assert not auth.verify_sandbox_approver_key(requester_secret)



def test_requester_and_approver_rotation_revokes_previous_credentials(
    authority, monkeypatch
):
    old_requester = REQUESTER_KEY
    old_approver = APPROVER_KEY
    new_requester = "new-requester-secret-for-rotation-tests-000000000001"
    new_approver = "new-approver-secret-for-rotation-tests-000000000002"

    monkeypatch.setenv("AGENT_API_KEYS", f"automation={old_requester}")
    monkeypatch.setenv("AGENT_APPROVER_KEYS", f"reviewer={old_approver}")
    assert auth.sandbox_requester_identity(old_requester) == "automation"
    assert auth.verify_sandbox_approver_key(old_approver)

    # The single-entry named configuration is a coordinated cutover: once the
    # replacement is active, the previous values no longer authenticate.
    monkeypatch.setenv("AGENT_API_KEYS", f"automation={new_requester}")
    monkeypatch.setenv("AGENT_APPROVER_KEYS", f"reviewer={new_approver}")
    assert auth.sandbox_requester_identity(old_requester) is None
    assert not auth.verify_api_key(old_requester)
    assert not auth.verify_sandbox_approver_key(old_approver)
    assert auth.sandbox_requester_identity(new_requester) == "automation"
    assert auth.verify_sandbox_approver_key(new_approver)


def test_request_record_reconciles_after_process_stops_after_audit_commit(
    authority, scope, monkeypatch
):
    append = sandbox_approval._append_audit

    def append_then_interrupt(*args, **kwargs):
        append(*args, **kwargs)
        raise SystemExit("simulated process termination after durable audit append")

    monkeypatch.setattr(sandbox_approval, "_append_audit", append_then_interrupt)
    with pytest.raises(SystemExit):
        _create(authority, scope)
    monkeypatch.setattr(sandbox_approval, "_append_audit", append)

    approval_id = next(
        path.stem for path in (authority / "sandbox-approvals").glob("*.json")
    )
    state = sandbox_approval.inspect(approval_id, requester="automation")
    assert state["status"] == "pending"
    assert state["audit_status"] == "written"
    assert [event["action"] for event in state["audit_history"]] == [
        "request_created"
    ]


def test_decision_record_reconciles_after_process_stops_after_audit_commit(
    authority, scope, monkeypatch
):
    created = _create(authority, scope)
    append = sandbox_approval._append_audit

    def append_then_interrupt(*args, **kwargs):
        append(*args, **kwargs)
        raise SystemExit("simulated process termination after durable audit append")

    monkeypatch.setattr(sandbox_approval, "_append_audit", append_then_interrupt)
    with pytest.raises(SystemExit):
        _approve(created)
    monkeypatch.setattr(sandbox_approval, "_append_audit", append)

    receipt = sandbox_approval.get_decision(
        created["approval_id"], requester="automation"
    )
    assert receipt["claims"]["decision"] == "approved"
    state = sandbox_approval.inspect(
        created["approval_id"], requester="automation"
    )
    assert state["status"] == "approved"
    assert state["audit_status"] == "written"


def test_consumption_retry_recovers_after_process_stops_after_audit_commit(
    authority, scope, monkeypatch
):
    created = _create(authority, scope)
    nonce = _approve(created)["receipt"]["claims"]["nonce"]
    request_id = str(uuid.uuid4())
    append = sandbox_approval._append_audit

    def append_then_interrupt(*args, **kwargs):
        append(*args, **kwargs)
        if args[1] == "consumed":
            raise SystemExit("simulated process termination after durable audit append")

    monkeypatch.setattr(sandbox_approval, "_append_audit", append_then_interrupt)
    with pytest.raises(SystemExit):
        sandbox_approval.consume(
            created["approval_id"],
            requester="automation",
            request_id=request_id,
            nonce=nonce,
            scope=scope,
        )
    monkeypatch.setattr(sandbox_approval, "_append_audit", append)

    outcome = sandbox_approval.consume(
        created["approval_id"],
        requester="automation",
        request_id=request_id,
        nonce=nonce,
        scope=scope,
    )
    assert outcome["status"] == "consumed"
    state = sandbox_approval.inspect(
        created["approval_id"], requester="automation"
    )
    assert state["status"] == "consumed"
    assert state["audit_status"] == "written"


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



def test_receipt_verification_rejects_validly_signed_self_approval(
    authority, scope
):
    receipt = _approve(_create(authority, scope))["receipt"]
    claims = dict(receipt["claims"])
    claims["approver"] = claims["requester"]
    private_key = serialization.load_pem_private_key(
        os.environ["SANDBOX_APPROVAL_SIGNING_PRIVATE_KEY"].encode("ascii"),
        password=None,
    )
    signature = private_key.sign(sandbox_approval._canonical(claims))
    self_approved = {
        **receipt,
        "claims": claims,
        "signature": base64.urlsafe_b64encode(signature)
        .decode("ascii")
        .rstrip("="),
    }
    assert not sandbox_approval.verify_receipt(
        self_approved,
        expected_issuer=ISSUER,
        expected_audience=AUDIENCE,
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



@pytest.mark.parametrize("transition", ["request", "decision", "consumption"])
def test_real_process_exit_after_audit_commit_recovers_exact_outcome(
    authority, scope, transition
):
    created = None if transition == "request" else _create(authority, scope)
    nonce = None
    request_id = None
    if transition == "consumption":
        nonce = _approve(created)["receipt"]["claims"]["nonce"]
        request_id = str(uuid.uuid4())

    script = r"""
import json
import os
import sys
from stage2_sdk_ai import sandbox_approval

# This subprocess test isolates process-crash recovery; the independent S3
# checkpoint gate is exercised by the parent-process integration tests.
sandbox_approval._verify_independent_audit_checkpoint = lambda **_kwargs: {}
real_append = sandbox_approval._append_audit

def append_then_exit(*args, **kwargs):
    real_append(*args, **kwargs)
    os._exit(86)

sandbox_approval._append_audit = append_then_exit
approval_id, transition = sys.argv[1], sys.argv[2]
if transition == "request":
    sandbox_approval.create_request(
        json.loads(os.environ["TEST_APPROVAL_SCOPE"]),
        requester="automation",
        issuer=os.environ["SANDBOX_APPROVAL_ISSUER"],
        audience=os.environ["SANDBOX_APPROVAL_AUDIENCE"],
    )
elif transition == "decision":
    sandbox_approval.decide(
        approval_id,
        approver_key=os.environ["TEST_APPROVER_KEY"],
        decision="approved",
    )
else:
    sandbox_approval.consume(
        approval_id,
        requester="automation",
        request_id=os.environ["TEST_REQUEST_ID"],
        nonce=os.environ["TEST_APPROVAL_NONCE"],
        scope=json.loads(os.environ["TEST_APPROVAL_SCOPE"]),
    )
"""
    env = os.environ.copy()
    env["TEST_APPROVER_KEY"] = APPROVER_KEY
    env["TEST_REQUEST_ID"] = request_id or ""
    env["TEST_APPROVAL_NONCE"] = nonce or ""
    env["TEST_APPROVAL_SCOPE"] = json.dumps(scope)
    approval_id = created["approval_id"] if created else "created-in-child"
    result = subprocess.run(
        [sys.executable, "-c", script, approval_id, transition],
        cwd=os.getcwd(),
        env=env,
        check=False,
        timeout=20,
    )
    assert result.returncode == 86

    if transition == "request":
        approval_files = list(
            (authority / "sandbox-approvals").glob("*.json")
        )
        assert len(approval_files) == 1
        approval_id = approval_files[0].stem
        state = sandbox_approval.inspect(
            approval_id, requester="automation"
        )
        assert state["status"] == "pending"
        assert state["audit_status"] == "written"
        assert [event["action"] for event in state["audit_history"]] == [
            "request_created"
        ]
    elif transition == "decision":
        receipt = sandbox_approval.get_decision(
            created["approval_id"], requester="automation"
        )
        assert receipt["claims"]["decision"] == "approved"
        state = sandbox_approval.inspect(
            created["approval_id"], requester="automation"
        )
        assert state["audit_status"] == "written"
        assert state["status"] == "approved"
    else:
        outcome = sandbox_approval.consume(
            created["approval_id"],
            requester="automation",
            request_id=request_id,
            nonce=nonce,
            scope=scope,
        )
        assert outcome["status"] == "consumed"
        state = sandbox_approval.inspect(
            created["approval_id"], requester="automation"
        )
        assert state["audit_status"] == "written"
        assert state["status"] == "consumed"


def test_audit_checkpoint_detects_rollback_to_an_earlier_valid_prefix(
    authority, scope
):
    created = _create(authority, scope)
    nonce = _approve(created)["receipt"]["claims"]["nonce"]
    sandbox_approval.consume(
        created["approval_id"],
        requester="automation",
        request_id=str(uuid.uuid4()),
        nonce=nonce,
        scope=scope,
    )
    audit_state = sandbox_approval.verify_audit_log()
    checkpoint = {
        "sequence": audit_state["events"],
        "head_hash": audit_state["last_hash"],
    }
    audit_path = authority / "sandbox-approvals" / "audit.jsonl"
    entries = audit_path.read_text(encoding="utf-8").splitlines()
    audit_path.write_text("\n".join(entries[:2]) + "\n", encoding="utf-8")

    with pytest.raises(
        sandbox_approval.SandboxApprovalError,
        match="truncated or diverges from checkpoint",
    ):
        sandbox_approval.verify_audit_log(expected_checkpoint=checkpoint)


def test_audit_incomplete_final_record_fails_closed(authority, scope):
    _create(authority, scope)
    audit_path = authority / "sandbox-approvals" / "audit.jsonl"
    with audit_path.open("a", encoding="utf-8") as handle:
        handle.write('{"partial":')
    with pytest.raises(
        sandbox_approval.SandboxApprovalError,
        match="incomplete final record",
    ):
        sandbox_approval.verify_audit_log()


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
            f"reviewer={APPROVER_KEY},"
            "second-reviewer=sandbox-second-approver-secret-for-tests-0000000000000003",
        )
        sandbox_approval.decide(
            created["approval_id"],
            approver_key="sandbox-second-approver-secret-for-tests-0000000000000003",
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



@pytest.mark.parametrize("decision", ["approve", "deny"])
def test_http_approver_rate_limit_blocks_both_decision_routes(
    authority, scope, monkeypatch, decision
):
    client = TestClient(app)
    created = client.post(
        "/v1/sandbox/approvals",
        json={"scope": scope},
        headers={"X-API-Key": REQUESTER_KEY},
    )
    assert created.status_code == 200
    approval_id = created.json()["approval_id"]
    monkeypatch.setattr(auth, "check_rate_limit", lambda *_args, **_kwargs: False)

    response = client.post(
        f"/v1/sandbox/approvals/{approval_id}/{decision}",
        headers={"X-Approver-Key": APPROVER_KEY},
    )

    assert response.status_code == 429
    assert sandbox_approval.inspect(
        approval_id, requester="automation"
    )["status"] == "pending"



def test_http_consume_rate_limit_blocks_before_authority_transition(
    authority, scope, monkeypatch
):
    client = TestClient(app)
    headers = {"X-API-Key": REQUESTER_KEY}
    created = client.post(
        "/v1/sandbox/approvals", json={"scope": scope}, headers=headers
    ).json()
    approval_id = created["approval_id"]
    approved = client.post(
        f"/v1/sandbox/approvals/{approval_id}/approve",
        headers={"X-Approver-Key": APPROVER_KEY},
    )
    assert approved.status_code == 200
    receipt = approved.json()["receipt"]
    monkeypatch.setattr(auth, "check_rate_limit", lambda *_args, **_kwargs: False)

    response = client.post(
        f"/v1/sandbox/approvals/{approval_id}/consume",
        json={
            "request_id": str(uuid.uuid4()),
            "nonce": receipt["claims"]["nonce"],
            "scope": scope,
        },
        headers=headers,
    )

    assert response.status_code == 429
    assert sandbox_approval.inspect(
        approval_id, requester="automation"
    )["status"] == "approved"



def test_http_read_and_consume_routes_enforce_requester_ownership(
    authority, scope, monkeypatch
):
    monkeypatch.setenv(
        "AGENT_API_KEYS",
        f"automation={REQUESTER_KEY},"
        "intruder=other-requester-secret-for-tests-00000000000000000003",
    )
    client = TestClient(app)
    owner_headers = {"X-API-Key": REQUESTER_KEY}
    intruder_headers = {"X-API-Key": "other-requester-secret-for-tests-00000000000000000003"}
    created = client.post(
        "/v1/sandbox/approvals",
        json={"scope": scope},
        headers=owner_headers,
    ).json()
    approval_id = created["approval_id"]
    approved = client.post(
        f"/v1/sandbox/approvals/{approval_id}/approve",
        headers={"X-Approver-Key": APPROVER_KEY},
    )
    assert approved.status_code == 200
    nonce = approved.json()["receipt"]["claims"]["nonce"]

    assert client.get(
        f"/v1/sandbox/approvals/{approval_id}", headers=intruder_headers
    ).status_code == 403
    assert client.get(
        f"/v1/sandbox/approvals/{approval_id}/decision",
        headers=intruder_headers,
    ).status_code == 403
    denied_consume = client.post(
        f"/v1/sandbox/approvals/{approval_id}/consume",
        json={
            "request_id": str(uuid.uuid4()),
            "nonce": nonce,
            "scope": scope,
        },
        headers=intruder_headers,
    )
    assert denied_consume.status_code == 403
    assert sandbox_approval.inspect(
        approval_id, requester="automation"
    )["status"] == "approved"



@pytest.mark.parametrize("decision", ["approve", "deny"])
def test_http_decision_audit_failure_never_returns_success(
    authority, scope, monkeypatch, decision
):
    client = TestClient(app)
    created = client.post(
        "/v1/sandbox/approvals",
        json={"scope": scope},
        headers={"X-API-Key": REQUESTER_KEY},
    ).json()
    approval_id = created["approval_id"]

    def fail_audit(*_args, **_kwargs):
        raise OSError("simulated decision audit failure")

    monkeypatch.setattr(sandbox_approval, "_append_audit", fail_audit)
    response = client.post(
        f"/v1/sandbox/approvals/{approval_id}/{decision}",
        headers={"X-Approver-Key": APPROVER_KEY},
    )

    assert response.status_code == 503
    state = sandbox_approval.inspect(approval_id, requester="automation")
    expected_status = "approved" if decision == "approve" else "denied"
    assert state["status"] == expected_status
    assert state["audit_status"] == "failed"
    assert client.get(
        f"/v1/sandbox/approvals/{approval_id}/decision",
        headers={"X-API-Key": REQUESTER_KEY},
    ).status_code == 409



def test_http_consume_audit_failure_is_operator_review_not_success(
    authority, scope, monkeypatch
):
    client = TestClient(app)
    headers = {"X-API-Key": REQUESTER_KEY}
    created = client.post(
        "/v1/sandbox/approvals", json={"scope": scope}, headers=headers
    ).json()
    approval_id = created["approval_id"]
    approved = client.post(
        f"/v1/sandbox/approvals/{approval_id}/approve",
        headers={"X-Approver-Key": APPROVER_KEY},
    )
    nonce = approved.json()["receipt"]["claims"]["nonce"]

    def fail_audit(*_args, **_kwargs):
        raise OSError("simulated consumption audit failure")

    monkeypatch.setattr(sandbox_approval, "_append_audit", fail_audit)
    response = client.post(
        f"/v1/sandbox/approvals/{approval_id}/consume",
        json={
            "request_id": str(uuid.uuid4()),
            "nonce": nonce,
            "scope": scope,
        },
        headers=headers,
    )

    assert response.status_code == 503
    state = sandbox_approval.inspect(approval_id, requester="automation")
    assert state["status"] == "consumed"
    assert state["audit_status"] == "failed"
    assert client.post(
        f"/v1/sandbox/approvals/{approval_id}/consume",
        json={
            "request_id": str(uuid.uuid4()),
            "nonce": nonce,
            "scope": scope,
        },
        headers=headers,
    ).status_code == 503


def test_http_state_changing_routes_reject_wrong_credential_role(authority, scope):
    client = TestClient(app)
    wrong_create = client.post(
        "/v1/sandbox/approvals",
        json={"scope": scope},
        headers={"X-Approver-Key": APPROVER_KEY},
    )
    assert wrong_create.status_code == 401

    created = client.post(
        "/v1/sandbox/approvals",
        json={"scope": scope},
        headers={"X-API-Key": REQUESTER_KEY},
    ).json()
    approval_id = created["approval_id"]
    requester_headers = {"X-API-Key": REQUESTER_KEY}

    for decision in ("approve", "deny"):
        response = client.post(
            f"/v1/sandbox/approvals/{approval_id}/{decision}",
            headers=requester_headers,
        )
        assert response.status_code == 403

    approved = client.post(
        f"/v1/sandbox/approvals/{approval_id}/approve",
        headers={"X-Approver-Key": APPROVER_KEY},
    )
    assert approved.status_code == 200
    wrong_consume = client.post(
        f"/v1/sandbox/approvals/{approval_id}/consume",
        json={
            "request_id": str(uuid.uuid4()),
            "nonce": approved.json()["receipt"]["claims"]["nonce"],
            "scope": scope,
        },
        headers={"X-Approver-Key": APPROVER_KEY},
    )
    assert wrong_consume.status_code == 401
    assert sandbox_approval.inspect(
        approval_id, requester="automation"
    )["status"] == "approved"


def test_http_create_audit_failure_returns_operator_review_not_success(
    authority, scope, monkeypatch
):
    client = TestClient(app)

    def fail_audit(*_args, **_kwargs):
        raise OSError("simulated request audit failure")

    monkeypatch.setattr(sandbox_approval, "_append_audit", fail_audit)
    response = client.post(
        "/v1/sandbox/approvals",
        json={"scope": scope},
        headers={"X-API-Key": REQUESTER_KEY},
    )

    assert response.status_code == 503
    assert "approval_id" not in response.json()
    record_path = next((authority / "sandbox-approvals").glob("*.json"))
    record = json.loads(record_path.read_text(encoding="utf-8"))
    assert record["status"] == "pending"
    assert record["audit_status"] == "failed"
    approval_attempt = client.post(
        f"/v1/sandbox/approvals/{record['approval_id']}/approve",
        headers={"X-Approver-Key": APPROVER_KEY},
    )
    assert approval_attempt.status_code == 503


def test_identical_consumption_retry_recovers_after_receipt_expiry(
    authority, scope, monkeypatch
):
    created = _create(authority, scope)
    receipt = _approve(created)["receipt"]
    nonce = receipt["claims"]["nonce"]
    expires_at = receipt["claims"]["exp"]
    request_id = str(uuid.uuid4())

    original = sandbox_approval.consume(
        created["approval_id"],
        requester="automation",
        request_id=request_id,
        nonce=nonce,
        scope=scope,
        now=expires_at - 1,
    )

    # Simulate a process interruption after the durable audit append but
    # before the final approval-record save.
    record_path = (
        authority / "sandbox-approvals" / f"{created['approval_id']}.json"
    )
    record = json.loads(record_path.read_text(encoding="utf-8"))
    record["status"] = "approved"
    record["decision"] = "approved"
    record["audit_status"] = "written"
    record["consumption"] = None
    record_path.write_text(json.dumps(record), encoding="utf-8")

    # The receipt is now expired. Recovery must verify it at the durable
    # consumption event timestamp, without making it valid for a new consume.
    monkeypatch.setattr(sandbox_approval.time, "time", lambda: expires_at + 1)
    assert not sandbox_approval.verify_receipt(
        receipt,
        expected_issuer=ISSUER,
        expected_audience=AUDIENCE,
    )

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

def test_consumption_recovery_rejects_reversed_audit_event_order(
    authority, scope, monkeypatch
):
    created = _create(authority, scope)
    receipt = _approve(created)["receipt"]
    nonce = receipt["claims"]["nonce"]
    expires_at = receipt["claims"]["exp"]
    request_id = str(uuid.uuid4())

    sandbox_approval.consume(
        created["approval_id"],
        requester="automation",
        request_id=request_id,
        nonce=nonce,
        scope=scope,
        now=expires_at - 1,
    )

    # Keep a valid global hash chain, but append the consumed event before
    # the approved event. Their timestamps remain in the original valid order.
    audit_path = authority / "sandbox-approvals" / "audit.jsonl"
    original_events = [
        json.loads(line)
        for line in audit_path.read_text(encoding="utf-8").splitlines()
    ]
    assert [event["action"] for event in original_events] == [
        "request_created", "approved", "consumed"
    ]
    reordered_events = [
        original_events[0], original_events[2], original_events[1]
    ]

    previous_hash = "0" * 64
    rebuilt_events = []
    for sequence, original_event in enumerate(reordered_events, start=1):
        event = dict(original_event)
        event.pop("hash")
        event["seq"] = sequence
        event["previous_hash"] = previous_hash
        digest = hashlib.sha256(sandbox_approval._canonical(event)).hexdigest()
        event["hash"] = digest
        rebuilt_events.append(event)
        previous_hash = digest

    audit_path.write_text(
        "".join(
            json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n"
            for event in rebuilt_events
        ),
        encoding="utf-8",
    )
    assert sandbox_approval.verify_audit_log()["valid"] is True

    # Simulate the interrupted final record save after the consumption append.
    record_path = (
        authority / "sandbox-approvals" / f"{created['approval_id']}.json"
    )
    record = json.loads(record_path.read_text(encoding="utf-8"))
    record["status"] = "approved"
    record["decision"] = "approved"
    record["audit_status"] = "written"
    record["consumption"] = None
    record_path.write_text(json.dumps(record), encoding="utf-8")

    monkeypatch.setattr(sandbox_approval.time, "time", lambda: expires_at + 1)
    with pytest.raises(
        sandbox_approval.SandboxApprovalError,
        match="decision must precede consumption",
    ):
        sandbox_approval.consume(
            created["approval_id"],
            requester="automation",
            request_id=request_id,
            nonce=nonce,
            scope=scope,
        )


@pytest.mark.parametrize("conflicting_action", ["denied", "expired"])
def test_consumption_recovery_rejects_conflicting_terminal_decision_event(
    authority, scope, monkeypatch, conflicting_action
):
    created = _create(authority, scope)
    receipt = _approve(created)["receipt"]
    nonce = receipt["claims"]["nonce"]
    expires_at = receipt["claims"]["exp"]
    request_id = str(uuid.uuid4())

    sandbox_approval.consume(
        created["approval_id"],
        requester="automation",
        request_id=request_id,
        nonce=nonce,
        scope=scope,
        now=expires_at - 1,
    )

    # Insert a conflicting terminal decision while preserving a valid global
    # sequence and hash chain. Recovery must validate the complete lifecycle,
    # not merely find one approved event among the terminal decisions.
    audit_path = authority / "sandbox-approvals" / "audit.jsonl"
    original_events = [
        json.loads(line)
        for line in audit_path.read_text(encoding="utf-8").splitlines()
    ]
    assert [event["action"] for event in original_events] == [
        "request_created", "approved", "consumed"
    ]
    conflicting_event = dict(original_events[1])
    conflicting_event["action"] = conflicting_action
    conflicting_event["details"] = {}
    reordered_events = [
        original_events[0],
        original_events[1],
        conflicting_event,
        original_events[2],
    ]

    previous_hash = "0" * 64
    rebuilt_events = []
    for sequence, original_event in enumerate(reordered_events, start=1):
        event = dict(original_event)
        event.pop("hash")
        event["seq"] = sequence
        event["previous_hash"] = previous_hash
        digest = hashlib.sha256(sandbox_approval._canonical(event)).hexdigest()
        event["hash"] = digest
        rebuilt_events.append(event)
        previous_hash = digest

    audit_path.write_text(
        "".join(
            json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n"
            for event in rebuilt_events
        ),
        encoding="utf-8",
    )
    assert sandbox_approval.verify_audit_log()["valid"] is True

    # Simulate the interrupted final record save after the consumption append.
    record_path = (
        authority / "sandbox-approvals" / f"{created['approval_id']}.json"
    )
    record = json.loads(record_path.read_text(encoding="utf-8"))
    record["status"] = "approved"
    record["decision"] = "approved"
    record["audit_status"] = "written"
    record["consumption"] = None
    record_path.write_text(json.dumps(record), encoding="utf-8")

    monkeypatch.setattr(sandbox_approval.time, "time", lambda: expires_at + 1)
    with pytest.raises(
        sandbox_approval.SandboxApprovalError,
        match="terminal decision history is ambiguous",
    ):
        sandbox_approval.consume(
            created["approval_id"],
            requester="automation",
            request_id=request_id,
            nonce=nonce,
            scope=scope,
        )

def test_sandbox_approval_fails_closed_when_independent_checkpoint_is_unavailable(
    authority, scope
):
    sandbox_approval._test_checkpoint_store.unavailable = True
    with pytest.raises(sandbox_approval.SandboxApprovalError, match="Independent sandbox audit"):
        _create(authority, scope)


def test_sandbox_approval_rejects_full_audit_rollback_behind_operator_checkpoint(
    authority, scope
):
    created = _create(authority, scope)
    checkpoint = audit_checkpoint_store.create_sandbox_audit_checkpoint(
        "sandbox-contract-test-store"
    )
    fake_s3 = sandbox_approval._test_checkpoint_store
    candidate_key = "audit-checkpoints/sandbox/latest.json"
    candidate_version_id = "synthetic-candidate-version-2"
    floor_fields = {
        "authority", "store_id", "sequence", "head_hash",
        "legacy_entries", "created_at", "checkpoint_id",
    }
    floor = {key: checkpoint[key] for key in floor_fields}
    floor.update({
        "candidate_version_id": candidate_version_id,
        "candidate_checkpoint_id": checkpoint["checkpoint_id"],
        "candidate_sequence": checkpoint["sequence"],
        "candidate_head_hash": checkpoint["head_hash"],
        "candidate_created_at": checkpoint["created_at"],
    })
    candidate_payload = json.dumps(checkpoint).encode("utf-8")
    fake_s3.objects[candidate_key] = candidate_payload
    fake_s3.version_ids[candidate_key] = candidate_version_id
    fake_s3.version_objects[candidate_key][candidate_version_id] = candidate_payload
    fake_s3.objects["audit-checkpoints/sandbox/trusted-floor.json"] = json.dumps(
        floor
    ).encode("utf-8")

    audit_path = authority / "sandbox-approvals" / "audit.jsonl"
    audit_path.write_bytes(b"")
    os.chmod(audit_path, 0o600)

    with pytest.raises(
        sandbox_approval.SandboxApprovalError,
        match="Independent sandbox audit checkpoint verification failed",
    ):
        sandbox_approval.inspect(created["approval_id"], requester="automation")



def test_sandbox_checkpoint_reads_exact_operator_pinned_s3_version(
    authority, scope
):
    created = _create(authority, scope)
    fake_s3 = sandbox_approval._test_checkpoint_store
    candidate_key = "audit-checkpoints/sandbox/latest.json"
    pinned_version = fake_s3.version_ids[candidate_key]

    # Simulate the mutable latest key being pointed at an older version.
    # The operator-pinned immutable version remains retrievable by VersionId.
    fake_s3.objects[candidate_key] = b'{"sequence":0,"head_hash":"'
    fake_s3.objects[candidate_key] += b'0' * 64 + b'"}'
    fake_s3.version_ids[candidate_key] = "synthetic-older-current-version"

    inspected = sandbox_approval.inspect(
        created["approval_id"], requester="automation"
    )
    assert inspected["approval_id"] == created["approval_id"]
    assert fake_s3.version_objects[candidate_key][pinned_version]


def test_sandbox_checkpoint_fails_closed_when_pinned_s3_version_is_missing(
    authority, scope
):
    _create(authority, scope)
    fake_s3 = sandbox_approval._test_checkpoint_store
    candidate_key = "audit-checkpoints/sandbox/latest.json"
    fake_s3.version_objects[candidate_key].clear()

    with pytest.raises(
        sandbox_approval.SandboxApprovalError,
        match="Independent sandbox audit checkpoint verification failed",
    ):
        _create(authority, scope)

def test_sandbox_approval_requires_explicit_checkpoint_policy(authority, scope, monkeypatch):
    monkeypatch.delenv("AGENT_SANDBOX_AUDIT_CHECKPOINT_MAX_AGE_SECONDS")
    with pytest.raises(sandbox_approval.SandboxApprovalError, match="Independent sandbox audit"):
        _create(authority, scope)


def test_legacy_approval_identity_labels_keep_existing_parser_compatibility(
    authority, monkeypatch
):
    requester_secret = "legacy-requester-secret"
    approver_secret = "legacy-approver-secret"
    for identity in ("team reviewer", "-owner", "team/reviewer", "x" * 129):
        monkeypatch.setenv("AGENT_API_KEYS", f"{identity}={requester_secret}")
        monkeypatch.setenv("AGENT_APPROVER_KEYS", f"{identity}={approver_secret}")
        assert auth._configured_approval_requester_keys() == [(identity, requester_secret)]
        assert auth._configured_approver_keys() == [(identity, approver_secret)]
        assert auth._configured_sandbox_requester_keys() == []
        assert auth._configured_sandbox_approver_keys() == []


def test_checkpoint_suffix_limit_is_enforced_across_concurrent_creates(
    authority, scope, monkeypatch
):
    monkeypatch.setenv("AGENT_SANDBOX_AUDIT_MAX_UNANCHORED_SUFFIX", "2")
    def create_one(index):
        try:
            return _create(authority, dict(scope, sandbox_id=f"sbx-{index:016x}"))
        except sandbox_approval.SandboxApprovalError as exc:
            return exc
    with ThreadPoolExecutor(max_workers=12) as executor:
        outcomes = list(executor.map(create_one, range(12)))
    created = [item for item in outcomes if isinstance(item, dict)]
    rejected = [
        item
        for item in outcomes
        if isinstance(item, sandbox_approval.SandboxApprovalError)
    ]
    assert len(created) == 2
    assert len(rejected) == 10
    assert sandbox_approval.verify_audit_log()["events"] == 2
    assert all(
        sandbox_approval._load(item["approval_id"])["audit_status"] == "written"
        for item in created
    )
    # Read-only inspection remains available at the cap; mutations reserve one
    # additional audit event and are blocked until the operator advances a checkpoint.
    assert (
        sandbox_approval.inspect(created[0]["approval_id"], requester="automation")[
            "status"
        ]
        == "pending"
    )


@pytest.mark.parametrize(
    "operation", ["create", "approve", "deny", "inspect", "decision", "consume"]
)
def test_http_lifecycle_routes_fail_closed_without_checkpoint_and_do_not_transition(
    authority, scope, operation
):
    client = TestClient(app)
    requester_headers = {"X-API-Key": REQUESTER_KEY}
    approver_headers = {"X-Approver-Key": APPROVER_KEY}
    fake_s3 = sandbox_approval._test_checkpoint_store
    if operation == "create":
        fake_s3.unavailable = True
        response = client.post(
            "/v1/sandbox/approvals",
            json={"scope": scope},
            headers=requester_headers,
        )
        assert response.status_code == 503
        assert list((authority / "sandbox-approvals").glob("*.json")) == []
        assert sandbox_approval.verify_audit_log()["events"] == 0
        return
    created_response = client.post(
        "/v1/sandbox/approvals",
        json={"scope": scope},
        headers=requester_headers,
    )
    assert created_response.status_code == 200
    approval_id = created_response.json()["approval_id"]
    if operation in {"approve", "deny"}:
        fake_s3.unavailable = True
        response = client.post(
            f"/v1/sandbox/approvals/{approval_id}/{operation}",
            headers=approver_headers,
        )
        expected_status, expected_events = "pending", 1
    else:
        approved = client.post(
            f"/v1/sandbox/approvals/{approval_id}/approve",
            headers=approver_headers,
        )
        assert approved.status_code == 200
        receipt = approved.json()["receipt"]
        fake_s3.unavailable = True
        expected_status, expected_events = "approved", 2
        if operation == "inspect":
            response = client.get(
                f"/v1/sandbox/approvals/{approval_id}",
                headers=requester_headers,
            )
        elif operation == "decision":
            response = client.get(
                f"/v1/sandbox/approvals/{approval_id}/decision",
                headers=requester_headers,
            )
        else:
            response = client.post(
                f"/v1/sandbox/approvals/{approval_id}/consume",
                json={
                    "request_id": str(uuid.uuid4()),
                    "nonce": receipt["claims"]["nonce"],
                    "scope": scope,
                },
                headers=requester_headers,
            )
    assert response.status_code == 503
    record = sandbox_approval._load(approval_id)
    assert record["status"] == expected_status
    assert record["audit_status"] == "written"
    assert sandbox_approval.verify_audit_log()["events"] == expected_events


def test_checkpoint_is_rechecked_after_per_approval_lock_is_acquired(
    authority, scope, monkeypatch
):
    created = _create(authority, scope)
    original_locked = sandbox_approval._locked
    fake_s3 = sandbox_approval._test_checkpoint_store
    @contextmanager
    def unavailable_after_lock(path):
        with original_locked(path):
            fake_s3.unavailable = True
            yield
    monkeypatch.setattr(sandbox_approval, "_locked", unavailable_after_lock)
    with pytest.raises(
        sandbox_approval.SandboxApprovalError,
        match="Independent sandbox audit checkpoint verification failed",
    ):
        _approve(created)
    record = sandbox_approval._load(created["approval_id"])
    assert record["status"] == "pending"
    assert record["audit_status"] == "written"
    assert sandbox_approval.verify_audit_log()["events"] == 1


def _is_audit_file_descriptor(fd, audit_path):
    try:
        return os.fstat(fd).st_ino == audit_path.stat().st_ino
    except OSError:
        return False


def test_audit_fsync_failure_remains_operator_review_state(authority, scope, monkeypatch):
    audit_path = authority / "sandbox-approvals" / "audit.jsonl"
    real_fsync = os.fsync
    def fail_audit_fsync(fd):
        if _is_audit_file_descriptor(fd, audit_path):
            raise OSError(errno.EIO, "simulated audit fsync failure")
        return real_fsync(fd)
    monkeypatch.setattr(sandbox_approval.os, "fsync", fail_audit_fsync)
    with pytest.raises(OSError, match="simulated audit fsync failure"):
        _create(authority, scope)
    monkeypatch.setattr(sandbox_approval.os, "fsync", real_fsync)
    approval_id = next(path.stem for path in (authority / "sandbox-approvals").glob("*.json"))
    record = sandbox_approval._load(approval_id)
    assert record["status"] == "pending"
    assert record["audit_status"] == "failed"
    assert sandbox_approval.verify_audit_log()["events"] == 1
    with pytest.raises(sandbox_approval.SandboxApprovalError, match="Request audit is incomplete"):
        sandbox_approval.decide(approval_id, approver_key=APPROVER_KEY, decision="approved")


def test_audit_enospc_before_append_remains_operator_review_state(authority, scope, monkeypatch):
    audit_path = authority / "sandbox-approvals" / "audit.jsonl"
    real_write = os.write
    def fail_audit_write(fd, data):
        if _is_audit_file_descriptor(fd, audit_path):
            raise OSError(errno.ENOSPC, "simulated audit disk full")
        return real_write(fd, data)
    monkeypatch.setattr(sandbox_approval.os, "write", fail_audit_write)
    with pytest.raises(OSError, match="simulated audit disk full"):
        _create(authority, scope)
    monkeypatch.setattr(sandbox_approval.os, "write", real_write)
    approval_id = next(path.stem for path in (authority / "sandbox-approvals").glob("*.json"))
    record = sandbox_approval._load(approval_id)
    assert record["audit_status"] == "failed"
    assert sandbox_approval.verify_audit_log()["events"] == 0
    with pytest.raises(sandbox_approval.SandboxApprovalError, match="Request audit is incomplete"):
        sandbox_approval.decide(approval_id, approver_key=APPROVER_KEY, decision="approved")


def test_torn_audit_append_is_detected_and_never_reconciled(authority, scope, monkeypatch):
    audit_path = authority / "sandbox-approvals" / "audit.jsonl"
    real_write = os.write
    interrupted = False
    def write_half_then_enospc(fd, data):
        nonlocal interrupted
        if _is_audit_file_descriptor(fd, audit_path) and not interrupted:
            interrupted = True
            real_write(fd, data[: max(1, len(data) // 2)])
            raise OSError(errno.ENOSPC, "simulated disk full during audit append")
        return real_write(fd, data)
    monkeypatch.setattr(sandbox_approval.os, "write", write_half_then_enospc)
    with pytest.raises(OSError, match="simulated disk full during audit append"):
        _create(authority, scope)
    monkeypatch.setattr(sandbox_approval.os, "write", real_write)
    approval_id = next(path.stem for path in (authority / "sandbox-approvals").glob("*.json"))
    record = sandbox_approval._load(approval_id)
    assert record["audit_status"] == "failed"
    with pytest.raises(sandbox_approval.SandboxApprovalError, match="incomplete final record"):
        sandbox_approval.verify_audit_log()
    with pytest.raises(sandbox_approval.SandboxApprovalError):
        sandbox_approval.inspect(approval_id, requester="automation")


@pytest.mark.parametrize("transition", ["request", "decision", "consumption"])
def test_process_exit_before_audit_append_never_reconciles_unproven_state(
    authority, scope, transition
):
    created = None if transition == "request" else _create(authority, scope)
    nonce = None
    request_id = None
    if transition == "consumption":
        nonce = _approve(created)["receipt"]["claims"]["nonce"]
        request_id = str(uuid.uuid4())

    script = r"""
import json
import os
import sys
from stage2_sdk_ai import sandbox_approval

sandbox_approval._verify_independent_audit_checkpoint = lambda **_kwargs: {}
sandbox_approval._append_audit = lambda *_args, **_kwargs: os._exit(87)
approval_id, transition = sys.argv[1], sys.argv[2]
scope = json.loads(os.environ["TEST_APPROVAL_SCOPE"])
if transition == "request":
    sandbox_approval.create_request(
        scope,
        requester="automation",
        issuer=os.environ["SANDBOX_APPROVAL_ISSUER"],
        audience=os.environ["SANDBOX_APPROVAL_AUDIENCE"],
    )
elif transition == "decision":
    sandbox_approval.decide(
        approval_id,
        approver_key=os.environ["TEST_APPROVER_KEY"],
        decision="approved",
    )
else:
    sandbox_approval.consume(
        approval_id,
        requester="automation",
        request_id=os.environ["TEST_REQUEST_ID"],
        nonce=os.environ["TEST_APPROVAL_NONCE"],
        scope=scope,
    )
"""
    env = os.environ.copy()
    env["TEST_APPROVER_KEY"] = APPROVER_KEY
    env["TEST_REQUEST_ID"] = request_id or ""
    env["TEST_APPROVAL_NONCE"] = nonce or ""
    env["TEST_APPROVAL_SCOPE"] = json.dumps(scope)
    approval_id = created["approval_id"] if created else "created-in-child"
    result = subprocess.run(
        [sys.executable, "-c", script, approval_id, transition],
        cwd=os.getcwd(),
        env=env,
        check=False,
        timeout=20,
    )
    assert result.returncode == 87

    if transition == "request":
        approval_files = list(
            (authority / "sandbox-approvals").glob("*.json")
        )
        assert len(approval_files) == 1
        approval_id = approval_files[0].stem
        expected_status = "pending"
        expected_events = 0
    elif transition == "decision":
        expected_status = "approved"
        expected_events = 1
    else:
        expected_status = "consumed"
        expected_events = 2

    record = sandbox_approval._load(approval_id)
    assert record["status"] == expected_status
    assert record["audit_status"] == "pending"
    reconciled = sandbox_approval._reconcile_pending_audit(approval_id, record)
    assert reconciled["status"] == expected_status
    assert reconciled["audit_status"] == "pending"
    assert sandbox_approval.verify_audit_log()["events"] == expected_events


def test_decision_reserves_suffix_capacity_before_changing_record(
    authority, scope, monkeypatch
):
    monkeypatch.setenv("AGENT_SANDBOX_AUDIT_MAX_UNANCHORED_SUFFIX", "1")
    created = _create(authority, scope)
    with pytest.raises(
        sandbox_approval.SandboxApprovalError,
        match="Independent sandbox audit checkpoint verification failed",
    ):
        _approve(created)
    record = sandbox_approval._load(created["approval_id"])
    assert record["status"] == "pending"
    assert record["audit_status"] == "written"
    assert sandbox_approval.verify_audit_log()["events"] == 1


def test_consumption_reserves_suffix_capacity_before_changing_record(
    authority, scope, monkeypatch
):
    monkeypatch.setenv("AGENT_SANDBOX_AUDIT_MAX_UNANCHORED_SUFFIX", "2")
    created = _create(authority, scope)
    nonce = _approve(created)["receipt"]["claims"]["nonce"]
    with pytest.raises(
        sandbox_approval.SandboxApprovalError,
        match="Independent sandbox audit checkpoint verification failed",
    ):
        sandbox_approval.consume(
            created["approval_id"],
            requester="automation",
            request_id=str(uuid.uuid4()),
            nonce=nonce,
            scope=scope,
        )
    record = sandbox_approval._load(created["approval_id"])
    assert record["status"] == "approved"
    assert record["audit_status"] == "written"
    assert sandbox_approval.verify_audit_log()["events"] == 2


def test_consumption_idempotent_retry_succeeds_at_suffix_cap(
    authority, scope, monkeypatch
):
    monkeypatch.setenv("AGENT_SANDBOX_AUDIT_MAX_UNANCHORED_SUFFIX", "3")
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
    assert sandbox_approval.verify_audit_log()["events"] == 3
    retried = sandbox_approval.consume(
        created["approval_id"],
        requester="automation",
        request_id=request_id,
        nonce=nonce,
        scope=scope,
    )
    assert retried == original
    assert sandbox_approval.verify_audit_log()["events"] == 3


def test_create_checkpoint_loss_after_record_lock_leaves_no_empty_record(
    authority, scope, monkeypatch
):
    original_locked = sandbox_approval._locked
    fake_s3 = sandbox_approval._test_checkpoint_store

    @contextmanager
    def unavailable_after_lock(path):
        with original_locked(path):
            fake_s3.unavailable = True
            yield

    monkeypatch.setattr(sandbox_approval, "_locked", unavailable_after_lock)
    with pytest.raises(
        sandbox_approval.SandboxApprovalError,
        match="Independent sandbox audit checkpoint verification failed",
    ):
        _create(authority, scope)
    assert list((authority / "sandbox-approvals").glob("*.json")) == []
    assert sandbox_approval.verify_audit_log()["events"] == 0
