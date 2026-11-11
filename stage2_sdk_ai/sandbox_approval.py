"""External sandbox approval authority with signed, one-time decisions.

This store is deliberately separate from the legacy note-write approval workflow.
It is a single-host file-backed authority and must not be shared over NFS or
across service instances with independent local disks.
"""
from __future__ import annotations

import base64
import fcntl
import hashlib
import json
import math
import os
import re
import secrets
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any
from uuid import UUID

from . import auth
from .secure_storage import (
    ensure_private_directory,
    fsync_directory,
    open_private_file,
    write_text_atomically,
)

APPROVAL_TTL_SECONDS = 15 * 60
MAX_CLOCK_SKEW_SECONDS = 60
MAX_AUDIT_BYTES = 64 * 1024 * 1024
_ID_RE = re.compile(r"^[0-9a-f]{32}$")
_NONCE_RE = re.compile(r"^[0-9a-f]{64}$")
_SHA_RE = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_KID_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
_SANDBOX_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
_REPO_RE = re.compile(r"^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$")
_ACTION = "prepare_pull_request"


class SandboxApprovalError(RuntimeError):
    """A sandbox approval operation failed closed."""


class SandboxApprovalNotFound(SandboxApprovalError):
    pass


class SandboxApprovalConflict(SandboxApprovalError):
    pass


class SandboxApprovalForbidden(SandboxApprovalConflict):
    pass


class SandboxApprovalConfigurationError(SandboxApprovalError):
    pass


def _verify_independent_audit_checkpoint() -> dict[str, Any]:
    """Fail closed unless the sandbox audit matches independently retained custody."""
    from .audit_checkpoint_store import (
        AuditCheckpointStoreError,
        verify_sandbox_audit_log_from_s3,
    )

    try:
        return verify_sandbox_audit_log_from_s3()
    except AuditCheckpointStoreError as exc:
        raise SandboxApprovalError(
            "Independent sandbox audit checkpoint verification failed; "
            "approval operations are paused for operator review"
        ) from exc



def _canonical(value: dict[str, Any]) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError) as exc:
        raise SandboxApprovalError("Approval data is not canonical JSON") from exc


def _store_dir() -> Path:
    configured = os.getenv("SANDBOX_APPROVALS_DIR", "").strip()
    if not configured or not os.path.isabs(configured):
        raise SandboxApprovalConfigurationError(
            "SANDBOX_APPROVALS_DIR must be an absolute private persistent path"
        )
    return Path(configured)


def _ensure_store() -> Path:
    directory = _store_dir()
    ensure_private_directory(directory)
    return directory


def _record_path(approval_id: str) -> Path:
    if not isinstance(approval_id, str) or not _ID_RE.fullmatch(approval_id):
        raise SandboxApprovalError("Invalid approval ID")
    return _store_dir() / (approval_id + ".json")


@contextmanager
def _locked(path: Path):
    directory = _ensure_store()
    lock_path = directory / (path.stem + ".lock")
    fd = open_private_file(lock_path, os.O_RDWR | os.O_CREAT)
    with os.fdopen(fd, "r+") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def _read_private_text(path: Path) -> str:
    fd = open_private_file(path, os.O_RDONLY, expected_mode=0o600)
    with os.fdopen(fd, "r", encoding="utf-8") as handle:
        return handle.read()


def _load(approval_id: str) -> dict[str, Any]:
    path = _record_path(approval_id)
    try:
        record = json.loads(_read_private_text(path))
    except FileNotFoundError as exc:
        raise SandboxApprovalNotFound("Approval not found") from exc
    except (OSError, ValueError, TypeError) as exc:
        raise SandboxApprovalError("Approval record requires operator review") from exc
    if not isinstance(record, dict) or record.get("approval_id") != approval_id:
        raise SandboxApprovalError("Approval record integrity check failed")
    return record


def _save(approval_id: str, record: dict[str, Any]) -> None:
    write_text_atomically(
        _record_path(approval_id),
        json.dumps(record, sort_keys=True, indent=2),
        _store_dir(),
    )


def _key_configuration() -> tuple[str, Any]:
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    except ImportError as exc:
        raise SandboxApprovalConfigurationError(
            "cryptography is required for sandbox approval signing"
        ) from exc
    kid = os.getenv("SANDBOX_APPROVAL_ACTIVE_KID", "").strip()
    pem = os.getenv("SANDBOX_APPROVAL_SIGNING_PRIVATE_KEY", "")
    if not _KID_RE.fullmatch(kid) or not pem:
        raise SandboxApprovalConfigurationError(
            "Sandbox approval signing configuration is unavailable"
        )
    try:
        key = serialization.load_pem_private_key(pem.encode("ascii"), password=None)
    except (ValueError, TypeError, UnicodeEncodeError) as exc:
        raise SandboxApprovalConfigurationError(
            "Sandbox approval signing key is invalid"
        ) from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise SandboxApprovalConfigurationError("Only Ed25519 signing keys are supported")
    return kid, key


def _verification_keys() -> dict[str, Any]:
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError as exc:
        raise SandboxApprovalConfigurationError(
            "cryptography is required for sandbox approval verification"
        ) from exc
    raw = os.getenv("SANDBOX_APPROVAL_VERIFY_KEYS", "")
    if not raw:
        raise SandboxApprovalConfigurationError(
            "Sandbox approval verification keys are unavailable"
        )
    try:
        configured = json.loads(raw)
        if not isinstance(configured, dict) or not configured:
            raise ValueError("empty key set")
        result: dict[str, Ed25519PublicKey] = {}
        for kid, pem in configured.items():
            if not isinstance(kid, str) or not _KID_RE.fullmatch(kid):
                raise ValueError("invalid key ID")
            if not isinstance(pem, str) or not pem:
                raise ValueError("invalid public key")
            key = serialization.load_pem_public_key(pem.encode("ascii"))
            if not isinstance(key, Ed25519PublicKey):
                raise ValueError("unsupported public key")
            result[kid] = key
        return result
    except (ValueError, TypeError, UnicodeEncodeError) as exc:
        raise SandboxApprovalConfigurationError(
            "Sandbox approval verification key set is invalid"
        ) from exc


def _validate_signing_configuration() -> None:
    try:
        from cryptography.hazmat.primitives import serialization
    except ImportError as exc:
        raise SandboxApprovalConfigurationError(
            "cryptography is required for sandbox approval signing"
        ) from exc
    kid, private_key = _key_configuration()
    trusted = _verification_keys().get(kid)
    if trusted is None:
        raise SandboxApprovalConfigurationError(
            "Active signing key is absent from the trusted verification key set"
        )
    active_public = private_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    trusted_public = trusted.public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    if not secrets.compare_digest(active_public, trusted_public):
        raise SandboxApprovalConfigurationError(
            "Active signing key does not match its trusted public key"
        )


def _read_audit_entries() -> list[dict[str, Any]]:
    audit_path = _store_dir() / "audit.jsonl"
    try:
        existing = _read_private_text(audit_path)
    except FileNotFoundError:
        return []
    if len(existing.encode("utf-8")) > MAX_AUDIT_BYTES:
        raise SandboxApprovalError("Sandbox approval audit exceeds its validation limit")
    if existing and not existing.endswith("\n"):
        raise SandboxApprovalError(
            "Sandbox approval audit has an incomplete final record"
        )
    previous_hash = "0" * 64
    entries: list[dict[str, Any]] = []
    for line_number, line in enumerate(existing.splitlines(), start=1):
        try:
            entry = json.loads(line)
            if not isinstance(entry, dict):
                raise ValueError("invalid event object")
            digest = entry.pop("hash")
            if (
                isinstance(entry.get("seq"), bool)
                or entry.get("seq") != len(entries) + 1
                or entry.get("previous_hash") != previous_hash
                or not isinstance(digest, str)
                or not secrets.compare_digest(
                    digest, hashlib.sha256(_canonical(entry)).hexdigest()
                )
            ):
                raise ValueError("invalid event chain")
            entry["hash"] = digest
            entries.append(entry)
            previous_hash = digest
        except (ValueError, TypeError, KeyError, AttributeError) as exc:
            raise SandboxApprovalError(
                f"Sandbox approval audit history is corrupt at line {line_number}"
            ) from exc
    return entries


def _read_audit_state() -> tuple[int, str]:
    entries = _read_audit_entries()
    return (
        len(entries),
        entries[-1]["hash"] if entries else "0" * 64,
    )


def _events_for(approval_id: str) -> list[dict[str, Any]]:
    directory = _ensure_store()
    lock_path = directory / ".audit.lock"
    fd = open_private_file(lock_path, os.O_RDWR | os.O_CREAT)
    with os.fdopen(fd, "r+") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_SH)
        try:
            return [
                entry
                for entry in _read_audit_entries()
                if entry.get("approval_id") == approval_id
            ]
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def _reconcile_pending_audit(
    approval_id: str, record: dict[str, Any]
) -> dict[str, Any]:
    """Complete a record marker only when the durable audit proves the transition.

    The audit append is the commit evidence. A restart may observe the event
    after the process stopped before saving audit_status="written". Reconcile
    only an exact, complete lifecycle; missing, conflicting, or corrupt evidence
    remains fail-closed for operator review.
    """
    # Explicit write failures remain operator-review states. Only a process
    # interruption that left the marker pending may be reconciled from a
    # complete durable event; a caught fsync/write error is never auto-cleared.
    if record.get("audit_status") != "pending":
        return record

    events = _events_for(approval_id)
    if not events:
        return record

    scope_hash = hashlib.sha256(_canonical(record["scope"])).hexdigest()
    if (
        events[0].get("action") != "request_created"
        or events[0].get("actor") != record.get("requester")
        or events[0].get("details")
        != {
            "nonce": record.get("nonce"),
            "created_at": record.get("created_at"),
            "expires_at": record.get("expires_at"),
            "issuer": record.get("issuer"),
            "audience": record.get("audience"),
        }
        or any(event.get("scope_sha256") != scope_hash for event in events)
    ):
        return record

    status = record.get("status")
    actions = [event.get("action") for event in events]
    if status == "pending":
        valid = actions == ["request_created"]
    elif status in {"approved", "denied", "expired"}:
        valid = actions == ["request_created", status]
        if valid:
            event = events[1]
            if status == "expired":
                valid = (
                    event.get("actor") == "system"
                    and isinstance(event.get("time"), (int, float))
                    and event.get("time") >= record.get("expires_at", float("inf"))
                )
            else:
                valid = event.get("actor") == record.get("approver")
            if status in {"approved", "denied"}:
                event_time = event.get("time")
                created_at = record.get("created_at")
                expires_at = record.get("expires_at")
                valid = (
                    valid
                    and isinstance(event_time, (int, float))
                    and math.isfinite(event_time)
                    and isinstance(created_at, (int, float))
                    and math.isfinite(created_at)
                    and isinstance(expires_at, (int, float))
                    and math.isfinite(expires_at)
                    and created_at <= event_time < expires_at
                )
            if status == "approved":
                valid = valid and event.get("details", {}).get(
                    "receipt"
                ) == record.get("receipt") and _receipt_matches_record(
                    record, now=event.get("time")
                )
            elif status == "denied":
                valid = valid and record.get("receipt") is None
    elif status == "consumed":
        valid = actions == ["request_created", "approved", "consumed"]
        if valid:
            decision_event, consumed_event = events[1], events[2]
            consumption = record.get("consumption") or {}
            details = consumed_event.get("details", {})
            decision_time = decision_event.get("time")
            consumed_time = consumed_event.get("time")
            created_at = record.get("created_at")
            expires_at = record.get("expires_at")
            expected_outcome = {
                "approval_id": approval_id,
                "status": "consumed",
                "request_id": consumption.get("request_id"),
                "payload_sha256": consumption.get("payload_sha256"),
            }
            valid = (
                decision_event.get("actor") == record.get("approver")
                and decision_event.get("details", {}).get("receipt")
                == record.get("receipt")
                and consumed_event.get("actor") == record.get("requester")
                and details.get("request_id") == consumption.get("request_id")
                and details.get("payload_sha256")
                == consumption.get("payload_sha256")
                and details.get("outcome") == expected_outcome
                and consumption.get("outcome") == expected_outcome
                and consumed_time == consumption.get("consumed_at")
                and isinstance(decision_time, (int, float))
                and math.isfinite(decision_time)
                and isinstance(consumed_time, (int, float))
                and math.isfinite(consumed_time)
                and isinstance(created_at, (int, float))
                and math.isfinite(created_at)
                and isinstance(expires_at, (int, float))
                and math.isfinite(expires_at)
                and created_at <= decision_time <= consumed_time < expires_at
                and decision_event.get("seq") < consumed_event.get("seq")
                and _receipt_matches_record(record, now=consumed_time)
            )
    else:
        valid = False

    if valid:
        record["audit_status"] = "written"
        _save(approval_id, record)
    return record


def verify_audit_log(
    expected_checkpoint: dict[str, Any] | None = None,
    *,
    expected_checkpoints: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Verify the complete local sandbox chain and an optional prefix anchor."""
    directory = _ensure_store()
    lock_path = directory / ".audit.lock"
    fd = open_private_file(lock_path, os.O_RDWR | os.O_CREAT)
    with os.fdopen(fd, "r+") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_SH)
        try:
            entries = _read_audit_entries()
            sequence = len(entries)
            last_hash = entries[-1]["hash"] if entries else "0" * 64
            result = {"valid": True, "events": sequence, "last_hash": last_hash}
            checkpoints = []
            if expected_checkpoint is not None:
                checkpoints.append(expected_checkpoint)
            if expected_checkpoints is not None:
                if not isinstance(expected_checkpoints, list):
                    raise SandboxApprovalError(
                        "Sandbox audit checkpoints must be supplied as a list"
                    )
                checkpoints.extend(expected_checkpoints)
            for index, checkpoint in enumerate(checkpoints):
                if (
                    not isinstance(checkpoint, dict)
                    or set(checkpoint) != {"sequence", "head_hash"}
                    or isinstance(checkpoint.get("sequence"), bool)
                    or not isinstance(checkpoint.get("sequence"), int)
                    or checkpoint["sequence"] < 0
                    or not isinstance(checkpoint.get("head_hash"), str)
                    or not _DIGEST_RE.fullmatch(checkpoint["head_hash"])
                ):
                    raise SandboxApprovalError("Sandbox audit checkpoint is malformed")
                checkpoint_sequence = checkpoint["sequence"]
                checkpoint_hash = (
                    "0" * 64
                    if checkpoint_sequence == 0
                    else (
                        entries[checkpoint_sequence - 1]["hash"]
                        if checkpoint_sequence <= sequence
                        else None
                    )
                )
                if (
                    checkpoint_sequence > sequence
                    or checkpoint_hash is None
                    or not secrets.compare_digest(
                        checkpoint_hash, checkpoint["head_hash"]
                    )
                ):
                    raise SandboxApprovalError(
                        "Sandbox audit history is truncated or diverges from checkpoint"
                    )
                if index == 0:
                    result["checkpoint_verified"] = True
                    result["checkpoint_sequence"] = checkpoint_sequence
            if checkpoints:
                result["checkpoints_verified"] = len(checkpoints)
            return result
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def _append_audit(
    approval_id: str,
    action: str,
    actor: str,
    scope: dict[str, Any],
    timestamp: float,
    details: dict[str, Any] | None = None,
) -> None:
    """Append and fsync a hash-chained event; refuse to extend corrupt history."""
    directory = _ensure_store()
    audit_path = directory / "audit.jsonl"
    lock_path = directory / ".audit.lock"
    lock_fd = open_private_file(lock_path, os.O_RDWR | os.O_CREAT)
    with os.fdopen(lock_fd, "r+") as lock_handle:
        fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX)
        try:
            sequence, previous_hash = _read_audit_state()
            event = {
                "seq": sequence + 1,
                "previous_hash": previous_hash,
                "action": action,
                "approval_id": approval_id,
                "actor": actor,
                "time": timestamp,
                "scope_sha256": hashlib.sha256(_canonical(scope)).hexdigest(),
                "details": details or {},
            }
            entry = dict(event)
            entry["hash"] = hashlib.sha256(_canonical(event)).hexdigest()
            encoded = (
                json.dumps(entry, sort_keys=True, separators=(",", ":")) + "\n"
            ).encode("ascii")
            created = False
            try:
                fd = open_private_file(audit_path, os.O_WRONLY | os.O_APPEND)
            except FileNotFoundError:
                fd = open_private_file(
                    audit_path,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_APPEND,
                )
                created = True
            with os.fdopen(fd, "ab") as audit_handle:
                view = memoryview(encoded)
                while view:
                    written = os.write(audit_handle.fileno(), view)
                    if written <= 0:
                        raise OSError("sandbox audit append made no progress")
                    view = view[written:]
                os.fsync(audit_handle.fileno())
            if created:
                fsync_directory(directory)
        finally:
            fcntl.flock(lock_handle.fileno(), fcntl.LOCK_UN)


def _validate_scope(scope: dict[str, Any]) -> dict[str, str]:
    if not isinstance(scope, dict):
        raise SandboxApprovalError("Approval scope must be an object")
    required = {
        "repository",
        "sandbox_id",
        "base_sha",
        "head_sha",
        "diff_sha256",
        "action",
    }
    if set(scope) != required:
        raise SandboxApprovalError("Approval scope has missing or unexpected fields")
    normalized = {key: scope[key] for key in required}
    if not isinstance(normalized["repository"], str) or not _REPO_RE.fullmatch(
        normalized["repository"]
    ):
        raise SandboxApprovalError("Invalid repository identity")
    if not isinstance(normalized["sandbox_id"], str) or not _SANDBOX_RE.fullmatch(
        normalized["sandbox_id"]
    ):
        raise SandboxApprovalError("Invalid sandbox ID")
    if any(
        not isinstance(normalized[field], str) or not _SHA_RE.fullmatch(normalized[field])
        for field in ("base_sha", "head_sha")
    ):
        raise SandboxApprovalError("Invalid base or head commit SHA")
    if normalized["base_sha"] == normalized["head_sha"]:
        raise SandboxApprovalError("Sandbox proposal must identify a changed head")
    if not isinstance(normalized["diff_sha256"], str) or not _DIGEST_RE.fullmatch(
        normalized["diff_sha256"]
    ):
        raise SandboxApprovalError("Invalid change-set digest")
    if normalized["action"] != _ACTION:
        raise SandboxApprovalError("Unsupported approval action")
    return normalized


def _claims(record: dict[str, Any]) -> dict[str, Any]:
    return {
        "iss": record["issuer"],
        "aud": record["audience"],
        "approval_id": record["approval_id"],
        "nonce": record["nonce"],
        "requester": record["requester"],
        "approver": record["approver"],
        "scope": record["scope"],
        "iat": record["created_at"],
        "exp": record["expires_at"],
        "decision": record["decision"],
    }


def _signed_receipt(record: dict[str, Any]) -> dict[str, Any]:
    _validate_signing_configuration()
    kid, private_key = _key_configuration()
    claims = _claims(record)
    signature = private_key.sign(_canonical(claims))
    return {
        "alg": "Ed25519",
        "kid": kid,
        "claims": claims,
        "signature": base64.urlsafe_b64encode(signature).decode("ascii").rstrip("="),
    }


def verify_receipt(
    receipt: dict[str, Any],
    *,
    expected_issuer: str,
    expected_audience: str,
    now: float | None = None,
) -> bool:
    """Verify signature, trust identity, audience, action and expiry."""
    try:
        from cryptography.exceptions import InvalidSignature
    except ImportError:
        return False
    if not isinstance(receipt, dict) or set(receipt) != {
        "alg",
        "kid",
        "claims",
        "signature",
    }:
        return False
    if receipt.get("alg") != "Ed25519" or not isinstance(receipt.get("claims"), dict):
        return False
    try:
        key = _verification_keys().get(receipt["kid"])
        if key is None:
            return False
        claims = receipt["claims"]
        required = {
            "iss",
            "aud",
            "approval_id",
            "nonce",
            "requester",
            "approver",
            "scope",
            "iat",
            "exp",
            "decision",
        }
        if set(claims) != required:
            return False
        if claims["iss"] != expected_issuer or claims["aud"] != expected_audience:
            return False
        if (
            claims["decision"] != "approved"
            or not isinstance(claims["scope"], dict)
            or _validate_scope(claims["scope"]) != claims["scope"]
            or not isinstance(claims["requester"], str)
            or not claims["requester"].strip()
            or not isinstance(claims["approver"], str)
            or not claims["approver"].strip()
            or claims["requester"] == claims["approver"]
            or not _ID_RE.fullmatch(claims["approval_id"])
            or not _NONCE_RE.fullmatch(claims["nonce"])
        ):
            return False
        current = time.time() if now is None else now
        if (
            isinstance(claims["iat"], bool)
            or not isinstance(claims["iat"], (int, float))
            or isinstance(claims["exp"], bool)
            or not isinstance(claims["exp"], (int, float))
            or claims["iat"] > current + MAX_CLOCK_SKEW_SECONDS
            or claims["exp"] <= current
            or claims["exp"] <= claims["iat"]
            or claims["exp"] - claims["iat"] > APPROVAL_TTL_SECONDS
        ):
            return False
        if not isinstance(receipt["signature"], str):
            return False
        encoded = receipt["signature"]
        signature = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
        key.verify(signature, _canonical(claims))
        return True
    except (
        SandboxApprovalError,
        InvalidSignature,
        ValueError,
        TypeError,
        KeyError,
        AttributeError,
    ):
        return False


def _receipt_matches_record(
    record: dict[str, Any], *, now: float | None = None
) -> bool:
    """Verify a stored receipt, optionally at its authoritative event time."""
    receipt = record.get("receipt")
    if not isinstance(receipt, dict):
        return False
    if not verify_receipt(
        receipt,
        expected_issuer=record.get("issuer", ""),
        expected_audience=record.get("audience", ""),
        now=now,
    ):
        return False
    return receipt.get("claims") == _claims(record)


def create_request(
    scope: dict[str, Any],
    *,
    requester: str,
    issuer: str,
    audience: str,
    now: float | None = None,
) -> dict[str, Any]:
    """Create an immutable pending request for an authenticated requester."""
    if not isinstance(requester, str) or not requester.strip() or len(requester) > 128:
        raise SandboxApprovalError("Invalid requester identity")
    if not isinstance(issuer, str) or not issuer or len(issuer) > 255:
        raise SandboxApprovalConfigurationError("Invalid authority issuer")
    if not isinstance(audience, str) or not audience or len(audience) > 255:
        raise SandboxApprovalConfigurationError("Invalid approval audience")
    validated_scope = _validate_scope(scope)
    _validate_signing_configuration()
    _verify_independent_audit_checkpoint()
    _ensure_store()
    created = time.time() if now is None else now
    approval_id = None
    for _ in range(8):
        candidate = secrets.token_hex(16)
        try:
            fd = open_private_file(
                _record_path(candidate), os.O_WRONLY | os.O_CREAT | os.O_EXCL
            )
        except FileExistsError:
            continue
        os.close(fd)
        approval_id = candidate
        break
    if approval_id is None:
        raise SandboxApprovalError("Could not reserve a unique approval ID")
    record = {
        "approval_id": approval_id,
        "issuer": issuer,
        "audience": audience,
        "nonce": secrets.token_hex(32),
        "requester": requester,
        "scope": validated_scope,
        "status": "pending",
        "decision": "pending",
        "approver": None,
        "created_at": created,
        "expires_at": created + APPROVAL_TTL_SECONDS,
        "receipt": None,
        "consumption": None,
        "audit_status": "pending",
    }
    with _locked(_record_path(approval_id)):
        _save(approval_id, record)
        try:
            _append_audit(
                approval_id,
                "request_created",
                requester,
                validated_scope,
                created,
                details={
                    "nonce": record["nonce"],
                    "created_at": record["created_at"],
                    "expires_at": record["expires_at"],
                    "issuer": issuer,
                    "audience": audience,
                },
            )
        except Exception:
            record["audit_status"] = "failed"
            try:
                _save(approval_id, record)
            except Exception:
                pass
            raise
        record["audit_status"] = "written"
        _save(approval_id, record)
    return {
        "approval_id": approval_id,
        "status": "pending",
        "scope": validated_scope,
        "expires_at": record["expires_at"],
    }


def decide(
    approval_id: str,
    *,
    approver_key: str,
    decision: str,
    now: float | None = None,
) -> dict[str, Any]:
    """Record one decision after independently authenticating the approver."""
    if not auth.verify_sandbox_approver_key(approver_key):
        raise SandboxApprovalForbidden("Configured approver credentials are required")
    try:
        approver = auth.sandbox_approver_identity(approver_key)
    except ValueError as exc:
        raise SandboxApprovalForbidden(
            "Configured approver identity is unavailable"
        ) from exc
    if decision not in {"approved", "denied"}:
        raise SandboxApprovalError("Invalid decision")
    _verify_independent_audit_checkpoint()
    path = _record_path(approval_id)
    with _locked(path):
        record = _reconcile_pending_audit(
            approval_id, _load(approval_id)
        )
        current = time.time() if now is None else now
        if record.get("audit_status") != "written":
            raise SandboxApprovalError("Request audit is incomplete; operator review required")
        events = _events_for(approval_id)
        expected_scope_hash = hashlib.sha256(_canonical(record["scope"])).hexdigest()
        if (
            not events
            or events[0].get("action") != "request_created"
            or events[0].get("actor") != record["requester"]
            or events[0].get("details")
            != {
                "nonce": record.get("nonce"),
                "created_at": record.get("created_at"),
                "expires_at": record.get("expires_at"),
                "issuer": record.get("issuer"),
                "audience": record.get("audience"),
            }
            or events[0].get("scope_sha256") != expected_scope_hash
            or any(event.get("scope_sha256") != expected_scope_hash for event in events)
        ):
            raise SandboxApprovalError("Approval request history requires operator review")
        if any(
            event.get("action") in {"approved", "denied", "expired", "consumed"}
            for event in events
        ):
            raise SandboxApprovalConflict("Audit history records a prior terminal decision")
        if record["status"] != "pending":
            raise SandboxApprovalConflict("Approval decision is already terminal")
        if (
            record["created_at"] > current + MAX_CLOCK_SKEW_SECONDS
            or record["expires_at"] <= current
        ):
            record["status"] = "expired"
            record["decision"] = "expired"
            record["audit_status"] = "pending"
            _save(approval_id, record)
            _append_audit(approval_id, "expired", "system", record["scope"], current)
            record["audit_status"] = "written"
            _save(approval_id, record)
            raise SandboxApprovalConflict("Approval request expired")
        if approver == record["requester"]:
            raise SandboxApprovalForbidden("Self-approval is forbidden")
        record["approver"] = approver
        record["decision"] = decision
        record["status"] = decision
        record["audit_status"] = "pending"
        if decision == "approved":
            record["receipt"] = _signed_receipt(record)
        _save(approval_id, record)
        try:
            _append_audit(
                approval_id,
                decision,
                approver,
                record["scope"],
                current,
                details={"receipt": record["receipt"]},
            )
        except Exception:
            record["audit_status"] = "failed"
            try:
                _save(approval_id, record)
            except Exception:
                pass
            raise
        record["audit_status"] = "written"
        _save(approval_id, record)
        return {
            "approval_id": approval_id,
            "status": record["status"],
            "decision": decision,
            "receipt": record["receipt"],
        }


def get_decision(approval_id: str, *, requester: str) -> dict[str, Any]:
    _verify_independent_audit_checkpoint()
    with _locked(_record_path(approval_id)):
        record = _reconcile_pending_audit(
            approval_id, _load(approval_id)
        )
    if record.get("requester") != requester:
        raise SandboxApprovalForbidden("Approval belongs to another requester")
    if (
        record.get("status") not in {"approved", "consumed"}
        or record.get("audit_status") != "written"
        or not record.get("receipt")
    ):
        raise SandboxApprovalConflict("No approved decision evidence is available")
    verify_audit_log()
    if not _receipt_matches_record(record):
        raise SandboxApprovalError("Signed decision evidence does not match its record")
    return record["receipt"]


def inspect(approval_id: str, *, requester: str) -> dict[str, Any]:
    _verify_independent_audit_checkpoint()
    with _locked(_record_path(approval_id)):
        record = _reconcile_pending_audit(
            approval_id, _load(approval_id)
        )
    if record.get("requester") != requester:
        raise SandboxApprovalForbidden("Approval belongs to another requester")
    events = _events_for(approval_id)
    return {
        "approval_id": approval_id,
        "status": record["status"],
        "decision": record["decision"],
        "audit_status": record.get("audit_status"),
        "scope": record["scope"],
        "created_at": record["created_at"],
        "expires_at": record["expires_at"],
        "consumption": record.get("consumption"),
        "audit_history": [
            {"action": event["action"], "actor": event["actor"], "time": event["time"]}
            for event in events
        ],
    }


def consume(
    approval_id: str,
    *,
    requester: str,
    request_id: str,
    nonce: str,
    scope: dict[str, Any],
    now: float | None = None,
) -> dict[str, Any]:
    """Consume once; only identical UUID, nonce and scope retries are idempotent."""
    try:
        normalized_request_id = str(UUID(request_id))
    except (ValueError, TypeError, AttributeError) as exc:
        raise SandboxApprovalError("A valid idempotency UUID is required") from exc
    if not isinstance(nonce, str) or not _NONCE_RE.fullmatch(nonce):
        raise SandboxApprovalError("A valid one-time approval nonce is required")
    validated_scope = _validate_scope(scope)
    fingerprint = hashlib.sha256(
        _canonical(
            {
                "approval_id": approval_id,
                "request_id": normalized_request_id,
                "nonce": nonce,
                "scope": validated_scope,
            }
        )
    ).hexdigest()
    _verify_independent_audit_checkpoint()
    path = _record_path(approval_id)
    with _locked(path):
        record = _reconcile_pending_audit(
            approval_id, _load(approval_id)
        )
        if record.get("requester") != requester:
            raise SandboxApprovalForbidden("Approval belongs to another requester")
        if not secrets.compare_digest(record.get("nonce", ""), nonce):
            raise SandboxApprovalConflict("Approval nonce does not match")
        events = _events_for(approval_id)
        expected_scope_hash = hashlib.sha256(_canonical(record["scope"])).hexdigest()
        if (
            not events
            or events[0].get("action") != "request_created"
            or events[0].get("actor") != record["requester"]
            or events[0].get("details")
            != {
                "nonce": record.get("nonce"),
                "created_at": record.get("created_at"),
                "expires_at": record.get("expires_at"),
                "issuer": record.get("issuer"),
                "audience": record.get("audience"),
            }
            or events[0].get("scope_sha256") != expected_scope_hash
            or any(event.get("scope_sha256") != expected_scope_hash for event in events)
        ):
            raise SandboxApprovalError("Approval request history requires operator review")
        consumed_events = [
            event for event in events if event.get("action") == "consumed"
        ]
        if consumed_events:
            if len(consumed_events) != 1:
                raise SandboxApprovalError("Duplicate consumption history requires operator review")
            consumed_event = consumed_events[0]
            details = consumed_event.get("details", {})
            if (
                details.get("request_id") != normalized_request_id
                or details.get("payload_sha256") != fingerprint
                or consumed_event.get("scope_sha256") != expected_scope_hash
            ):
                raise SandboxApprovalConflict("Approval has already been consumed")

            # A retry is authorized by the durable consumption event, not by
            # whether the original short-lived receipt is still current.
            # Verify the receipt at the recorded consumption time and prove
            # that both the decision and consumption occurred within its TTL.
            decision_events = [
                event
                for event in events
                if event.get("action") in {"approved", "denied", "expired"}
            ]
            if (
                len(decision_events) != 1
                or decision_events[0].get("action") != "approved"
            ):
                raise SandboxApprovalError(
                    "Approval terminal decision history is ambiguous; operator review required"
                )
            decision_event = decision_events[0]
            decision_sequence = decision_event.get("seq")
            consumed_sequence = consumed_event.get("seq")
            if (
                isinstance(decision_sequence, bool)
                or not isinstance(decision_sequence, int)
                or isinstance(consumed_sequence, bool)
                or not isinstance(consumed_sequence, int)
                or decision_sequence >= consumed_sequence
            ):
                raise SandboxApprovalError(
                    "Approval decision must precede consumption in the audit log"
                )
            decision_at = decision_event.get("time")
            consumed_at = consumed_event.get("time")
            created_at = record.get("created_at")
            expires_at = record.get("expires_at")
            timestamps = (created_at, decision_at, consumed_at, expires_at)
            if any(
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(value)
                for value in timestamps
            ) or not (
                created_at <= decision_at <= consumed_at < expires_at
            ):
                raise SandboxApprovalError(
                    "Consumption audit evidence is outside the approval validity window"
                )
            if (
                decision_event.get("actor") != record.get("approver")
                or consumed_event.get("actor") != requester
                or decision_event.get("details", {}).get("receipt")
                != record.get("receipt")
            ):
                raise SandboxApprovalError(
                    "Consumption audit evidence does not match the approved record"
                )
            expected_outcome = {
                "approval_id": approval_id,
                "status": "consumed",
                "request_id": normalized_request_id,
                "payload_sha256": fingerprint,
            }
            if details.get("outcome") != expected_outcome:
                raise SandboxApprovalError(
                    "Consumption audit outcome does not match its request"
                )
            if not _receipt_matches_record(record, now=consumed_at):
                raise SandboxApprovalError(
                    "Signed decision evidence does not match its record"
                )
            outcome = dict(expected_outcome)
            record["status"] = "consumed"
            record["decision"] = "approved"
            record["audit_status"] = "written"
            record["consumption"] = {
                "request_id": normalized_request_id,
                "payload_sha256": fingerprint,
                "consumed_at": consumed_events[0]["time"],
                "outcome": outcome,
            }
            _save(approval_id, record)
            return outcome
        if record.get("consumption") is not None:
            raise SandboxApprovalError(
                "Consumption record lacks audit proof; operator review required"
            )
        current = time.time() if now is None else now
        if record.get("audit_status") != "written":
            raise SandboxApprovalError("Approval audit is incomplete; operator review required")
        decision_events = [
            event for event in events
            if event.get("action") in {"approved", "denied", "expired"}
        ]
        if len(decision_events) != 1 or decision_events[0].get("action") != "approved":
            raise SandboxApprovalConflict("Audit history does not authorize consumption")
        if record["status"] != "approved" or record["decision"] != "approved":
            raise SandboxApprovalConflict("Approval is not in an approved state")
        if not _receipt_matches_record(record):
            raise SandboxApprovalError("Signed approval does not match its stored scope")
        if (
            record["expires_at"] <= current
            or record["created_at"] > current + MAX_CLOCK_SKEW_SECONDS
        ):
            raise SandboxApprovalConflict("Approval request expired")
        if record["scope"] != validated_scope:
            raise SandboxApprovalConflict("Approval scope does not match")
        outcome = {
            "approval_id": approval_id,
            "status": "consumed",
            "request_id": normalized_request_id,
            "payload_sha256": fingerprint,
        }
        record["status"] = "consumed"
        record["audit_status"] = "pending"
        record["consumption"] = {
            "request_id": normalized_request_id,
            "payload_sha256": fingerprint,
            "consumed_at": current,
            "outcome": outcome,
        }
        _save(approval_id, record)
        try:
            _append_audit(
                approval_id,
                "consumed",
                requester,
                validated_scope,
                current,
                details={
                    "request_id": normalized_request_id,
                    "payload_sha256": fingerprint,
                    "outcome": outcome,
                },
            )
        except Exception:
            record["audit_status"] = "failed"
            try:
                _save(approval_id, record)
            except Exception:
                pass
            raise
        record["audit_status"] = "written"
        _save(approval_id, record)
        return outcome
