import io
import json

import pytest

from stage2_sdk_ai import approval, audit_checkpoint_store


class FakeS3:
    def __init__(self, payload):
        self.payload = payload
        self.request = None

    def get_object(self, **kwargs):
        self.request = kwargs
        return {"Body": io.BytesIO(self.payload)}


def test_s3_checkpoint_fetch_uses_configured_bucket_and_key(monkeypatch):
    checkpoint = {
        "version": 1,
        "sequence": 2,
        "legacy_entries": 0,
        "head_hash": "a" * 64,
        "created_at": 123.0,
    }
    client = FakeS3(json.dumps(checkpoint).encode())
    verified = []
    monkeypatch.setattr(
        approval, "verify_audit_log",
        lambda supplied: verified.append(supplied) or {"valid": True},
    )

    result = audit_checkpoint_store.load_s3_checkpoint(
        client, bucket="private-checkpoints", key="audit/latest.json"
    )

    assert result == checkpoint
    assert verified == [checkpoint]
    assert client.request == {
        "Bucket": "private-checkpoints", "Key": "audit/latest.json"
    }


def test_s3_checkpoint_rejects_duplicate_json_keys(monkeypatch):
    client = FakeS3(
        b'{"version":1,"version":1,"sequence":0,"legacy_entries":0,'
        b'"head_hash":"' + b"0" * 64 + b'","created_at":123.0}'
    )
    with pytest.raises(audit_checkpoint_store.AuditCheckpointStoreError):
        audit_checkpoint_store.load_s3_checkpoint(
            client, bucket="private-checkpoints", key="audit/latest.json"
        )


def test_s3_checkpoint_rejects_oversized_response():
    client = FakeS3(b"x" * (audit_checkpoint_store.MAX_CHECKPOINT_BYTES + 1))
    with pytest.raises(audit_checkpoint_store.AuditCheckpointStoreError, match="size"):
        audit_checkpoint_store.load_s3_checkpoint(
            client, bucket="private-checkpoints", key="audit/latest.json"
        )


def test_s3_checkpoint_requires_bucket_configuration(monkeypatch):
    monkeypatch.delenv("AGENT_AUDIT_CHECKPOINT_S3_BUCKET", raising=False)
    with pytest.raises(audit_checkpoint_store.AuditCheckpointStoreError, match="not configured"):
        audit_checkpoint_store.load_s3_checkpoint(FakeS3(b"{}"))


def test_export_checkpoint_writes_private_file(monkeypatch, tmp_path):
    monkeypatch.setattr(
        approval, "create_audit_checkpoint",
        lambda: {
            "version": 1,
            "sequence": 0,
            "legacy_entries": 0,
            "head_hash": "0" * 64,
            "created_at": 123.0,
        },
    )
    destination = tmp_path / "private" / "checkpoint.json"

    result = audit_checkpoint_store.export_audit_checkpoint(destination)

    assert json.loads(destination.read_text(encoding="utf-8")) == result
    assert destination.stat().st_mode & 0o777 == 0o600
    assert destination.parent.stat().st_mode & 0o777 == 0o700
