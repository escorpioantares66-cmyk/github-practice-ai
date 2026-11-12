from __future__ import annotations

import importlib.util
import os

import pytest

from fastapi.testclient import TestClient

from stage2_sdk_ai import api, deployment_readiness, sandbox_approval
from stage2_sdk_ai.storage_paths import data_path, data_root


def _configure_synthetic_readiness(monkeypatch, tmp_path):
    monkeypatch.setenv("APP_DATA_DIR", str(tmp_path))
    monkeypatch.delenv("APP_REQUIRE_MOUNTED_DATA_DIR", raising=False)
    monkeypatch.setenv("AWS_REGION", "eu-central-1")
    for key in deployment_readiness.REQUIRED_APPROVAL_ENV:
        monkeypatch.setenv(key, "synthetic-test-value")
    monkeypatch.setenv("SANDBOX_APPROVALS_DIR", str(tmp_path / "sandbox-approvals"))
    monkeypatch.setenv(
        "AGENT_QUOTA_DB_PATH", str(tmp_path / ".agent_state" / "quotas.sqlite3")
    )
    monkeypatch.setattr(
        importlib.util,
        "find_spec",
        lambda name: object() if name == "boto3" else None,
    )


def _allow_synthetic_checkpoint(monkeypatch):
    monkeypatch.setattr(
        sandbox_approval,
        "_verify_independent_audit_checkpoint",
        lambda: {
            "valid": True,
            "policy_accepted": True,
            "trusted_floor_verified": True,
        },
        raising=False,
    )


def test_data_paths_use_configured_absolute_root(monkeypatch, tmp_path):
    monkeypatch.setenv("APP_DATA_DIR", str(tmp_path))

    assert data_root() == tmp_path
    assert data_path("approvals") == tmp_path / "approvals"


def test_relative_data_root_is_rejected(monkeypatch):
    monkeypatch.setenv("APP_DATA_DIR", "relative-data")

    with pytest.raises(ValueError, match="absolute path"):
        data_root()


@pytest.mark.parametrize("configured_root", [None, ""])
def test_required_mount_rejects_missing_or_blank_data_root(
    monkeypatch, configured_root
):
    if configured_root is None:
        monkeypatch.delenv("APP_DATA_DIR", raising=False)
    else:
        monkeypatch.setenv("APP_DATA_DIR", configured_root)
    monkeypatch.setenv("APP_REQUIRE_MOUNTED_DATA_DIR", "true")

    with pytest.raises(RuntimeError, match="APP_DATA_DIR is required"):
        data_root()


def test_data_path_rejects_parent_traversal(monkeypatch, tmp_path):
    monkeypatch.setenv("APP_DATA_DIR", str(tmp_path))

    with pytest.raises(ValueError, match="beneath APP_DATA_DIR"):
        data_path("..", "outside.txt")


def test_data_path_rejects_absolute_component(monkeypatch, tmp_path):
    monkeypatch.setenv("APP_DATA_DIR", str(tmp_path))

    with pytest.raises(ValueError, match="beneath APP_DATA_DIR"):
        data_path("/tmp/outside.txt")


def test_data_path_rejects_existing_symlink_escape(monkeypatch, tmp_path):
    data_dir = tmp_path / "data"
    outside_dir = tmp_path / "outside"
    data_dir.mkdir()
    outside_dir.mkdir()
    (data_dir / "escape").symlink_to(outside_dir, target_is_directory=True)
    monkeypatch.setenv("APP_DATA_DIR", str(data_dir))

    with pytest.raises(ValueError, match="beneath APP_DATA_DIR"):
        data_path("escape", "secret.txt")


def test_readiness_fails_when_persistent_mount_is_missing(monkeypatch):
    monkeypatch.delenv("APP_DATA_DIR", raising=False)
    monkeypatch.delenv("APP_REQUIRE_MOUNTED_DATA_DIR", raising=False)

    report = deployment_readiness.readiness_report()

    assert report["status"] == "not_ready"
    assert report["checks"]["persistent_data_directory"] is False
    assert report["checks"]["sandbox_checkpoint_enforcement"] is False
    assert "SANDBOX_APPROVAL_SIGNING_PRIVATE_KEY" in report["missing_configuration"]


def test_readiness_passes_only_with_verified_checkpoint_policy(monkeypatch, tmp_path):
    _configure_synthetic_readiness(monkeypatch, tmp_path)
    _allow_synthetic_checkpoint(monkeypatch)

    report = deployment_readiness.readiness_report()

    assert report["status"] == "ready"
    assert all(report["checks"].values())
    assert report["missing_configuration"] == []


def test_readiness_fails_when_checkpoint_enforcement_is_not_installed(
    monkeypatch, tmp_path
):
    _configure_synthetic_readiness(monkeypatch, tmp_path)
    monkeypatch.delattr(
        sandbox_approval, "_verify_independent_audit_checkpoint", raising=False
    )

    report = deployment_readiness.readiness_report()

    assert report["status"] == "not_ready"
    assert report["checks"]["sandbox_checkpoint_enforcement"] is False


def test_readiness_fails_when_checkpoint_verification_raises(monkeypatch, tmp_path):
    _configure_synthetic_readiness(monkeypatch, tmp_path)

    def unavailable():
        raise RuntimeError("synthetic S3 outage")

    monkeypatch.setattr(
        sandbox_approval,
        "_verify_independent_audit_checkpoint",
        unavailable,
        raising=False,
    )

    report = deployment_readiness.readiness_report()

    assert report["status"] == "not_ready"
    assert report["checks"]["sandbox_checkpoint_enforcement"] is False


@pytest.mark.parametrize(
    "result",
    [
        None,
        {},
        {"valid": True, "policy_accepted": False, "trusted_floor_verified": True},
        {"valid": True, "policy_accepted": True, "trusted_floor_verified": False},
        {"valid": False, "policy_accepted": True, "trusted_floor_verified": True},
    ],
)
def test_readiness_rejects_unaccepted_checkpoint_result(monkeypatch, tmp_path, result):
    _configure_synthetic_readiness(monkeypatch, tmp_path)
    monkeypatch.setattr(
        sandbox_approval,
        "_verify_independent_audit_checkpoint",
        lambda: result,
        raising=False,
    )

    report = deployment_readiness.readiness_report()

    assert report["status"] == "not_ready"
    assert report["checks"]["sandbox_checkpoint_enforcement"] is False


def test_readiness_requires_actual_mount_when_configured(monkeypatch, tmp_path):
    _configure_synthetic_readiness(monkeypatch, tmp_path)
    _allow_synthetic_checkpoint(monkeypatch)
    monkeypatch.setenv("APP_REQUIRE_MOUNTED_DATA_DIR", "true")
    monkeypatch.setattr("os.path.ismount", lambda _path: False)

    report = deployment_readiness.readiness_report()

    assert report["status"] == "not_ready"
    assert report["checks"]["persistent_data_directory"] is False


def test_configured_production_data_root_rejects_unmounted_directory(monkeypatch, tmp_path):
    monkeypatch.setenv("APP_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("APP_REQUIRE_MOUNTED_DATA_DIR", "true")
    monkeypatch.setattr("os.path.ismount", lambda _path: False)

    with pytest.raises(RuntimeError, match="mounted persistent disk"):
        data_root()


def test_readiness_rejects_sandbox_store_outside_persistent_root(monkeypatch, tmp_path):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    monkeypatch.setenv("APP_DATA_DIR", str(data_dir))
    monkeypatch.setenv("SANDBOX_APPROVALS_DIR", str(tmp_path / "outside-store"))

    assert deployment_readiness._path_is_within_data_root(
        os.getenv("SANDBOX_APPROVALS_DIR", "")
    ) is False



@pytest.mark.parametrize(
    "component",
    [
        "C:/outside/secret.txt",
        "//server/share/secret.txt",
        r"..\outside\secret.txt",
    ],
)
def test_data_path_rejects_windows_absolute_and_backslash_traversal(
    monkeypatch, tmp_path, component
):
    monkeypatch.setenv("APP_DATA_DIR", str(tmp_path))

    with pytest.raises(ValueError, match="beneath APP_DATA_DIR"):
        data_path(component)

def test_healthz_is_liveness_only_and_does_not_call_checkpoint(
    monkeypatch, tmp_path
):
    monkeypatch.setattr(api, "persistent_storage_ready", lambda: True)

    def checkpoint_must_not_run():
        raise AssertionError("liveness must not call external checkpoint custody")

    monkeypatch.setattr(
        sandbox_approval,
        "_verify_independent_audit_checkpoint",
        checkpoint_must_not_run,
        raising=False,
    )
    client = TestClient(api.app)

    response = client.get("/healthz")

    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_readyz_is_the_explicit_security_readiness_gate(monkeypatch):
    monkeypatch.setattr(
        api,
        "readiness_report",
        lambda: {
            "status": "not_ready",
            "checks": {"sandbox_checkpoint_enforcement": False},
            "missing_configuration": [],
        },
    )
    client = TestClient(api.app)

    response = client.get("/readyz")

    assert response.status_code == 503
    assert response.json()["detail"]["status"] == "not_ready"


def test_readyz_returns_success_only_for_ready_report(monkeypatch):
    expected = {
        "status": "ready",
        "checks": {"sandbox_checkpoint_enforcement": True},
        "missing_configuration": [],
    }
    monkeypatch.setattr(api, "readiness_report", lambda: expected)
    client = TestClient(api.app)

    response = client.get("/readyz")

    assert response.status_code == 200
    assert response.json() == expected
