from __future__ import annotations

import importlib.util

import pytest

from stage2_sdk_ai import deployment_readiness
from stage2_sdk_ai.storage_paths import data_path, data_root


def test_data_paths_use_configured_absolute_root(monkeypatch, tmp_path):
    monkeypatch.setenv("APP_DATA_DIR", str(tmp_path))

    assert data_root() == tmp_path
    assert data_path("approvals") == tmp_path / "approvals"


def test_relative_data_root_is_rejected(monkeypatch):
    monkeypatch.setenv("APP_DATA_DIR", "relative-data")

    with pytest.raises(ValueError, match="absolute path"):
        data_root()


def test_readiness_fails_when_persistent_mount_is_missing(monkeypatch):
    monkeypatch.delenv("APP_DATA_DIR", raising=False)

    report = deployment_readiness.readiness_report()

    assert report["status"] == "not_ready"
    assert report["checks"]["persistent_data_directory"] is False
    assert "SANDBOX_APPROVAL_SIGNING_PRIVATE_KEY" in report["missing_configuration"]


def test_readiness_passes_synthetic_configuration_and_existing_data_dir(
    monkeypatch, tmp_path
):
    monkeypatch.setenv("APP_DATA_DIR", str(tmp_path))
    monkeypatch.delenv("APP_REQUIRE_MOUNTED_DATA_DIR", raising=False)
    monkeypatch.setenv("AWS_REGION", "eu-central-1")
    for key in deployment_readiness.REQUIRED_APPROVAL_ENV:
        monkeypatch.setenv(key, "synthetic-test-value")
    monkeypatch.setattr(
        importlib.util, "find_spec",
        lambda name: object() if name == "boto3" else None,
    )

    report = deployment_readiness.readiness_report()

    assert report["status"] == "ready"
    assert all(report["checks"].values())
    assert report["missing_configuration"] == []


def test_readiness_requires_actual_mount_when_configured(monkeypatch, tmp_path):
    monkeypatch.setenv("APP_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("APP_REQUIRE_MOUNTED_DATA_DIR", "true")
    monkeypatch.setattr("os.path.ismount", lambda _path: False)
    monkeypatch.setenv("AWS_REGION", "eu-central-1")
    for key in deployment_readiness.REQUIRED_APPROVAL_ENV:
        monkeypatch.setenv(key, "synthetic-test-value")
    monkeypatch.setattr(
        importlib.util, "find_spec",
        lambda name: object() if name == "boto3" else None,
    )

    report = deployment_readiness.readiness_report()

    assert report["status"] == "not_ready"
    assert report["checks"]["persistent_data_directory"] is False
