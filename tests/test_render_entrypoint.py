from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from scripts import render_entrypoint


def _mock_data_root_stat(monkeypatch):
    monkeypatch.setattr(
        Path,
        "stat",
        lambda self, *args, **kwargs: type(
            "Info", (), {"st_uid": 10001, "st_mode": stat.S_IFDIR | stat.S_IRWXU}
        )(),
    )


def test_root_bootstrap_clears_groups_then_drops_privileges(monkeypatch, tmp_path):
    calls = []
    monkeypatch.setenv("APP_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("PORT", "10000")
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(os, "getegid", lambda: 10001)
    monkeypatch.setattr(os, "getgroups", lambda: [])
    _mock_data_root_stat(monkeypatch)
    monkeypatch.setattr(
        os, "setgroups", lambda groups: calls.append(("setgroups", groups))
    )
    monkeypatch.setattr(
        os, "chown", lambda path, uid, gid: calls.append(("chown", uid, gid))
    )
    monkeypatch.setattr(
        os, "chmod", lambda path, mode: calls.append(("chmod", mode))
    )
    monkeypatch.setattr(os, "setgid", lambda gid: calls.append(("setgid", gid)))
    monkeypatch.setattr(os, "setuid", lambda uid: calls.append(("setuid", uid)))
    monkeypatch.setattr(
        os, "execvpe", lambda *args: calls.append(("exec", args[0]))
    )

    render_entrypoint.drop_privileges_and_exec()

    assert calls == [
        ("setgroups", []),
        ("chown", 10001, 10001),
        ("chmod", stat.S_IRWXU),
        ("setgid", 10001),
        ("setuid", 10001),
        ("exec", "uvicorn"),
    ]


def test_root_entrypoint_fails_closed_if_supplementary_groups_cannot_be_cleared(
    monkeypatch, tmp_path
):
    monkeypatch.setenv("APP_DATA_DIR", str(tmp_path))
    monkeypatch.setattr(os, "geteuid", lambda: 0)

    def deny_setgroups(_groups):
        raise PermissionError("synthetic setgroups failure")

    monkeypatch.setattr(os, "setgroups", deny_setgroups)
    monkeypatch.setattr(
        os, "execvpe", lambda *args: pytest.fail("server must not be executed")
    )

    with pytest.raises(PermissionError, match="setgroups"):
        render_entrypoint.drop_privileges_and_exec()


def test_non_root_entrypoint_requires_exact_identity_and_no_extra_groups(
    monkeypatch, tmp_path
):
    monkeypatch.setenv("APP_DATA_DIR", str(tmp_path))
    monkeypatch.setattr(os, "geteuid", lambda: 10001)
    monkeypatch.setattr(os, "getegid", lambda: 10001)
    monkeypatch.setattr(os, "getgroups", lambda: [20000])
    _mock_data_root_stat(monkeypatch)
    monkeypatch.setattr(
        os, "execvpe", lambda *args: pytest.fail("server must not be executed")
    )

    with pytest.raises(RuntimeError, match="supplementary groups"):
        render_entrypoint.drop_privileges_and_exec()


def test_non_root_entrypoint_rejects_wrong_effective_gid(monkeypatch, tmp_path):
    monkeypatch.setenv("APP_DATA_DIR", str(tmp_path))
    monkeypatch.setattr(os, "geteuid", lambda: 10001)
    monkeypatch.setattr(os, "getegid", lambda: 20000)
    monkeypatch.setattr(os, "getgroups", lambda: [])
    _mock_data_root_stat(monkeypatch)

    with pytest.raises(RuntimeError, match="unprivileged GID"):
        render_entrypoint.drop_privileges_and_exec()


def test_entrypoint_rejects_invalid_port(monkeypatch, tmp_path):
    monkeypatch.setenv("APP_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("PORT", "70000")
    monkeypatch.setattr(os, "geteuid", lambda: 10001)
    monkeypatch.setattr(os, "getegid", lambda: 10001)
    monkeypatch.setattr(os, "getgroups", lambda: [])
    _mock_data_root_stat(monkeypatch)

    with pytest.raises(RuntimeError, match="PORT"):
        render_entrypoint.drop_privileges_and_exec()
