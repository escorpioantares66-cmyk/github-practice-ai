from __future__ import annotations

import os
import stat

import pytest

from scripts import render_entrypoint


def test_root_bootstrap_chowns_only_mount_root_then_drops_privileges(
    monkeypatch, tmp_path
):
    calls = []
    monkeypatch.setenv("APP_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("PORT", "10000")
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(os, "chown", lambda path, uid, gid: calls.append(("chown", uid, gid)))
    monkeypatch.setattr(os, "chmod", lambda path, mode: calls.append(("chmod", mode)))
    monkeypatch.setattr(os, "setgid", lambda gid: calls.append(("setgid", gid)))
    monkeypatch.setattr(os, "setuid", lambda uid: calls.append(("setuid", uid)))
    monkeypatch.setattr(os, "execvpe", lambda *args: calls.append(("exec", args[0])))

    render_entrypoint.drop_privileges_and_exec()

    assert calls == [
        ("chown", 10001, 10001),
        ("chmod", stat.S_IRWXU),
        ("setgid", 10001),
        ("setuid", 10001),
        ("exec", "uvicorn"),
    ]


def test_entrypoint_rejects_invalid_port(monkeypatch, tmp_path):
    monkeypatch.setenv("APP_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("PORT", "70000")
    monkeypatch.setattr(os, "geteuid", lambda: 10001)
    monkeypatch.setattr(Path, "stat", lambda self: type("Info", (), {
        "st_uid": 10001, "st_mode": stat.S_IFDIR | stat.S_IRWXU
    })())

    with pytest.raises(RuntimeError, match="PORT"):
        render_entrypoint.drop_privileges_and_exec()
