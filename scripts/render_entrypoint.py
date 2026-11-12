"""Prepare the mounted data root, drop privileges, and exec the API server."""
from __future__ import annotations

import os
import stat
from pathlib import Path


APP_UID = 10001
APP_GID = 10001


def drop_privileges_and_exec() -> None:
    """Chown only the mount root, then run the application as an unprivileged UID."""
    raw_root = os.getenv("APP_DATA_DIR", "/var/data").strip()
    root = Path(raw_root).expanduser()
    if not root.is_absolute() or root.is_symlink() or not root.is_dir():
        raise RuntimeError("APP_DATA_DIR must be an existing absolute directory")

    if os.geteuid() == 0:
        # A fresh Render disk may be root-owned. Only the mount root is adjusted;
        # existing application records are never recursively rewritten.
        os.chown(root, APP_UID, APP_GID)
        os.chmod(root, stat.S_IRWXU)
        os.setgid(APP_GID)
        os.setuid(APP_UID)
    elif os.geteuid() != APP_UID:
        raise RuntimeError("API process must run as the configured unprivileged UID")

    info = root.stat()
    if info.st_uid != APP_UID or stat.S_IMODE(info.st_mode) & 0o077:
        raise RuntimeError("Persistent data root ownership or permissions are unsafe")

    port = os.getenv("PORT", "10000")
    if not port.isascii() or not port.isdecimal() or not 1 <= int(port) <= 65535:
        raise RuntimeError("PORT must be a valid TCP port")
    os.execvpe(
        "uvicorn",
        [
            "uvicorn",
            "stage2_sdk_ai.api:app",
            "--host",
            "0.0.0.0",
            "--port",
            port,
        ],
        os.environ,
    )


if __name__ == "__main__":
    drop_privileges_and_exec()
