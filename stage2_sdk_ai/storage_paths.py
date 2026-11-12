"""Resolve application-owned data paths for local and disk-backed deployments."""
from __future__ import annotations

import os
from pathlib import Path


def data_root() -> Path:
    """Return APP_DATA_DIR and fail closed if the required disk is not mounted."""
    configured = os.getenv("APP_DATA_DIR", "").strip()
    if not configured:
        return Path(".")
    root = Path(configured).expanduser()
    if not root.is_absolute():
        raise ValueError("APP_DATA_DIR must be an absolute path")
    if os.getenv("APP_REQUIRE_MOUNTED_DATA_DIR", "").lower() == "true":
        if (
            not root.is_dir()
            or root.is_symlink()
            or not os.path.ismount(root)
            or not os.access(root, os.W_OK | os.X_OK)
        ):
            raise RuntimeError("APP_DATA_DIR must be a writable mounted persistent disk")
    return root


def data_path(*parts: str) -> Path:
    """Resolve a data path beneath APP_DATA_DIR (or the legacy local directory)."""
    return data_root().joinpath(*parts)
