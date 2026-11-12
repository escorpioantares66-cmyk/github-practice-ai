"""Resolve application-owned data paths for local and disk-backed deployments."""
from __future__ import annotations

import os
from pathlib import Path


def data_root() -> Path:
    """Return APP_DATA_DIR, requiring an absolute path when explicitly configured."""
    configured = os.getenv("APP_DATA_DIR", "").strip()
    if not configured:
        return Path(".")
    root = Path(configured).expanduser()
    if not root.is_absolute():
        raise ValueError("APP_DATA_DIR must be an absolute path")
    return root


def data_path(*parts: str) -> Path:
    """Resolve a data path beneath APP_DATA_DIR (or the legacy local directory)."""
    return data_root().joinpath(*parts)
