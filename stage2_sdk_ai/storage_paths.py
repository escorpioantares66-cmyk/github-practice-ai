"""Resolve application-owned data paths for local and disk-backed deployments."""
from __future__ import annotations

import os
from pathlib import Path, PureWindowsPath


def data_root() -> Path:
    """Return APP_DATA_DIR and fail closed if the required disk is not mounted."""
    configured = os.getenv("APP_DATA_DIR", "").strip()
    require_mount = os.getenv("APP_REQUIRE_MOUNTED_DATA_DIR", "").lower() == "true"
    if not configured:
        if require_mount:
            raise RuntimeError(
                "APP_DATA_DIR is required when APP_REQUIRE_MOUNTED_DATA_DIR=true"
            )
        return Path(".")

    root = Path(configured).expanduser()
    if not root.is_absolute():
        raise ValueError("APP_DATA_DIR must be an absolute path")
    if require_mount:
        if (
            not root.is_dir()
            or root.is_symlink()
            or not os.path.ismount(root)
            or not os.access(root, os.W_OK | os.X_OK)
        ):
            raise RuntimeError("APP_DATA_DIR must be a writable mounted persistent disk")
    return root


def data_path(*parts: str) -> Path:
    """Resolve a path beneath APP_DATA_DIR and reject traversal or symlink escape."""
    root = data_root()
    root_resolved = root.resolve(strict=False)
    candidate = root
    for part in parts:
        if not isinstance(part, str) or not part:
            raise ValueError("Data path components must be non-empty strings")
        component = Path(part)
        windows_component = PureWindowsPath(part)
        if (
            component.is_absolute()
            or windows_component.is_absolute()
            or windows_component.drive
            or ".." in component.parts
            or ".." in windows_component.parts
        ):
            raise ValueError("Data path must remain beneath APP_DATA_DIR")
        candidate = candidate / component

    resolved = candidate.resolve(strict=False)
    try:
        resolved.relative_to(root_resolved)
    except ValueError as exc:
        raise ValueError("Data path must remain beneath APP_DATA_DIR") from exc
    return resolved
