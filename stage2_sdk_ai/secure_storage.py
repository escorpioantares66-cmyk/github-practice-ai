"""Small, fail-closed helpers for private local application storage.

Storage directories must be real directories (never symlinks). Data files are
opened without following symlinks and are created with owner-only permissions.
These checks reduce accidental exposure and common local path-redirection risks;
they do not make a shared, attacker-writable filesystem safe against every
possible time-of-check/time-of-use race.
"""
from __future__ import annotations

import os
import stat
import tempfile
from pathlib import Path


class UnsafeStoragePathError(ValueError):
    """Raised when a configured storage path is not a safe local directory."""


def ensure_private_directory(path: Path) -> Path:
    """Create/check a directory chain and restrict the leaf directory to 0700."""
    target = Path(os.path.abspath(os.fspath(path)))
    current = Path(target.anchor)
    for part in target.parts[1:]:
        current = current / part
        try:
            current.mkdir(mode=0o700)
        except FileExistsError:
            pass
        try:
            info = current.lstat()
        except OSError as exc:
            raise UnsafeStoragePathError(f"Cannot inspect storage directory: {current}") from exc
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise UnsafeStoragePathError(f"Storage path component is not a real directory: {current}")
    try:
        os.chmod(target, 0o700, follow_symlinks=False)
    except (NotImplementedError, OSError) as exc:
        raise UnsafeStoragePathError(f"Cannot secure storage directory: {target}") from exc
    return target


def open_private_file(path: Path, flags: int, mode: int = 0o600) -> int:
    """Open a file without following a final-component symlink."""
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    cloexec = getattr(os, "O_CLOEXEC", 0)
    fd = os.open(path, flags | nofollow | cloexec, mode)
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode):
        os.close(fd)
        raise UnsafeStoragePathError(f"Storage target is not a regular file: {path}")
    os.fchmod(fd, mode)
    return fd


def read_private_text(path: Path) -> str:
    fd = open_private_file(path, os.O_RDONLY)
    with os.fdopen(fd, "r", encoding="utf-8") as handle:
        return handle.read()


def write_text_atomically(path: Path, content: str, directory: Path) -> None:
    """Write owner-only content and atomically replace a file in a safe directory."""
    safe_directory = ensure_private_directory(directory)
    if Path(path).parent != directory and Path(os.path.abspath(path)).parent != safe_directory:
        raise UnsafeStoragePathError("Atomic-write destination must be directly inside its storage directory")
    fd, temporary_name = tempfile.mkstemp(
        prefix=f".{Path(path).name}.", suffix=".tmp", dir=safe_directory
    )
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, safe_directory / Path(path).name)
        directory_fd = os.open(safe_directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if os.path.exists(temporary_name):
            os.unlink(temporary_name)
