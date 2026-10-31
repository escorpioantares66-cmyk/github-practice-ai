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


def _open_directory_chain(path: Path, create: bool = False) -> int:
    """Open a directory by walking each component relative to verified dirfds."""
    target = Path(os.path.abspath(os.fspath(path)))
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    fd = os.open(target.anchor, flags)
    try:
        for part in target.parts[1:]:
            try:
                next_fd = os.open(part, flags, dir_fd=fd)
            except FileNotFoundError:
                if not create:
                    raise
                os.mkdir(part, 0o700, dir_fd=fd)
                next_fd = os.open(part, flags, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        os.fchmod(fd, 0o700)
        return fd
    except Exception:
        os.close(fd)
        raise


def ensure_private_directory(path: Path) -> Path:
    """Create/check a private directory using descriptor-relative traversal."""
    target = Path(os.path.abspath(os.fspath(path)))
    fd = _open_directory_chain(target, create=True)
    os.close(fd)
    return target


def open_private_file(path: Path, flags: int, mode: int = 0o600) -> int:
    """Open a regular file relative to a verified, no-follow parent directory."""
    parent_fd = _open_directory_chain(Path(path).parent, create=False)
    try:
        fd = os.open(
            Path(path).name,
            flags | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
            mode,
            dir_fd=parent_fd,
        )
    finally:
        os.close(parent_fd)
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode):
        os.close(fd)
        raise UnsafeStoragePathError(f"Storage target is not a regular file: {path}")
    os.fchmod(fd, mode)
    return fd


def fsync_directory(path: Path) -> None:
    """Persist directory-entry changes after creating or replacing data files."""
    directory_fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def read_private_text(path: Path) -> str:
    fd = open_private_file(path, os.O_RDONLY)
    with os.fdopen(fd, "r", encoding="utf-8") as handle:
        return handle.read()


def write_text_atomically(path: Path, content: str, directory: Path) -> None:
    """Atomically replace a file using only the verified directory descriptor."""
    safe_directory = ensure_private_directory(directory)
    destination = Path(path)
    if Path(os.path.abspath(destination.parent)) != safe_directory:
        raise UnsafeStoragePathError(
            "Atomic-write destination must be directly inside its storage directory"
        )
    directory_fd = _open_directory_chain(safe_directory, create=False)
    temporary_name = f".{destination.name}.{os.urandom(12).hex()}.tmp"
    fd = -1
    try:
        fd = os.open(
            temporary_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
            0o600,
            dir_fd=directory_fd,
        )
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            fd = -1
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(
            temporary_name,
            destination.name,
            src_dir_fd=directory_fd,
            dst_dir_fd=directory_fd,
        )
        os.fsync(directory_fd)
    finally:
        if fd >= 0:
            os.close(fd)
        try:
            os.unlink(temporary_name, dir_fd=directory_fd)
        except FileNotFoundError:
            pass
        os.close(directory_fd)
