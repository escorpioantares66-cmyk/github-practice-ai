"""Small, fail-closed helpers for private local application storage.

Storage directories must be real directories (never symlinks). Data files are
opened without following symlinks and are created with owner-only permissions.
These checks reduce accidental exposure and common local path-redirection risks;
they do not make a shared, attacker-writable filesystem safe against every
possible time-of-check/time-of-use race.
"""
from __future__ import annotations

import errno
import os
import stat
from pathlib import Path


class UnsafeStoragePathError(ValueError):
    """Raised when a configured storage path is not a safe local directory."""


def _open_directory_chain(path: Path, create: bool = False) -> int:
    """Open a directory from the nearest accessible ancestor using dirfds."""
    target = Path(os.path.abspath(os.fspath(path)))
    if target == Path(target.anchor):
        raise UnsafeStoragePathError(
            "The filesystem root cannot be used as a private storage directory"
        )
    flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )

    # Android/Termux may deny opening '/'. Find an accessible ancestor above
    # the target, then verify every remaining component without following links.
    anchor = target.parent
    while True:
        try:
            fd = os.open(anchor, flags)
            break
        except (PermissionError, FileNotFoundError, NotADirectoryError):
            parent = anchor.parent
            if parent == anchor:
                raise
            anchor = parent

    try:
        relative_parts = target.relative_to(anchor).parts
        for part in relative_parts:
            try:
                next_fd = os.open(part, flags, dir_fd=fd)
            except FileNotFoundError:
                if not create:
                    raise
                try:
                    os.mkdir(part, 0o700, dir_fd=fd)
                except FileExistsError:
                    # Another creator won the race; validate what now exists.
                    pass
                next_fd = os.open(part, flags, dir_fd=fd)
            except OSError as exc:
                if exc.errno in {errno.ELOOP, errno.ENOTDIR}:
                    raise UnsafeStoragePathError(
                        f"Storage directory contains a symlink or non-directory: {part}"
                    ) from exc
                raise
            os.close(fd)
            fd = next_fd
        if create:
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
    """Persist directory-entry changes through a no-follow directory descriptor."""
    directory_fd = _open_directory_chain(path, create=False)
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
        fsync_directory(safe_directory)
    finally:
        if fd >= 0:
            os.close(fd)
        try:
            os.unlink(temporary_name, dir_fd=directory_fd)
        except FileNotFoundError:
            pass
        os.close(directory_fd)
