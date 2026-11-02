"""Crash-recoverable, opt-in rotation for the hash-chained approval audit log.

Rotation is copy-only by default. Destructive truncation requires an explicit
flag and a fresh independently retained checkpoint for the exact active head.
"""
from __future__ import annotations

import base64
import fcntl
import hashlib
import json
import math
import os
import re
import stat
from pathlib import Path
from typing import Any

from .secure_storage import (
    ensure_private_directory,
    fsync_directory,
    open_private_file,
    write_text_atomically,
)

SEGMENT_FORMAT_VERSION = 1
MAX_SEGMENT_BYTES = 128 * 1024 * 1024
MAX_SEGMENT_COUNT = 10_000
_ZERO_HASH = "0" * 64
_SEGMENT_NAME = re.compile(r"audit-segment-\d{20}-[0-9a-f]{16}\.json")


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"),
        ensure_ascii=False, allow_nan=False,
    ).encode("utf-8")


def _paths(archive_dir: Path | None = None) -> tuple[Path, Path, Path]:
    from . import approval

    audit_path = approval._audit_file
    return (
        audit_path.with_name("audit.anchor.json"),
        audit_path.with_name("audit.rotation.json"),
        archive_dir or audit_path.parent / "audit-segments",
    )


def _read_private(path: Path, limit: int) -> bytes:
    if path.is_symlink():
        raise ValueError("rotation evidence cannot be a symlink")
    info = path.lstat()
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.geteuid()
        or info.st_nlink != 1
        or stat.S_IMODE(info.st_mode) != 0o600
    ):
        raise ValueError("rotation evidence must be a private single-link file")
    fd = open_private_file(path, os.O_RDONLY)
    with os.fdopen(fd, "rb") as handle:
        raw = handle.read(limit + 1)
    if len(raw) > limit:
        raise ValueError("rotation evidence exceeds the configured size limit")
    return raw


def _write_json(path: Path, value: dict[str, Any]) -> None:
    parent = ensure_private_directory(path.parent)
    write_text_atomically(path, _canonical(value).decode("utf-8"), parent)
    fsync_directory(parent)


def _base(sequence: int = 0, head_hash: str = _ZERO_HASH,
          legacy_entries: int = 0) -> dict[str, Any]:
    return {
        "sequence": sequence,
        "head_hash": head_hash,
        "legacy_entries": legacy_entries,
    }


def _empty_state() -> dict[str, Any]:
    return {
        "checkpoint": _base(),
        "hashes": {0: _ZERO_HASH},
        "entries": 0,
        "segments": 0,
    }


def _validate_checkpoint(checkpoint: Any) -> dict[str, Any]:
    from . import approval

    if (
        not isinstance(checkpoint, dict)
        or set(checkpoint) != {
            "version", "sequence", "legacy_entries", "head_hash", "created_at"
        }
        or isinstance(checkpoint.get("version"), bool)
        or checkpoint.get("version") != 1
        or isinstance(checkpoint.get("sequence"), bool)
        or not isinstance(checkpoint.get("sequence"), int)
        or checkpoint["sequence"] < 0
        or isinstance(checkpoint.get("legacy_entries"), bool)
        or not isinstance(checkpoint.get("legacy_entries"), int)
        or checkpoint["legacy_entries"] < 0
        or not isinstance(checkpoint.get("head_hash"), str)
        or not re.fullmatch(r"[0-9a-f]{64}", checkpoint["head_hash"])
        or isinstance(checkpoint.get("created_at"), bool)
        or not isinstance(checkpoint.get("created_at"), (int, float))
        or not math.isfinite(checkpoint["created_at"])
        or checkpoint["created_at"] <= 0
    ):
        raise approval.AuditLogIntegrityError("audit checkpoint is malformed")
    return _base(
        checkpoint["sequence"], checkpoint["head_hash"],
        checkpoint["legacy_entries"],
    )


def _decode_segment(raw: bytes, expected_file_hash: str | None = None
                    ) -> tuple[dict[str, Any], bytes, str]:
    from . import approval

    try:
        envelope = json.loads(raw)
    except (UnicodeDecodeError, ValueError) as exc:
        raise approval.AuditLogIntegrityError("audit segment is not valid JSON") from exc
    if (
        not isinstance(envelope, dict)
        or set(envelope) != {"manifest", "data"}
        or not isinstance(envelope["manifest"], dict)
        or not isinstance(envelope["data"], dict)
        or set(envelope["data"]) != {"audit_log_base64"}
    ):
        raise approval.AuditLogIntegrityError("audit segment envelope is malformed")
    manifest = envelope["manifest"]
    required = {
        "format_version", "segment_id", "base_sequence", "base_hash",
        "base_legacy_entries", "end_sequence", "end_hash",
        "end_legacy_entries", "previous_segment", "previous_segment_sha256",
        "data_sha256", "data_bytes",
    }
    if (
        set(manifest) != required
        or manifest.get("format_version") != SEGMENT_FORMAT_VERSION
    ):
        raise approval.AuditLogIntegrityError("audit segment manifest schema is invalid")
    try:
        content = base64.b64decode(
            envelope["data"]["audit_log_base64"], validate=True
        )
        if (
            len(content) > approval.MAX_AUDIT_LOG_BYTES
            or len(content) != manifest["data_bytes"]
            or hashlib.sha256(content).hexdigest() != manifest["data_sha256"]
        ):
            raise ValueError
        core = {key: value for key, value in manifest.items() if key != "segment_id"}
        segment_id = hashlib.sha256(_canonical(core)).hexdigest()
        if manifest["segment_id"] != segment_id:
            raise ValueError
        actual_hash = hashlib.sha256(raw).hexdigest()
        if expected_file_hash is not None and actual_hash != expected_file_hash:
            raise ValueError
        for key in ("base_hash", "end_hash"):
            if not isinstance(manifest[key], str) or not re.fullmatch(
                r"[0-9a-f]{64}", manifest[key]
            ):
                raise ValueError
        for key in (
            "base_sequence", "end_sequence", "base_legacy_entries",
            "end_legacy_entries", "data_bytes",
        ):
            if (
                isinstance(manifest[key], bool)
                or not isinstance(manifest[key], int)
                or manifest[key] < 0
            ):
                raise ValueError
        previous = manifest["previous_segment"]
        previous_sha = manifest["previous_segment_sha256"]
        if previous is not None and (
            not isinstance(previous, str)
            or not _SEGMENT_NAME.fullmatch(previous)
            or not isinstance(previous_sha, str)
            or not re.fullmatch(r"[0-9a-f]{64}", previous_sha)
        ):
            raise ValueError
        if previous is None and previous_sha is not None:
            raise ValueError
        base_checkpoint = _base(
            manifest["base_sequence"], manifest["base_hash"],
            manifest["base_legacy_entries"],
        )
        sequence, head_hash, _, legacy_entries, _ = approval._audit_chain_state(
            content, base_checkpoint=base_checkpoint
        )
        if (
            sequence != manifest["end_sequence"]
            or head_hash != manifest["end_hash"]
            or legacy_entries != manifest["end_legacy_entries"]
        ):
            raise ValueError
    except (KeyError, TypeError, ValueError, approval.AuditLogIntegrityError) as exc:
        raise approval.AuditLogIntegrityError(
            "audit segment integrity verification failed"
        ) from exc
    return manifest, content, hashlib.sha256(raw).hexdigest()


def _verify_anchor(anchor: dict[str, Any] | None, archive_dir: Path
                   ) -> dict[str, Any]:
    from . import approval

    if anchor is None:
        return _empty_state()
    required = {
        "version", "latest_segment", "latest_segment_sha256",
        "sequence", "head_hash", "legacy_entries",
    }
    if (
        not isinstance(anchor, dict)
        or set(anchor) != required
        or anchor.get("version") != 1
        or isinstance(anchor.get("sequence"), bool)
        or not isinstance(anchor.get("sequence"), int)
        or anchor["sequence"] < 0
        or isinstance(anchor.get("legacy_entries"), bool)
        or not isinstance(anchor.get("legacy_entries"), int)
        or anchor["legacy_entries"] < 0
        or not isinstance(anchor.get("head_hash"), str)
        or not re.fullmatch(r"[0-9a-f]{64}", anchor["head_hash"])
        or not isinstance(anchor.get("latest_segment"), str)
        or not _SEGMENT_NAME.fullmatch(anchor["latest_segment"])
        or not isinstance(anchor.get("latest_segment_sha256"), str)
        or not re.fullmatch(r"[0-9a-f]{64}", anchor["latest_segment_sha256"])
    ):
        raise approval.AuditLogIntegrityError("audit rotation anchor is malformed")
    if archive_dir.is_symlink():
        raise approval.AuditLogIntegrityError("audit segment directory cannot be a symlink")
    info = archive_dir.lstat()
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) != 0o700
    ):
        raise approval.AuditLogIntegrityError("audit segment directory is not private")

    expected_name = anchor["latest_segment"]
    expected_hash = anchor["latest_segment_sha256"]
    reverse_segments: list[tuple[dict[str, Any], bytes]] = []
    seen: set[str] = set()
    while expected_name is not None:
        if expected_name in seen or len(seen) >= MAX_SEGMENT_COUNT:
            raise approval.AuditLogIntegrityError(
                "audit segment chain has a cycle or exceeds its limit"
            )
        seen.add(expected_name)
        raw = _read_private(archive_dir / expected_name, MAX_SEGMENT_BYTES)
        manifest, content, _ = _decode_segment(raw, expected_hash)
        reverse_segments.append((manifest, content))
        expected_name = manifest["previous_segment"]
        expected_hash = manifest["previous_segment_sha256"]

    checkpoint = _base()
    hashes: dict[int, str] = {0: _ZERO_HASH}
    entries = 0
    for manifest, content in reversed(reverse_segments):
        if (
            manifest["base_sequence"] != checkpoint["sequence"]
            or manifest["base_hash"] != checkpoint["head_hash"]
            or manifest["base_legacy_entries"] != checkpoint["legacy_entries"]
        ):
            raise approval.AuditLogIntegrityError("audit segment chain is discontinuous")
        sequence, head_hash, count, legacy_count, segment_hashes = (
            approval._audit_chain_state(content, base_checkpoint=checkpoint)
        )
        checkpoint = _base(sequence, head_hash, legacy_count)
        hashes.update(segment_hashes)
        entries += count
    if (
        checkpoint["sequence"] != anchor["sequence"]
        or checkpoint["head_hash"] != anchor["head_hash"]
        or checkpoint["legacy_entries"] != anchor["legacy_entries"]
    ):
        raise approval.AuditLogIntegrityError(
            "audit rotation anchor does not match its segments"
        )
    return {
        "checkpoint": checkpoint,
        "hashes": hashes,
        "entries": entries,
        "segments": len(reverse_segments),
    }


def load_verified_anchor(archive_dir: Path | None = None) -> dict[str, Any]:
    """Return the verified archive head; block reads during interrupted rotation."""
    from . import approval

    anchor_path, journal_path, target_dir = _paths(archive_dir)
    if journal_path.is_symlink():
        raise approval.AuditLogIntegrityError("rotation journal cannot be a symlink")
    if journal_path.exists():
        raise approval.AuditLogIntegrityError(
            "audit rotation recovery is pending; audit writes are blocked"
        )
    if anchor_path.is_symlink():
        raise approval.AuditLogIntegrityError("audit anchor cannot be a symlink")
    if not anchor_path.exists():
        if target_dir.exists() and target_dir.is_symlink():
            raise approval.AuditLogIntegrityError(
                "audit segment directory cannot be a symlink"
            )
        return _empty_state()
    try:
        anchor = json.loads(_read_private(anchor_path, 64 * 1024))
    except (UnicodeDecodeError, ValueError) as exc:
        raise approval.AuditLogIntegrityError("audit anchor is malformed") from exc
    return _verify_anchor(anchor, target_dir)


def _build_segment(content: bytes, base_checkpoint: dict[str, Any],
                   end_checkpoint: dict[str, Any],
                   previous: dict[str, Any] | None
                   ) -> tuple[dict[str, Any], bytes, str]:
    core = {
        "format_version": SEGMENT_FORMAT_VERSION,
        "base_sequence": base_checkpoint["sequence"],
        "base_hash": base_checkpoint["head_hash"],
        "base_legacy_entries": base_checkpoint["legacy_entries"],
        "end_sequence": end_checkpoint["sequence"],
        "end_hash": end_checkpoint["head_hash"],
        "end_legacy_entries": end_checkpoint["legacy_entries"],
        "previous_segment": previous["latest_segment"] if previous else None,
        "previous_segment_sha256": (
            previous["latest_segment_sha256"] if previous else None
        ),
        "data_sha256": hashlib.sha256(content).hexdigest(),
        "data_bytes": len(content),
    }
    segment_id = hashlib.sha256(_canonical(core)).hexdigest()
    manifest = {**core, "segment_id": segment_id}
    data = {"audit_log_base64": base64.b64encode(content).decode("ascii")}
    raw = _canonical({"manifest": manifest, "data": data})
    if len(raw) > MAX_SEGMENT_BYTES:
        raise ValueError("audit segment exceeds the 128 MiB archive limit")
    filename = f"audit-segment-{end_checkpoint['sequence']:020d}-{segment_id[:16]}.json"
    return manifest, raw, filename


def _anchor_for(manifest: dict[str, Any], filename: str,
                file_hash: str) -> dict[str, Any]:
    return {
        "version": 1,
        "latest_segment": filename,
        "latest_segment_sha256": file_hash,
        "sequence": manifest["end_sequence"],
        "head_hash": manifest["end_hash"],
        "legacy_entries": manifest["end_legacy_entries"],
    }


def _read_journal(path: Path) -> dict[str, Any] | None:
    from . import approval

    if path.is_symlink():
        raise approval.AuditLogIntegrityError("rotation journal cannot be a symlink")
    if not path.exists():
        return None
    try:
        journal = json.loads(_read_private(path, 128 * 1024))
    except (UnicodeDecodeError, ValueError) as exc:
        raise approval.AuditLogIntegrityError("rotation journal is corrupt") from exc
    required = {
        "version", "phase", "active_sha256", "active_size",
        "old_anchor", "new_anchor", "expected_checkpoint",
    }
    if (
        not isinstance(journal, dict)
        or set(journal) != required
        or journal.get("version") != 1
        or journal.get("phase") != "prepared"
        or not isinstance(journal.get("active_sha256"), str)
        or not re.fullmatch(r"[0-9a-f]{64}", journal["active_sha256"])
        or isinstance(journal.get("active_size"), bool)
        or not isinstance(journal.get("active_size"), int)
        or journal["active_size"] <= 0
    ):
        raise approval.AuditLogIntegrityError("rotation journal schema is invalid")
    _validate_checkpoint(journal["expected_checkpoint"])
    if journal["old_anchor"] is not None and not isinstance(journal["old_anchor"], dict):
        raise approval.AuditLogIntegrityError("rotation journal old anchor is invalid")
    if not isinstance(journal["new_anchor"], dict):
        raise approval.AuditLogIntegrityError("rotation journal new anchor is invalid")
    return journal


def _current_anchor(path: Path, archive_dir: Path) -> dict[str, Any] | None:
    from . import approval

    if path.is_symlink():
        raise approval.AuditLogIntegrityError("audit anchor cannot be a symlink")
    if not path.exists():
        return None
    try:
        anchor = json.loads(_read_private(path, 64 * 1024))
    except (UnicodeDecodeError, ValueError) as exc:
        raise approval.AuditLogIntegrityError("audit anchor is malformed") from exc
    _verify_anchor(anchor, archive_dir)
    return anchor


def _clear_journal(path: Path) -> None:
    if path.is_symlink():
        raise ValueError("rotation journal cannot be a symlink")
    path.unlink()
    fsync_directory(path.parent)


def _matches(left: dict[str, Any], right: dict[str, Any]) -> bool:
    return all(left[key] == right[key] for key in (
        "sequence", "head_hash", "legacy_entries"
    ))


def rotate_audit_log(
    archive_dir: Path | None = None,
    *,
    truncate: bool = False,
    expected_checkpoint: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Archive the active segment; truncate only after explicit verification."""
    from . import approval

    if not isinstance(truncate, bool):
        raise ValueError("truncate must be a boolean")
    if truncate and expected_checkpoint is None:
        raise ValueError(
            "destructive rotation requires an independently retained checkpoint"
        )
    anchor_path, journal_path, target_dir = _paths(archive_dir)
    fd = open_private_file(approval._audit_file, os.O_RDWR | os.O_CREAT)
    with os.fdopen(fd, "r+b") as audit_file:
        fcntl.flock(audit_file.fileno(), fcntl.LOCK_EX)
        try:
            if _read_journal(journal_path) is not None:
                raise approval.AuditLogIntegrityError(
                    "an earlier rotation must be recovered before a new rotation"
                )
            anchor_state = load_verified_anchor(target_dir)
            base_checkpoint = anchor_state["checkpoint"]
            audit_file.seek(0)
            content = audit_file.read(approval.MAX_AUDIT_LOG_BYTES + 1)
            if len(content) > approval.MAX_AUDIT_LOG_BYTES:
                raise approval.AuditLogIntegrityError(
                    "active audit log exceeds its size limit"
                )
            sequence, head_hash, count, legacy_count, _ = (
                approval._audit_chain_state(content, base_checkpoint=base_checkpoint)
            )
            if not content:
                return {"status": "no_active_data", "truncated": False}
            end_checkpoint = _base(sequence, head_hash, legacy_count)
            if truncate:
                checked = _validate_checkpoint(expected_checkpoint)
                if not _matches(end_checkpoint, checked):
                    raise approval.AuditLogIntegrityError(
                        "external checkpoint must match the exact active audit head"
                    )
            current_anchor = _current_anchor(anchor_path, target_dir)
            manifest, segment_raw, filename = _build_segment(
                content, base_checkpoint, end_checkpoint, current_anchor
            )
            ensure_private_directory(target_dir)
            segment_path = target_dir / filename
            if segment_path.exists() or segment_path.is_symlink():
                existing = _read_private(segment_path, MAX_SEGMENT_BYTES)
                if existing != segment_raw:
                    raise approval.AuditLogIntegrityError(
                        "conflicting audit segment already exists"
                    )
            else:
                write_text_atomically(
                    segment_path, segment_raw.decode("utf-8"), target_dir
                )
                fsync_directory(target_dir)
            file_hash = hashlib.sha256(segment_raw).hexdigest()
            new_anchor = _anchor_for(manifest, filename, file_hash)
            verified = _verify_anchor(new_anchor, target_dir)
            if not _matches(verified["checkpoint"], end_checkpoint):
                raise approval.AuditLogIntegrityError(
                    "new audit segment head did not verify"
                )
            result = {
                "status": "archived_copy",
                "truncated": False,
                "archive_path": str(segment_path),
                "archive_sha256": file_hash,
                "entries_archived": count,
                "head_sequence": sequence,
                "head_hash": head_hash,
                "source_modified": False,
            }
            if not truncate:
                return result

            journal = {
                "version": 1,
                "phase": "prepared",
                "active_sha256": hashlib.sha256(content).hexdigest(),
                "active_size": len(content),
                "old_anchor": current_anchor,
                "new_anchor": new_anchor,
                "expected_checkpoint": expected_checkpoint,
            }
            _write_json(journal_path, journal)
            _write_json(anchor_path, new_anchor)
            audit_file.seek(0)
            os.ftruncate(audit_file.fileno(), 0)
            os.fsync(audit_file.fileno())
            _clear_journal(journal_path)
            result.update({
                "status": "rotated",
                "truncated": True,
                "source_modified": True,
                "active_bytes_remaining": 0,
            })
            return result
        finally:
            fcntl.flock(audit_file.fileno(), fcntl.LOCK_UN)


def recover_audit_rotation(
    archive_dir: Path | None = None,
    *,
    allow_truncate: bool = False,
) -> dict[str, Any]:
    """Inspect or explicitly finish a rotation interrupted after its journal."""
    from . import approval

    if not isinstance(allow_truncate, bool):
        raise ValueError("allow_truncate must be a boolean")
    anchor_path, journal_path, target_dir = _paths(archive_dir)
    fd = open_private_file(approval._audit_file, os.O_RDWR | os.O_CREAT)
    with os.fdopen(fd, "r+b") as audit_file:
        fcntl.flock(audit_file.fileno(), fcntl.LOCK_EX)
        try:
            journal = _read_journal(journal_path)
            if journal is None:
                return {"status": "no_pending_rotation", "recovered": False}
            new_state = _verify_anchor(journal["new_anchor"], target_dir)
            new_checkpoint = new_state["checkpoint"]
            if not _matches(
                new_checkpoint, _validate_checkpoint(journal["expected_checkpoint"])
            ):
                raise approval.AuditLogIntegrityError(
                    "journal checkpoint does not match verified archive"
                )
            current_anchor = _current_anchor(anchor_path, target_dir)
            current_raw = _canonical(current_anchor) if current_anchor else None
            old_raw = (
                _canonical(journal["old_anchor"])
                if journal["old_anchor"] else None
            )
            new_raw = _canonical(journal["new_anchor"])
            if current_raw not in {old_raw, new_raw}:
                raise approval.AuditLogIntegrityError(
                    "rotation anchor changed outside the journaled operation"
                )

            audit_file.seek(0)
            active = audit_file.read(approval.MAX_AUDIT_LOG_BYTES + 1)
            if len(active) > approval.MAX_AUDIT_LOG_BYTES:
                raise approval.AuditLogIntegrityError(
                    "active audit log exceeds its size limit"
                )
            if not active:
                if current_raw != new_raw:
                    _write_json(anchor_path, journal["new_anchor"])
                _clear_journal(journal_path)
                return {
                    "status": "recovered_complete",
                    "recovered": True,
                    "truncated": True,
                    "source_modified": False,
                }
            if (
                len(active) != journal["active_size"]
                or hashlib.sha256(active).hexdigest() != journal["active_sha256"]
            ):
                raise approval.AuditLogIntegrityError(
                    "active audit log differs from journaled and empty states"
                )
            old_state = (
                _verify_anchor(journal["old_anchor"], target_dir)
                if journal["old_anchor"] is not None else _empty_state()
            )
            old_sequence, old_hash, _, old_legacy, _ = (
                approval._audit_chain_state(
                    active, base_checkpoint=old_state["checkpoint"]
                )
            )
            if not _matches(
                _base(old_sequence, old_hash, old_legacy), new_checkpoint
            ):
                raise approval.AuditLogIntegrityError(
                    "archive does not cover the journaled active audit log"
                )
            if not allow_truncate:
                return {
                    "status": "verified_pending_truncation",
                    "recovered": False,
                    "truncated": False,
                    "source_modified": False,
                }
            if current_raw != new_raw:
                _write_json(anchor_path, journal["new_anchor"])
            audit_file.seek(0)
            os.ftruncate(audit_file.fileno(), 0)
            os.fsync(audit_file.fileno())
            _clear_journal(journal_path)
            return {
                "status": "recovered_and_rotated",
                "recovered": True,
                "truncated": True,
                "source_modified": True,
            }
        finally:
            fcntl.flock(audit_file.fileno(), fcntl.LOCK_UN)
