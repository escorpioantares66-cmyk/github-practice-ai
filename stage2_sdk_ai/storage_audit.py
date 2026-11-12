"""Read-only inventory and retention review for persistent application storage.

This module inspects filesystem metadata and reuses the existing read-only
retention planner. It never creates directories, opens files for writing,
changes permissions, rotates logs, archives records, or deletes data.
"""
from __future__ import annotations

import math
import os
import stat
import time
from pathlib import Path
from typing import Any

from . import approval, quota_store, write_tools
from .retention import RETENTION_DAYS, plan_retention
from .secure_storage import UnsafeStoragePathError, _open_directory_chain
from .storage_paths import data_path

MAX_SCAN_ENTRIES = 100_000
MAX_SCAN_DEPTH = 8
VECTOR_STORE_DEFAULT_PATH = data_path("data", "faiss_store")
VECTOR_STORE_MAX_BYTES = 64 * 1024 * 1024
_SQLITE_SIDECARS = ("-wal", "-shm", "-journal")
_DIRECTORY_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_DIRECTORY", 0)
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_CLOEXEC", 0)
)


def _private_metadata(info: os.stat_result, *, directory: bool) -> bool:
    expected_mode = 0o700 if directory else 0o600
    return (
        info.st_uid == os.geteuid()
        and stat.S_IMODE(info.st_mode) == expected_mode
        and (directory or info.st_nlink == 1)
    )


def _empty_inventory(path: Path) -> dict[str, Any]:
    return {
        "path": str(path),
        "status": "unknown",
        "regular_files": 0,
        "directories": 0,
        "symlinks": 0,
        "special_files": 0,
        "unreadable_entries": 0,
        "unsafe_permissions": 0,
        "total_bytes": 0,
        "extension_counts": {},
        "truncated": False,
        "entries_examined": 0,
    }


def _record_file(
    result: dict[str, Any], name: str, info: os.stat_result
) -> None:
    result["regular_files"] += 1
    result["total_bytes"] += info.st_size
    suffix = Path(name).suffix.lower() or "[no extension]"
    extensions = result["extension_counts"]
    extensions[suffix] = extensions.get(suffix, 0) + 1
    if not _private_metadata(info, directory=False):
        result["unsafe_permissions"] += 1


def _scan_directory_fd(
    fd: int,
    result: dict[str, Any],
    *,
    depth: int,
    budget: list[int],
    max_entries: int,
    max_depth: int,
) -> None:
    try:
        # scandir yields entries incrementally; listdir would allocate the full
        # directory before the scan budget could take effect.
        with os.scandir(fd) as entries:
            for entry in entries:
                if budget[0] >= max_entries:
                    result["truncated"] = True
                    return
                name = entry.name
                budget[0] += 1
                result["entries_examined"] += 1
                try:
                    info = os.stat(name, dir_fd=fd, follow_symlinks=False)
                except OSError:
                    result["unreadable_entries"] += 1
                    continue

                if stat.S_ISLNK(info.st_mode):
                    result["symlinks"] += 1
                elif stat.S_ISREG(info.st_mode):
                    _record_file(result, name, info)
                elif stat.S_ISDIR(info.st_mode):
                    result["directories"] += 1
                    if not _private_metadata(info, directory=True):
                        result["unsafe_permissions"] += 1
                    if depth >= max_depth:
                        result["truncated"] = True
                        continue
                    child_fd = -1
                    try:
                        child_fd = os.open(name, _DIRECTORY_FLAGS, dir_fd=fd)
                        opened_info = os.fstat(child_fd)
                        if (opened_info.st_dev, opened_info.st_ino) != (
                            info.st_dev, info.st_ino
                        ):
                            result["unreadable_entries"] += 1
                            os.close(child_fd)
                            child_fd = -1
                            continue
                        _scan_directory_fd(
                            child_fd,
                            result,
                            depth=depth + 1,
                            budget=budget,
                            max_entries=max_entries,
                            max_depth=max_depth,
                        )
                    except OSError:
                        result["unreadable_entries"] += 1
                    finally:
                        if child_fd >= 0:
                            os.close(child_fd)
                else:
                    result["special_files"] += 1
    except OSError:
        result["unreadable_entries"] += 1


def inspect_storage_path(
    path: str | Path,
    *,
    max_entries: int = MAX_SCAN_ENTRIES,
    max_depth: int = MAX_SCAN_DEPTH,
) -> dict[str, Any]:
    """Inventory one path without following symlinks or reading file contents."""
    target = Path(os.path.abspath(Path(path).expanduser()))
    result = _empty_inventory(target)
    if (
        isinstance(max_entries, bool)
        or not isinstance(max_entries, int)
        or max_entries < 1
        or isinstance(max_depth, bool)
        or not isinstance(max_depth, int)
        or max_depth < 0
    ):
        raise ValueError("scan limits must be non-negative integers")

    parent_fd = -1
    root_fd = -1
    try:
        parent_fd = _open_directory_chain(target.parent, create=False)
        info = os.stat(target.name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        result["status"] = "missing"
        return result
    except UnsafeStoragePathError:
        result["status"] = "symlink"
        result["symlinks"] = 1
        return result
    except OSError:
        result["status"] = "unreadable"
        result["unreadable_entries"] += 1
        return result
    finally:
        if parent_fd >= 0 and result["status"] in {
            "missing", "symlink", "unreadable"
        }:
            os.close(parent_fd)
            parent_fd = -1

    if stat.S_ISLNK(info.st_mode):
        result["status"] = "symlink"
        result["symlinks"] = 1
    elif stat.S_ISREG(info.st_mode):
        result["status"] = "present"
        _record_file(result, target.name, info)
    elif not stat.S_ISDIR(info.st_mode):
        result["status"] = "special_file"
        result["special_files"] = 1
    else:
        result["status"] = "present"
        result["directories"] = 1
        if not _private_metadata(info, directory=True):
            result["unsafe_permissions"] += 1
        try:
            root_fd = os.open(target.name, _DIRECTORY_FLAGS, dir_fd=parent_fd)
            opened_info = os.fstat(root_fd)
            if (opened_info.st_dev, opened_info.st_ino) != (info.st_dev, info.st_ino):
                result["status"] = "changed_during_scan"
                result["unreadable_entries"] += 1
            else:
                _scan_directory_fd(
                    root_fd,
                    result,
                    depth=0,
                    budget=[0],
                    max_entries=max_entries,
                    max_depth=max_depth,
                )
        except OSError:
            result["status"] = "unreadable"
            result["unreadable_entries"] += 1
    if root_fd >= 0:
        os.close(root_fd)
    if parent_fd >= 0:
        os.close(parent_fd)
    return result

def _inspect_leaf(path: Path) -> dict[str, Any]:
    """Inspect a single file or missing path without opening its contents."""
    target = Path(os.path.abspath(path.expanduser()))
    result = _empty_inventory(target)
    parent_fd = -1
    try:
        parent_fd = _open_directory_chain(target.parent, create=False)
        info = os.stat(target.name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        result["status"] = "missing"
    except UnsafeStoragePathError:
        result["status"] = "symlink"
        result["symlinks"] = 1
    except OSError:
        result["status"] = "unreadable"
        result["unreadable_entries"] = 1
    else:
        if stat.S_ISLNK(info.st_mode):
            result["status"] = "symlink"
            result["symlinks"] = 1
        elif stat.S_ISREG(info.st_mode):
            result["status"] = "present"
            _record_file(result, target.name, info)
        else:
            result["status"] = "special_file"
            result["special_files"] = 1
    finally:
        if parent_fd >= 0:
            os.close(parent_fd)
    return result


def _inspect_directory_metadata(path: Path) -> dict[str, Any]:
    """Check a storage parent directory without enumerating or changing it."""
    target = Path(os.path.abspath(path.expanduser()))
    result: dict[str, Any] = {
        "path": str(target),
        "status": "unknown",
        "symlinks": 0,
        "unsafe_permissions": 0,
    }
    fd = -1
    try:
        fd = _open_directory_chain(target, create=False)
        info = os.fstat(fd)
    except FileNotFoundError:
        result["status"] = "missing"
    except UnsafeStoragePathError:
        result["status"] = "symlink"
        result["symlinks"] = 1
    except OSError:
        result["status"] = "unreadable"
    else:
        result["status"] = "present"
        if not _private_metadata(info, directory=True):
            result["unsafe_permissions"] = 1
    finally:
        if fd >= 0:
            os.close(fd)
    return result

def _quota_database_path() -> Path:
    configured = os.getenv("AGENT_QUOTA_DB_PATH", "").strip()
    target = Path(configured).expanduser() if configured else quota_store.DEFAULT_DB_PATH
    return Path(os.path.abspath(target))


def _quota_inventory() -> dict[str, Any]:
    database = _quota_database_path()
    files = {"database": _inspect_leaf(database)}
    for suffix in _SQLITE_SIDECARS:
        files[suffix.lstrip("-")] = _inspect_leaf(
            database.with_name(database.name + suffix)
        )
    return {
        "path": str(database),
        "parent_directory": _inspect_directory_metadata(database.parent),
        "files": files,
        "total_bytes": sum(item["total_bytes"] for item in files.values()),
        "database_contents_inspected": False,
        "table_row_counts": None,
    }


def _retention_inventory(now: float) -> dict[str, Any]:
    try:
        plan = plan_retention(
            now=now,
            max_approval_records=MAX_SCAN_ENTRIES,
        )
    except Exception as exc:
        return {
            "status": "unavailable",
            "error_type": type(exc).__name__,
            "audit_log_verified": False,
            "eligible_approval_records": None,
            "approval_records_scanned": None,
            "approval_records_excluded": {},
        }

    scan_truncated = plan.get("approval_records_scan_truncated") is True
    return {
        "status": (
            "incomplete"
            if scan_truncated
            else "verified" if plan.get("audit_log_verified") is True else "failed"
        ),
        "retention_days": plan.get("retention_days", RETENTION_DAYS),
        "approval_records_scanned": plan.get("approval_records_scanned", 0),
        "approval_records_scan_limit": plan.get("approval_records_scan_limit"),
        "approval_records_scan_truncated": scan_truncated,
        "eligible_approval_records": plan.get("approval_records_eligible", 0),
        "approval_records_excluded": plan.get("approval_records_excluded", {}),
        "audit_log_verified": plan.get("audit_log_verified") is True,
        "audit_entries_scanned": plan.get("audit_entries_scanned", 0),
        "active_audit_entries_older_than_cutoff": plan.get(
            "active_audit_entries_older_than_cutoff", 0
        ),
        "audit_head_sequence": plan.get("audit_head_sequence", 0),
        "audit_archive_mode": plan.get("audit_archive_mode", "unknown"),
        "source_modified": False,
    }


def _finding(
    severity: str, code: str, message: str, recommendation: str
) -> dict[str, str]:
    return {
        "severity": severity,
        "code": code,
        "message": message,
        "recommendation": recommendation,
    }


def run_storage_audit(now: float | None = None) -> dict[str, Any]:
    """Return a read-only storage inventory and 90-day retention assessment.

    File content is not returned. SQLite is inspected only through filesystem
    metadata so this command cannot initialize a database or create sidecars.
    """
    current = time.time() if now is None else now
    if (
        isinstance(current, bool)
        or not isinstance(current, (int, float))
        or not math.isfinite(current)
        or current <= 0
    ):
        raise ValueError("now must be a positive finite timestamp")

    approval_dir = approval._approvals_dir
    audit_file = approval._audit_file
    notes_dir = write_tools._notes_dir
    approval_archive_dir = approval_dir.parent / "archive"
    audit_segments_dir = audit_file.parent / "audit-segments"

    approvals = inspect_storage_path(approval_dir)
    logs = inspect_storage_path(audit_file.parent)
    segments = inspect_storage_path(audit_segments_dir)
    active_audit = _inspect_leaf(audit_file)
    notes = inspect_storage_path(notes_dir)
    approval_archive = inspect_storage_path(approval_archive_dir)
    quota = _quota_inventory()
    vector_store = inspect_storage_path(VECTOR_STORE_DEFAULT_PATH)
    retention = _retention_inventory(float(current))

    areas = {
        "approvals": {
            **approvals,
            "approval_json_records": approvals["extension_counts"].get(".json", 0),
            "lock_files": approvals["extension_counts"].get(".lock", 0),
        },
        "audit": {
            **logs,
            "active_log": active_audit,
            "segments": segments,
            "active_log_limit_bytes": approval.MAX_AUDIT_LOG_BYTES,
            "segment_archive_is_automatically_pruned": False,
        },
        "notes": notes,
        "approval_archive": {
            **approval_archive,
            "automatic_source_deletion": False,
        },
        "quota_database": quota,
        "vector_store_default": {
            **vector_store,
            "configured_default_path": str(VECTOR_STORE_DEFAULT_PATH),
            "store_file_limit_bytes": VECTOR_STORE_MAX_BYTES,
            "custom_instance_paths_discoverable": False,
        },
    }

    findings: list[dict[str, str]] = []
    for area_name, inventory in (
        ("approvals", approvals),
        ("audit", logs),
        ("audit_segments", segments),
        ("notes", notes),
        ("approval_archive", approval_archive),
        ("vector_store_default", vector_store),
    ):
        if inventory["symlinks"]:
            findings.append(_finding(
                "critical",
                f"{area_name}_symlink_detected",
                f"{area_name} contains {inventory['symlinks']} symlink path(s); "
                "they were not followed.",
                "Inspect the affected storage path and replace unsafe links only "
                "through a reviewed recovery procedure.",
            ))
        if inventory["unsafe_permissions"]:
            findings.append(_finding(
                "warning",
                f"{area_name}_permissions",
                f"{area_name} contains {inventory['unsafe_permissions']} path(s) with "
                "unexpected ownership, permissions, or link count.",
                "Review ownership, mode 0700 for directories, and mode 0600 plus "
                "single-link status for files.",
            ))
        if inventory["unreadable_entries"] or inventory["status"] in {
            "unreadable", "changed_during_scan"
        }:
            findings.append(_finding(
                "warning",
                f"{area_name}_incomplete_scan",
                f"{area_name} could not be fully inspected.",
                "Check filesystem access and rerun the audit; do not infer that "
                "uninspected data is absent.",
            ))
        if inventory["truncated"]:
            findings.append(_finding(
                "warning",
                f"{area_name}_scan_limited",
                f"{area_name} exceeded the configured scan depth or entry limit.",
                "Increase the explicit scan limits only after confirming the "
                "storage tree is trusted.",
            ))

    if active_audit["status"] == "present":
        active_bytes = active_audit["total_bytes"]
        if active_bytes >= int(approval.MAX_AUDIT_LOG_BYTES * 0.8):
            findings.append(_finding(
                "warning",
                "active_audit_log_near_capacity",
                f"The active audit log is using {active_bytes} bytes of its "
                f"{approval.MAX_AUDIT_LOG_BYTES}-byte limit.",
                "Follow the verified operator rotation procedure; do not truncate "
                "without an independently retained checkpoint.",
            ))

    if approvals["regular_files"]:
        findings.append(_finding(
            "warning",
            "approval_records_remain_in_active_store",
            "Approval records and per-record lock files remain in the active store "
            "after retention snapshots; this audit does not remove them.",
            "Keep unresolved execution and recovery records available. Design a "
            "separately reviewed lifecycle/archive index before any deletion.",
        ))
    if segments["regular_files"]:
        findings.append(_finding(
            "warning",
            "audit_archive_grows_without_pruning",
            "Verified audit segments are retained and are not automatically deleted, "
            "so total audit history can grow without a finite cap.",
            "Preserve all segments; monitor capacity and arrange an independently "
            "administered backup before considering a separate retention policy.",
        ))
    if notes["regular_files"]:
        findings.append(_finding(
            "warning",
            "notes_have_no_automatic_retention",
            "Note files persist in requester-scoped directories and this project has "
            "no automatic note-retention policy.",
            "Define ownership, backup, and expiry rules before proposing cleanup; "
            "do not delete user notes automatically.",
        ))
    if quota["files"]["database"]["status"] == "present":
        findings.append(_finding(
            "warning",
            "daily_usage_has_no_retention",
            "The quota database stores daily_usage history without an implemented "
            "retention policy; table rows were not read by this metadata-only audit.",
            "Choose a financial/accounting retention period before adding bounded "
            "aggregation or pruning.",
        ))
    quota_parent = quota["parent_directory"]
    if quota_parent["symlinks"]:
        findings.append(_finding(
            "critical", "quota_parent_symlink",
            "The quota database parent is a symlink and was not followed.",
            "Restore a private, real application-owned directory before using quota storage.",
        ))
    if quota_parent["unsafe_permissions"]:
        findings.append(_finding(
            "warning", "quota_parent_permissions",
            "The quota database parent is not an owner-only directory.",
            "Restrict the quota database parent to the application owner with mode 0700.",
        ))
    for file_name, file_info in quota["files"].items():
        if file_info["symlinks"]:
            findings.append(_finding(
                "critical", f"quota_{file_name}_symlink",
                f"The quota {file_name} path is a symlink and was not followed.",
                "Inspect the quota storage path and restore a private regular file "
                "through a reviewed recovery procedure.",
            ))
        if file_info["unsafe_permissions"]:
            findings.append(_finding(
                "warning", f"quota_{file_name}_permissions",
                f"The quota {file_name} file has unexpected ownership, permissions, or link count.",
                "Review the file owner, mode 0600, and single-link requirement.",
            ))
        if file_info["unreadable_entries"]:
            findings.append(_finding(
                "warning", f"quota_{file_name}_unreadable",
                f"The quota {file_name} path could not be inspected.",
                "Check filesystem access and rerun the audit before making storage decisions.",
            ))

    if retention["status"] == "incomplete":
        findings.append(_finding(
            "warning",
            "retention_approval_scan_limited",
            "The approval-record scan reached its configured limit; retention "
            "eligibility is incomplete and must not be treated as a full inventory.",
            "Review the reported scan limit and rerun with an explicitly approved "
            "higher bound if a complete inventory is required.",
        ))
    elif retention["status"] != "verified":
        findings.append(_finding(
            "critical",
            "retention_or_audit_verification_failed",
            "The existing approval retention planner could not verify the complete "
            "local audit history.",
            "Stop approval-sensitive maintenance and investigate the integrity error "
            "before any archival or cleanup operation.",
        ))

    return {
        "schema_version": 1,
        "mode": "read_only",
        "scanned_at_epoch": float(current),
        "source_modified": False,
        "storage_mutations_performed": 0,
        "areas": areas,
        "retention": retention,
        "findings": findings,
        "scope_notes": [
            "Filesystem inventory uses metadata only and does not return file contents "
            "or approval identifiers.",
            "The existing retention planner reads approval records and verifies the "
            "local audit chain; it does not archive or delete them.",
            "SQLite files and sidecars are measured without opening the database; "
            "row counts and WAL contents are not inspected.",
            "Only the default vector-store path is discoverable; custom "
            "RealVectorStore persist_path values must be supplied separately.",
            "A local hash-chain verification is not a substitute for checking an "
            "independently retained external audit checkpoint.",
        ],
    }
