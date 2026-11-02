# Read-only storage and retention audit

## Run it

Use the CLI from the project environment:

~~~bash
gh-ai --storage-audit
~~~

Or call it from Python:

~~~python
from stage2_sdk_ai.storage_audit import run_storage_audit

report = run_storage_audit()
print(report)
~~~

The report is JSON-compatible and includes filesystem inventory, the existing
90-day approval retention dry-run, audit-chain verification status, and
actionable findings. It does not return note contents, approval payloads, or
approval identifiers.

## Read-only guarantees

The inventory uses lstat, directory file descriptors, and no-follow metadata
checks. It does not follow symlinks, read regular-file contents, create missing
directories, change modes, or write database files. It measures the quota
database and its SQLite sidecars by file metadata only; it does not open SQLite,
execute SQL, or report row counts.

The retention section reuses retention.plan_retention(). That planner reads
approval records and the audit history to determine which records could be
copied into a retention snapshot and to verify the local segmented audit chain.
It remains a dry-run: eligible IDs are removed from the public report, no
snapshot is created, and source records are not changed or deleted.

The command performs no archive creation, audit rotation, truncation, cleanup,
or AWS calls. It performs no application-level writes, content changes,
permission changes, or directory-entry changes. source_modified remains false
and storage_mutations_performed remains zero. Because the retention planner
reads approval and audit files, the host filesystem may update access-time
metadata according to its mount policy (for example, relatime or noatime).

## What is inventoried

| Area | Inventory |
|---|---|
| Approvals | JSON record count, lock-file count, total bytes, permissions, links |
| Audit | Active JSONL log, audit-segment archive, rotation metadata and bytes |
| Approval archive | Existing private retention snapshots and their bytes |
| Notes | Requester-scoped note files, directories and total bytes |
| Quota database | Database and SQLite sidecar file sizes; no row-level inspection |
| Vector store | Default .test_rag persistence path; custom instance paths are not discoverable |

The filesystem scan is bounded by 100,000 entries and depth 8 by default. A
truncated or unreadable inventory is explicitly marked; missing data must not
be interpreted as an empty store.

## Retention findings and current limits

- Approval JSON records remain in the active store after copy-only retention
  snapshots. Lock files are also persistent. Do not remove records until quota
  enforcement, approval lifecycle history, and operator recovery have a
  separately reviewed archival/index design.
- Audit segments are preserved and are not automatically deleted. The 64 MiB
  limit applies to the active audit segment, not total archived history.
- daily_usage rows persist in SQLite. Expired rate events and reservations are
  removed lazily by quota operations, but no retention policy for daily usage
  is implemented. Row counts are intentionally not inspected by this command.
- Requester-scoped note files have no automatic expiry policy. User content
  must not be removed without an explicit ownership and retention policy.
- Only the default vector-store directory can be inventoried. Applications
  that construct RealVectorStore with a custom persist_path must include
  that path in a separate operator inventory.
- Local hash-chain verification proves internal consistency, not authenticity
  against a privileged host attacker. It does not replace verification against
  an independently retained external checkpoint.

This command is an assessment tool, not a cleanup tool. Any future retention,
aggregation, archive deletion, or storage compaction must be implemented as a
separate change with recovery analysis, explicit policy, and dedicated tests.
