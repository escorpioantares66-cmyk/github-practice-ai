# Approval and audit retention: implementation plan

## Policy

- Retention threshold: 90 days (7,776,000 seconds), evaluated in UTC using persisted event timestamps.
- Archive destination: private local storage, owner-only directory permissions (0700) and files (0600).
- Archival is not deletion. The first implementation is copy-only and must leave active approval records and the active audit log byte-for-byte unchanged.
- No automatic deletion or active-log truncation is in scope.

## Current constraints found during review

- Approval records are individual JSON files under the configured approval directory.
- The append-only audit history is a single JSONL file with a SHA-256 hash chain and a 64 MiB validation limit.
- Audit verification currently assumes the full history is present in one file. Moving old lines out would invalidate the existing sequence and previous-hash assumptions.
- Approval quota enforcement scans the active approval JSON files. Moving records changes quota semantics unless archival is explicitly integrated into the scan.
- Recovery inspection scans approval JSON files. Unresolved consumed executions must never disappear from operator recovery merely because they are old.
- SQLite daily usage retention is separate from approval/audit retention and is not changed by this work.

## Stage 1: non-destructive archive

1. Add a retention planner using an injectable UTC clock. It reports eligible records and exclusion reasons without changing storage.
2. An approval record is eligible only when its timestamp is older than 90 days, its file is a regular private file (not a symlink), its schema and ID validate, and its request/transition audit markers are complete.
3. Exclude corrupt, unreadable, symlinked, audit-incomplete, and unresolved execution/recovery records. Expired pending and terminal records may be considered only when their audit state is complete and they cannot be executed or replayed.
4. Audit archival must preserve chain context. Stage 1 should archive a verified immutable snapshot or verified prefix with sequence/hash metadata; it must not create a disconnected fragment that appears independently authoritative.
5. Archive writes must use private directories, no-follow file operations, atomic replacement, fsync, and a manifest containing format version, creation time, policy threshold, record identifiers, byte lengths, and SHA-256 digests.
6. Verify every written archive artifact against its manifest before reporting success.
7. Re-running the same archive operation must be idempotent. A conflicting archive artifact must fail closed; never overwrite it silently.
8. Keep originals untouched. Return a report of archived, skipped, and failed items without exposing note content or credentials.

## Stage 2: verified rotation (separate change)

Only after Stage 1 and its tests are stable, design a segmented audit format that verifies archived segments and the active segment as one continuous chain. Preserve sequence numbers, previous-hash links, legacy-prefix integrity, and independent checkpoint compatibility. Rotation must be crash-safe and recoverable. No truncation or deletion until the full-chain verifier confirms the archived segment and the new active segment.

## Security and regression test matrix

- UTC boundary: exactly 90 days is not older than the threshold; just older is eligible.
- Clock injection: deterministic results; invalid/future timestamps fail closed.
- Eligibility: complete audited terminal/expired records can be copied; pending executable or unresolved recovery records are excluded.
- Integrity: malformed JSON, ID/filename mismatch, missing audit marker, corrupt audit chain, and invalid manifest fail closed.
- Filesystem: symlinked archive directory, symlinked source, hard-linked source, non-regular files, unsafe permissions/ownership, and path traversal are rejected.
- Atomicity: simulated write/fsync/replace failures leave source records and source audit bytes unchanged; incomplete archive artifacts are not treated as successful.
- Idempotency: retry after success produces the same verified result; conflicting archive content is not overwritten.
- Concurrency: two archive workers cannot create conflicting manifests or race source state.
- Privacy: archive metadata and reports do not disclose note content, API keys, or approver credentials.
- Regression: approval quotas, pending listing, operator recovery, approval lifecycle, replay rejection, and audit checkpoint verification remain correct.
- Capacity: planner and archive verification handle the existing 64 MiB audit-log limit without reading unbounded data.

## Acceptance criteria

- The feature is opt-in; no background scheduler or automatic cleanup is introduced.
- Dry-run is the default.
- Copy-only archival leaves all source bytes and source paths unchanged.
- Archive verification is explicit and independently testable.
- Existing CI gates pass, including dependency audit, Ruff, full tests, coverage, and package build.
- A separate review/approval is required before any future active-store rotation or deletion.
