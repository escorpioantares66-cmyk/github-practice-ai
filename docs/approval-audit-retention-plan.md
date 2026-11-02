# Approval and audit retention: implementation plan

## Policy

- Retention threshold: 90 days (7,776,000 seconds), evaluated in UTC using persisted event timestamps.
- Archive destination: private local storage, owner-only directory permissions (0700) and files (0600).
- Archived evidence is never automatically deleted. Copy-only audit archival is the default; destructive active-log truncation is a separate explicit opt-in guarded by verification and recovery checks.
- Approval JSON records are not moved or deleted by audit rotation. SQLite usage retention remains a separate policy.

## Current constraints found during review

- Approval records are individual JSON files under the configured approval directory.
- The active append-only audit history is a JSONL segment with a SHA-256 hash chain and a 64 MiB validation limit. After verified rotation, earlier segments are retained in a linked private archive and an anchor records the archived head.
- Audit verification must validate the entire segment chain before validating the active suffix. Sequence numbers, previous-hash links, legacy-prefix integrity, and external checkpoint compatibility must remain continuous.
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

## Stage 2: verified segmented rotation

The implementation uses immutable, individually verified audit segments. Each segment records its base sequence/hash, ending sequence/hash, legacy-prefix count, content digest, and digest link to the preceding segment. A private anchor identifies the latest verified segment. The active JSONL file continues from that checkpoint without resetting sequence numbers or breaking previous-hash links.

### Default and destructive modes

- The default rotate_audit_log() operation is copy-only. It writes and verifies a segment but leaves the active audit log byte-for-byte unchanged.
- Destructive rotation requires truncate=True and a fresh expected_checkpoint from approval.create_audit_checkpoint(). The operator must store that checkpoint independently before authorizing truncation.
- Before truncation, the implementation verifies the complete existing segment chain, the active log, the new segment, the continuity links, and the exact external checkpoint.
- It then writes a durable private rotation journal, advances the anchor atomically, truncates and fsyncs the active log, and only then clears the journal. Archived segments are never automatically deleted.
- A pending journal blocks normal audit appends and verification. recover_audit_rotation() verifies the archive and journal first. It does not truncate by default; allow_truncate=True is required to finish an interrupted truncation. Unexpected active bytes, missing segments, or invalid links fail closed.
- The archive directory and evidence files must be owner-private, regular files, single-link, and non-symlink paths. A missing active log after a rotation anchor exists is an integrity error, not an empty history.

### Storage and operational limits

The 64 MiB limit applies to each active segment. This bounds the size of the live append file, but it does not impose a finite cap on total archived history: preserving all evidence means the archive continues to grow. Re-validating the complete archive chain is proportional to archived history, so this local single-host design is appropriate only while that verification cost remains operationally acceptable. The archive remains local to the host and is not an off-device backup. Approval JSON records remain in the active approval store so quota enforcement and operator recovery are unchanged. SQLite daily usage retention is not changed by this audit-rotation implementation.

Example operator sequence:

1. Call approval.create_audit_checkpoint() and save the returned checkpoint outside the application storage.
2. Call rotate_audit_log() first to create and verify a non-destructive copy.
3. After reviewing the independently retained checkpoint and verified segment, call rotate_audit_log(truncate=True, expected_checkpoint=checkpoint) to authorize truncation.
4. After an interruption, inspect with recover_audit_rotation(); explicitly pass allow_truncate=True only when recovery confirms the journaled segment and active bytes match.

No scheduler or automatic cleanup is introduced.

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
