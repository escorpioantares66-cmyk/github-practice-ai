# Independent audit checkpoint: local candidate design

## Decision status

**Sandbox v1 integration implemented on the PR #54 feature branch; operational custody and deployment are not yet verified.**

The sandbox approval lifecycle now requires read-only retrieval and verification of an independently retained S3 candidate checkpoint and operator-accepted trusted floor before create, decide, inspect, decision retrieval or consume operations. Missing configuration, unavailable custody, rollback or policy failure pauses the operation. The main approval audit's existing S3 helper remains optional and is not changed by this sandbox integration. No production S3 bucket, IAM policy, operator identity or runtime configuration is provisioned by this code change.

The local operator-owned filesystem checkpoint described in the original proposal is superseded for the PR #54 sandbox integration by the S3 candidate/trusted-floor design. The Linux two-UID test remains evidence for that filesystem proof only; it is not evidence of S3 IAM or production custody.

## Current implementation findings

### Main approval audit

- `approval.verify_audit_log(expected_checkpoint)` can compare the complete verified local history with a supplied checkpoint.
- `approval.create_audit_checkpoint()` creates a checkpoint from the current verified chain head.
- The normal verifier accepts no checkpoint, and normal approval operations do not require one.
- The existing `audit_checkpoint_store.py` integration retrieves an S3 checkpoint, but it is optional and is not part of the normal approval operation path.
- The main checkpoint schema contains version, chained sequence, legacy-entry count, head hash, and creation time.

### Sandbox approval audit

- `sandbox_approval.verify_audit_log()` verifies only the local sandbox audit hash chain.
- The sandbox chain has its own event sequence and last hash, so it requires a distinct authority identifier and checkpoint state. A main-approval checkpoint must never be accepted for the sandbox log, or vice versa.
- PR #54 wires the existing versioned checkpoint envelope and policy verifier to separate S3 candidate and trusted-floor objects for the sandbox authority. The application reads both objects; operator credentials publish them.
- Runtime operation requires an operator-provisioned store ID, S3 bucket and object keys, explicit maximum checkpoint age and maximum unanchored suffix. These values have no code defaults and missing configuration fails closed.

### Storage boundary

The existing private-storage helpers require files and directories to be owned by the effective application UID and use owner-only permissions. They are appropriate for application-owned private data, but cannot directly read a checkpoint owned by a separate operator UID.

The current implementation's trust boundary is an independently administered S3 bucket and operator identity. A separate object key or directory under the same application credentials is not an independent boundary.

## Current S3 trust boundary

The PR #54 sandbox integration reads two distinct S3 objects before every lifecycle operation:

- **Candidate checkpoint:** the latest operator-published statement of the sandbox audit head.
- **Trusted floor:** the last checkpoint explicitly accepted by the operator and retained separately from application-writable state.

The application role is restricted by design to reading the two exact object keys. Publication and floor advancement use separate operator credentials. The code does not provision the bucket, IAM policy, operator identity, version retention, backup process, or runtime policy values.

This boundary assumes the AWS account, operator identity, and host/runtime remain trusted. It does not protect against compromise of an administrator able to replace or delete both trust anchors, compromise of the operator credentials, host root/kernel compromise, or loss of every independent trusted-floor copy. S3 versioning alone is not immutable retention against an administrator with version-delete privileges.

The original local operator-owned filesystem proposal is retained only as historical design context; it is not the implemented PR #54 checkpoint transport. The Linux two-UID proof does not establish the S3/IAM boundary.

## Checkpoint envelope

Use a strict, versioned envelope with exact fields:

- `format_version`: checkpoint format version;
- `authority`: fixed identifier distinguishing the main approval log from the sandbox approval log;
- `store_id`: stable identifier for the specific audit store, preventing cross-store substitution;
- `sequence`: the authority-specific sequence number;
- `head_hash`: SHA-256 hash at that sequence;
- `legacy_entries`: main approval legacy-prefix count; zero for the sandbox authority;
- `created_at`: checkpoint snapshot creation time in UTC epoch seconds;
- `checkpoint_id`: unique publication identifier.

Reject duplicate JSON keys, unknown or missing fields, booleans in integer fields, invalid hashes, non-finite timestamps, invalid authority/store identifiers, and files above a small fixed size limit. The two authorities must use separate checkpoint files or separately keyed envelopes and must never share sequence state.

The initial format is deliberately not a replacement for the existing audit event formats. It is an independently retained statement of a verified head.

## Freshness, rollback, and unanchored suffix

A checkpoint for sequence N proves the local history only through sequence N. It can detect a rewrite or truncation that changes history at or before N. It does **not** prove that entries appended after N have not been rewritten.

This limitation is material. A periodic manually published checkpoint leaves an unanchored suffix between publications. A maximum checkpoint age bounds elapsed time, but does not prove that the suffix is intact.

Therefore:

1. A checkpoint must never be silently accepted merely because it is well-formed.
2. A checkpoint behind the current head must be reported as a valid prefix anchor, not as proof of the entire current log.
3. The operational policy must define a maximum unanchored suffix and publication cadence before any enforcement decision.
4. If exact current-head anchoring is required for every approval-sensitive operation, the checkpoint must match the current head. A manual operator publication process cannot provide this continuously without blocking operations between publications.
5. A stale or lower-sequence checkpoint must not be replaced automatically. Checkpoint rollback or unexplained sequence regression requires operator investigation.
6. A local file alone cannot prove its own monotonic history against an operator/root attacker who can restore an older file. The trust claim is limited to the application-UID threat model.

No freshness duration or publication cadence is selected in this document. That requires an explicit operational decision based on the expected approval volume and acceptable unanchored suffix.

## Publication and recovery protocol

1. The operator reads and verifies the complete relevant audit history using the authority-specific verifier.
2. The operator reviews the current head and any unresolved integrity/recovery findings.
3. The operator exports a checkpoint for that exact authority, store, sequence, and head hash.
4. The operator validates the exported envelope and publishes it atomically to the operator-owned read-only path.
5. The operator confirms ownership, group, modes, file identity, and the published content after replacement.
6. The application reads the checkpoint without write capability and compares it with the correct audit history.
7. If the checkpoint is missing, unreadable, malformed, stale under the eventual policy, rolled back, or inconsistent, the system reports an integrity failure. It does not generate a replacement.
8. Recovery preserves all audit bytes and checkpoint artifacts. An operator investigates from the last known trusted checkpoint, verifies archived segments and active history, and records the recovery decision before publishing any new checkpoint.
9. If the trusted checkpoint is lost and no independently retained copy exists, the history cannot be silently re-established as trusted by exporting the current head. That would bless potentially rewritten history.

Crash tests must cover interruption before temporary-file fsync, after file fsync but before rename, after rename but before directory fsync, and after publication but before operator confirmation. Recovery must distinguish an old valid checkpoint from a newly published but durability-uncertain checkpoint. It must never infer success from a partially completed publication.

## Historical filesystem-candidate proof gates (superseded)

The following UID and filesystem checks apply only to the earlier local-file candidate. They must not be presented as proof of the current S3 trust boundary.

### Historical filesystem and identity proof

- Run the application under a dedicated non-privileged UID.
- Run checkpoint publication under a different operator UID.
- Prove application read succeeds.
- Prove application create, write, truncate, chmod, unlink, rename, and parent-directory mutation fail with permission errors.
- Prove the application cannot access operator-only temporary files or publication credentials.
- Reject same-UID configurations and writable parent directories.
- Repeat on the actual intended host filesystem; unit tests that run both roles as the same UID are not proof.

### Integrity and policy proof for the current S3 integration

For both audit authorities, test:
- missing, malformed, duplicate-key, oversized, wrong-authority, wrong-store, and tampered checkpoints;
- valid checkpoint with later append-only events;
- truncation before and at the checkpoint sequence;
- altered history before the checkpoint;
- rewritten unanchored suffix after the checkpoint, demonstrating the known detection gap;
- stale checkpoint, sequence regression, and restoration of an older checkpoint;
- checkpoint path symlink, hard link, ownership, group, and mode violations;
- independent checkpoint substitution between main and sandbox logs.

### Recovery proof

- Simulate each publication interruption point.
- Preserve the prior checkpoint when publication fails.
- Ensure no automatic checkpoint advancement after an integrity failure.
- Demonstrate operator-only recovery from a known trusted checkpoint.
- Demonstrate that loss of the only trusted checkpoint does not produce a falsely trusted replacement.
- Preserve approval execution recovery records and audit evidence during all recovery paths.

## Enforcement gate

For the sandbox approval API, checkpoint verification is now enforced in the PR #54 code path and missing/unavailable trust anchors fail closed. This is not evidence that the feature branch is deployed or that its external custody is provisioned. The main approval authority remains outside this enforcement change.

Before sandbox F-03 can be considered operationally closed, all of the following must be true:

1. The actual deployment has a separately administered checkpoint bucket and operator identity.
2. The application role is proven read-only for the exact candidate and trusted-floor objects.
3. The stable store ID and explicit freshness/unanchored-suffix policy are selected and configured.
4. The initial candidate and trusted floor are reviewed and independently published.
5. Rollback, tampering, stale/missing checkpoint, S3 outage, crash and recovery tests pass against the intended storage boundary.
6. The deployed runtime configuration is independently verified.
7. A human reviews the security boundary and the owner accepts the remaining operational risks.

This design record does not authorize a deployment, account provisioning, paid service, destructive rotation, audit truncation, or a change to the Cloudflare prototype.
