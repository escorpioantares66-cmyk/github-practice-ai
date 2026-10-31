# Audit log integrity

The approval audit log remains JSON Lines at `logs/audit.jsonl`. New entries include:

- `seq`: monotonically increasing chain sequence number
- `previous_hash`: SHA-256 digest of the preceding chained entry
- `hash`: SHA-256 digest of the canonical entry fields, excluding `hash`

Canonical JSON uses sorted keys, compact separators, UTF-8, and rejects non-finite numbers. The verifier rejects invalid schemas, duplicate JSON keys, invalid hashes, sequence gaps, broken links, reordered entries, incomplete trailing lines, and legacy entries inserted after the chain begins.

## Existing log compatibility

Existing three-field entries (`action`, `time`, `record`) are accepted as a legacy prefix. On the first new append, the first chained entry's `previous_hash` commits to the SHA-256 digest of the exact legacy-prefix bytes. This does not retroactively prove that legacy entries were authentic before the upgrade; it detects changes to that prefix after the first chained entry is written.

## External checkpoints and verification

Create a checkpoint with `stage2_sdk_ai.approval.create_audit_checkpoint()`. It returns a versioned object containing the chained sequence, legacy-prefix entry count, head hash, and creation time. Store this object independently of the host and audit directory (for example, in a separately administered secrets/configuration system or offline operator record).

Pass the retained object to `stage2_sdk_ai.approval.verify_audit_log(expected_checkpoint)`. Verification checks the complete local chain and confirms that the checkpoint sequence still exists with the same hash and legacy-prefix count. A checkpoint remains valid when newer entries are appended. If the log is truncated behind the checkpoint, replaced with an empty file, or diverges at the checkpoint sequence, verification raises `AuditLogIntegrityError`. A malformed or modified checkpoint is also rejected.

A checkpoint created before any chained event can anchor an existing legacy-only prefix (sequence zero plus the legacy-prefix digest). Keep checkpoints after important milestones and rotate/store them independently. Checkpoints kept only beside the log are not independent trust anchors.

The verifier without an expected checkpoint proves only internal consistency. It cannot detect deletion of a valid suffix. External checkpoint verification is therefore required for operational truncation detection.

## Security boundary

A local SHA-256 chain detects accidental or partial tampering, deletion, and reordering when the attacker cannot also replace the trusted head hash. It is **not** a digital signature and does not prevent an attacker with write access to the entire local storage area from rewriting the complete log and recalculating all hashes. The independently retained head hash is the external trust anchor. Stronger unattended anchoring requires a separately administered append-only service, signed checkpoint, or HMAC/signing key held outside this machine; none is silently assumed or configured by this implementation.

The log is still protected by private filesystem permissions, no-follow file opens, an exclusive advisory lock, bounded validation, and durable append semantics. Those controls do not protect against a privileged attacker who controls the host or can replace both the log and its external checkpoint.
