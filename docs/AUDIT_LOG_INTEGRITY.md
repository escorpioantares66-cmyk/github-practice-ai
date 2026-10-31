# Audit log integrity

The approval audit log remains JSON Lines at `logs/audit.jsonl`. New entries include:

- `seq`: monotonically increasing chain sequence number
- `previous_hash`: SHA-256 digest of the preceding chained entry
- `hash`: SHA-256 digest of the canonical entry fields, excluding `hash`

Canonical JSON uses sorted keys, compact separators, UTF-8, and rejects non-finite numbers. The verifier rejects invalid schemas, duplicate JSON keys, invalid hashes, sequence gaps, broken links, reordered entries, incomplete trailing lines, and legacy entries inserted after the chain begins.

## Existing log compatibility

Existing three-field entries (`action`, `time`, `record`) are accepted as a legacy prefix. On the first new append, the first chained entry's `previous_hash` commits to the SHA-256 digest of the exact legacy-prefix bytes. This does not retroactively prove that legacy entries were authentic before the upgrade; it detects changes to that prefix after the first chained entry is written.

## Verify the log

Call `stage2_sdk_ai.approval.verify_audit_log()`. It validates the complete log under the same exclusive file lock used by appends and returns:

- `valid`: true only when the complete local history validates
- `entries`: total legacy plus chained entries
- `chained_entries`: number of chained entries
- `head_hash`: current chain head (or the legacy-prefix digest before the first chained append)

Keep a copy of `head_hash` outside the machine and outside the audit directory after important milestones. Compare a later verification result with that independently retained value to detect whole-log replacement, truncation, or a rewrite that recalculates every local hash.

## Security boundary

A local SHA-256 chain detects accidental or partial tampering, deletion, and reordering when the attacker cannot also replace the trusted head hash. It is **not** a digital signature and does not prevent an attacker with write access to the entire local storage area from rewriting the complete log and recalculating all hashes. The independently retained head hash is the external trust anchor. Stronger unattended anchoring requires a separately administered append-only service, signed checkpoint, or HMAC/signing key held outside this machine; none is silently assumed or configured by this implementation.

The log is still protected by private filesystem permissions, no-follow file opens, an exclusive advisory lock, bounded validation, and durable append semantics. Those controls do not protect against a privileged attacker who controls the host or can replace both the log and its external checkpoint.
