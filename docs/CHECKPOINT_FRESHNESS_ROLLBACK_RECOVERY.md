# Checkpoint freshness, rollback, and recovery policy verification

## Scope and enforcement status

This milestone adds an explicit policy-verification function for the existing
main and sandbox checkpoint envelopes. It does not connect the function to
approval routes, sandbox lifecycle operations, startup, or any enforcement
decision. Mandatory checkpoint enforcement remains disabled.

No production freshness duration, publication cadence, or maximum unanchored
suffix is selected here. The caller must provide both limits explicitly to
the policy verifier. This prevents a test-only value from silently becoming a
production security policy.

## Trust model: checkpoint plus independent trusted floor

A checkpoint file by itself cannot prove that it has not been replaced by an
older valid checkpoint. A local hash chain also cannot prove monotonicity if
an attacker can restore both the audit data and its checkpoint.

Rollback detection therefore requires two separate pieces of state:

1. The candidate checkpoint for the relevant authority and store.
2. A trusted floor representing the last checkpoint accepted by the operator.

The trusted floor must be retained independently of the candidate checkpoint
and must not be writable or restorable by the application UID. It preserves
the accepted sequence, head hash, legacy-prefix count, and publication
timestamp for that authority/store. The floor's checkpoint ID is retained for
operator evidence. If the floor is stored beside the candidate in the same
rollbackable location, it does not provide rollback protection.

This model protects against application-UID compromise only while the
operator-controlled floor remains trustworthy. It does not protect against
host root, kernel, operator-account, or physical recovery compromise. A local
file and a local floor cannot prove their own monotonic history against an
attacker who can restore both.

The floor schema is exactly:

| Field | Meaning |
| --- | --- |
| `authority` | `main` or `sandbox` |
| `store_id` | Trusted identity of that audit store |
| `sequence` | Last operator-accepted sequence |
| `head_hash` | Hash at that accepted sequence |
| `legacy_entries` | Main audit legacy-prefix count; always zero for sandbox |
| `created_at` | Last accepted checkpoint timestamp |
| `checkpoint_id` | Last accepted checkpoint identifier |

Main and sandbox floors must be retained independently. A floor from one
authority or store cannot be used for another.

## Policy verifier

`stage2_sdk_ai.audit_checkpoint_integrity.verify_checkpoint_with_policy`
requires:

- candidate checkpoint;
- authority and trusted store ID;
- independently loaded trusted floor;
- explicit evaluation time;
- explicit maximum checkpoint age in seconds;
- explicit maximum unanchored suffix event count.

The verifier first compares the candidate against the trusted floor,
then verifies both anchors against one locked audit-history snapshot, and
finally evaluates age and suffix limits. This prevents a locally valid,
rehashed history from being accepted merely because a newer candidate was
generated after the rewrite: the earlier operator-trusted prefix must still be
present. Checking both anchors from one locked snapshot also prevents an
intervening audit rewrite from making two separate reads validate different
histories. The floor includes the main legacy-prefix count so the main
verifier can validate its exact historical boundary. It rejects:

- candidate sequence below the trusted floor;
- a different head hash at the same sequence;
- a checkpoint timestamp older than the trusted floor;
- a timestamp in the future;
- age greater than the configured maximum;
- an unanchored suffix greater than the configured maximum;
- missing candidate or missing trusted floor;
- malformed floor, wrong authority, or wrong store identity;
- a trusted floor whose sequence/hash no longer matches the audit history.

The policy function has no defaults and does not persist or advance the floor.
A successful return means only that the supplied checkpoint passed this
explicit verification call. The operator must separately decide whether to
retain it as the new floor. No code path automatically updates trusted state.

A zero maximum age or zero unanchored suffix is permitted as an explicit
strict policy. The operator must set the checkpoint timestamp at the
checkpointing event, not reuse a timestamp from an earlier snapshot. Time
comparisons use the supplied wall-clock timestamp; the host must have an
operator-managed, trustworthy clock. Clock rollback or future-dated
checkpoint timestamps are rejected rather than silently corrected.

## Rollback and recovery behavior

### Restored older checkpoint

If the candidate sequence is lower than the trusted floor, verification
raises `AuditCheckpointRollbackError`, even when the candidate is a valid
prefix of the current audit history. This is the key case a local hash-chain
check alone cannot identify.

If the candidate has the same sequence but a different head hash, it is
treated as a conflicting history and rejected. A lower publication timestamp
is also rejected, including when the sequence and head hash are unchanged.

### Missing candidate or lost trusted floor

If either the candidate checkpoint or trusted floor is missing, verification
raises `AuditCheckpointRecoveryRequired`. It does not export the current
audit head as a replacement, create a new floor, or infer that current local
history is trusted.

Recovery must preserve the audit log, archived segments, candidate checkpoint,
floor copies, and diagnostic evidence. An operator must investigate from an
independently retained trusted copy. If every trusted floor copy is lost, the
current audit head cannot be silently re-established as trusted. Any
re-baselining requires a separately reviewed, explicit operator decision and
must record the loss of the previous trust anchor.

### Recovery procedure

1. Stop any proposed checkpoint advancement; do not truncate or rewrite audit
   data.
2. Preserve byte-for-byte copies of active audit files, archived segments,
   candidate checkpoint files, floor copies, and relevant filesystem metadata.
3. Compare the candidate with the independently retained floor and verify the
   full main or sandbox audit history.
4. Determine whether the event is a stale checkpoint, sequence rollback,
   same-sequence fork, audit truncation, checkpoint loss, or filesystem
   publication failure.
5. Record the operator's findings and recovery decision outside the
   application-writable storage boundary.
6. Only after independent review may an operator publish a new checkpoint and
   update the separately protected floor. Never perform either action as an
   automatic response to an integrity failure.

If the operator floor itself may have been rolled back, this procedure cannot
restore trust from the current local files alone. Escalate to an independent
backup or other trusted evidence.

## Tests added

The focused checkpoint integrity suite now covers:

- age exactly at the configured boundary and age beyond the limit;
- suffix exactly at the configured boundary and suffix beyond the limit;
- restoration of an older valid main checkpoint;
- restoration of an older valid sandbox checkpoint;
- validly rehashed main history rewritten after the trusted floor;
- validly rehashed sandbox history rewritten after the trusted floor;
- same-sequence publication-time regression;
- future-dated checkpoint;
- missing checkpoint and missing trusted floor;
- invalid policy limits and cross-store floor substitution;
- main and sandbox policy acceptance with explicit limits.

Run:

```sh
PYTHONPATH=. CI=true OPENAI_API_KEY=sk-test-mocked pytest -q -o addopts="" tests/test_audit_checkpoint_integrity.py
```

## Gates before enforcement

1. Run the two-UID filesystem proof on the actual intended Linux host, not only
   the GitHub runner. Inspect UID/GID separation, ACLs, mount options,
   supplementary groups, checkpoint and floor ownership, and every ancestor
   directory.
2. Demonstrate that the application UID cannot write, replace, restore, or
   delete either the checkpoint or trusted floor.
3. Select production freshness and suffix limits based on actual audit volume
   and operational requirements; this document intentionally selects none.
4. Demonstrate backup and recovery of the trusted floor independently from
   the candidate checkpoint.
5. Test rollback, missing-floor, lost-checkpoint, publication interruption,
   and operator recovery on the target filesystem.
6. Complete full CI and human security review.
7. Obtain explicit approval for a separate runtime-enforcement change.

Until every gate is complete, checkpoint verification remains opt-in and
mandatory enforcement remains disabled. This work does not authorize paid
infrastructure, deployment changes, destructive truncation, checkpoint
self-repair, or changes to the Cloudflare prototype.
