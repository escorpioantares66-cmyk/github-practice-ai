# Sandbox approval audit checkpoint runbook

## Purpose and enforcement

The sandbox approval authority now verifies its local audit history against two
independently retained S3 objects before every approval lifecycle operation:

1. **Candidate checkpoint** — the latest operator-published audit head.
2. **Trusted floor** — the last checkpoint explicitly accepted by the operator.

The API application role has read-only access. It cannot create, advance,
replace, delete or restore either object. Missing configuration, unavailable
S3 access, invalid objects, rollback, excessive checkpoint age or an excessive
unanchored suffix fail closed and pause approval operations.

This is a single-host v1 control. It does not provide protection against
compromise of the AWS account administrator, operator credentials, host root,
kernel or physical recovery environment.

## Required runtime configuration

Set these values through the deployment's secret/configuration mechanism.
Do not commit credentials or account identifiers to the repository.

| Variable | Requirement |
| --- | --- |
| `AGENT_AUDIT_CHECKPOINT_S3_BUCKET` | Dedicated private S3 bucket |
| `AGENT_SANDBOX_AUDIT_CHECKPOINT_S3_KEY` | Candidate object key; defaults to `audit-checkpoints/sandbox/latest.json` |
| `AGENT_SANDBOX_AUDIT_CHECKPOINT_FLOOR_S3_KEY` | Trusted-floor object key; defaults to `audit-checkpoints/sandbox/trusted-floor.json` |
| `AGENT_SANDBOX_AUDIT_STORE_ID` | Stable, unique operator-provisioned ID for this sandbox audit store |
| `AGENT_SANDBOX_AUDIT_CHECKPOINT_MAX_AGE_SECONDS` | Explicit maximum candidate age; no default |
| `AGENT_SANDBOX_AUDIT_MAX_UNANCHORED_SUFFIX` | Explicit maximum events after the candidate checkpoint; no default |
| `AWS_REGION` or `AWS_DEFAULT_REGION` | Region for the S3 client |

The candidate and trusted-floor keys must be different. The store ID must
remain stable for the lifetime of the audit history; do not reuse it for
another environment, authority or tenant.

Choose the age and suffix limits as an explicit risk/operations decision.
A lower suffix limit narrows the amount of unanchored history but requires
more frequent operator publication. A suffix limit of zero requires a
checkpoint at the exact current audit head before the next operation. The
code deliberately selects neither limit.

## S3 and IAM boundary

1. Use a dedicated private bucket with Block Public Access enabled, bucket
   owner enforced object ownership, default encryption and versioning.
2. Store the candidate and trusted floor at the two configured object keys.
   Keep version history and backup/recovery procedures under operator control.
3. Give the API application role only `s3:GetObject` on those two exact object
   ARNs. It must not have `s3:PutObject`, `s3:DeleteObject`,
   `s3:DeleteObjectVersion`, `s3:ListBucket`, bucket-policy administration
   or IAM administration permissions.
4. Use a separate operator identity/profile to publish checkpoint objects.
   Its credentials must not be available to the API process or stored in the
   application environment.
5. Consider S3 Object Lock only after reviewing retention, cost and recovery
   requirements. Versioning alone is not immutable retention against an
   administrator who can delete object versions.

The application reads both exact object keys on each approval operation.
It does not cache a successful verification as a substitute for checking the
current external trust anchors.

## Initial bootstrap

Bootstrap must be performed before enabling approval routes:

1. Provision the private sandbox approval directory under the application
   service identity. Create an empty regular `audit.jsonl` file with mode
   `0600`; the directory must be private and owned by the application UID.
2. Set the stable store ID and the S3 bucket/key/policy configuration.
3. Under the application identity, create an in-memory sandbox checkpoint.
   The command below emits a bundle to standard output; the shell redirection
   should be performed by the operator so the application cannot write the
   operator's staging file:

```bash
sudo -u APP_SERVICE_USER python - <<'PY' > sandbox-checkpoint-bundle.json
import json
import os
from stage2_sdk_ai.audit_checkpoint_store import create_sandbox_audit_checkpoint

checkpoint = create_sandbox_audit_checkpoint(
    os.environ["AGENT_SANDBOX_AUDIT_STORE_ID"]
)
floor_fields = (
    "authority", "store_id", "sequence", "head_hash",
    "legacy_entries", "created_at", "checkpoint_id",
)
trusted_floor = {field: checkpoint[field] for field in floor_fields}
print(json.dumps(
    {"checkpoint": checkpoint, "trusted_floor": trusted_floor},
    sort_keys=True,
    separators=(",", ":"),
))
PY
```

4. Have the operator inspect the generated checkpoint and confirm that it
   identifies authority `sandbox`, the intended store ID, sequence zero and
   the all-zero head hash for the empty audit log.
5. Split the bundle into the two JSON objects and publish them using the
   separate operator AWS profile:

```bash
jq -c .checkpoint sandbox-checkpoint-bundle.json > latest.json
jq -c .trusted_floor sandbox-checkpoint-bundle.json > trusted-floor.json
aws s3 cp latest.json s3://YOUR_BUCKET/audit-checkpoints/sandbox/latest.json \
  --profile audit-checkpoint-admin
aws s3 cp trusted-floor.json s3://YOUR_BUCKET/audit-checkpoints/sandbox/trusted-floor.json \
  --profile audit-checkpoint-admin
```

6. Verify both object contents and their versions using the operator identity.
   Confirm that the API role can retrieve both objects but cannot write,
   replace, delete or list them.
7. Start with synthetic requests and verify that approval operations succeed
   only while the external checkpoint service is available and the local
   history matches the trusted anchors.

The bootstrap command assumes the operator has supplied the configured
environment to the application process. Do not run it against an existing
store after an integrity failure to create a replacement trust anchor.

## Checkpoint advancement

Checkpoint advancement is a human-controlled operation:

1. Preserve the current audit file and existing S3 objects.
2. Verify the current audit chain and compare it with the existing candidate
   and trusted floor.
3. Investigate any mismatch, stale checkpoint, rollback, missing object or
   unanchored suffix policy failure. Do not publish a replacement to clear an
   integrity error.
4. Under the application identity, emit a new candidate checkpoint for the
   current sandbox audit head.
5. The operator independently reviews the candidate, event sequence and
   reason for advancement.
6. Publish the new candidate object. Advance the trusted floor only after the
   operator explicitly accepts that checkpoint. Preserve prior S3 versions and
   record the operator, timestamp, checkpoint ID and review evidence outside
   the application-writable store.

The API role must never receive the operator publishing credentials. An
application-generated checkpoint is only a candidate until the operator
reviews and publishes it.


## Concurrency, checkpoint freshness and residual windows

All sandbox approval lifecycle operations on one host are serialized by a
private application-owned policy lock. The lock covers S3 candidate/floor
verification, the per-approval transition and its audit append. This prevents
concurrent requests for different approval IDs from all passing the same
unanchored-suffix check and collectively exceeding the configured suffix cap.
The per-approval lock is then acquired, and candidate/floor verification is
repeated while that lock is held, immediately before the record is read or
changed.

This is a single-host guarantee. Do not share the file-backed store across
hosts or NFS. The policy lock does not serialize an independent operator
changing S3 objects after the application has retrieved them. S3 object-version
IDs are not pinned by this integration, and code does not make the trusted
floor immutable. Operator publication, version retention and IAM custody
remain part of the trusted computing base; independently verify those
controls.

The suffix is a deliberate risk budget, not a claim that unanchored events are
tamper-proof. A configured maximum of N permits up to N audit events after the
candidate checkpoint to remain outside the anchored prefix. Select N and the
checkpoint age/cadence together based on the maximum rollback/replay window
the owner will accept. For the strongest approval assurance, use a zero-event
suffix and publish/accept a checkpoint after each audit append before another
approval-sensitive operation; this can pause the service between operator
publications. A larger suffix improves availability but increases unanchored
history exposure. Do not choose a production value implicitly in code or
infer that a low age limit removes the suffix risk.

## Interrupted record writes before audit append

A process can stop after the approval record is saved with
`audit_status="pending"` but before the corresponding audit event is appended.
That state is not equivalent to a successful transition. On restart, automatic
reconciliation is allowed only if the audit contains the exact complete
lifecycle and matches the record's scope, actor, receipt, timestamps and
consumption details. If the event is missing, partial, conflicting or corrupt,
the operation remains unavailable for operator review; do not reset the
record to pending, delete the event, truncate the log, or generate a replacement
checkpoint to make it pass. Preserve the record and audit bytes, compare them
with the last trusted floor, and record an operator-controlled recovery
decision outside application-writable storage.

## Failure and recovery

Approval operations pause if either object is missing or unreadable, if S3 is
unavailable, if the candidate or floor has the wrong authority/store ID, if
the candidate regresses behind the floor, if the local log no longer contains
the trusted floor, or if freshness/suffix policy is exceeded.

On failure:

1. Stop approval-sensitive operations; do not delete or rewrite audit data.
2. Preserve the active audit file, candidate, trusted floor, S3 object versions
   and relevant logs/metadata.
3. Compare local history with the last independently retained trusted floor.
4. Determine whether the event is checkpoint loss, stale publication,
   truncation, full-store rollback, a same-sequence fork or an S3 access issue.
5. Record the investigation and recovery decision outside application storage.
6. Resume only after an operator has verified the history and deliberately
   published a new candidate/floor pair.

If every trusted floor copy is lost, do not export the current local head and
silently declare it trusted. Re-baselining requires a separately reviewed
owner decision and explicit evidence that the previous trust anchor was lost.

## Verification status and remaining operational gates

The repository tests use synthetic S3 objects and temporary audit storage.
The Linux two-UID proof demonstrates a separate operator-owned read-only
checkpoint filesystem boundary on a GitHub-hosted Linux runner. Neither test
proves that a production S3 bucket, IAM policy, operator identity, backup
process, deployment environment or selected policy values have been
provisioned.

Before production use, independently verify the actual bucket, exact IAM
permissions, operator credential separation, version retention, backup and
recovery, stable store ID, chosen age/suffix limits and the deployed API
configuration. No production deployment or permission change is authorized
by this runbook.
