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


## Amazon S3 checkpoint storage (read-only application integration)

The application integration deliberately has **read-only S3 access**. It does not upload or overwrite the trusted checkpoint: an application process that can both rewrite the audit log and publish a new trusted head could defeat the external trust anchor. An operator publishes checkpoints using separate AWS credentials; the running application can only retrieve and verify them.

### Low-cost AWS setup

1. In the AWS Console, create a dedicated S3 bucket in a region near your users. Use a globally unique bucket name. Keep **Block all public access** enabled, **Bucket owner enforced** object ownership, and default server-side encryption enabled.
2. Enable **S3 Versioning**. Each operator upload to the checkpoint key then preserves the prior version. Do not grant the application role permission to write, delete, or list objects.
3. Create a dedicated IAM role/user for the application with only `s3:GetObject` on this one object ARN: `arn:aws:s3:::YOUR_BUCKET/audit-checkpoints/latest.json`. Do not attach broad S3 policies. Prefer short-lived role credentials where available; otherwise protect the read-only credentials on the host.
4. Keep a separate operator/admin identity for publishing checkpoints. Protect its credentials separately from the application runtime. Do not put either credential in Git, source files, shell history, or issue comments.

Versioning retains prior object versions but is not the same as immutable retention: an administrator with version-delete privileges can still remove them. S3 Object Lock is an optional stronger control, but it must be enabled when creating the bucket and cannot later be disabled; assess retention and cost requirements before enabling it.

### Install and configure the application

Install the optional S3 dependency in the project environment:

```bash
python -m pip install -e '.[audit-s3]'
```

Configure the application with its **read-only** AWS credentials using your normal secure credential provider (IAM role, AWS profile, or environment injected by your host). Set:

```bash
export AGENT_AUDIT_CHECKPOINT_S3_BUCKET="YOUR_BUCKET"
export AGENT_AUDIT_CHECKPOINT_S3_KEY="audit-checkpoints/latest.json"
export AWS_REGION="YOUR_AWS_REGION"
```

The application can now verify using:

```python
from stage2_sdk_ai.audit_checkpoint_store import verify_audit_log_from_s3

result = verify_audit_log_from_s3()
print(result)
```

The helper retrieves a bounded JSON object, rejects duplicate JSON keys and malformed responses, and verifies the local audit log against the external checkpoint. Missing credentials, missing objects, or integrity mismatches fail closed with `AuditCheckpointStoreError`.

### Publish or advance a checkpoint (operator action)

After a trusted operator has reviewed the audit log, export a checkpoint locally:

```python
from stage2_sdk_ai.audit_checkpoint_store import export_audit_checkpoint

export_audit_checkpoint("private-checkpoint/latest.json")
```

Then, using the separate operator AWS profile (not the application's read-only credentials), upload it:

```bash
aws s3 cp private-checkpoint/latest.json \
  s3://YOUR_BUCKET/audit-checkpoints/latest.json \
  --profile audit-checkpoint-admin
```

Because bucket versioning is enabled, the previous `latest.json` version remains available. Restrict the admin profile and its credentials; it is the authority that advances the trusted checkpoint. Confirm the uploaded object in the AWS Console or with the admin profile before relying on it.

### Operational cautions

- Create and publish the first checkpoint only after reviewing the existing legacy prefix. It anchors the history from that point forward; it cannot authenticate pre-upgrade legacy events.
- Publish checkpoints at a defined cadence (for example, after each reviewed maintenance window or release), not automatically from the same application identity that writes the log.
- If verification fails, stop approval-sensitive operations and investigate. Do not automatically replace the S3 checkpoint with a newly generated one.
- The application role must not have `s3:PutObject`, `s3:DeleteObject`, `s3:DeleteObjectVersion`, or bucket-policy administration permissions.
