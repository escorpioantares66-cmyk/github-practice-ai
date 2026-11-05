# Main and sandbox checkpoint-integrity verification

## Scope and status

This milestone adds an explicit verification API for two independent audit
authorities. It is **not** a runtime dependency and does not enable mandatory
checkpoint enforcement.

- Main approval history uses authority identifier `main`.
- Sandbox approval history uses authority identifier `sandbox`.
- Each requires a separate operator-provisioned `store_id` and independently
  retained checkpoint.
- A checkpoint for one authority or store is rejected when supplied for the
  other.
- No checkpoint is automatically created, published, repaired, rotated, or
  deleted by this verification API.

## Envelope

The strict version-1 JSON envelope contains exactly:

| Field | Meaning |
| --- | --- |
| `format_version` | Integer format version, currently 1 |
| `authority` | Exactly `main` or `sandbox` |
| `store_id` | Stable identity supplied by trusted operator configuration |
| `sequence` | Authority-specific chained-event sequence |
| `head_hash` | SHA-256 hash at that sequence |
| `legacy_entries` | Main legacy-prefix count; always zero for sandbox |
| `created_at` | Positive finite UTC epoch timestamp |
| `checkpoint_id` | 32-character lowercase hexadecimal publication ID |

Validation rejects missing or unknown fields, duplicate JSON keys, boolean
values in integer fields, invalid hashes, non-finite timestamps, invalid
identities, and payloads larger than 16 KiB. The expected authority and
`store_id` must come from trusted configuration supplied by the caller; the
values inside the untrusted envelope are only compared against those inputs.

## How to use the verifier

The module `stage2_sdk_ai.audit_checkpoint_integrity` exposes:

- `create_checkpoint_envelope(authority, store_id)`: creates an in-memory
  snapshot of the verified head. It does not write or publish it.
- `serialize_checkpoint(...)` and `parse_checkpoint(...)`: canonical,
  bounded JSON serialization and strict parsing.
- `verify_checkpoint(checkpoint, authority, store_id)`: verifies the matching
  main or sandbox audit chain against the supplied checkpoint.

A successful verification anchors history only through
`checkpoint_sequence`. The result reports `current_sequence` and
`unanchored_suffix`. A nonzero suffix is valid append-only history after the
anchor, but it is **not independently checkpointed**. This code intentionally
does not decide freshness, maximum suffix size, or whether that suffix is
acceptable for a sensitive operation.

## Integrity and recovery boundaries

Tampering, truncation, or divergence at or before the stored sequence fails
verification. A lower-sequence checkpoint may verify as a valid prefix; it
must not be described as proof of the current head. The verifier does not
automatically advance or replace a checkpoint after any error.

The local checkpoint file path, ownership, group, permissions, ACLs, mount
options, publication credentials, and crash durability remain separate
operator responsibilities covered only in part by the Linux two-UID proof.
This API does not read a checkpoint path or claim that a passed object came
from an independent location.

The main and sandbox audit stores retain their existing write and lifecycle
behavior. In particular, this change does not alter approval consumption,
execution recovery, audit rotation, retention, note storage, deployment, or the
Cloudflare prototype.

## Tests

Run the focused suite:

```sh
PYTHONPATH=. CI=true OPENAI_API_KEY=sk-test-mocked pytest -q -o addopts="" tests/test_audit_checkpoint_integrity.py tests/test_audit_checkpoint_store.py
```

The tests cover both authority chains, valid append-only suffix reporting,
tampering before the anchor, cross-authority/store rejection, strict envelope
validation, duplicate-key parsing, payload bounds, and canonical round-trip.

## Gates still open

1. Run the two-UID filesystem proof on the actual intended Linux host and
   inspect its ACLs, mount options, supplementary groups, and ancestor paths.
2. Choose an acceptable checkpoint publication cadence and maximum
   unanchored suffix before enforcement is considered.
3. Define and test operational freshness/rollback handling, including restore
   of an older checkpoint and loss of the only trusted copy.
4. Review production store identity provisioning and checkpoint backup/recovery.
5. Obtain explicit human approval for a separate runtime-enforcement change.

Mandatory enforcement remains disabled. This verification milestone does not
authorize paid infrastructure, deployment, destructive truncation, or
checkpoint self-repair.
