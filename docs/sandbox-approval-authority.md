# Sandbox approval authority API

This API is separate from the existing note-write approval endpoints. It does not
change /write, /approve, /deny, /write/execute, or their stored records.

## Deployment configuration

Configure these values through the service runtime or a secret manager. Never
commit credentials or the private signing key.

- AGENT_API_KEYS: explicitly named requester credentials, for example
  second-brain=REQUESTER_SECRET.
- AGENT_APPROVER_KEYS: separately provisioned named approver credentials,
  for example owner=APPROVER_SECRET. The same human must use the same stable
  identity in both variables; self-approval is rejected.
- Each sandbox-approval requester and approver secret must contain at least
  32 ASCII characters. Generate independent random values with
  `python -c "import secrets; print(secrets.token_urlsafe(32))"`. Do not use
  human-created passwords, shared secrets, repository variables visible to
  untrusted workflows, or values copied between roles. Legacy unnamed keys
  and shorter credentials remain available only to unrelated legacy API
  paths; they cannot authenticate to this versioned approval API.
- SANDBOX_APPROVAL_ISSUER: stable authority identifier, for example
  github-practice-ai.
- SANDBOX_APPROVAL_AUDIENCE: intended relying-party identifier, for example
  second-brain.
- SANDBOX_APPROVALS_DIR: absolute path to a private, persistent directory
  outside the repository checkout and sandbox workspaces.
- SANDBOX_APPROVAL_ACTIVE_KID: active signing-key identifier.
- SANDBOX_APPROVAL_SIGNING_PRIVATE_KEY: Ed25519 private key in PEM format.
- SANDBOX_APPROVAL_VERIFY_KEYS: JSON object mapping key IDs to Ed25519
  public-key PEM strings. Include the active key and any previous public keys
  still needed to verify unexpired receipts.

The active private key must match the public key under the active key ID.
Missing or inconsistent configuration fails closed. Protect the service host,
private key, storage directory and backups independently of the caller.

## HTTP contract

All routes are under /v1/sandbox/approvals.

| Method and path | Authentication | Purpose |
|---|---|---|
| POST /v1/sandbox/approvals | X-API-Key | Create a pending request |
| POST /{id}/approve | X-Approver-Key | Approve once and return signed receipt |
| POST /{id}/deny | X-Approver-Key | Deny once |
| GET /{id}/decision | X-API-Key | Retrieve signed decision evidence |
| GET /{id} | X-API-Key | Inspect decision and consumption state |
| POST /{id}/consume | X-API-Key | Consume once or retrieve identical retry outcome |

The create request contains only scope:

- repository: owner/repository
- sandbox_id: stable sandbox identifier
- base_sha: exact recorded base commit
- head_sha: exact proposed commit
- diff_sha256: SHA-256 digest of the complete reviewed change set
- action: exactly prepare_pull_request

The authority derives requester and approver identities from their authenticated
credentials. It rejects extra request fields. The request scope cannot be changed
after creation. Requests expire after 15 minutes. The configured identity is an
operator-assigned principal label, not proof of a natural person's identity.
The owner must independently verify credential custody, holder identity and
separation of duties before enabling a production approval workflow.

## Signed decision

An approved decision returns a receipt with Ed25519 algorithm, a key ID, claims
and a URL-safe base64 signature. The signature covers canonical JSON of all
claims: issuer, audience, approval ID, nonce, requester, approver, full scope,
issue time, expiry and decision.

A relying party must verify the signature using its independently provisioned
trusted public keys, check the expected issuer and audience, enforce expiry,
and compare every scope field with its current sandbox state. In particular it
must recompute the full diff digest and confirm base and head SHAs before
consumption. A valid signature alone is not permission to act on a different
sandbox or commit.

## One-time consumption and recovery

The consume body contains:

- request_id: caller-generated UUID persisted before the request is sent;
- nonce: the exact nonce from the signed receipt;
- scope: the complete original scope, unchanged.

The first successful consume atomically records the UUID, nonce, exact-payload
digest and result. A retry with the same UUID, nonce and identical scope returns
the same result. A different UUID, nonce or payload is rejected. The authority
never resets a consumed approval.

If a response or audit write is uncertain, inspect the approval using the same
requester identity and reconcile its persisted state. After restart, the
authority may mark an incomplete record/audit status complete only when the
existing hash-chained audit proves the exact expected lifecycle in order and
matches the immutable request scope, actor, signed receipt and consumption
fingerprint. It never invents a missing event or recreates an approval from a
mutable record. Missing, partial, conflicting or corrupt evidence remains
fail-closed and requires operator recovery; it is not a reason to issue a new
approval automatically. The audit file is fsynced after append, and its parent
directory is fsynced when the audit file is first created. Record replacement
uses a temporary file, file fsync, atomic rename and directory fsync.

## Storage and key rotation limitations

The approval store uses private local files and POSIX file locking. It is a
single-host design: do not run multiple hosts against shared storage, NFS, or
independent ephemeral disks. Use one authoritative service instance with a
persistent private volume. A future multi-host deployment requires a separately
designed transactional store and concurrency proof.

For key rotation, provision the new private key and matching public key under a
new key ID, make that key ID active, and retain the old public key during the
verification overlap. Remove the old public key only after all receipts signed
with it have expired and any required recovery window has closed. Never copy the
private key to the relying application.

The hash-chained local audit log is integrity-checked before it is extended
and before inspection or decision evidence is returned. When a process stops
after a durable audit append but before the record's completion marker is
saved, the next operation reconciles only an exact event sequence that matches
the stored request, actor, scope, receipt and consumption outcome. A missing
event, incomplete final line, conflicting terminal event or corrupt chain
blocks authorization and requires operator review. Terminal decision and
consume events are checked against mutable records so restoring an old record
cannot re-authorize a completed approval while the audit history remains
intact. The local hash chain alone cannot detect rollback of the entire
audit file to an earlier valid snapshot. The sandbox approval lifecycle now
requires a separately retained S3 candidate checkpoint and operator-accepted
trusted-floor manifest before create, decision, inspection, decision retrieval
and consumption. The manifest pins the candidate's exact S3 VersionId and
checkpoint content identity. The application role has `s3:GetObject` access to
the manifest and `s3:GetObjectVersion` access to the candidate object; operator
credentials publish candidates and advance the manifest/floor. The verifier
checks authority, stable store identity, both historical anchors, candidate
version/content pin, candidate age and the explicit maximum unanchored suffix.
Missing configuration, unavailable S3 custody, a missing pinned version,
rollback or policy failure pauses approval operations for operator review.
See `docs/SANDBOX_AUDIT_CHECKPOINT_RUNBOOK.md`.

This code path does not provision the S3 bucket, IAM policy, operator identity,
stable store ID or policy values. The deployed runtime must be independently
configured and verified. A checkpoint proves history only through its sequence;
events after it remain an unanchored suffix bounded by the configured policy.


## Approver authorization boundary

The sandbox approval authority accepts the approver credential at its decision
boundary and resolves the principal identity itself. Callers must not pass an
asserted approver identity: the authority validates the credential against the
explicitly named `AGENT_APPROVER_KEYS` allow-list and requires the requester
allow-list to contain explicit identities as well. The resolved identity is
stored in the decision and signed receipt; the raw credential is never stored.

The HTTP layer also authenticates and rate-limits approver requests before
dispatch. The authority repeats credential validation so internal callers
cannot bypass authorization by supplying a fabricated principal name. Invalid,
missing, legacy unnamed, malformed, or role-conflicting credentials fail closed.

## API lifecycle enforcement matrix

Every state-changing HTTP route delegates the transition to the authority and
must preserve its result rather than treating an attempted transition as
success:

| Route | Required principal | Ownership / lifecycle rule | Audit requirement |
|---|---|---|---|
| POST collection | Named requester | Creates only a pending request owned by that requester | Creation event must be durable before success |
| POST /{id}/approve | Named approver | Approver must differ from requester; only pending, unexpired requests may transition | Approval event and signed receipt must be durable before success |
| POST /{id}/deny | Named approver | Same separation-of-duties and pending-only transition; denial is terminal | Denial event must be durable before success |
| POST /{id}/consume | Owning named requester | Approved receipt, nonce, full scope and idempotency UUID must match; only identical retries are accepted | Consumption event must be durable; uncertain writes remain consumed and require review |
| GET /{id} | Owning named requester | No cross-requester inspection | Audit history is parsed and integrity-checked |
| GET /{id}/decision | Owning named requester | Evidence is returned only for a completed approved decision | Audit chain and signed receipt must verify |

The versioned API tests exercise authorization and rate limiting on both decision
routes and consumption, requester isolation on both read routes and consumption,
terminal decisions, identical-only consume retries, and fail-closed HTTP
responses when decision or consumption audit writes fail. These HTTP checks
complement—not replace—the authority's own identity, scope, transition, and
hash-chain validation.

The legacy note-write API has a separate lifecycle: `POST /write` creates a
request for the authenticated requester, `POST /approve` and `POST /deny`
require a separately configured approver, and `POST /write/execute` requires
the owning requester and a durably audited, unconsumed approval. Its existing
API tests cover self-approval, ownership mismatch, terminal decisions,
audit-write failures, replay, and execution recovery.



## Credential custody, rotation and human identity

Provision requester and approver secrets independently, through an operator-
controlled secret manager or equivalent restricted deployment mechanism. Grant
read access to each secret only to the service component and human/operator
role that requires it. Keep secret values out of source control, build logs,
CI output, audit records, issue comments and pull-request descriptions.

The approval parser rejects unnamed principals, malformed or duplicate entries,
secrets shorter than 32 ASCII characters, and any secret reused across requester
and approver roles. To rotate or revoke a credential, replace or remove its
single named entry in the authoritative secret configuration and restart or
reload the service through its controlled deployment procedure. The old value
must cease authenticating after the configuration change is active. This
configuration does not support overlapping old and new secrets for the same
identity; plan rotation as a coordinated cutover and verify the old credential
is rejected.

These controls establish distinct configured credential principals. They do
not prove that two credentials are held by two different natural persons, that
a credential holder is the named person, or that an approver completed MFA or
WebAuthn step-up. Those claims require the separate human identity assurance
milestone.
