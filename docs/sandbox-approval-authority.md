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
after creation. Requests expire after 15 minutes.

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
requester identity and reconcile its persisted state. An incomplete audit state
or corrupt audit chain fails closed and requires operator review; it is not a
reason to issue a new approval automatically.

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

The hash-chained local audit log is integrity-checked before it is extended and
before inspection or decision evidence is returned. Terminal decision and consume
events are checked against mutable records so restoring an old record cannot
re-authorize a completed approval while the audit history remains intact. It is
not a substitute for independent protected backups or a remote immutable audit
checkpoint.
