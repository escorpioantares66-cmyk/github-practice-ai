# Secure note approval workflow

The note-writing API uses three separate capabilities:

- **Requester credential** (`X-API-Key`): may create a pending note-write request and execute an already-approved request.
- **Approver credential** (`X-Approver-Key`): may approve a pending request. It cannot create or execute writes by itself.
- **Approval ID**: an opaque, random, one-time capability that refers to the exact stored operation. It is not a substitute for either credential.

## Required configuration

Set both variables in the server environment. Use independently generated, high-entropy secrets and never commit them:

~~~sh
export AGENT_API_KEYS="requester-a=replace-with-a-long-random-requester-secret"
export AGENT_APPROVER_KEYS="replace-with-a-different-long-random-approver-secret"
~~~

Requester entries use `identity=secret` syntax and may be comma-separated. Keep the identity label stable when rotating a requester's secret; the approval record stores the label, never the raw secret. Legacy bare secrets remain accepted and receive a deterministic non-secret fingerprint identity, but explicit labels are preferred. An empty or missing allow-list fails closed. Do not reuse the same secret for both roles. Use HTTPS in deployment and keep secrets in the deployment secret manager.

## Lifecycle

### 1. Request a write

~~~http
POST /write
X-API-Key: <requester-secret>
Content-Type: application/json

{"path":"release-notes.md","content":"Approved text"}
~~~

The server canonicalizes the filename and stores the exact path and content in a `pending` approval, bound to the authenticated requester's configured identity. The response contains an `approval_id`.

### 2. Approve the request

~~~http
POST /approve?approval_id=<approval-id>
X-Approver-Key: <approver-secret>
~~~

Only a configured approver key can perform this transition. The approval store independently revalidates that credential before changing state and stores only a non-secret fingerprint as the approver identity. Only `pending` records can be approved or denied. The normal API key is not accepted as an approver credential. Approval IDs are 128-bit random values (32 lowercase hexadecimal characters); legacy 8-character IDs are rejected.

### 3. Deny a request when it should not proceed

~~~http
POST /deny
X-Approver-Key: <approver-secret>
Content-Type: application/json

{"approval_id":"<approval-id>","reason":"Not authorized"}
~~~

Denial is a terminal transition. A denied request cannot be approved or executed.

### 4. Execute the approved write

~~~http
POST /write/execute
X-API-Key: <requester-secret>
Content-Type: application/json

{"approval_id":"<approval-id>"}
~~~

The execution endpoint deliberately accepts no path or content fields. The authenticated requester identity must match the owner stored on the approval; a different valid requester receives `403` without consuming the approval. The rightful owner can then execute it. Execution loads the stored approved payload, validates its canonical path and content limit, atomically consumes the approval under a per-record lock, and atomically replaces the destination file. A concurrent or later replay cannot execute the same approval again.

## Expected failures

- `401`: missing or invalid requester API key.
- `403`: missing or invalid approver key.
- `404`: approval ID does not exist.
- `409`: request is pending, denied, already consumed, mismatched, or otherwise cannot transition.
- `422`: malformed approval ID or invalid note request. The execute endpoint rejects client-supplied path/content fields.
- `429`: requester or approver rate limit exceeded.

## Operational notes

- Configure separate, random secrets for requester and approver roles.
- Rotate credentials by temporarily allowing old and new keys, then removing the old key.
- Back up the `approvals/`, `logs/`, and `notes/` data directories according to the deployment's retention policy.
- Treat approval records and audit logs as sensitive: they contain note contents and operation metadata. Storage directories are restricted to mode `0700`; approval, lock, audit, and note files are restricted to mode `0600`.
- Storage paths reject symlinked directory components, and sensitive files are opened with no-follow semantics. Note writes use a same-directory temporary file, `fsync`, atomic replacement, and directory `fsync`. Keep the storage root writable only by the service account; these checks are defense in depth, not protection against a hostile process running as that same account.
- The approval store currently uses local filesystem locks (`fcntl.flock`). Deploy it on a filesystem with reliable advisory-lock and atomic-rename semantics; do not share this file-backed store across hosts or network filesystems without validating those guarantees.
- The consume-before-write sequence is intentionally at-most-once. A consumed approval is never reset to approved, including when note writing or failure reporting fails. A failed write returns an operator-review status; if failure metadata cannot be saved, the original failure is still logged and the approval remains consumed. If failure metadata is saved but its audit append fails, the response distinguishes that incomplete audit state.
- **Operator recovery procedure:** (1) Do not retry or manually reset the consumed approval. (2) Inspect the private approval JSON and its `execution_failure` field, then inspect the matching audit entries and service logs using the approval ID. (3) Inspect the destination note itself before taking action: a directory-`fsync` error can occur after `os.replace`, meaning the new contents may already be visible even though the operation returned an error. Compare the destination with the approved payload without copying sensitive contents into general logs. (4) If the destination already contains the approved payload, treat the write as completed and do not create a duplicate request. If it does not, or its state is uncertain, escalate for manual review; only after confirming the intended state should an operator create a new approval request. Never replay the consumed ID.
- If the `consumed` audit append fails after the consumed state is committed, execution fails closed: the note write is not attempted, the approval remains consumed, and the service records an operator-review failure. Do not replay the approval. If failure metadata cannot be recorded, use the service log and approval record to reconstruct the event.
- If the stored approved payload is malformed or no longer canonical, execution records a validation failure against the consumed approval and returns an operator-review status. Do not attempt to repair the payload in place or replay the approval; submit a fresh request only after operator inspection.
- If the approval record cannot be updated, the structured service log still records the original filesystem exception and separately records the failure to persist recovery metadata. Treat the approval record, destination file, audit log, and service log together as the recovery evidence; do not assume a missing `execution_failure` field means the destination was untouched.