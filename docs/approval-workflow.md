# Secure note approval workflow

The note-writing API uses three separate capabilities:

- **Requester credential** (`X-API-Key`): may create a pending note-write request and execute an already-approved request.
- **Approver credential** (`X-Approver-Key`): may approve a pending request. It cannot create or execute writes by itself.
- **Approval ID**: an opaque, random, one-time capability that refers to the exact stored operation. It is not a substitute for either credential.

## Required configuration

Set both variables in the server environment. Use independently generated, high-entropy secrets and never commit them:

~~~sh
export AGENT_API_KEYS="replace-with-a-long-random-requester-secret"
export AGENT_APPROVER_KEYS="replace-with-a-different-long-random-approver-secret"
~~~

Comma-separated values are supported for controlled key rotation. An empty or missing allow-list fails closed. Do not reuse the same secret for both roles. Use HTTPS in deployment and keep secrets in the deployment secret manager.

## Lifecycle

### 1. Request a write

~~~http
POST /write
X-API-Key: <requester-secret>
Content-Type: application/json

{"path":"release-notes.md","content":"Approved text"}
~~~

The server canonicalizes the filename and stores the exact path and content in a `pending` approval. The response contains an `approval_id`.

### 2. Approve the request

~~~http
POST /approve?approval_id=<approval-id>
X-Approver-Key: <approver-secret>
~~~

Only a configured approver key can perform this transition. Only `pending` records can be approved or denied. The normal API key is not accepted as an approver credential.

### 3. Execute the approved write

~~~http
POST /write/execute
X-API-Key: <requester-secret>
Content-Type: application/json

{"approval_id":"<approval-id>"}
~~~

The execution endpoint deliberately accepts no path or content fields. It loads the stored approved payload, validates its canonical path and content limit, atomically consumes the approval under a per-record lock, and atomically replaces the destination file. A concurrent or later replay cannot execute the same approval again.

## Expected failures

- `401`: missing or invalid requester API key.
- `403`: missing or invalid approver key.
- `404`: approval ID does not exist.
- `409`: request is pending, denied, already consumed, mismatched, or otherwise cannot transition.
- `422`: malformed approval ID or invalid note request.
- `429`: requester or approver rate limit exceeded.

## Operational notes

- Configure separate, random secrets for requester and approver roles.
- Rotate credentials by temporarily allowing old and new keys, then removing the old key.
- Back up the `approvals/`, `logs/`, and `notes/` data directories according to the deployment's retention policy.
- Treat approval records and audit logs as sensitive: they contain note contents and operation metadata.
- The approval store currently uses local filesystem locks (`fcntl.flock`). Deploy it on a filesystem with reliable advisory-lock and atomic-rename semantics; do not share this file-backed store across hosts or network filesystems without validating those guarantees.
- The consume-before-write sequence is intentionally at-most-once. If the process crashes after consuming an approval but before the atomic file replacement completes, an operator must create a new request rather than replay the consumed approval.