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
- `429`: requester or approver rate limit exceeded, or the requester reached an approval-creation quota.
 - `503`: approval-store integrity prevents safe quota enforcement; new requests are paused for operator review.

## Operational notes

- Configure separate, random secrets for requester and approver roles.
- Rotate credentials by temporarily allowing old and new keys, then removing the old key.
- Back up the `approvals/`, `logs/`, and `notes/` data directories according to the deployment's retention policy.
- Treat approval records as sensitive: they contain note contents and operation metadata. New audit events store a SHA-256 fingerprint of the canonical operation arguments instead of the arguments themselves. Older audit entries may still contain note contents, so existing audit history remains sensitive. Storage directories are restricted to mode `0700`; approval, lock, audit, and note files are restricted to mode `0600`.
- Storage paths reject symlinked directory components, and sensitive files are opened with no-follow semantics. Note writes use a same-directory temporary file, `fsync`, atomic replacement, and directory `fsync`. Keep the storage root writable only by the service account; these checks are defense in depth, not protection against a hostile process running as that same account.
- The approval store currently uses local filesystem locks (`fcntl.flock`). Deploy it on a filesystem with reliable advisory-lock and atomic-rename semantics; do not share this file-backed store across hosts or network filesystems without validating those guarantees.
- The consume-before-write sequence is intentionally at-most-once. A consumed approval is never reset to approved, including when note writing or failure reporting fails. A failed write returns an operator-review status; if failure metadata cannot be saved, the original failure is still logged and the approval remains consumed. If failure metadata is saved but its audit append fails, the response distinguishes that incomplete audit state.
- Every consumed approval receives an `execution_outcome.status: started` marker before the filesystem side effect. After the note replacement succeeds, the service persists `completed` and appends an `execution_succeeded` audit event. A completed outcome is considered fully audited only when `execution_outcome.audit_status` is `written`.
- **Operator recovery inspection:** A configured approver can call `GET /operator/recovery` with `X-Approver-Key`. The endpoint is read-only, rate-limited, and returns unresolved consumed executions without returning note content. It includes legacy consumed records without an outcome marker, executions left at `started`, failed or uncertain outcomes, and completed outcomes whose audit is incomplete.
- **Operator recovery procedure:** (1) Never retry or manually reset a consumed approval. (2) Inspect the recovery listing, the private approval JSON, matching audit entries, and service logs using the approval ID. (3) Inspect the destination note itself: a crash after replacement but before the completed marker leaves the outcome at `started`, and a directory-`fsync` error can occur after `os.replace`. Compare the destination with the approved payload without copying sensitive contents into general logs. (4) If the destination contains the approved payload, treat the write as completed. If it does not, or its state is uncertain, escalate for manual review. Only after confirming the intended state should an operator create a new approval request. Never replay the consumed ID.
- If the `consumed` audit append fails after the consumed state is committed, execution fails closed: the note write is not attempted, the approval remains consumed, and the service records an operator-review failure. Do not replay the approval. If failure metadata cannot be recorded, use the service log and approval record to reconstruct the event.
- If the stored approved payload is malformed or no longer canonical, execution records a validation failure against the consumed approval and returns an operator-review status. Do not attempt to repair the payload in place or replay the approval; submit a fresh request only after operator inspection.
- If the approval record cannot be updated, the structured service log still records the original filesystem exception and separately records the failure to persist recovery metadata. Treat the approval record, destination file, audit log, and service log together as the recovery evidence; do not assume a missing `execution_failure` field means the destination was untouched.

## Approval and denial audit integrity

An approval or denial transition is committed with approval_audit_status set to pending before its audit event is appended. The audit event is written with the intended written marker; only after the append succeeds is the approval record updated to written. Execution is permitted only when an approved record has approval_audit_status set to written.

If the audit append fails, the terminal approval/denial state is retained, the record is marked failed when that metadata update is possible, and the API returns HTTP 500 with an operator-review instruction. If the audit append succeeds but the final record update fails, the record remains pending and execution is still blocked. These states are deliberately fail-closed: do not edit the record to written or retry the transition without reconciling the private approval record and audit log. A fresh request is required after operator review when execution is still needed.


## Request creation audit integrity

A newly created request starts with `request_audit_status: pending`. The request audit event is appended before the record is marked `written`. Approval and denial transitions are rejected unless the stored request audit marker is `written`. If the audit append fails, the record is marked `failed` when possible; if that marker update also fails, the original `pending` marker remains fail-closed. If the audit append succeeds but the final marker update fails, the request also remains unapprovable. The API returns HTTP 500 with the approval ID and an operator-review instruction. Do not manually change the marker or retry approval; reconcile the approval record and audit log first.


## Approval-record and audit-log integrity

New approval records are first reserved with an exclusive, owner-only file creation and then made visible as complete JSON through an atomic replacement. If persistence fails before the replacement completes, the reservation is removed when possible; an interrupted or malformed leftover is never considered pending.

The pending-request scan validates each record independently. Malformed JSON, invalid encoding, non-object data, and record-ID/filename mismatches are excluded from the queue and logged for operator review. The scan continues so one damaged file cannot hide unrelated valid requests. A corrupt record is not repaired or automatically deleted.

Audit history is append-only. Before appending, the writer takes the audit-file lock and validates every existing JSONL entry, including the terminating newline and required event fields. If the log has an incomplete trailing entry or a malformed complete entry, new appends stop and the existing bytes are left unchanged. Operators must preserve a copy of the original log, investigate the interrupted event using approval records and service logs, and perform an explicitly documented recovery; the application never truncates or silently rewrites audit history.

If an in-process append fails after writing only part of an event, the writer attempts to truncate back to the original file length while holding the exclusive lock and fsyncs that rollback. If rollback itself fails, treat the audit log as requiring operator review. A process crash can still leave an incomplete final line; the next writer detects it and refuses to append.

## Approval creation quotas

Approval creation is limited per authenticated requester identity:

- At most **10 active pending approvals** at a time. A pending approval stops counting after it is approved, denied, or expires.
- At most **100 approval requests per UTC calendar day**. Approved, denied, consumed, expired, and audit-incomplete requests all count toward this daily quota; deciding a request does not reset it.
- Quota checks and record reservation run under a filesystem lock, so concurrent threads and worker processes cannot race past the limits.
- If the approval directory contains a corrupt, unreadable, symlinked, or future-dated record, new requests fail closed with HTTP 503 rather than risk under-counting usage. Operators must inspect the store before accepting new requests.
- Quota exhaustion returns HTTP 429. The response identifies the limit without exposing stored operation data.

The limits are constants in `stage2_sdk_ai.approval` and can be adjusted deliberately after reviewing workload and storage capacity. They are per requester identity, not per API secret; use stable labelled credentials so rotation does not reset the quota.

## Identity-based rate limiting

Configure requester credentials using stable identity labels, for example `AGENT_API_KEYS=worker-a=secret-one,worker-b=secret-two`. Configure approvers the same way with `AGENT_APPROVER_KEYS=reviewer-a=secret-three`. Rate-limit buckets use the identity label, not the secret, so rotating a secret while retaining its identity does not reset the requester's or approver's rate limit. Legacy bare secrets remain accepted for compatibility, but their derived fingerprint identity changes when the secret changes; migrate to labelled credentials to preserve buckets across rotation.


## Final adversarial hardening notes

Every state-changing approval operation validates the JSON record schema, filename/record ID binding, required payload fields, allowed lifecycle state, and audit-state values while holding the per-record lock. Corrupt records are rejected with an operator-review status and are never transitioned.

Rate-limit check-and-increment and reset operations are synchronized within a Python process. This prevents concurrent threads in one worker from exceeding the configured window. The limiter remains process-local: multi-worker or multi-host deployments must put a shared atomic limiter (for example Redis with a single atomic script) in front of the API; do not claim a global limit from the in-memory implementation.

Audit events are checked for an exact event envelope, allowed action, numeric timestamp, and a record object containing a valid approval ID plus either legacy arguments or a SHA-256 argument fingerprint. New events never persist note content in the audit log. Validation is bounded to 64 MiB; once the active audit file reaches that size, appends fail closed. Operators should archive/rotate only through an explicit, documented procedure that preserves the original immutable segment and verifies its integrity before creating a new active segment. This bound limits per-append parsing cost but is not a substitute for implementing segmented audit storage before sustained high-volume production use.

Private storage operations now walk directory components with no-follow directory descriptors and perform file opens, temporary-file creation, replacement, and directory fsync relative to the verified directory descriptor. This reduces pathname substitution races. The storage root must still be owned by the service account and not writable by untrusted users; it does not defend against a malicious process with the same account privileges.
