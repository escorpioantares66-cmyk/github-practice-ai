# Security and operational limitations

## Persistent quota storage and cost accounting

Requester and approver rate-limit events and daily model usage are stored in
SQLite at `.agent_state/quotas.sqlite3` by default. Override the location with
`AGENT_QUOTA_DB_PATH`. The parent directory is created with mode 0700 and the
database is restricted to mode 0600. SQLite write transactions serialize quota
decisions across local worker processes sharing the same persistent filesystem.

This is a **single-host** design. Do not put the SQLite database on NFS or
assume it coordinates separate machines/containers with independent disks.
The database must live on persistent storage; ephemeral deployment filesystems
will lose quota history on replacement or redeploy.

The API reserves a conservative worst-case allowance before running its
bounded three-call agent loop. Reservations expire after one hour if a process
crashes and are released when a request completes. Actual usage is recorded
from the provider response's prompt and completion token counts. Missing usage
or a failed durable usage write stops further agent execution. The default
pricing configuration is for `gpt-4o-mini`: USD 0.15 per million input tokens
and USD 0.60 per million output tokens. Override with
`AGENT_MODEL_INPUT_USD_PER_1M` and `AGENT_MODEL_OUTPUT_USD_PER_1M` when model
or provider pricing changes. Cached input is conservatively charged at the
uncached input rate.

These application records are estimates of provider charges, not a provider
invoice or a guaranteed billing cap. They exclude non-model charges, taxes,
platform fees, and model calls outside this instrumented agent path. Reconcile
them against provider billing and usage dashboards.


## Additional application-level controls

- All note reads and writes, including direct SDK calls, require an explicit non-empty requester identity and use a SHA-256-derived owner directory. Missing identities fail closed; there is no shared `notes/` fallback. Existing files in the legacy shared directory are not automatically migrated or exposed through the SDK. This is application-level separation; operators must still protect the host filesystem and backups.
- Approval requests expire 15 minutes after creation. Expired records are rejected at approval and consumption time and are omitted from the pending list. Expired records remain on disk for operator/audit review.
- The ASGI request middleware limits concurrent body buffering to 16 requests per process and caps each body at 1 MiB. This is a per-process memory bound, not a substitute for connection limits and request timeouts at a reverse proxy.
- Prompt-injection phrase screening is heuristic only. The agent's tool allowlist, strict argument validation, and requester-scoped note access are the actual privilege boundaries.
- Output redaction covers common high-confidence PII patterns; it is not comprehensive data-loss prevention.


## Approval clock integrity

Approval expiry uses the host wall clock because approval records persist across
process restarts. A record whose creation timestamp is more than 60 seconds in
the future relative to the current host clock is rejected as expired. This
fails closed on significant backward clock adjustments; it does not replace
reliable time synchronization. Production hosts should run a time
synchronization service and alert on clock drift. Small clock adjustments
within the 60-second tolerance can still affect the effective expiry window.


## Direct SDK note access

Callers of `tools.read_note`, `write_tools.write_note`, and
`write_tools.execute_approved_write` must pass the same trusted requester
identity used when creating the approval. Omitting the identity is rejected.
Do not accept requester identities from model-generated tool arguments or
untrusted request-body fields; derive them from authenticated application
context. The legacy shared `notes/<filename>` location is no longer used by
these SDK operations. If existing shared notes must be retained, migrate them
to the correct owner directory through a separately reviewed operator process.
