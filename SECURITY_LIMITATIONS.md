# Security and operational limitations

## Process-local rate limits and cost budgets

The current rate limiter and daily cost budget are maintained in process memory.

- Rate-limit counters are local to one running application process.
- Cost totals roll over at the UTC calendar-day boundary while the process is running.
- Cost reservations are atomic within one process, so concurrent requests handled by that process cannot all spend the same unreserved budget.
- Both rate-limit counters and cost totals are lost when the process restarts.
- Multiple application workers or instances do not share counters or budget totals. Each process enforces its own local limits.

This is an intentional low-cost deployment trade-off, not a distributed quota guarantee. It is suitable only when the application runs as a single process and operators accept reset-on-restart behavior.

Before deploying multiple workers/instances, or when daily spending limits must survive restarts, move rate-limit and cost-budget state to a shared persistent backend and enforce reservations atomically there. Do not treat the current in-memory controls as a global spending cap.


## Additional application-level controls

- API note reads and writes are scoped to a requester identity using a SHA-256-derived directory name. This is application-level separation; operators must still protect the host filesystem and backups.
- Approval requests expire 15 minutes after creation. Expired records are rejected at approval and consumption time and are omitted from the pending list. Expired records remain on disk for operator/audit review.
- The ASGI request middleware limits concurrent body buffering to 16 requests per process and caps each body at 1 MiB. This is a per-process memory bound, not a substitute for connection limits and request timeouts at a reverse proxy.
- Prompt-injection phrase screening is heuristic only. The agent's tool allowlist, strict argument validation, and requester-scoped note access are the actual privilege boundaries.
- Output redaction covers common high-confidence PII patterns; it is not comprehensive data-loss prevention.
