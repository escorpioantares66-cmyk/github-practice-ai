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
