# ADR 0001: Tenant-scoped authorization and transactional sandbox approvals

- Status: proposed; owner review required before implementation
- Date: 2026-11-09
- Scope: SaaS authorization authority for issue #49
- Supersedes: nothing
- Related: `docs/sandbox-approval-authority.md` (single-workspace v1 contract)

## Context

The existing `/v1/sandbox/approvals` authority is a useful, fail-closed single-host
boundary. It authenticates named requester and approver credentials, rejects
self-approval, binds an Ed25519 receipt to repository/sandbox/base/head/diff/action,
and provides one-time consumption with identical-only retries and recovery inspection.

Its file-backed records and `fcntl.flock` coordination are intentionally single-host.
The v1 scope does not include tenant or business identity, membership, per-tenant
policy, agent/service identity, or multi-instance transactional coordination. It
must not be horizontally scaled or reused as a multi-tenant SaaS authority.

## Decision proposed

Build a separately versioned tenant-scoped approval authority (v2) while retaining
v1 for the current single-workspace deployment until a separately reviewed migration
and cutover. Do not weaken or silently reinterpret v1 records or receipts.

### 1. Trusted identity and context

- The SaaS identity/control plane is the issuer of short-lived, signed internal
  identity assertions. The authority validates signature, issuer, audience,
  key ID, time bounds, token ID and revocation/suspension state.
- Required assertion claims: `sub` (stable principal), `principal_type`
  (`human` or `service`), `tenant_id`, `business_id`, `agent_id`
  (required for service principals and null for human principals),
  `credential_id`, `iat`, `nbf`, `exp`, and `jti`. The signing key ID
  belongs in the authenticated token header, not a caller-controlled claim.
- Roles and scopes, when present, are hints/upper bounds only. The authority
  must re-read current tenant/business membership, credential status and policy
  from its authoritative records for each state-changing request. It must not
  rely on stale role, scope or policy claims as the sole authorization check.
  The active `policy_version` is selected and persisted by the authority; a
  caller or assertion cannot choose a weaker version.
- Tenant, business and principal values are derived only from the verified
  assertion and current membership/policy records. Request JSON may identify a
  resource but cannot override authenticated identity.
- Assertions are audience-restricted to this service and short-lived (target:
  five minutes). Signing-key rotation uses overlapping key IDs; revocation and
  tenant suspension must block new decisions and consumption without waiting
  for long-lived tokens to expire.
- Human approvers authenticate independently from agents/services. The authority
  enforces tenant/business membership, explicit approver role, action/resource
  permission, approval limits, separation of duties and self-approval rejection.
  A platform support principal receives no tenant approval rights by default.

The exact control-plane assertion issuer and key-discovery mechanism must be
selected before implementation. The authority must not accept unsigned
agent-supplied tenant IDs or trust forwarded identity headers from arbitrary
network callers.

### 2. Immutable approval scope

Every v2 approval binds all of the following:

- `tenant_id`, `business_id`;
- authenticated requester principal and principal type;
- authenticated agent/service identity (when applicable);
- action and canonical resource identity;
- exact canonical payload digest;
- policy version and required approver role/limit;
- approval ID, one-time nonce, creation time and expiry.

The service computes the canonical payload digest from validated fields. A caller
cannot supply a digest that substitutes for server-side validation. Any change to
tenant, business, principal, agent, action, resource, payload, or policy version
requires a new approval.

### 3. Transactional persistence and concurrency

Use PostgreSQL as the proposed multi-instance authority store, subject to owner
acceptance of the operational dependency and deployment plan. The schema must
include tenant/business ownership columns on every approval, decision, consumption,
idempotency, and audit record.

- Enforce tenant/business isolation in application authorization and database
  row-level security (RLS). Use transaction-local tenant/business context set
  only from verified identity and clear it using transaction-scoped settings;
  never store context in pooled session state.
- Apply `FORCE ROW LEVEL SECURITY` to tenant-owned tables. The application
  connection role must not own protected tables, be superuser, or have
  `BYPASSRLS`. Migration/maintenance roles are separate, audited and never
  exposed to request handlers. Test both application-level checks and RLS under
  the actual least-privilege runtime role.
- Require composite foreign keys and unique constraints that include tenant
  and business identifiers where ownership is relevant. Approval-to-decision,
  approval-to-consumption, idempotency and audit joins must preserve the same
  tenant/business tuple.
- Create, decision and consume idempotency are each scoped to tenant, business,
  authenticated principal, operation and idempotency key. Store the exact
  canonical request digest and terminal response. An identical retry returns
  the same persisted result; an altered payload or conflicting principal
  returns a stable conflict.
- Decision and consumption are conditional transactional state transitions.
  A row lock or compare-and-set on an explicit state/version column must produce
  exactly one winner across concurrent service instances. Nonce and receipt IDs
  must be unique within their defined issuer/tenant scope.
- Persist state changes, idempotency outcome and the authoritative append-only
  audit row in one database transaction. An outbox row may be written in the
  same transaction for downstream notifications; asynchronous delivery is not
  the audit commit. A response lost after commit is recovered by replaying the
  same idempotency key and exact payload, never by creating a second approval
  or resetting a consumed one.
- Do not use process-local locks, SQLite WAL, file locks, or filesystem records
  as the cross-instance serialization mechanism.

### 4. Signed decision receipt v2

Use Ed25519 and a versioned receipt envelope. Required claims:

`ver`, `iss`, `aud`, `jti`, `approval_id`, `nonce`, `tenant_id`,
`business_id`, `requester`, `requester_type`, `agent_id`, `approver`,
`action`, `resource`, `payload_sha256`, `policy_version`, `decision`,
`iat`, `nbf`, and `exp`. The envelope contains `alg=Ed25519` and
`kid`; `kid` is not duplicated in the signed claims.

- Define one canonical serialization algorithm and publish byte-for-byte test
  vectors shared by the authority and Second Brain verifier. The v2 contract
  should use RFC 8785 JSON Canonicalization Scheme (JCS), UTF-8 bytes, reject
  duplicate JSON keys/non-finite numbers, and constrain numeric claims to
  integer Unix seconds. Use a maintained JCS implementation rather than a
  hand-written approximation; validate all claim types/ranges before signing.
- The envelope identifies `alg=Ed25519` and `kid`; the relying service pins
  trusted public keys and verifies signature, issuer, audience, version, time,
  tenant, business, principal, agent, action, resource, payload digest and policy.
- A receipt is not a bearer authorization by itself. The authority must
  re-check current tenant/business status, membership, policy version and
  revocation at consumption time.
- Key rotation supports a documented overlap period. Revoked keys, tenant
  offboarding and credential revocation prevent new consumption. Existing
  evidence remains inspectable under the retention policy.

### 5. API and stable errors

Expose a versioned v2 API distinct from v1. The exact OpenAPI schema and response
examples are a required implementation artifact. At minimum it supports:
create pending request, approve, deny, retrieve signed decision, inspect state,
consume once, and requester-scoped recovery inspection.

All routes authenticate a verified assertion. Tenant/business path components
are selectors only and must match verified context. Read, decision, consume and
recovery operations must return indistinguishable not-found/forbidden behavior
where needed to prevent cross-tenant resource enumeration. Mutating endpoints
require an idempotency key and persist the request digest/outcome. Reusing a key
with the same principal and byte-equivalent canonical request returns the
original outcome; reusing it with a different request conflicts. Approve and
deny are also idempotent: an identical decision retry returns the durable
decision, while a different decision or approver cannot replace it.

Define machine-stable error codes independent of human-readable messages:
`AUTHENTICATION_REQUIRED`, `IDENTITY_INVALID`, `TENANT_SUSPENDED`,
`BUSINESS_ACCESS_DENIED`, `ACTION_FORBIDDEN`, `APPROVAL_NOT_FOUND`,
`APPROVAL_EXPIRED`, `APPROVAL_TERMINAL`, `SELF_APPROVAL_FORBIDDEN`,
`SCOPE_MISMATCH`, `IDEMPOTENCY_CONFLICT`, `REPLAY_REJECTED`,
`RECEIPT_INVALID`, `POLICY_VERSION_STALE`, `STORAGE_UNAVAILABLE`,
`AUDIT_INCOMPLETE`, and `RECOVERY_REQUIRED`. Map these to documented HTTP
statuses and never expose internal paths, secrets, cross-tenant existence, or
raw stored payloads.

### 6. Audit, support, retention and offboarding

- Audit events bind tenant/business, actor, action, resource, scope digest,
  policy version, approval/decision/consume IDs, outcome and time. Events are
  append-only and tamper-evident; the write and domain transition commit
  atomically.
- Tenant users can inspect only their tenant/business audit view. Cross-tenant
  platform investigations require a separately authenticated, time-bounded,
  least-privilege support grant, reason code, immutable audit record and
  approval where policy requires it.
- Tenant suspension blocks new requests, decisions and consumption immediately
  after the authoritative status check. Membership, credential and policy
  revocation must have a defined cache invalidation/introspection strategy;
  stale authorization caches must never outlive the stated revocation bound.
  Offboarding revokes credentials, invalidates outstanding approvals, applies
  documented retention/legal-hold rules, and prevents future use of old receipts.
- Retention, backup, restore, signing-key custody, disaster recovery and
  incident response are deployment gates, not assumptions of the database.

## Migration and compatibility

1. Keep v1 endpoints, receipt format, file store and single-host deployment
   constraint unchanged during v2 design and implementation.
2. Add v2 tables and service paths without changing v1 record interpretation.
3. Prove tenant isolation, concurrency, receipt verification and recovery in
   synthetic staging before any tenant traffic.
4. Define explicit migration/cutover and rollback procedures. Do not copy v1
   records into a tenant by inference; any migration requires verified ownership
   mapping and audit evidence.
5. Remove or deprecate v1 only after an owner-approved migration, a recovery
   window, and proof that no v1 consumers remain.

## Required adversarial acceptance

- Cross-tenant lookup, decision, inspection, consumption and recovery are denied.
- Business A approvers cannot act for Business B, including within one tenant.
- Body/path/header identity spoofing cannot change verified tenant/principal.
- Tenant suspension, membership removal, credential revocation and stale policy
  prevent new decisions and consumption.
- Receipt replay across tenant, business, principal, agent, action, resource,
  payload, policy version, audience and key ID is rejected.
- Concurrent create/decide/consume across independent service instances produces
  one durable transition and deterministic identical-retry outcomes.
- Database, identity, signing-key and audit failures fail closed and remain
  inspectable/recoverable without resetting approvals.
- RLS tests run under the production-like non-owner, non-superuser application
  role with `FORCE ROW LEVEL SECURITY`; connection-pool tests prove context
  cannot leak between requests.
- Support access is just-in-time, time-bounded, purpose-bound and least-privilege.
  It requires an auditable grant (and dual approval where risk policy requires),
  cannot approve tenant operations by default, and expires automatically.
- Existing v1 approval, replay, audit, recovery and SDK-pin regression tests pass.

## Delivery gates

1. **Architecture review:** owner accepts this ADR, the control-plane identity
   assertion contract, PostgreSQL deployment assumptions, threat model and
   migration strategy. No v2 code before this gate.
2. **Identity and schema:** versioned principal assertion validation, tenant/
   business membership model, migrations, RLS and credential revocation tests.
3. **Transactional repository:** create/decision/consume/idempotency/outbox
   transactions, concurrent multi-instance tests and recovery inspection.
4. **API and receipt v2:** OpenAPI contract, stable errors, JCS test vectors,
   Ed25519 key rotation/revocation and Second Brain verifier contract.
5. **Adversarial verification:** full cross-tenant/business, replay, suspension,
   storage-failure, audit-failure, RLS and pool-isolation suite.
6. **Migration and operations:** synthetic staging, backup/restore, incident,
   retention, offboarding and rollback exercises.
7. **Production gate:** exact-head CI, independent security review, deployment
   evidence and explicit owner approval. The existing v1 single-host limit
   remains in force until this gate is complete.

## Non-goals

This ADR does not authorize production deployment, live tenant data, automatic
approval, unrestricted agent actions, canonical writes, direct pushes, merges,
or ELIM onboarding. It does not make Second Brain an authorization authority.
