# Ecosystem Integration Contract — Central Approval Authority

- **Status:** Founder-approved ecosystem role; general company-action API is a future versioned capability
- **Version:** 1.0
- **Date:** 2026-11-24
- **Applies to:** `github-practice-ai`
- **Companion:** ASP Founder Command Centre integration and Second Brain Boss Foundation integration contracts

> This document allocates the Central Approval Authority role to this repository. It does not broaden the existing sandbox v1 API, accept the proposed tenant-scoped ADR on PR #52, or claim that a general company-action approval service is implemented.

## 1. Role and authority

`github-practice-ai` is the ecosystem's **Central Approval Authority**. Its current v1 implementation authenticates named requester and approver credentials for the narrow sandbox workflow; those configured labels do not establish natural-person identity or MFA. The broader Founder-authentication ceremony, company-action policy evaluation, and company-wide approval validity/revocation service described in this contract are future v2 capabilities, not claims about the current v1 implementation.

It is not the Boss, business registry, identity root, general policy/capability enforcement plane, execution dispatcher, provider adapter or Delta.

The Authority/Safety Plane remains the canonical owner of company identity, agent registration, business registry, active capability/policy decisions, execution admission, GOA ordering, audit/witness enforcement and containment. The GAI approval service is the single approval-decision/signing service used by the ecosystem.

## 2. Authority mapping to ASP

The ASP architecture uses a logical AUTH-03 Approval Authority domain and a separate GOA execution-ordering/consumption authority. For the ecosystem:
- **AUTH-03 decision/receipt service = this repository.**
- **GOA canonical execution consumption and dispatch-start ordering = ASP.**

This mapping preserves the ASP v1.3 logical contract: AUTH-03 owns approval validity/revocation and ticket issuance; GOA owns canonical execution consumption and commits it atomically with `DISPATCH_STARTED`. GAI may retain a non-authoritative projection of company-action ticket consumption for inspection, but it must not create a competing canonical consumption ledger for that v2 flow.

The existing sandbox v1 API is a compatibility exception: its own service currently owns its narrow request/decision/consume lifecycle because it is not yet integrated with the company-wide ASP GOA.

## 3. Existing v1 sandbox authority — unchanged

The current API documented in `docs/sandbox-approval-authority.md` remains a distinct, narrow contract:
- Routes under `/v1/sandbox/approvals`: create, approve, deny, retrieve decision, inspect request and consume.
- Named requester and approver credentials are independently provisioned and authenticated by the authority.
- Requester and approver must be distinct; self-approval is rejected.
- Exact scope fields: `repository`, `sandbox_id`, `base_sha`, `head_sha`, `diff_sha256`, `action`.
- The only permitted action is `prepare_pull_request`.
- The authority issues an Ed25519-signed receipt binding issuer, audience, approval ID, nonce, requester, approver, full scope, issue time, expiry and decision.
- Receipt TTL is 900 seconds; maximum clock skew is 60 seconds.
- Relying clients verify signature, independently pinned public key, issuer, audience, expiry and every current scope field.
- Consumption is one-time; only identical retries with the same request UUID, nonce and unchanged scope return the original result.
- File-backed storage and POSIX locking are single-host. It must not be horizontally scaled or treated as a multi-host authority.
- The hash-chained local audit log is not a substitute for independent protected checkpoints.

Second Brain PR #21 is a client integration for this exact sandbox contract and pins a specific GAI source commit for contract tests. Do not widen the v1 action to generic business operations or reinterpret its receipt fields.

## 4. Future company-action v2 contract

The ecosystem needs approval for consequential operations beyond GitHub pull-request preparation. That is a separate, versioned API and schema; it is not implemented by the current v1 sandbox API.

### 4.1 Authenticated request context

The ASP Identity Authority is the canonical issuer for Founder and machine identities. For company-action v2, GAI validates a short-lived, audience-restricted signed assertion from the configured ASP issuer. It must verify signature, issuer, audience, key ID, time bounds, token ID and current credential/revocation/suspension status.

The authority derives principal and company/business context from the verified assertion and current authoritative membership/policy records. It must not trust tenant/business/principal/agent values from request JSON, arbitrary headers or Boss-supplied claims.

Required identity context:
- stable principal ID and type (`human` or `service`);
- `company_id`, mandatory ASP `tenant_id`, and `business_id` where applicable;
- `agent_id` for service/agent principals;
- credential ID, token ID/JTI, issuer, audience and bounded validity;
- current authorization/approver eligibility resolved by the authority.

Human Founder approval uses a separate strong authentication ceremony. A machine credential or authenticated Boss session is never evidence of Founder approval. The requester and approver must be distinct where separation of duties applies.

The current v1 API continues to use its named requester/approver credentials. Do not silently switch v1 to the future assertion protocol.

### 4.2 Canonical approval scope

A company-action approval request must bind:
- `company_id`, `tenant_id`, `business_id`;
- authenticated requester principal/type and requesting agent/service identity;
- `task_id`, `plan_id` and delegation reference;
- action identifier and canonical resource identity;
- exact canonical payload digest, derived/verified by the authority from validated content;
- the policy decision reference and version selected by the ASP Authorization Authority;
- the ASP-resolved risk tier, required Founder approver eligibility/limit and resource envelope;
- approval ID, unpredictable nonce, issuer, intended enforcement audience, issue time and expiry.

Any change to principal, business, agent, action, resource, material parameter, canonical payload digest, policy version or intended audience requires a new approval. A caller-provided digest is not a substitute for server-side canonicalization.

The ASP security `tenant_id` is mandatory in company-action v2 because it is part of the ASP typed scope and AUTH-10 tenant registry. V1 has one Founder-controlled company tenant; this does not imply a customer-facing multi-tenant SaaS product. GAI PR #52's proposed tenant-scoped persistence/service architecture and Second Brain PR #20's proposed independently owned customer tenants remain unaccepted; this contract does not accept their proposed storage topology or delivery model.

### 4.3 Logical operations

The future v2 API must provide versioned equivalents of:
- create an approval request;
- inspect a request and its authoritative state;
- approve or deny through the authenticated Founder ceremony;
- retrieve signed decision/ticket evidence;
- inspect validity/revocation state;
- reconcile a request after an uncertain response.

These are logical operations, not committed HTTP paths. Route names, storage topology, database choice, transaction boundaries and deployment are not selected by this document.

### 4.4 Ticket and GOA consumption

For company-action v2, GAI issues a signed, audience-bound ticket after an approved decision. It carries exact canonical scope and validity/revocation references. ASP independently verifies the ticket and current policy before dispatch.

The ASP GOA is the sole canonical one-time execution-consumption authority. It atomically commits ticket consumption with `DISPATCH_STARTED` in the same ordered transition. GAI's receipt/decision store remains authoritative for whether the approval is valid, revoked or expired; it is not authoritative for whether the company action has begun execution. A GOA consumption result may be projected into GAI for read-only status, but that projection cannot authorize or reverse dispatch.

If ticket verification, current policy, containment, GOA state or the commit outcome is uncertain, dispatch is denied/held and reconciled using the same stable operation identity. A consumed ticket cannot be replayed for another dispatch.

## 5. Approval decision policy boundary

For company-action v2, **ASP is the policy authority; GAI is the approval decision authority.** ASP's Authorization Authority resolves the applicable policy version, classifies the operation's risk, determines whether Founder approval is required, and supplies the authoritative approval requirements and resource/limit envelope. GAI must not author, select, version, or weaken that policy.

Using authenticated, integrity-protected policy context supplied by ASP, GAI performs the approval-specific checks within AUTH-03: independently authenticates the Founder approver under the required ceremony, enforces requester/approver separation, confirms the approver satisfies the supplied eligibility and limit requirements, and binds the decision/ticket to the exact canonical action and scope. GAI may reject an incomplete, stale, contradictory, or unverifiable policy context; it must not substitute a locally chosen policy or silently reinterpret the risk tier.

ASP remains authoritative for identity lifecycle, agent capabilities, business status, policy selection and evaluation, action admission, execution enforcement, and GOA dispatch ordering. A valid GAI approval is necessary where policy requires it, but is never an ASP admission decision or execution capability.

This v2 division is a target integration contract, not a claim that the current sandbox v1 API consumes ASP policy context. V1 retains its existing named requester/approver credential and narrow prepare_pull_request workflow unchanged.

GAI must not:
- let the Boss approve its own action;
- let an agent assert that the Founder approved;
- allow a caller to choose a weaker policy version or risk tier;
- authorize an operation outside the canonical business/resource/action scope;
- turn an approval into a general capability grant;
- permit execution merely because a valid receipt exists, without ASP admission and GOA consumption;
- let Delta approve an action or approve its own recovery.

Approval means the Founder approved the exact presented operation. It does not guarantee the provider can execute it, prove that dispatch occurred, or prove the provider outcome.

## 6. Audit and evidence separation

Keep these evidence types distinct:
- approval decision and signed ticket;
- mutable approval validity/revocation state;
- GOA canonical ticket-consumption/dispatch-start record;
- ASP audit and witness evidence;
- provider outcome evidence;
- Boss task/result projection.

A valid signed receipt is not an audit-custody receipt, witness receipt, dispatch record or provider success. GAI must not infer GOA commit from a local response timeout or Second Brain task state.

For v1 sandbox approvals, preserve existing local hash-chain and external checkpoint requirements; do not claim that the local log alone is independently immutable. For v2, the GAI audit event must be durably correlated to the ASP transition and must expose a reconciliation path without becoming a competing GOA log.

## 7. Failure semantics

- Invalid, expired, revoked, wrong-audience, scope-mismatched or replayed ticket: reject.
- Requester/approver identity cannot be established: reject.
- Approver is requester or not eligible: reject.
- ASP identity/policy service unavailable or stale: hold new consequential decisions/consumption as required by the current policy; no fallback trust.
- GOA unavailable or uncertain: no dispatch; reconcile same ticket/operation identity.
- Delta containment active or unverifiable: ASP denies affected dispatch regardless of approval.
- Changed action or payload after approval: new approval required.
- Audit integrity failure: fail closed and require governed recovery.
- Duplicate identical retry: return the original persisted outcome only where the relevant protocol defines identical retry; never create a second approval or reset a consumed ticket.

## 8. Ten alignment resolutions relevant to this repository

| Item | Resolution |
|---|---|
| Approval ownership | GAI is the one Central Approval Authority and AUTH-03 service implementation. ASP remains identity/policy/admission/GOA enforcement. |
| General action scope | Keep v1 sandbox-only; design company-action v2 separately with canonical business/action/payload scope and ASP GOA consumption. |
| Business Registry | Consume ASP's canonical `company_id`/`business_id` and registry version; never create or own business records here. |
| Founder UI | No UI ownership; receive canonical approval presentation/context from ASP and return signed decision evidence. |
| Boss maturity | Treat Second Brain as requester/coordinator only; do not assume task proposals are executable or approved. |
| Delta | Accept independent findings/containment status as inputs; cannot approve. ASP enforces interrupt. No Delta repo was visible. |
| Identity | ASP is the identity issuer; GAI verifies v2 assertions. Existing v1 named credentials remain unchanged. |
| Risk and policy | ASP selects and versions policy, classifies risk and supplies approval requirements; GAI applies AUTH-03 approver authentication/separation and exact-scope decision checks against that authenticated context. Neither may redefine the other's authority. |
| GOA | ASP GOA owns v2 canonical consumption with dispatch start; preserve the narrow v1 consume route for the sandbox API. |
| Transport/deployment | Logical contract is transport-neutral; no new hosting or multi-host assumption. |

## 9. Current proposals and qualification boundaries

- GAI PR #52's tenant-scoped ADR is proposed and owner review is required; this document does not accept it.
- GAI PR #54 remains a draft security-remediation PR; it is not modified by this contract.
- The current sandbox v1 service is single-host and narrowly scoped.
- Company-action v2 requires a separately reviewed ADR, schema, identity/key trust design, transactional persistence, race/replay/revocation tests, audit/recovery qualification and explicit Founder acceptance.
- No deployment, paid infrastructure, migration or production readiness is authorized here.

## 10. Change control

This document is an ecosystem integration contract, not a replacement for `docs/sandbox-approval-authority.md`, `docs/approval-authorization.md`, or the proposed tenant-scoped ADR. Those remain authoritative for their own current scopes. A future v2 implementation must be introduced through a separately reviewed ADR and exact-head implementation PR. Any change to receipt claims, scope, identity issuer, revocation, ticket semantics or GOA consumption requires cross-repository compatibility review.
