# Render deployment readiness — github-practice-ai

Status: preparation only. No Render service, disk, AWS bucket, IAM role, secret,
or deployment has been created by this work.

## Scope and branch relationship

This preparation branch starts from API `main` at
`4f5b5e6871fd10009a20f2d0c870a20adaa4c938`. It deliberately does not modify
PR #54 (`security/approval-f01-f02-remediation`, head
`6d9899d4abf3a9e49379af39da58eb60657e2a0b)).

**Do not deploy this branch as a production approval authority.** It does not
contain PR #54's sandbox candidate/trusted-floor enforcement. PR #54 must first
be independently reviewed and integrated under its own authorization, then
this deployment preparation must be reconciled against that resulting main
head and re-tested. The Blueprint includes the PR #54 runtime settings as
preparation, not evidence that the current branch enforces them.

## Proposed Render service

- Service: `github-practice-ai`
- Type/runtime: public web service, Docker
- Dockerfile: repository root
- Region: Frankfurt (provisional; Render region is immutable after creation)
- Instance plan: Starter (paid; owner cost approval required)
- Instance count: exactly one
- Auto deploy: off; deployment is manual after CI and human release approval
- Health check: `/healthz` (liveness only)
- Disk: one provisional 1 GB persistent disk mounted at `/var/data`
- Preview environments: disabled by omission/default; no preview service is
  intended for the approval authority

The plan and disk size are placeholders for owner review, not a purchase
authorization. Disk capacity can be increased but not reduced. Region and
service type are difficult/immutable decisions after creation. Confirm region,
monthly compute cost, disk cost, backup expectations and retention before
creating any resource.

A disk-backed Render service is single-instance and does not support
zero-downtime deploys. Redeploys stop the old instance before starting the new
one, causing a short interruption. This is accepted only for the v1
single-host/file-backed authority. It is not a multi-host or multi-tenant
SaaS deployment.

## Application data layout

All application-owned durable files must be under `APP_DATA_DIR`:

| Data | Path |
|---|---|
| Legacy approval records | `/var/data/approvals` |
| Legacy append-only audit | `/var/data/logs/audit.jsonl` |
| Notes | `/var/data/notes` |
| Quota/rate-limit SQLite | `/var/data/.agent_state/quotas.sqlite3` |
| Sandbox approval records and audit | `/var/data/sandbox-approvals` |

The application must not silently fall back to its container filesystem when
`APP_DATA_DIR` is set incorrectly. The Blueprint sets
`APP_REQUIRE_MOUNTED_DATA_DIR=true`; `/readyz` verifies the configured path
exists, is writable and is an actual mount point. The application health check
remains `/healthz` so a temporary dependency outage does not cause Render to
mistake process liveness for a failed deploy. `/readyz` is a separate,
non-secret readiness diagnostic.

The persistent disk is not a backup system. Keep independently retained,
tested backups and checkpoint versions. Render disk snapshots are whole-disk
recovery artifacts; they are not a substitute for application-consistent
recovery or independent S3 audit custody.

## Container requirements

The Docker image installs the `audit-s3` extra so `boto3` is present. The
server binds to Render's `PORT` environment variable, falling back to 10000
for local use. The container runs Uvicorn as PID 1 through a shell command;
graceful signal forwarding/shutdown must be tested before release.

## Environment variables

The Blueprint uses `sync: false` for secrets and operator-provided values.
Render prompts for these values during initial Blueprint creation only; later
Blueprint syncs do not update them. Do not put real values in this repository.

Required approval configuration includes:

- `AGENT_API_KEYS`, `AGENT_APPROVER_KEYS`
- `SANDBOX_APPROVAL_ACTIVE_KID`
- `SANDBOX_APPROVAL_SIGNING_PRIVATE_KEY`
- `SANDBOX_APPROVAL_VERIFY_KEYS`
- `SANDBOX_APPROVAL_ISSUER`, `SANDBOX_APPROVAL_AUDIENCE`
- `SANDBOX_APPROVALS_DIR`
- `AGENT_AUDIT_CHECKPOINT_S3_BUCKET`
- `AGENT_SANDBOX_AUDIT_CHECKPOINT_S3_KEY`
- `AGENT_SANDBOX_AUDIT_CHECKPOINT_FLOOR_S3_KEY`
- `AGENT_SANDBOX_AUDIT_STORE_ID`
- `AGENT_SANDBOX_AUDIT_CHECKPOINT_MAX_AGE_SECONDS`
- `AGENT_SANDBOX_AUDIT_MAX_UNANCHORED_SUFFIX`
- `AWS_REGION`

The S3 object keys, stable store ID, freshness limit and maximum unanchored
suffix must be explicitly reviewed. Do not use guessed or default policy
values. The readiness endpoint checks presence, not correctness, authenticity
or successful use of these values.

### AWS credential delivery — unresolved release blocker

The code uses boto3's default credential chain. No Render-to-AWS workload
identity or role-assumption arrangement has been provisioned or proven.
Do not solve this by casually adding long-lived AWS access keys to the
Blueprint. Before deployment, select and test a credential delivery method
that supports rotation and limits the application identity to exact
`s3:GetObject` access on the two checkpoint objects. Keep operator publishing
credentials entirely separate. If the available hosting integration requires
static credentials, document the residual risk, rotation schedule, storage
and emergency revocation procedure, and obtain explicit owner acceptance.

## S3 and IAM

Use a dedicated private bucket with Block Public Access enabled, versioning,
encryption at rest and TLS-only access. Candidate and trusted-floor objects
must be separate keys. Do not grant the application `s3:PutObject`,
`s3:DeleteObject`, `s3:ListBucket`, bucket-policy administration or IAM
administration.

See `docs/aws/sandbox-checkpoint-readonly-policy.example.json` for the
application policy template. Replace the bucket placeholder only in the
operator's deployment environment; never commit account-specific identifiers
or credentials.

The operator publisher must use a different identity. It may publish the
candidate and advance the trusted floor only through the reviewed runbook,
with human confirmation, immutable/versioned evidence and a record of who
accepted each floor. The application must never repair or re-baseline either
object after a mismatch.

## Release gates

All gates below are required before any live deployment:

1. PR #54 is integrated through its own exact-head review and authorization;
   deployment code is reconciled with that resulting main commit.
2. Run the complete test suite, focused approval tests, lint and Docker build
   against the exact proposed deployment commit.
3. Validate `render.yaml` using current Render Blueprint validation; this
   branch has not yet been applied or synced to Render.
4. Verify `/healthz` liveness and `/readyz` fail-closed behavior using
   synthetic configuration and temporary storage.
5. Prove all legacy and sandbox records, logs, notes and SQLite state are
   written beneath the mounted disk; restart and redeploy in a non-production
   service and verify persistence.
6. Prove exactly one service instance, no autoscaling, no preview service and
   manual deployment only.
7. Prove the application AWS identity can read the two exact S3 objects and
   cannot list, write, overwrite, delete or change bucket/IAM configuration.
8. Prove a separate operator identity can publish only through the documented
   checkpoint procedure; verify object version history and independent
   recovery.
9. Run missing-object, malformed-object, wrong-store, rollback, stale
   checkpoint, excessive unanchored suffix and S3-outage tests. Approval
   operations must fail closed.
10. Verify requester/approver separation, signing/verification key rotation,
    restart recovery, log redaction, rate limiting and exact runtime source SHA.
11. Obtain human security review of the deployment evidence and explicit
    owner approval of region, plan, disk size, cost, AWS credential model and
    deployment commit.

## Acceptance evidence to retain

Record the exact source SHA, Docker image digest, Blueprint validation result,
Render service settings, disk mount proof, instance count, health/readiness
results, S3/IAM permission tests, checkpoint IDs and versions, recovery test
results, and human reviewer disposition. Do not record secret values.

## Explicit non-actions

This preparation does not create a Render service or Blueprint, attach a disk,
create an S3 bucket, create IAM identities/policies, enter credentials, run a
deployment, merge PR #54, modify `main`, or change production permissions.
