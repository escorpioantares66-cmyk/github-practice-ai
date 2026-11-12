# Render deployment readiness — github-practice-ai

Status: preparation only. No Render service, disk, AWS bucket, IAM role, secret,
or deployment has been created by this work.

## Scope and branch relationship

This preparation branch starts from API `main` at
`4f5b5e6871fd10009a20f2d0c870a20adaa4c938`. It deliberately does not modify
PR #54 (`security/approval-f01-f02-remediation`, head
`6d9899d4abf3a9e49379af39da58eb60657e2a0b).

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
- Health check: `/healthz` (persistent-disk mount gate; no external S3 probe)
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
| Audit rotation anchor, journal and state | `/var/data/logs/audit.anchor.json`, `/var/data/logs/audit.rotation.json`, `/var/data/logs/audit.rotation-state.json` |
| Rotated audit segments | `/var/data/logs/audit-segments` |
| Approval retention archives | `/var/data/archive` |
| Notes | `/var/data/notes` |
| Quota/rate-limit SQLite | `/var/data/.agent_state/quotas.sqlite3` |
| RAG vector index | `/var/data/data/faiss_store` |
| Sandbox approval records and audit | `/var/data/sandbox-approvals` |

The application must not silently fall back to its container filesystem when
`APP_DATA_DIR` is set incorrectly. The Blueprint sets
`APP_REQUIRE_MOUNTED_DATA_DIR=true`; `/readyz` verifies the configured path
exists, is writable and is an actual mount point. `/readyz` also verifies the sandbox approval directory and quota database are beneath that root. The Render health check remains `/healthz` and verifies the local persistent data mount only; it does not probe S3. The application refuses to start/use configured persistent paths if the required mount is missing. `/readyz` separately reports non-secret configuration and dependency readiness.

The persistent disk is not a backup system. Keep independently retained,
tested backups and checkpoint versions. Render disk snapshots are whole-disk
recovery artifacts; they are not a substitute for application-consistent
recovery or independent S3 audit custody.

## Container requirements

The Docker image installs the `audit-s3` extra and declares Uvicorn as a runtime dependency. It binds to Render's `PORT` environment variable, falling back to 10000 for local use. A small root bootstrap clears supplementary groups, adjusts ownership of only the mounted data-root directory, sets GID/UID 10001, verifies the effective UID/GID and empty supplementary-group list, then uses `exec` to make Uvicorn PID 1. It never recursively changes existing data ownership. The code-level checks and mocked syscall tests do not replace a container-level process-identity proof; verify the actual mounted-disk ownership and Uvicorn credentials in a non-production service before release.

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
values. The readiness endpoint checks configuration presence and performs a live
candidate/trusted-floor policy verification against the local sandbox audit.
This proves the current checkpoint policy check succeeded; it does not prove
the AWS identity is limited to the intended IAM permissions or that operator
custody and credential rotation are correct. Those remain separate release gates.

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
4. Verify `/healthz` persistent-mount gating and `/readyz` fail-closed behavior using
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


## Adversarial review remediation plan and acceptance tests

This section records the fresh review findings F-DEP-01 through F-DEP-06.
F-DEP-01 has a code change prepared; F-DEP-06 and F-DEP-02 now have code
changes and focused tests prepared on this branch. None of these changes has
been executed in CI or independently runtime-verified. F-DEP-03 through
F-DEP-05 remain open to the extent described below.

### F-DEP-06 — Medium: fail closed when the required data root is absent

**Status:** Code change and focused tests prepared on this branch; test
execution and full storage-call-site validation remain pending.

When `APP_REQUIRE_MOUNTED_DATA_DIR=true`, `data_root()` now raises if
`APP_DATA_DIR` is absent or blank instead of silently returning the current
working directory. Legacy local fallback to `Path(".")` remains available
only when the mounted-disk requirement is not enabled.

`data_path()` now rejects empty components, POSIX/Windows absolute
components, parent-directory traversal and paths that resolve outside the
configured root through an existing symlink. This is a path-resolution
defense-in-depth check, not a race-free substitute for safe file-opening
primitives such as `O_NOFOLLOW` at the final file boundary.

Acceptance tests:

1. With `APP_REQUIRE_MOUNTED_DATA_DIR=true` and `APP_DATA_DIR` unset or
   blank, `data_root()` raises; it never returns `Path(".")`.
2. With the requirement disabled and `APP_DATA_DIR` absent, legacy local
   behavior remains available.
3. Relative configured roots are rejected.
4. `data_path()` rejects absolute components, Windows drive/UNC components,
   empty components and any `..` traversal.
5. An existing symlink beneath the root that resolves outside the root is
   rejected.
6. All existing storage call sites continue to resolve beneath the intended
   data root in unit and integration tests.

### F-DEP-01 — High: readiness must prove checkpoint enforcement

**Status:** Code change prepared on this branch; full verification remains
pending PR #54 integration and exact-head CI.

The /readyz endpoint now requires the sandbox approval module's production
_independent audit checkpoint verifier and executes it. Readiness accepts
only a result that explicitly reports valid, policy_accepted and
trusted_floor_verified as true. Missing verifier, S3 errors, malformed
evidence, stale/rollback policy failures and invalid results make the
endpoint report not_ready. The endpoint does not expose exception text or
credential details.

The current branch intentionally does not contain PR #54's enforcement
implementation. Therefore its readiness result must remain not_ready until
PR #54 is independently reviewed/integrated and this branch is reconciled
with that code. A synthetic verifier is used only in unit tests.

Acceptance tests:

1. With all environment variables and boto3 present but no verifier function,
   /readyz returns 503 and the enforcement check is false.
2. If the verifier raises for missing S3 objects, S3 outage, malformed
   checkpoint, wrong store ID, rollback, stale candidate or excessive
   unanchored suffix, /readyz returns 503.
3. A result missing any of valid, policy_accepted or trusted_floor_verified,
   or setting any to false, is rejected.
4. Only a successful live verification of candidate and trusted floor against
   the local audit history can make the enforcement check true.
5. The report contains no exception text, secret values, AWS credentials or
   checkpoint object contents.
6. After PR #54 integration, verify that every sandbox lifecycle operation
   (create, approve/deny, inspect, decision retrieval and consume) independently
   invokes the same fail-closed verifier; readiness success must not replace
   operation-time verification.
7. /healthz remains a local liveness/persistent-mount check and does not
   become dependent on S3 availability. /readyz is the explicit external
   security-readiness check.

### F-DEP-02 — Medium: complete privilege dropping

**Status:** Code change and focused mocked tests prepared on this branch;
container-level identity proof and test execution remain pending.

The root entrypoint now calls `os.setgroups([])` while privileged and before
`setgid(10001)` and `setuid(10001)`. It then verifies effective UID 10001,
effective GID 10001 and an empty supplementary-group list immediately before
exec. Non-root startup is accepted only when it already has that exact
identity. Failure to clear groups or satisfy identity checks prevents server
startup. Ownership changes remain limited to the mount root.

Acceptance tests:

1. When starting as root, the entrypoint clears supplementary groups before
   setting the target GID and UID.
2. The process verifies effective UID 10001, effective GID 10001 and an empty
   supplementary group list immediately before exec.
3. The order is supplementary-group clearing, setgid, then setuid; failure
   at any step prevents server startup.
4. Non-root startup is rejected unless effective UID/GID and supplementary
   groups satisfy the documented policy.
5. Tests prove no recursive ownership changes occur and only the mount root
   is changed.
6. A container-level test inspects the actual Uvicorn process credentials,
   not only mocked syscall order.

### F-DEP-03 — Medium: separate liveness from security readiness

**Status:** Partially addressed by F-DEP-01; runtime behavior remains unverified.

Acceptance tests:

1. /healthz returns success only when the required local persistent mount is
   present, writable and safe.
2. /healthz does not make S3 calls; a simulated S3 outage does not cause a
   liveness failure when local storage remains healthy.
3. /readyz returns 503 when checkpoint verification fails, required
   configuration is absent, the mounted storage is unsafe, or configured
   durable paths escape the data root.
4. /readyz returns 200 only after a successful candidate-and-floor policy
   verification and all other readiness checks pass.
5. Responses never expose secrets, AWS SDK exception text, credentials or
   checkpoint payloads.
6. Tests exercise the actual FastAPI routes and status codes, not only the
   helper function.

### F-DEP-04 — High: prove AWS credential delivery and custody

**Status:** Operational blocker; no AWS resources or permissions are
authorized or provisioned.

Acceptance tests:

1. The application obtains credentials through the owner-approved,
   rotatable delivery mechanism; no operator publishing credentials are
   available to the API process.
2. The application identity can perform s3:GetObject on the exact candidate
   and trusted-floor object ARNs.
3. The application identity is denied s3:ListBucket, s3:PutObject,
   s3:DeleteObject, version deletion, bucket-policy changes and IAM
   administration.
4. The separate operator identity can perform only the documented checkpoint
   publication/advancement workflow and is not present in application
   environment variables or process credentials.
5. Rotation, expiry, revocation and outage recovery are exercised in a
   non-production environment.
6. Evidence includes the effective IAM policy, identity, exact object ARNs,
   positive and negative API tests, rotation result and operator review record.

### F-DEP-05 — Medium: prove complete persistent-storage coverage

**Status:** Code-path review completed; integration proof pending.

Acceptance tests:

1. Exercise approval records, audit append, audit rotation state and segments,
   retention archives, notes, quota SQLite database and sidecars, vector
   index, and sandbox approval records/audit.
2. Trace every durable write and assert its resolved path is beneath the
   mounted APP_DATA_DIR; reject symlink escapes and unexpected relative paths.
3. Restart the container and verify all records, indexes, counters and audit
   sequence/hash state survive unchanged.
4. Exercise disk-full, read-only mount, missing mount, permission failure and
   interrupted write scenarios; security-sensitive operations fail closed.
5. Verify the actual mounted volume and Uvicorn process in a non-production
   Render service before release.
6. Retain a path inventory and test evidence tied to the exact deployed commit.

### Execution order and release gates

1. Complete F-DEP-06 data-root fail-closed and containment tests.
2. Complete F-DEP-02 privilege hardening tests and container-level identity
   proof.
3. Integrate PR #54 only after its separate review and explicit merge
   authorization; reconcile this branch against the resulting main commit.
4. Run F-DEP-01 tests against the real integrated verifier and prove all
   lifecycle operations invoke it at operation time.
5. Complete F-DEP-03 FastAPI route and failure-mode tests.
6. Resolve F-DEP-04 credential delivery, IAM least privilege and operator
   separation with owner approval.
7. Complete F-DEP-05 mounted-volume persistence and recovery tests.
8. Run the complete repository test suite, Ruff, Docker build and official
   Render Blueprint validation on the exact final branch head.
9. Obtain independent human security review and explicit owner release
   authorization before any service or cloud resource is created.

No item in this plan authorizes a merge, PR creation, Render/AWS resource
creation, credential entry, permission change or deployment.
