# OpenAI Python SDK 3.46.0 application assessment

**Assessment snapshot:** 2026-11-06  
**Candidate:** `openai==3.46.0`  
**Production baseline:** `openai==1.40.0`  
**Decision:** **NO-GO for production migration; continue isolated evaluation.**  
**Scope:** evidence and test reporting only. This report does not authorize a dependency, lockfile, production, or Termux change.

## Executive decision

SDK 3.46.0 has a materially newer transport stack and additional SDK-level capabilities, but the evidence does not establish that it is safer or more capable for this application in production. The candidate passes the application integration coverage already added for its real SDK transport path (subject to the CI evidence limits below), and the HTTPX2 version floor used by the candidate CI job is above the fixed versions for the HTTPX2 advisories reviewed here. However:

- SDK 3.46.0 requires Python >=3.10; this project declares Python >=3.9.
- It replaces the SDK-managed `httpx` transport with `httpx2`, changing the transport, custom-client, proxy, TLS trust-store and dependency surface.
- The SDK permits AnyIO >=4.10,<5, which includes versions affected by three reviewed AnyIO advisories. A candidate runtime resolved to AnyIO >=4.14.2 is needed to clear those findings.
- The current application primarily exercises Chat Completions. New SDK capabilities do not become application capabilities without deliberate implementation and tests. The current `AIClient.embed` path is a deterministic local mock, not a provider-backed embedding request.
- There is not yet a fully matched performance, failure-rate, TLS/proxy, or supported-platform A/B dataset comparing 1.40.0 and 3.46.0.

Keep `openai==1.40.0` as the production pin. A future GO requires the gates in [Acceptance criteria](#acceptance-criteria).

## Reproducible test protocol

The repository's dedicated `sdk-transport-compat` CI job installs the candidate in an isolated GitHub Actions matrix:

| Runtime | Role |
|---|---|
| Python 3.13 | Required candidate compatibility |
| Python 3.14 | Required candidate compatibility |
| Python 3.15 | Experimental only; `continue-on-error` |

The candidate job installs `openai==3.46.0`, `httpx2>=2.15.1,<3`, Starlette/FastAPI and test tooling, runs `pip check`, and executes:

```bash
PYTHONPATH=. python -m pytest -q -o addopts="" tests/test_openai_sdk_transport_compat.py
```

The test module currently contains **17 test functions**. Coverage includes:

- Sync and async SDK client construction and deterministic cleanup.
- Chat Completions, embeddings and streaming over in-process HTTPX2 `MockTransport`.
- Application RAG/embedding wrappers and the asynchronous `AIClient` wrapper.
- Responses and Realtime WebSocket endpoint construction.
- Realtime workload-identity rejection rules.
- Agent-loop integration, propagation of exhausted provider errors, and authenticated `/query` API integration with requester quota accounting.
- Starlette TestClient behavior without the legacy HTTPX deprecation.

No test makes a live OpenAI API call or uses a billable provider request.

### Recorded test evidence and limitations

- PR #45, merged as [`b3ee3624309efee0e1e993a4064c21d8a56bb218`](https://github.com/escorpioantares66-cmyk/github-practice-ai/commit/b3ee3624309efee0e1e993a4064c21d8a56bb218), added lifecycle fixes, provider-error propagation, and real SDK transport/API integration tests. The PR was reported green before merge.
- PR #45's description records a prior Termux CPython 3.14.8 smoke test of 13 tests. This is historical device evidence, not a fresh run performed by this assessment.
- The 17 test functions are present in the candidate CI module. A function count is not itself a passing test result. The fresh matrix result and exact resolved dependency graph must be captured by the assessment workflow artifact; do not infer a pass from the presence of the tests.
- This assessment environment did not execute GitHub Actions jobs or run tests on the user's Termux device. The workflow added with this report records the candidate dependency freeze and `pip-audit` output without installing the audit tool into the candidate environment.

## Dependency and platform comparison

| Area | Production baseline (project metadata) | SDK 3.46.0 candidate metadata | Assessment |
|---|---|---|---|
| Python | Project supports >=3.9 | SDK requires >=3.10 | **Compatibility regression** for Python 3.9 |
| HTTP transport | `httpx==0.28.1` and SDK 1.40.0 | `httpx2>=2.12,<3`; legacy `httpx` is no longer installed by the SDK | **Material migration**; custom transports and integrations must use HTTPX2 |
| Jiter | Project `jiter>=0.4,<1` | SDK `jiter>=0.16,<1` | Higher native floor; user's separate Jiter 0.18.0 validation is encouraging but not a complete stack validation |
| AnyIO | Project `anyio>=4.0` | SDK `anyio>=4.10,<5` | Broad range admits vulnerable releases; resolve and audit exact version |
| Pydantic | Project `pydantic>=2.12` | SDK `pydantic>=1.10.13,<3` with exclusions for early 2.x | Wider SDK compatibility range; project constraint currently controls its own resolver |
| typing-extensions | Not explicitly direct-pinned by project | SDK `typing-extensions>=4.14,<5` | New runtime floor; capture exact resolved version |
| httpcore2 | Not present in baseline SDK transport graph | Transitive HTTPX2 transport dependency | Capture exact version from candidate freeze and audit independently |

The SDK's published metadata and HTTPX2 migration guide are linked below. Candidate CI deliberately uses HTTPX2 >=2.15.1, but the actual resolved version and paired `httpcore2` version must be read from the attached freeze artifact, not assumed from the lower bound.

## Security advisory findings

The following are **dependency advisories**, not advisories against the OpenAI SDK package itself. The OpenAI SDK repository's Security page stated that it had no published security advisories at the time of this snapshot. That statement is not proof that the SDK has no undisclosed or future vulnerabilities.

### OpenAI SDK package itself

| Component | Result |
|---|---|
| `openai==3.46.0` | **No published SDK-package advisory identified** in the reviewed official GitHub Security page and public package metadata as of this snapshot. This is a point-in-time public-source result, not a guarantee of absence. |

Sources: [openai-python Security](https://github.com/openai/openai-python/security), [PyPI openai 3.46.0](https://pypi.org/project/openai/3.46.0/).

### Runtime dependency advisories

| Advisory (published) | Component and affected range | Severity | Impact | 3.46.0 applicability |
|---|---|---|---|---|
| [GHSA-7mj9-2mp8-4m2p / CVE-2026-84381](https://osv.dev/vulnerability/GHSA-7mj9-2mp8-4m2p) (2026-09-08) | `httpx2` 2.6.0–2.9.1; underlying `httpcore2` before 2.10.0 | High, CVSS 8.1 | WSS through SOCKS5 may be sent without TLS, exposing credentials and frames | **Not affected if** candidate resolves HTTPX2 >=2.15.1 and matching httpcore2 >=2.10.0. The candidate workflow's HTTPX2 lower bound clears the fixed range; exact resolved pair still must be recorded. |
| [GHSA-f2fp-rgf2-35cp / CVE-2026-84378](https://osv.dev/vulnerability/GHSA-f2fp-rgf2-35cp) (2026-09-08) | `httpx2` before 2.10.0 | Medium, CVSS 5.9 | Quadratic SSE line buffering can cause CPU exhaustion | **Not affected** by HTTPX2 >=2.15.1. |
| [GHSA-h4x7-gw46-3wm6 / CVE-2026-84379](https://osv.dev/vulnerability/PYSEC-2026-3848) (2026-09-08) | `httpx2` before 2.11.0 | Medium, CVSS 5.3 | CR/LF injection into multipart part headers when untrusted upload metadata is passed | **Not affected** by HTTPX2 >=2.15.1. |
| [GHSA-pf96-p4fj-6566 / CVE-2026-84380](https://osv.dev/vulnerability/PYSEC-2026-3849) (2026-09-08) | `httpx2` before 2.11.0 | Medium, CVSS 5.6 | Conflicting Content-Length and Transfer-Encoding headers can create request-smuggling ambiguity | **Not affected** by HTTPX2 >=2.15.1. |
| [GHSA-8xx6-hgc6-gc2m / CVE-2026-84382](https://osv.dev/vulnerability/GHSA-8xx6-hgc6-gc2m) (2026-09-08) | `httpx2` before 2.12.0 | High, CVSS 7.5 | Streaming decompression can allocate very large intermediate buffers and exhaust memory | **Not affected** by HTTPX2 >=2.15.1. |
| [GHSA-82r6-8w77-94w6 / CVE-2026-63374](https://osv.dev/vulnerability/GHSA-82r6-8w77-94w6) (2026-09-18) | `anyio`; OSV records fixed version 4.14.2 | Critical, CVSS v4 9.3 | IDNA 2003 hostname encoding can permit TLS certificate spoofing for affected internationalized hostnames when the connection is redirected | **Applicability uncertain until exact AnyIO version is captured**; SDK range >=4.10,<5 permits versions before 4.14.2. |
| [GHSA-3w57-8xmc-8v26 / CVE-2026-63349](https://osv.dev/vulnerability/GHSA-3w57-8xmc-8v26) (2026-09-18) | `anyio` 4.14.0–4.14.1; fixed 4.14.2 | High, CVSS v4 7.0 | `open_process` can fail to apply `extra_groups`, undermining intended supplementary-group privilege dropping | **Applicability uncertain until exact AnyIO version is captured**; the SDK's open-ended range admits affected releases. |
| [GHSA-5p39-cfhj-2xmp / CVE-2026-64847](https://osv.dev/vulnerability/PYSEC-2026-4024) (2026-10-01) | `anyio`; OSV records fixed version 4.14.2 | Medium, CVSS v4 6.8 | Process-pool workers can block indefinitely if stderr fills an undrained pipe | **Applicability uncertain until exact AnyIO version is captured**; require AnyIO >=4.14.2 to clear the OSV fixed boundary. |

For the HTTPX2 findings, the patched floors are 2.10.0 (WSS/SOCKS and SSE), 2.11.0 (multipart and request framing), and 2.12.0 (decompression). HTTPX2 >=2.15.1 is beyond all those floors. The AnyIO advisories are the unresolved dependency risk: SDK 3.46.0's declared range does not itself exclude affected AnyIO versions.

### Other requested dependency checks

- `httpcore2`: the WSS/SOCKS advisory above is fixed at 2.10.0. The candidate's exact paired version must be confirmed from the freeze artifact.
- `jiter`: no matching public OSV advisory was identified in the scoped search for this snapshot; exact package audit remains required.
- `pydantic`: no matching advisory for the `pydantic` distribution was identified in the scoped search. Advisories for the separate `pydantic-ai` project are not applicable to the `pydantic` package and are intentionally excluded.
- `typing-extensions`: no matching public OSV advisory was identified in the scoped search; exact package audit remains required.
- `anyio`: three findings above require exact version verification.
- `httpx2`: five findings above have fixed versions below the candidate workflow's stated lower bound.

## Reproducing and collecting evidence

From a clean checkout of the assessment branch:

```bash
python -m pip install "openai==3.46.0" "httpx2>=2.15.1,<3" \
  "starlette[full]>=1.2,<2" "fastapi>=0.115" \
  "pytest>=8" "pytest-asyncio>=0.23" "cachetools>=5"
python -m pip check
PYTHONPATH=. python -m pytest -q -o addopts="" \
  tests/test_openai_sdk_transport_compat.py
```

The CI job additionally runs `scripts/audit_sdk_candidate_env.sh`. It records:
- Python/platform and exact `openai`, `httpx2`, `httpcore2`, `anyio`, `jiter`, `pydantic`, and `typing-extensions` versions;
- a complete `pip freeze --all` dependency snapshot;
- a `pip-audit` JSON report scanned against the candidate environment from a separate temporary audit-tool virtual environment;
- the audit exit status.

Download the `sdk-3.46.0-evidence` artifact from the candidate CI job. Compare the exact dependency versions to the affected/fixed ranges above. Do not mark an advisory clear based only on the broad requirement specifier.

## Acceptance criteria

A production GO requires all of the following, with immutable CI evidence:

1. Baseline and candidate tested against the same application commit and equivalent supported Python versions.
2. All application unit, API, quota, auth, streaming, cancellation, retry, timeout, and client-lifecycle tests pass on both stacks.
3. Candidate `pip check` passes and `pip-audit` reports no unresolved applicable findings; the exact resolved AnyIO version is >=4.14.2, and HTTPX2/httpcore2 are on patched versions.
4. TLS certificate verification, proxy behavior, custom transport integration, and HTTPX2 trust-store behavior are explicitly tested.
5. Python 3.9 support is either preserved through a deliberate compatibility strategy or formally retired as a separate product decision; it must not disappear as an incidental SDK upgrade.
6. Termux CPython 3.14 native wheels are independently verified and runtime smoke tests pass on the actual device only after explicit user authorization.
7. Matched workload measurements show no unacceptable regression in latency, memory, error rate, or resource use.
8. The report is reviewed and the user explicitly authorizes any production dependency change.

## Final recommendation

**NO-GO for production migration today.** The HTTPX2 advisory set is clearable with the candidate's current transport floor, but the AnyIO dependency range is too broad to establish safety without the exact resolved environment. The project also loses declared Python 3.9 compatibility, and the current test set does not yet prove performance or security superiority over 1.40.0.

Continue isolated evaluation. Do not change the production SDK pin, dependency files, Termux installation, or production configuration on the strength of this report alone.

## Primary references

- [OpenAI SDK 3.46.0 PyPI metadata](https://pypi.org/project/openai/3.46.0/)
- [OpenAI SDK source metadata](https://github.com/openai/openai-python/blob/main/pyproject.toml)
- [OpenAI SDK HTTPX2 migration guide](https://github.com/openai/openai-python/blob/main/httpx2.md)
- [OpenAI SDK security policy and advisories](https://github.com/openai/openai-python/security)
- [HTTPX2 2.15.1 PyPI release](https://pypi.org/project/httpx2/2.15.1/)
- [HTTPX2 2.12.0 changelog](https://github.com/pydantic/httpx2/blob/main/src/httpx2/CHANGELOG.md)
- [OSV](https://osv.dev/) advisory records linked in the tables above.
