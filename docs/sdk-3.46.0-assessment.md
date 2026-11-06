# OpenAI Python SDK 3.46.0 application assessment

**Assessment snapshot:** 2026-11-07  
**CI evidence run:** 2026-11-06 (PR #46 head `0d070985074f9ead813bca315a03dcd5177aec51`)  
**Candidate:** `openai==3.46.0`  
**Production baseline:** `openai==1.40.0`  
**Decision:** **NO-GO for production migration; continue isolated evaluation.**  
**Scope:** evidence and test reporting only. This report does not authorize a dependency, lockfile, production, or Termux change.

## Executive decision

SDK 3.46.0 has a materially newer transport stack and additional SDK-level capabilities. PR #46's CI artifacts now provide measured evidence: the 17-test SDK transport/API integration suite passed on Python 3.13.18, 3.14.10, and the experimental 3.15.2 runner; `pip check` passed; and `pip-audit` reported zero vulnerabilities across 36 installed distributions in each matrix environment. The exact resolved AnyIO and HTTPX2 dependency versions are above the fixed boundaries for the reviewed advisories. This is positive evidence for the isolated candidate environment, but it does not establish production superiority. Remaining limitations are:

- SDK 3.46.0 requires Python >=3.10; this project declares Python >=3.9.
- The SDK migrates its transport from legacy `httpx` to `httpx2`. The CI environment did contain both `httpx==0.28.1` and `httpx2==2.16.0`; compatibility across the application's broader proxy, TLS, custom-transport, and trust-store configurations remains to be demonstrated.
- The SDK's broad AnyIO requirement (`>=4.10,<5`) does not itself enforce the safe floor found in this run (`4.16.0`). Keep a resolver constraint or explicit dependency policy in any future deployment plan.
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
- **Fresh CI result:** workflow run [#42295660361](https://github.com/escorpioantares66-cmyk/github-practice-ai/actions/runs/42295660361) completed successfully. All three SDK transport matrix jobs and all four regular `build` jobs (Python 3.11–3.14) completed successfully. The Python 3.15 matrix entry is explicitly experimental (`continue-on-error: true`). The separate Linux checkpoint-boundary workflow [#42295660077](https://github.com/escorpioantares66-cmyk/github-practice-ai/actions/runs/42295660077) also completed successfully.
- **Python 3.13.18:** `17 passed, 3 warnings in 1.70s`; `pip check` passed; `pip-audit` exit code `0`, with no vulnerabilities reported across 36 installed distributions.
- **Python 3.14.10:** `17 passed, 3 warnings in 1.63s`; `pip check` passed; `pip-audit` exit code `0`, with no vulnerabilities reported across 36 installed distributions.
- **Python 3.15.2 (experimental):** `17 passed, 3 warnings in 1.68s`; `pip check` passed; `pip-audit` exit code `0`, with no vulnerabilities reported across 36 installed distributions.
- Each artifact also contains the exact `pip freeze --all`, environment metadata, JSON audit output, and complete pytest output. The warning summary includes Pydantic class-based `Config` deprecations; the logs also emit a pytest-asyncio fixture-loop-scope deprecation notice. These are warnings, not test failures, and should be cleaned up before relying on the candidate stack long term.
- These are GitHub-hosted Linux x86_64 results. They do not replace a fresh Termux CPython 3.14 device test. PR #45's earlier Termux CPython 3.14.8 smoke result remains historical evidence only.

## Dependency and platform comparison

| Area | Production baseline (project metadata) | SDK 3.46.0 candidate metadata | Assessment |
|---|---|---|---|
| Python | Project supports >=3.9 | SDK requires >=3.10 | **Compatibility regression** for Python 3.9 |
| HTTP transport | `httpx==0.28.1` and SDK 1.40.0 | `httpx2>=2.12,<3`; legacy `httpx` is no longer installed by the SDK | **Material migration**; custom transports and integrations must use HTTPX2 |
| Jiter | Project `jiter>=0.4,<1` | SDK `jiter>=0.16,<1` | Higher native floor; candidate CI resolved `jiter==0.19.0` on all three matrix runners; the prior Termux 0.18.0 validation remains separate historical evidence |
| AnyIO | Project `anyio>=4.0` | SDK `anyio>=4.10,<5` | Candidate CI resolved `anyio==4.16.0` (above the reviewed fixed boundary); SDK metadata still permits earlier vulnerable versions unless the deployment resolver constrains it |
| Pydantic | Project `pydantic>=2.12` | SDK `pydantic>=1.10.13,<3` with exclusions for early 2.x | Wider SDK compatibility range; project constraint currently controls its own resolver |
| typing-extensions | Not explicitly direct-pinned by project | SDK `typing-extensions>=4.14,<5` | Candidate CI resolved `typing-extensions==4.16.0`; no finding was reported by the CI `pip-audit` scan |
| httpcore2 | Not present in baseline SDK transport graph | Transitive HTTPX2 transport dependency | Candidate CI resolved `httpcore2==2.16.0`, above the reviewed 2.10.0 fixed floor |

The CI artifacts show the same resolved candidate stack on all three Python versions. The candidate workflow's `pip check` step succeeded on each runner.

| Python runner | `openai` | `httpx2` | `httpcore2` | `anyio` | `jiter` | `pydantic` | `typing-extensions` | Test result |
|---|---:|---:|---:|---:|---:|---:|---:|---|
| 3.13.18 | 3.46.0 | 2.16.0 | 2.16.0 | 4.16.0 | 0.19.0 | 2.14.3 | 4.16.0 | 17 passed |
| 3.14.10 | 3.46.0 | 2.16.0 | 2.16.0 | 4.16.0 | 0.19.0 | 2.14.3 | 4.16.0 | 17 passed |
| 3.15.2 (experimental) | 3.46.0 | 2.16.0 | 2.16.0 | 4.16.0 | 0.19.0 | 2.14.3 | 4.16.0 | 17 passed |

The complete freeze also contains `httpx==0.28.1` alongside `httpx2==2.16.0`, so both transport packages are present in this full application/test environment. The SDK's migration away from legacy HTTPX should not be interpreted as proof that the application no longer installs or uses legacy HTTPX elsewhere. The artifact contains the authoritative full dependency snapshot for each runner.

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
| [GHSA-7mj9-2mp8-4m2p / CVE-2026-84381](https://osv.dev/vulnerability/GHSA-7mj9-2mp8-4m2p) (2026-09-08) | `httpx2` 2.6.0–2.9.1; underlying `httpcore2` before 2.10.0 | High, CVSS 8.1 | WSS through SOCKS5 may be sent without TLS, exposing credentials and frames | **Not affected in the measured CI environment:** `httpx2==2.16.0` and `httpcore2==2.16.0`, both beyond the affected ranges and fixed floors. |
| [GHSA-f2fp-rgf2-35cp / CVE-2026-84378](https://osv.dev/vulnerability/GHSA-f2fp-rgf2-35cp) (2026-09-08) | `httpx2` before 2.10.0 | Medium, CVSS 5.9 | Quadratic SSE line buffering can cause CPU exhaustion | **Not affected in the measured CI environment:** `httpx2==2.16.0`. |
| [GHSA-h4x7-gw46-3wm6 / CVE-2026-84379](https://osv.dev/vulnerability/PYSEC-2026-3848) (2026-09-08) | `httpx2` before 2.11.0 | Medium, CVSS 5.3 | CR/LF injection into multipart part headers when untrusted upload metadata is passed | **Not affected in the measured CI environment:** `httpx2==2.16.0`. |
| [GHSA-pf96-p4fj-6566 / CVE-2026-84380](https://osv.dev/vulnerability/PYSEC-2026-3849) (2026-09-08) | `httpx2` before 2.11.0 | Medium, CVSS 5.6 | Conflicting Content-Length and Transfer-Encoding headers can create request-smuggling ambiguity | **Not affected in the measured CI environment:** `httpx2==2.16.0`. |
| [GHSA-8xx6-hgc6-gc2m / CVE-2026-84382](https://osv.dev/vulnerability/GHSA-8xx6-hgc6-gc2m) (2026-09-08) | `httpx2` before 2.12.0 | High, CVSS 7.5 | Streaming decompression can allocate very large intermediate buffers and exhaust memory | **Not affected in the measured CI environment:** `httpx2==2.16.0`. |
| [GHSA-82r6-8w77-94w6 / CVE-2026-63374](https://osv.dev/vulnerability/GHSA-82r6-8w77-94w6) (2026-09-18) | `anyio`; OSV records fixed version 4.14.2 | Critical, CVSS v4 9.3 | IDNA 2003 hostname encoding can permit TLS certificate spoofing for affected internationalized hostnames when the connection is redirected | **Not affected in the measured CI environment:** `anyio==4.16.0`, above the OSV fixed boundary 4.14.2. The SDK's broad range still permits earlier versions if future resolution is not constrained. |
| [GHSA-3w57-8xmc-8v26 / CVE-2026-63349](https://osv.dev/vulnerability/GHSA-3w57-8xmc-8v26) (2026-09-18) | `anyio` 4.14.0–4.14.1; fixed 4.14.2 | High, CVSS v4 7.0 | `open_process` can fail to apply `extra_groups`, undermining intended supplementary-group privilege dropping | **Not affected in the measured CI environment:** `anyio==4.16.0`, outside the affected 4.14.0–4.14.1 range. Preserve a minimum-version constraint so this remains true after future resolution. |
| [GHSA-5p39-cfhj-2xmp / CVE-2026-64847](https://osv.dev/vulnerability/PYSEC-2026-4024) (2026-10-01) | `anyio`; OSV records fixed version 4.14.2 | Medium, CVSS v4 6.8 | Process-pool workers can block indefinitely if stderr fills an undrained pipe | **Not affected in the measured CI environment:** `anyio==4.16.0`, above the OSV fixed boundary 4.14.2. |

The measured CI versions clear all eight reviewed dependency-advisory ranges: `httpx2==2.16.0` and `httpcore2==2.16.0` exceed the HTTPX2 fixes, and `anyio==4.16.0` exceeds the AnyIO 4.14.2 fix boundary. In addition, `pip-audit==2.10.1` returned exit code 0 and listed no vulnerabilities in any of the 36 installed distributions on each runner. This result is specific to the resolved artifact environments and the advisory data available to the scanner at run time; it is not a guarantee against undisclosed vulnerabilities or future advisories. The declared AnyIO range remains broad enough to permit a vulnerable version if resolution is changed or constrained differently.

### Other requested dependency checks

- `httpcore2==2.16.0`: the measured version is above the 2.10.0 fixed floor for the WSS/SOCKS finding.
- `jiter==0.19.0`, `pydantic==2.14.3`, and `typing-extensions==4.16.0`: no vulnerabilities were reported for these distributions by the candidate's `pip-audit` scan. This is a scanner snapshot, not a guarantee of absence.
- `anyio==4.16.0`: beyond the reviewed 4.14.2 fix boundary; all three reviewed AnyIO findings are cleared for the measured CI environment.
- `httpx2==2.16.0` and `httpcore2==2.16.0`: both are beyond the reviewed affected ranges; all five reviewed HTTPX2 findings are cleared for the measured CI environment.
- Each `pip-audit.json` artifact contains 36 distributions and zero vulnerability entries.

## Reproducing and collecting evidence

From a clean checkout of the assessment branch, create a disposable virtual environment first (do not install into the system Python or the Termux base environment):

```bash
python -m venv .venv-sdk-candidate
. .venv-sdk-candidate/bin/activate
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

The evidence is stored as three artifacts attached to [workflow run #42295660361](https://github.com/escorpioantares66-cmyk/github-practice-ai/actions/runs/42295660361):

| Runner | Artifact name | Artifact ID | SHA-256 digest |
|---|---|---:|---|
| Python 3.13.18 | `sdk-3.46.0-evidence-python-3.13` | `13541287151` | `22737d0a055aee714647777ec7d1e6bb0c95379e5618c542950ccf55e6eadcac` |
| Python 3.14.10 | `sdk-3.46.0-evidence-python-3.14` | `13541807042` | `becfe38f496fdf7dec739f653d19821c515caba9d2f38481847193632b04e272` |
| Python 3.15.2 (experimental) | `sdk-3.46.0-evidence-python-3.15` | `13540714960` | `204a8b212ec9e129f940006cdbd7f98eeb9cb4aa4b4fbb47bbde4717e555ed4d` |

GitHub reported all three artifacts unexpired at review time, with retention through 2026-12-06. Use the artifact files—not the dependency specifiers alone—as the immutable evidence for this run. The Python 3.15 result is informational/experimental and is not a required compatibility gate.

## Acceptance criteria

A production GO requires all of the following, with immutable CI evidence:

1. Baseline and candidate tested against the same application commit and equivalent supported Python versions.
2. All application unit, API, quota, auth, streaming, cancellation, retry, timeout, and client-lifecycle tests pass on both stacks.
3. Candidate `pip check` passes and `pip-audit` reports no applicable findings for the exact resolved dependency graph; AnyIO is constrained to >=4.14.2, and HTTPX2/httpcore2 remain on patched versions.
4. TLS certificate verification, proxy behavior, custom transport integration, and HTTPX2 trust-store behavior are explicitly tested.
5. Python 3.9 support is either preserved through a deliberate compatibility strategy or formally retired as a separate product decision; it must not disappear as an incidental SDK upgrade.
6. Termux CPython 3.14 native wheels are independently verified and runtime smoke tests pass on the actual device only after explicit user authorization.
7. Matched workload measurements show no unacceptable regression in latency, memory, error rate, or resource use.
8. The report is reviewed and the user explicitly authorizes any production dependency change.

## Final recommendation

**NO-GO for production migration today.** The measured candidate CI environments are clean against the reviewed advisories: all three matrix runs passed 17/17 tests, `pip check` passed, and `pip-audit` found zero vulnerabilities across 36 installed distributions per runner. The exact resolved HTTPX2/httpcore2 and AnyIO versions clear the reviewed findings. However, this does not establish that SDK 3.46.0 is safer or more capable than 1.40.0 for production. The project still loses declared Python 3.9 compatibility; the SDK's open-ended AnyIO requirement can resolve differently in future; transport/TLS/proxy behavior is not yet exhaustively tested; no matched performance/failure-rate comparison exists; and no fresh test has been run on the actual Termux device.

Continue isolated evaluation. Do not change the production SDK pin, dependency files, Termux installation, or production configuration on the strength of this report alone.

## Primary references

- [OpenAI SDK 3.46.0 PyPI metadata](https://pypi.org/project/openai/3.46.0/)
- [OpenAI SDK source metadata](https://github.com/openai/openai-python/blob/main/pyproject.toml)
- [OpenAI SDK HTTPX2 migration guide](https://github.com/openai/openai-python/blob/main/httpx2.md)
- [OpenAI SDK security policy and advisories](https://github.com/openai/openai-python/security)
- [HTTPX2 2.15.1 PyPI release](https://pypi.org/project/httpx2/2.15.1/)
- [HTTPX2 2.12.0 changelog](https://github.com/pydantic/httpx2/blob/main/src/httpx2/CHANGELOG.md)
- [OSV](https://osv.dev/) advisory records linked in the tables above.
