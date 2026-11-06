# SDK 3.46.0 transport compatibility assessment

**Branch:** `assessment/sdk-3.46.0-transport-compatibility`  
**Base:** `main` at `190e125fd580f884369668670a07308641e0fb12`  
**Candidate:** `openai==3.46.0` with its HTTPX2 transport  
**Production baseline:** `openai==1.40.0`  
**Decision:** **NO-GO for production migration remains unchanged.**

## Purpose

This isolated assessment closes a specific evidence gap identified by the merged SDK 3.46.0 assessment: transport tests must cover more than SDK client construction and in-process mock requests. The HTTPX2 migration changes certificate trust-store behavior and transport configuration. This branch tests those boundaries without modifying application runtime code or production dependencies.

## Test coverage added

The dedicated candidate CI job runs `tests/test_sdk_transport_network_compat.py` in addition to the existing `tests/test_openai_sdk_transport_compat.py` suite.

The new tests use only loopback-bound local HTTP/HTTPS servers and synthetic credentials:

1. **Custom CA trust:** create a short-lived self-signed loopback certificate and verify an SDK request using an explicit `ssl.SSLContext` passed to `DefaultHttpx2Client`.
2. **Environment trust configuration:** verify that the SDK's default HTTPX2 client honors `SSL_CERT_FILE`, and that `trust_env=False` does not inherit that environment-provided trust bundle.
3. **Proxy behavior:** verify that an environment-configured HTTP proxy is used by default and that a custom client with `trust_env=False` bypasses it.
4. **Timeout behavior:** verify that HTTPX2 raises a read timeout against a deliberately slow loopback server.
5. **Connection failure mapping:** verify that the SDK surfaces a transport connection failure as `APIConnectionError` when retries are disabled.

The tests make no public network requests, do not use a real OpenAI API key, and do not make billable provider calls.

## Scope boundaries

- No application runtime or production transport configuration changes.
- No change to `openai==1.40.0` in `pyproject.toml` or production requirements.
- Candidate dependency installation is confined to the existing dedicated GitHub Actions matrix job.
- No production API calls.
- No Termux installation, device mutation, or local environment change.
- No SDK migration or production rollout.

The candidate CI job installs `cryptography` only to generate ephemeral test certificates. It does not add `cryptography` as a new production dependency; it is already a direct project dependency.

## Remaining limitations

Passing these tests will establish the tested HTTPX2 behaviors on GitHub-hosted Linux runners. It will not, by itself, establish:

- behavior through the user's actual corporate, ISP, or deployment proxies;
- OS trust-store contents on Android/Termux or production containers;
- SOCKS proxy behavior or TLS interception by a real enterprise proxy;
- platform-specific CA bundle paths or certificate provisioning;
- parity with SDK 1.40.0 under a matched set of the same TLS/proxy scenarios.

A later authorized Termux test is still required. Do not install the candidate SDK on the user's device without explicit authorization.

## Acceptance gate

This PR is a test-and-evidence milestone only. Require all candidate transport tests, regular project CI, Ruff, and dependency audit to pass. Record exact runner versions and results in the PR. Keep the production pin and the existing NO-GO migration recommendation unchanged until all migration gates in `docs/sdk-3.46.0-assessment.md` are satisfied and the user explicitly authorizes a production change.
