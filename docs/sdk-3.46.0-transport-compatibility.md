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

The new tests use only loopback-bound local HTTP/HTTPS servers, a loopback CONNECT proxy, and synthetic credentials:

1. **Custom CA trust:** create a short-lived self-signed loopback certificate and verify an SDK request using an explicit `ssl.SSLContext` passed to `DefaultHttpx2Client`.
2. **Environment trust configuration:** verify that the SDK's default HTTPX2 client honors `SSL_CERT_FILE`, and that `trust_env=False` does not inherit that environment-provided trust bundle.
3. **HTTP proxy behavior:** verify that an environment-configured HTTP proxy is used by default and that a custom client with `trust_env=False` bypasses it.
4. **HTTPS CONNECT and TLS validation:** route an SDK HTTPS request through a local CONNECT proxy, verify the CONNECT authority, and validate the target certificate using the environment-provided CA bundle.
5. **TLS negative case:** when `trust_env=False` disables the test CA bundle, assert that the SDK error chain contains a certificate-verification failure rather than accepting any generic connection error.
6. **SDK timeout mapping:** configure the actual `OpenAI` client with a short timeout and retries disabled, then assert that the SDK surfaces `APIConnectionError` wrapping an HTTPX2 `ReadTimeout` against a deliberately slow loopback server.
7. **Connection failure mapping:** verify that the SDK surfaces a transport connection failure as `APIConnectionError` when retries are disabled.

The tests make no public network requests, do not use a real OpenAI API key, and do not make billable provider calls.

## Scope boundaries

- No application runtime or production transport configuration changes.
- No change to `openai==1.40.0` in `pyproject.toml` or production requirements.
- Candidate dependency installation is confined to the existing dedicated GitHub Actions matrix job.
- No production API calls.
- No global Termux package changes.
- No SDK migration or production rollout.

The candidate CI job pins `httpx2==2.16.0`, the exact version resolved by the previously reviewed CI evidence, so subsequent runs exercise a reproducible HTTPX2 transport version. The candidate CI job installs `cryptography` only to generate ephemeral test certificates. It does not add `cryptography` as a new production dependency; it is already a direct project dependency.

## Isolated Android/Termux validation stage

The opt-in device stage consists of:

- `scripts/check_termux_sdk_compat.sh`: verifies the retained native wheelhouse and SHA256 manifest before creating a temporary virtual environment; installs `openai==3.46.0` and exactly `httpx2==2.16.0` only inside that venv.
- `scripts/test_termux_sdk_live_tls.py`: records Python, Android platform, OpenSSL, OpenAI SDK, and HTTPX2 versions; performs direct HTTPS probes using the Termux OpenSSL CA bundle and Certifi CA bundle, with proxy inheritance disabled.
- `tests/test_sdk_transport_network_compat.py`: exercises untrusted-certificate rejection, SDK timeout mapping, and connection-error mapping against loopback services.
- `tests/test_openai_sdk_transport_compat.py`: runs the broader SDK/application integration checks.
- `scripts/run_termux_sdk_compat_with_evidence.sh`: captures the complete isolated run transcript and exit status in `termux-sdk-3.46.0-termux-evidence.txt`, including the version and CA-probe output.

The direct HTTPS probe defaults to `https://example.com/`; set `TERMUX_TLS_TEST_URL` to a suitable HTTPS endpoint if the network blocks that host. Set `TERMUX_EVIDENCE_FILE` to choose a different report destination.

The wrapper and underlying installer both require `ALLOW_TERMUX_TEST_INSTALL=1`, and the installer requires an explicit `WHEELHOUSE_DIR`. The temporary venv is removed on exit. The global Termux Python environment and existing production `openai==1.40.0` installation are not modified. The retained native wheelhouse is read and verified but not modified.

**Authorization status:** The user has authorized transferring the verified wheelhouse and running this isolated validation. The actual transfer and device run have not yet been completed; device results remain pending.

The authenticated proxy and SOCKS cases remain out of scope because no proxy is configured in the user's reported Termux environment.

## Remaining limitations

Passing these tests will establish the tested HTTPX2 behaviors on GitHub-hosted Linux runners and, after the authorized device run, on the tested Termux installation. It will not, by itself, establish:

- behavior through the user's actual corporate, ISP, or deployment proxies;
- behavior in production containers or other Android versions;
- SOCKS proxy behavior or TLS interception by a real enterprise proxy;
- parity with SDK 1.40.0 under a matched set of the same TLS/proxy scenarios.

## Acceptance gate

This PR is a test-and-evidence milestone only. Require all candidate transport tests, regular project CI, Ruff, and dependency audit to pass. Review the complete Termux evidence transcript after the device run. Keep the production pin and the existing NO-GO migration recommendation unchanged until all migration gates in `docs/sdk-3.46.0-assessment.md` are satisfied and the user explicitly authorizes a production change.
