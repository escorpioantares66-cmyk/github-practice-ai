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


## Native wheel source-identity investigation (2026-11-07)

This section records the read-only provenance follow-up for the locally generated Android API 24 wheelhouse and the separately cached Android API 33 wheels. No package was installed, no source was downloaded, and no native build was run during this investigation.

### Upstream source release references

| Package | Upstream source identity/reference | Published sdist SHA-256 | Publisher provenance |
|---|---|---|---|
| `jiter==0.18.0` | `pydantic/jiter`, commit `fc2da0bd1fb699a6c4e9641e9e1c06fa6d5d93e8` | `a0ca63fd9450a212e4e658d4cfe0ab4977c4f9b0003c68828b843c65e27662ff` | PyPI displays a verified GitHub Actions publishing attestation for this sdist and commit. |
| `pydantic-core==2.50.4` | PR #42 reference: `pydantic/pydantic`, tag `core-v2.50.4`, commit `ea492e04654ab7f7a1f9287ea912419452ead4dd` | **Not established in this investigation** | PyPI lists the 2.50.4 sdist as **Without provenance**. The exact sdist SHA-256 has not been independently extracted from the release-file metadata in this investigation. |

Public release references:
- jiter: https://pypi.org/project/jiter/0.18.0/
- pydantic-core: https://pypi.org/project/pydantic_core/2.50.4/

### Local archive availability and comparison status

The Termux wheelhouse build log records downloads named `jiter-0.18.0.tar.gz` and `pydantic_core-2.50.4.tar.gz`, followed by successful wheel builds. The log excerpt does not record source archive digests or source VCS identities.

A read-only search under `$HOME` found neither source archive. The pip cache inspection found only these cached wheel files:
- `jiter-0.18.0-cp314-cp314-android_33_arm64_v8a.whl`
- `pydantic_core-2.50.1-cp314-cp314-android_33_arm64_v8a.whl`
- `pydantic_core-2.50.4-cp314-cp314-android_33_arm64_v8a.whl`

It did not recover either source archive. Consequently, the locally downloaded source distributions cannot currently be compared against the upstream sdist hashes above. In particular:
- jiter's upstream sdist has a verified publishing attestation, but the exact local archive used by the Termux build has not been hash-verified against it;
- pydantic-core's published sdist checksum is known, but PyPI reports no publishing provenance for that release, and the exact local archive used by the Termux build has not been hash-verified against it.

The `Repository commit: d644194dda0b6e00035ca6976c02fa5d81f8d586` recorded in the local `BUILD-INFO.txt` identifies the project repository checkout used to run the build script. It is not either package's upstream source commit and does not establish the source archive identity.

### Wheel and native-extension identity observations

The locally generated API 24 wheels have the following recorded whole-wheel SHA-256 values:
- jiter: `86cafd710426934de4571c03eb768e4c8ecc89687247fa1dd9c2a3bd68b90426`
- pydantic-core: `2abe8bf828e8cea327bf9a900223fca8151b9392578bf1f7f8e8c65090446600`

The cached API 33 wheels have these whole-wheel SHA-256 values:
- jiter: `09e5ca7993c487b8beaf6ce6befeba16937a2e9c9b9959710c2bbdc15560cbaf`
- pydantic-core 2.50.4: `ebf888e6c5ef9fe8d8d4b7a8c68861ff95d6f699bb6320d6e4a4e63cb4bd76fa`

The user-provided embedded native extension hashes are identical across the API 24 and API 33 wheels:
- jiter: `5b220cf7cf177104cb927d9f375bcdaeaa0c7c678466efcaf40d68e06b1c177d`
- pydantic-core: `f581f4ad221c1b1527c847d4c70fffe62344991a0739242c0e4f60a26b922a3b`

These extension hashes do **not** match the PR #42 independently attested native extensions:
- jiter PR #42: `892b3fba41c25b406308a83c81492bbcb31238b0f2c9b3b8046cf0a8d73765`
- pydantic-core PR #42: `12cdf82028a452773368aa55528494dd85420dfc4a2474c05aa750b8f03b2e62`

Matching extension hashes across API 24 and API 33 show that the embedded native bytes are identical between those two wheel sets. They do not prove how or when those bytes were built, nor that the source archives were authentic. Different hashes from PR #42 show the local extensions are not byte-identical to the PR #42 reference outputs; that alone does not demonstrate a defect or malicious modification.

### Validation-script limitation

The current build and compatibility scripts verify wheel versions, Android platform tags, and wheelhouse manifest checksums. They do not:
- record or enforce source sdist SHA-256 values;
- record or enforce upstream source VCS commits;
- compare embedded native extension hashes with PR #42 attestations; or
- lock and attest the complete native build dependency environment.

A wheelhouse manifest proves consistency with the recorded wheel hashes, not source provenance. This limitation remains open and must not be described as a completed source-provenance verification.

### Updated decision and required next evidence

**Decision remains NO-GO for installing the retained candidate wheels or migrating the production SDK.** The source archive comparison is pending because the exact source archives are unavailable locally. The pydantic-core PyPI sdist also lacks publisher provenance.

To close the archive comparison without rebuilding or installing anything, recover the exact original source archives from an independently retained build artifact or trusted local backup, then calculate SHA-256 and compare them with the PyPI references above. Do not substitute newly downloaded archives as proof of what the earlier build consumed.

The production pin remains `openai==1.40.0`. No production dependency, lockfile, application runtime, or `main` branch change is part of this assessment.


### Follow-up verification and correction (2026-11-07)

A fresh review of the PyPI release page reconfirmed:
- jiter 0.18.0's sdist SHA-256 and its PyPI-verified GitHub Actions publishing attestation;
- pydantic-core 2.50.4's sdist is marked **Without provenance**.

The PyPI page content retrieved for pydantic-core in this review did not expose a source-archive SHA-256. Accordingly, the earlier value `aead3b74b68396bf0feab5d57e050b730ded7df55853c1e048a87e00aaf033c6` is withdrawn from this report and must not be used as an authoritative checksum. No pydantic-core upstream sdist checksum is asserted here.

**Original archive comparison outcome: NOT PERFORMED.** No recovered SHA-256 values for the exact original Termux-consumed source archives were supplied or found in the currently available PR evidence. The previously reported Termux searches found neither archive in the home directory nor in pip's listed cache contents. Therefore there is no valid basis to report either source comparison as PASS or FAIL.

Required input to complete the comparison:
- SHA-256 of the exact original `jiter-0.18.0.tar.gz` consumed by the Termux build;
- SHA-256 of the exact original `pydantic_core-2.50.4.tar.gz` consumed by the Termux build;
- evidence tying each hash to the original build inputs (for example, preserved build artifact/manifest or contemporaneous build record).

Do not substitute a newly downloaded sdist for either original archive. The jiter comparison can be evaluated against its attested PyPI digest once the original hash is recovered. The pydantic-core comparison additionally remains limited by the absence of PyPI publisher provenance.

Production remains pinned to `openai==1.40.0`; migration and candidate wheel installation remain **NO-GO**. No native rebuild, installation, transfer, production dependency change, or `main` modification was performed in this follow-up.
