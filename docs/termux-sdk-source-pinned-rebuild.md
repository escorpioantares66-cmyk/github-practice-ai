# Source-pinned Termux native wheel rebuild

This stage supersedes the historical API24 wheel artifacts for validation only. It does **not** modify or delete the original `$HOME/pr41-api24-wheelhouse`.

## Pinned upstream source

| Package | Version | Repository | Immutable commit |
|---|---:|---|---|
| jiter | 0.18.0 | `pydantic/jiter` | `fc2da0bd1fb699a6c4e9641e9e1c06fa6d5d93e8` |
| pydantic-core | 2.50.4 | `pydantic/pydantic`, subdirectory `pydantic-core/` | `ea492e04654ab7f7a1f9287ea912419452ead4dd` |

Both source commits contain Cargo lockfiles. The build script records each source tree hash, lockfile hash, exact commit, Python/OpenSSL versions, Android platform, maturin, Rust and Cargo versions, and build-relevant environment values. It invokes maturin in locked mode and verifies the resulting package versions and exact Android CPython wheel tags.

**Publisher-provenance limitation:** PyPI marks pydantic-core 2.50.4 as without provenance. Pinning and rebuilding from the upstream Git commit provides source identity for this new build, but it does not create or imply a missing PyPI publisher attestation.

## Termux build procedure

Run from the repository checkout on the Android device. This creates a new directory and refuses to overwrite it if it already exists.

```bash
git status --short
git switch assessment/sdk-3.46.0-termux-source-pinned-rebuild

# Confirm the historical wheelhouse exists and choose a distinct output path.
test -d "$HOME/pr41-api24-wheelhouse"
test ! -e "$HOME/pr41-api24-source-pinned-wheelhouse"

# Use the currently active Termux Python and the recorded maturin 1.16.0.
PREFIX="$PREFIX" \
ORIGINAL_WHEELHOUSE_DIR="$HOME/pr41-api24-wheelhouse" \
SOURCE_PINNED_WHEELHOUSE_DIR="$HOME/pr41-api24-source-pinned-wheelhouse" \
bash scripts/build_termux_sdk_wheels_from_pinned_sources.sh
```

Do not install these wheels globally. The build writes only to the new wheelhouse. It snapshots all regular files in the original wheelhouse before and after the build and fails if their hashes differ.

Review the generated evidence before proceeding:

```bash
cat "$HOME/pr41-api24-source-pinned-wheelhouse/BUILD-EVIDENCE.txt"
cat "$HOME/pr41-api24-source-pinned-wheelhouse/SHA256SUMS.txt"
sha256sum "$HOME/pr41-api24-source-pinned-wheelhouse"/*.whl
```

Keep the original wheelhouse intact. Do not copy the new wheels over it or rename the original directory.

## Isolated Termux validation

Only after reviewing the source and wheel hashes, run the existing isolated validation against the **new** wheelhouse:

```bash
ALLOW_TERMUX_TEST_INSTALL=1 \
WHEELHOUSE_DIR="$HOME/pr41-api24-source-pinned-wheelhouse" \
bash scripts/run_termux_sdk_compat_with_evidence.sh
```

The runner verifies the wheel versions, API tag and exact wheelhouse manifest before creating a temporary virtual environment. It installs the candidate SDK and native wheels only inside that environment and removes the environment on exit. It does not modify the global Termux Python installation or either wheelhouse.

The validation covers:

- Direct HTTPS with the Termux OpenSSL CA bundle.
- Direct HTTPS with the Certifi CA bundle.
- Rejection of an untrusted certificate.
- SDK timeout translation to `APIConnectionError`.
- SDK connection-failure translation to `APIConnectionError`.
- Python, OpenSSL, SDK, HTTPX2 and platform version evidence.
- The broader SDK transport compatibility tests.

The network tests use loopback test servers and synthetic credentials; they do not make OpenAI API calls or incur provider charges. The live HTTPS check uses the configured public test endpoint and no API key.

## Evidence to return

Attach or paste the complete output of the build and validation runners, plus:

```bash
sha256sum "$HOME/pr41-api24-source-pinned-wheelhouse"/*.whl
cat "$HOME/pr41-api24-source-pinned-wheelhouse/BUILD-EVIDENCE.txt"
cat "$HOME/pr41-api24-source-pinned-wheelhouse/SHA256SUMS.txt"
```

Record any failure as a failure; do not patch around it or silently rebuild with different dependencies. Preserve the failed evidence and stop for review.

## Acceptance criteria

- Both source commits and source tree hashes match the pins above.
- Both Cargo lockfiles are present and locked builds succeed.
- Exactly one wheel each is produced for jiter 0.18.0 and pydantic-core 2.50.4.
- Both wheels match the active Termux Python Android API/platform tag.
- Original wheelhouse contents remain byte-for-byte unchanged.
- Both CA bundle probes succeed with certificate verification enabled.
- Untrusted certificate, timeout and connection-error tests behave as expected.
- The complete evidence report is retained.

This stage supplies new source-pinned build evidence. It does not, by itself, resolve the separate pydantic-core publisher-attestation gap or authorize migration of the production SDK from 1.40.0. Production remains pinned to 1.40.0 and the migration recommendation remains **NO-GO** until the evidence is reviewed.
