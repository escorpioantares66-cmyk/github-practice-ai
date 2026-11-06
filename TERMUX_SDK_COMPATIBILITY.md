# Termux OpenAI SDK compatibility check

This is a candidate-stack experiment only. It does **not** change the production
package pins in `pyproject.toml`, `requirements-fallback.txt`, or
`requirements-termux.txt`.

The Termux validation is deliberately split into two stages. The native wheel
target is derived from the active interpreter's `sysconfig.get_platform()`,
not from the physical device's Android release. For the current CPython 3.14
Termux runtime, that platform is `android-24-arm64_v8a`, even when the device
itself reports Android API 33. Maturin's `ANDROID_API_LEVEL` controls the
minimum Android API targeted by the generated wheel.

## Stage 1: build and verify only

From the repository root on the actual Termux device:

```bash
ALLOW_TERMUX_NATIVE_BUILD=1 bash scripts/build_termux_sdk_wheels.sh
```

The script derives the Android API target from Python's platform tag, rejects
conflicting `ANDROID_API_LEVEL` overrides, and builds exactly
`jiter==0.18.0` and `pydantic-core==2.50.4` from their source distributions.
It disables both pip's wheel cache and binary-wheel selection so previously
cached or published API-33 artifacts cannot be reused.

The script requires the explicit `ALLOW_TERMUX_NATIVE_BUILD=1` opt-in before
starting. It uses `pip wheel`: build-backend requirements are installed into
temporary isolated build environments, but neither target package is installed
into the active interpreter or a runtime virtual environment. No build is
started merely by invoking the script without that opt-in. The generated
wheels and build log are retained in
`$HOME/pr41-api24-wheelhouse` by default (or in the path supplied through
`WHEELHOUSE_DIR`). It verifies package versions, the exact CPython/Android
wheel tags, and SHA256 hashes, and writes `BUILD-INFO.txt`,
`WHEEL-VERIFICATION.txt`, and `SHA256SUMS.txt`.

Do not rename wheels or force-install a wheel whose tag does not match the
interpreter.

## Stage 2: isolated SDK runtime test (requires explicit authorization)

Only after reviewing the Stage 1 wheel tags and hashes, explicitly authorize
installation into a temporary virtual environment by running:

```bash
ALLOW_TERMUX_TEST_INSTALL=1 \
WHEELHOUSE_DIR="$HOME/pr41-api24-wheelhouse" \
bash scripts/check_termux_sdk_compat.sh
```

Without `ALLOW_TERMUX_TEST_INSTALL=1`, the script exits before creating a
virtual environment or installing candidate packages. When authorized, it
checks the wheel metadata again, installs the exact native versions and the
candidate OpenAI SDK 3.46.0 / HTTPX2 / Starlette test stack into a temporary
virtual environment, runs `pip check`, constructs sync/async SDK clients, and
runs the in-process transport tests. The temporary environment is removed on
exit; the verified wheelhouse is retained.

No API key, external OpenAI request, or billable API call is used. A successful
Stage 2 run validates the candidate stack on the actual Android runtime; it
does not promote candidate dependency pins into production.

The scripts do not install system packages. A Rust toolchain is required for
native source builds and must be provisioned separately if it is not already
available.

## Verified device result (2026-11-06)

The two-stage procedure was completed on the actual Android/Termux device:

- Device: Android API 33, AArch64.
- Interpreter: CPython 3.14.8.
- Interpreter platform: `android-24-arm64_v8a`.
- Native wheels built and verified:
  - `jiter-0.18.0-cp314-cp314-android_24_arm64_v8a.whl`
    - SHA256: `86cafd710426934de4571c03eb768e4c8ecc89687247fa1dd9c2a3bd68b90426`
  - `pydantic_core-2.50.4-cp314-cp314-android_24_arm64_v8a.whl`
    - SHA256: `2abe8bf828e8cea327bf9a900223fca8151b9392578bf1f7f8e8c65090446600`
- Runtime smoke test: **7 passed in 0.88s**.
- Final script result: `Termux OpenAI SDK compatibility smoke test passed.`
- The script reported that only the temporary virtual environment was modified and removed on exit; the verified wheelhouse was left untouched.

Pytest emitted a `PytestDeprecationWarning` because the asyncio fixture loop scope is not explicitly configured. It did not fail the run. This warning is recorded separately from the passing test result and should be addressed as test-configuration cleanup, not treated as a runtime compatibility failure.

This is device-specific evidence for the isolated candidate stack only. It does not change or recommend changing the production `openai==1.40.0` baseline, and it does not authorize merging this draft PR.
