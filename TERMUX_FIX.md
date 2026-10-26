# Termux Android aarch64 Fix

Root cause: pip on android tag `android_33_aarch64` cannot find manylinux wheel for `jiter`.
Error: `Could not find a version that satisfies requirement jiter<1,>=0.4.0 (from versions: none)`
Build log: `jiter could not determine the Android API level`

Fix:
export ANDROID_API_LEVEL=33
export CARGO_BUILD_TARGET=aarch64-linux-android
pkg install rust clang pkg-config libffi openssl
pip install maturin
pip install --no-binary jiter jiter --no-cache-dir
pip install -e .

Platform verified:
- Android 13 API 33 aarch64
- Python 3.14.8 Clang 21
- 43 tests passed, 74.07% coverage
