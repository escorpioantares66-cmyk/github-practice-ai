#!/bin/bash
set -e
API=$(getprop ro.build.version.sdk 2>/dev/null || echo 33)
export ANDROID_API_LEVEL=$API
export CARGO_BUILD_TARGET=aarch64-linux-android
echo "Using ANDROID_API_LEVEL=$ANDROID_API_LEVEL"
pkg install -y rust clang pkg-config libffi openssl 2>/dev/null || true
python -m pip install --upgrade pip setuptools wheel maturin
python -m pip install --no-binary jiter jiter --no-cache-dir -v
python -m pip install -e .
python -c "import jiter, openai; print(f'OK jiter {jiter.__version__} openai {openai.__version__}')"
