# Termux OpenAI SDK compatibility check

This is a candidate-stack test only. It does **not** change the package pins in
`pyproject.toml`, `requirements-fallback.txt`, or `requirements-termux.txt`.

From the repository root, after checking out
`compat/python-314-315-runtime`, run:

```bash
bash scripts/check_termux_sdk_compat.sh
```

The script creates a temporary virtual environment, installs OpenAI SDK 3.46.0,
HTTPX2, Starlette's HTTPX2-based test client, and the transport test tools. It
then runs the real SDK tests with in-process HTTPX2 transports. No API key or
billable API request is used. The temporary environment is removed on exit.

Termux may need a Rust toolchain to compile the `jiter` dependency when a
compatible Android wheel is unavailable. Install it separately with
`pkg install rust` if pip reports a Rust/maturin build failure. The script
does not install system packages or modify the existing Termux Python
environment.

A successful run verifies the candidate SDK's package installation, dependency
consistency, default sync/async client construction, chat/streaming/embedding
request paths, and Starlette TestClient integration on the actual Android
runtime. It does not promote the candidate dependency pins into production.
