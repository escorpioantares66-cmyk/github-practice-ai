# github-practice-ai — v1.1.1

**Latest verified CI (2026-11-03): Python 3.11 and 3.12 passed — 377 tests — 92% coverage — dependency audit and package builds passed.**

[[CI Senior v1.0](https://github.[STRIPPED 66 bytes].yml/badge.svg)](https://github.com/escorpioantares66-cmyk/github-practice-ai/actions)
[[ci-hardened-v1.1](https://github.[STRIPPED 75 bytes].yml/badge.svg)](https://github.com/escorpioantares66-cmyk/github-practice-ai/actions)
[[publish-v1.1-to-pypi](https://github.[STRIPPED 71 bytes].yml/badge.svg)](https://github.com/escorpioantares66-cmyk/github-practice-ai/actions/workflows/publish.yml)
[[PyPI version](https://img.shields.io/pypi/v/github-practice-ai?color=gold&label=PyPI%20LIVE%201.1.1)](https://pypi.org/project/github-practice-ai/1.1.1/)
[[Python 3.11 | 3.12](https://img.shields.io/badge/python-3.11%20%7C%203.12-blue)](https://www.python.org)
[[Ruff GREEN](https://img.shields.io/badge/ruff-GREEN-brightgreen)](https://docs.astral.sh/ruff/)
[[Coverage 92%](https://img.shields.io/badge/coverage-92%25-brightgreen)](https://github.com/escorpioantares66-cmyk/github-practice-ai)
[[License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

> AI SDK with a security-focused approval workflow, requester-scoped storage, audit integrity controls, and mobile-friendly Termux support.

## Security and quality gates

- Pull requests to `main` run the required Python 3.11 and 3.12 CI matrix.
- CI runs `pip-audit`, Ruff, focused approval tests, the full test suite, and an 80% minimum coverage gate.
- CI builds and validates wheel/sdist packages, runs `gh-ai --check`, and performs the read-only storage/retention audit.
- Weekly Dependabot proposals are configured for Python dependencies and GitHub Actions. Updates are not auto-merged.

## Security documentation

- [Security policy](SECURITY.md)
- [Security and operational limitations](SECURITY_LIMITATIONS.md)
- [Approval authorization configuration](docs/approval-authorization.md)
- [Approval workflow](docs/approval-workflow.md)
- [Audit log integrity and external checkpoints](docs/AUDIT_LOG_INTEGRITY.md)
- [Storage growth and retention audit](docs/storage-growth-audit.md)

### Install

```bash
pip install github-practice-ai==1.1.1
# Termux aarch64 Python 3.14 bypass jiter Rust hell:
pip install github-practice-ai==1.1.1 --no-deps
pip install --only-binary=:all: openai==1.40.0 httpx==0.27.0 cachetools anyio -q || true

### External sandbox approval authority

See [Sandbox approval authority API](docs/sandbox-approval-authority.md) for the separate Ed25519-signed, one-time approval interface. Existing note-write approval endpoints remain unchanged.
