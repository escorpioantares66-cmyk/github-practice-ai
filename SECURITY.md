# Security Policy

## Reporting a vulnerability

Do not report suspected vulnerabilities in public GitHub issues or discussions.
Use the repository's private vulnerability reporting / Security Advisory flow
when it is available. If private reporting is unavailable, contact the
maintainer privately through GitHub before disclosing the issue publicly.

Include the affected version or commit, impact, reproduction steps, and any
relevant logs with secrets removed. Never include a real `OPENAI_API_KEY`,
requester credential, approver credential, or other secret in a report.

## CI and test credentials

CI uses the non-secret `sk-test-mocked` value with `CI=true` to exercise
mocked provider paths. Real provider credentials must not be added to CI,
repository files, workflow logs, or test fixtures.

## Supported versions

The latest published `1.1.x` release is the supported release line. Older
release lines, including `v1.0-senior`, are not maintained for security fixes.
Upgrade to the latest supported release before reporting a vulnerability.
