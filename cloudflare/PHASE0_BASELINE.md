# Cloudflare approval authority prototype — Phase 0 baseline

## Status

Phase: 0 — baseline freeze and acceptance-test inventory  
Branch: `feat/cloudflare-approval-authority-prototype`  
Base branch: `main`  
Base commit: `cf006a4708fb26ee150dcaad1245f28bc3e3dcee`  
Deployment/account status: no Cloudflare account connected; no resources provisioned; no deployment performed.

This document records the baseline inspected before any Cloudflare implementation. It does not claim that tests were executed in this environment.

## Isolation and change-control

- The feature branch was created directly from the verified main commit above.
- All prototype work is confined to this feature branch.
- Do not merge, rebase, or update `main` as part of this prototype.
- Preserve the existing Linux/POSIX implementation and API as the compatibility reference.
- No production credentials, private signing keys, account identifiers, or secrets belong in this branch.

## Baseline build and CI contract

Repository configuration at the baseline:

- Python package requires Python `>=3.9`.
- Existing CI build matrix: Python 3.11 and 3.12.
- Existing CI runs Ruff, dependency vulnerability audit, focused approval/recovery tests, full pytest with an 80% coverage gate, wheel/sdist build and Twine validation, CLI check, and read-only storage audit.
- Existing package dependencies include FastAPI, Pydantic, and `cryptography>=44.0.0`; the main package also includes OpenAI/httpx and other SDK dependencies.
- The current production launch model is a conventional Python application, not a Workers entry point.

## Frozen source/test references

The following files were fetched from the new feature branch at the base commit. Blob IDs are recorded to make the baseline reproducible.

| Path | Blob SHA |
|---|---|
| `pyproject.toml` | `dd16f173043146bcbe2a220d2c03a49248eca2d5` |
| `.github/workflows/ci-hardened.yml` | `482a1bea5f6747d7d7a668bde13813843f7b6e7c` |
| `tests/test_sandbox_approval_authority.py` | `50db5679a438b04400f0668ca26270db1b7c70da` |
| `tests/test_approval_hardening.py` | `09bc1a5aabc6b80ac3488e06d98f613a88e29622` |
| `tests/test_approval_write_failure.py` | `c1905889c68d9d2da9a8404421a902957618d832` |
| `tests/test_quota_store.py` | `d96763486ebde76619285f0965867afdc89cb975` |

## Acceptance-test inventory

There are 92 existing test functions across the four baseline suites below. The Cloudflare port must preserve each security outcome and API contract. Filesystem-specific fault injection should be translated into equivalent Durable Object transaction, commit/rollback, eviction, or response-loss tests rather than copied literally.

### External sandbox approval authority — 31 tests

File: `tests/test_sandbox_approval_authority.py`

- `test_signed_decision_is_bound_to_expected_issuer_audience_and_scope`
- `test_tampered_signed_decision_is_rejected`
- `test_unknown_key_id_is_rejected`
- `test_key_rotation_keeps_old_receipts_verifiable_during_overlap`
- `test_missing_or_mismatched_signing_configuration_fails_closed`
- `test_request_scope_rejects_extra_fields_and_wrong_action`
- `test_self_approval_and_duplicate_decision_are_rejected`
- `test_scope_mismatch_cannot_consume_approval`
- `test_one_time_consumption_allows_only_identical_idempotent_retry`
- `test_same_idempotency_key_with_changed_scope_is_rejected`
- `test_consumption_state_survives_reopen_and_is_inspectable`
- `test_requester_cannot_inspect_another_principals_approval`
- `test_denial_is_terminal_and_never_produces_signed_approval`
- `test_http_api_authenticates_requester_and_approver`
- `test_http_api_rejects_self_approval`
- `test_http_consume_is_idempotent_and_scope_bound`
- `test_concurrent_consumption_has_exactly_one_distinct_request_winner`
- `test_wrong_nonce_cannot_consume_approval`
- `test_audit_chain_records_request_decision_and_consumption`
- `test_corrupt_audit_history_blocks_inspection_and_new_requests`
- `test_legacy_unnamed_requester_key_cannot_create_sandbox_approval`
- `test_signed_receipt_expires`
- `test_audit_failure_after_consumption_never_reopens_approval`
- `test_audit_history_prevents_replay_after_approval_record_rollback`
- `test_audit_history_prevents_second_approval_after_record_rollback`
- `test_duplicate_generated_approval_id_does_not_overwrite_existing`
- `test_http_deny_is_terminal_and_has_no_decision_receipt`
- `test_http_api_fails_closed_when_signing_configuration_is_missing`
- `test_http_api_applies_requester_rate_limit`
- `test_http_api_rejects_extra_scope_fields`
- `test_missing_crypto_library_disables_only_sandbox_authority`

### Approval lifecycle and audit hardening — 28 tests

File: `tests/test_approval_hardening.py`

- `test_malformed_ids_are_rejected`
- `test_approved_request_cannot_be_denied_again`
- `test_denied_request_cannot_be_approved`
- `test_unknown_well_formed_id_remains_not_found`
- `test_new_approval_ids_are_32_hex_characters`
- `test_legacy_8_character_approval_ids_are_rejected`
- `test_direct_approval_calls_reject_unconfigured_keys`
- `test_same_principal_cannot_approve_or_deny_with_separate_secrets`
- `test_concurrent_approve_and_deny_have_one_winner`
- `test_malformed_approval_field_types_are_isolated`
- `test_pending_scan_uses_complete_record_validation`
- `test_audit_hash_chain_verifies_and_detects_entry_tampering`
- `test_audit_hash_chain_detects_deleted_or_reordered_entries`
- `test_audit_append_refuses_to_cross_validation_limit`
- `test_audit_hash_chain_anchors_legacy_prefix`
- `test_audit_hash_chain_rejects_duplicate_json_keys`
- `test_audit_writes_are_serialized_across_processes`
- `test_external_checkpoint_detects_suffix_truncation`
- `test_checkpoint_rejects_modified_checkpoint_and_supports_legacy_migration`
- `test_audit_event_validation_rejects_inconsistent_state`
- `test_audit_event_validation_rejects_nested_non_finite_values`
- `test_audit_event_validation_rejects_incomplete_consumption_metadata`
- `test_audit_event_validation_rejects_incomplete_execution_failure_metadata`
- `test_request_approval_rejects_invalid_payload_before_writing`
- `test_request_approval_accepts_valid_json_payload_and_logs_it`
- `test_pending_approval_limit_is_released_after_decision`
- `test_daily_approval_limit_counts_decided_requests`
- `test_pending_limit_cannot_be_bypassed_by_concurrent_processes`

### Write-failure and operator recovery — 24 tests

File: `tests/test_approval_write_failure.py`

- `test_failed_write_records_operator_recovery_context_without_replay`
- `test_failure_metadata_write_error_does_not_hide_original_or_enable_replay`
- `test_audit_append_failure_is_distinguished_from_record_failure`
- `test_directory_fsync_failure_after_replace_requires_destination_inspection`
- `test_consumed_audit_failure_prevents_write_and_records_recovery`
- `test_invalid_approved_payload_is_recorded_for_operator_review`
- `test_approval_audit_failure_blocks_execution_and_preserves_consumed_safety`
- `test_approval_audit_record_update_failure_leaves_approval_unexecutable`
- `test_denial_audit_failure_keeps_denial_terminal_and_reports_incomplete_audit`
- `test_request_audit_append_failure_leaves_request_unapprovable`
- `test_request_audit_status_persistence_failure_leaves_request_unapprovable`
- `test_initial_approval_record_failure_cleans_reserved_file`
- `test_pending_scan_skips_corrupt_record_and_returns_valid_pending`
- `test_audit_log_incomplete_trailing_entry_is_not_extended`
- `test_audit_partial_write_is_rolled_back_before_next_append`
- `test_audit_log_invalid_complete_line_is_not_rewritten`
- `test_corrupt_record_is_rejected_by_approve_and_consume`
- `test_successful_write_persists_completed_outcome_and_audit`
- `test_success_recording_failure_leaves_started_outcome_for_inspection`
- `test_success_audit_failure_is_visible_to_operator`
- `test_recovery_listing_surfaces_corrupt_approval_records`
- `test_restored_approved_snapshot_cannot_replay_consumed_approval`
- `test_restored_approved_snapshot_cannot_replay_after_audit_rotation`
- `test_execution_failure_cannot_overwrite_terminal_outcome`

### Existing quota-store behavior — 9 tests

File: `tests/test_quota_store.py`

- `test_rate_limit_persists_across_connections`
- `test_rate_limit_window_expires_using_persisted_wall_clock`
- `test_rate_limit_is_atomic_across_processes`
- `test_cost_reservations_are_atomic_across_processes`
- `test_daily_usage_and_reservations_survive_reopen`
- `test_model_usage_records_token_counts_and_cost`
- `test_database_and_directory_permissions_are_private`
- `test_database_symlink_is_rejected`
- `test_shared_quota_parent_is_rejected_without_chmod`

The quota suite contains both authority-relevant rate limiting and broader model-cost accounting. The initial Cloudflare prototype should migrate only authority-specific limits; full model-cost reservations remain out of scope unless separately approved.

## Required Cloudflare-specific additions

The 92 baseline tests are necessary but not sufficient. Add runtime-specific coverage for:

1. Worker module startup/import without importing unsupported SDK subsystems.
2. Ed25519 key parsing and signature interoperability with existing Linux receipts.
3. Durable Object persistence across eviction/re-instantiation.
4. Concurrent decision and consumption transactions with exactly one winner.
5. Transaction rollback on exceptions and interruption.
6. Commit succeeds but HTTP response is lost; identical retry returns the committed result.
7. Altered retry conflicts; no second consumption or execution.
8. Storage unavailable/corrupt state fails closed.
9. Audit event and approval state commit atomically.
10. Independent checkpoint verification, restore, and rollback detection.
11. Secret isolation and key-rotation overlap.
12. API schema/status/header compatibility with the existing FastAPI routes.
13. Worker CPU/memory and free-tier request/storage budget measurements.


## Source compatibility inventory

A source-level scan was completed against the baseline files. This is a static inventory, not a runtime compatibility claim.

| Component | Observed baseline dependencies / assumptions | Cloudflare implication |
|---|---|---|
| `sandbox_approval.py` | Imports `fcntl`; uses advisory file locks, file descriptors, append writes, `os.fsync`, local paths and private files. | Cannot be ported unchanged. Replace file locking and local records with Durable Object transactions; preserve state-machine and idempotency semantics. |
| `secure_storage.py` | Uses POSIX directory descriptors, `O_DIRECTORY`, `O_NOFOLLOW`, `dir_fd`, effective UID checks, `fchmod`, `fsync`, `os.replace`, and unlink/cleanup. | Filesystem security boundary is not available in Workers. Replace with platform storage boundary; do not emulate filesystem guarantees with ephemeral files. |
| `quota_store.py` | Uses local `sqlite3`, filesystem paths, chmod/ownership checks and transactions. | Authority rate limits need Durable Object SQLite; existing local SQLite implementation cannot be the persistent Worker store. General model-cost quota migration stays out of scope. |
| `auth.py` | Imports `threading`, constructs a module-level `threading.Lock`, and imports the local quota store. | Avoid importing this module in the Worker path until its locking and storage dependencies are separated. |
| `sandbox_approval_api.py` | FastAPI router and Pydantic models; imports both `auth` and `sandbox_approval`. | HTTP contract can be retained, but the route's broad imports must be decoupled from POSIX storage and process-local locking. |

The baseline approval API imports `auth` and `sandbox_approval` at module load. Therefore, simply wrapping the existing router in a Worker ASGI adapter is not a safe compatibility strategy. Build a narrow Worker-facing application and adapter layer while retaining the existing API schema, status behavior, and signed receipt contract.

Cryptography is declared as `cryptography>=44.0.0` in the main package. Ed25519 is used by the approval implementation through PEM serialization and the Ed25519 private/public key APIs. This scan does not establish that the exact package build, PEM handling, or signature operations work in the Cloudflare Python runtime; that remains a Phase 1 runtime-spike gate.

## Phase 0 verification limits

The GitHub repository connector permits remote source inspection and branch commits, but does not provide a local checkout or test runner in this workflow. Consequently, the baseline pytest/coverage suite has **not** been executed in this session. Do not treat the 92-test inventory as a passing test result. Before Phase 1 code changes, run the exact baseline on a local checkout of commit `cf006a4708fb26ee150dcaad1245f28bc3e3dcee` and capture:
- Python interpreter and dependency versions;
- focused approval/recovery test results;
- full test result and coverage percentage;
- Ruff and dependency-audit results;
- package build and CLI/storage-audit results.

The combined commit-status endpoint returned no legacy status entries for the baseline SHA; this is not evidence that required GitHub Actions checks are absent or failed. Verify Actions check runs in GitHub before treating the baseline CI state as current.

## Updated Phase 0 exit criteria

- [x] Feature branch created from the exact baseline commit.
- [x] Baseline configuration and CI contract recorded.
- [x] Existing acceptance-test inventory recorded (92 tests).
- [x] Static source inventory of filesystem, locking, SQLite, API-import, and crypto assumptions recorded.
- [ ] Local baseline test/coverage and CI-equivalent results captured.
- [ ] Phase 0 reviewed and explicitly closed before Phase 1 implementation begins.

## Phase 0 exit criteria

- [x] Feature branch created from the exact baseline commit.
- [x] Baseline configuration and CI contract recorded.
- [x] Existing acceptance-test inventory recorded (92 tests).
- [ ] Local baseline test/coverage run captured before runtime changes.
- [ ] Source dependency/import and POSIX primitive inventory cross-checked against the baseline source.
- [ ] Phase 0 reviewed before Phase 1 implementation begins.

## Next step

Complete the remaining local baseline verification and source dependency/import inventory. Do not add a Worker entry point, Durable Object schema, runtime dependency file, account configuration, or deployment workflow until Phase 0 is reviewed and closed.
