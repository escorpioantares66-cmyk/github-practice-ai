"""Regression tests for cross-process approval execution and recovery boundaries."""

import hashlib
import json
import multiprocessing
import os
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest
from fastapi.testclient import TestClient

os.environ.setdefault("OPENAI_API_KEY", "sk-test-mocked")
os.environ.setdefault("CI", "true")

from stage2_sdk_ai import approval, auth, tools, write_tools
from stage2_sdk_ai.api import app

API_KEY = "test-api-key"
APPROVER_KEY = "test-approver-key"


@pytest.fixture
def approval_environment(monkeypatch, tmp_path):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-real-approval-test")
    monkeypatch.setenv("AGENT_API_KEYS", f"automation={API_KEY}")
    monkeypatch.setenv("AGENT_APPROVER_KEYS", f"reviewer={APPROVER_KEY}")
    monkeypatch.setattr(approval, "_approvals_dir", tmp_path / "approvals")
    monkeypatch.setattr(approval, "_audit_file", tmp_path / "logs" / "audit.jsonl")
    monkeypatch.setattr(write_tools, "_notes_dir", tmp_path / "notes")
    monkeypatch.setattr(tools, "_notes_dir", tmp_path / "notes")
    auth.reset_rate()
    yield tmp_path
    auth.reset_rate()


def _approved_note(path="race.md", content="one authorized write"):
    request = write_tools.write_note(path, content, requester="agent")
    assert request["status"] == "needs_approval"
    approved = approval.approve(
        request["approval_id"], approver_key=APPROVER_KEY
    )
    assert approved["status"] == "approved"
    return request["approval_id"]


def _execute_in_process(approval_id, barrier, result_queue):
    """Worker target: wait until all processes are ready, then execute once."""
    barrier.wait(timeout=15)
    result = write_tools.execute_approved_write(
        approval_id, requester="agent"
    )
    result_queue.put(result.get("status"))


def test_multiprocess_execution_has_exactly_one_winner(approval_environment):
    """Independent worker processes cannot execute the same approval twice."""
    context = multiprocessing.get_context("fork")
    approval_id = _approved_note()
    barrier = context.Barrier(2)
    result_queue = context.Queue()
    workers = [
        context.Process(
            target=_execute_in_process,
            args=(approval_id, barrier, result_queue),
        )
        for _ in range(2)
    ]

    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join(timeout=30)

    assert all(not worker.is_alive() for worker in workers)
    assert [worker.exitcode for worker in workers] == [0, 0]
    statuses = sorted(result_queue.get(timeout=5) for _ in workers)
    assert statuses == ["invalid_transition", "written"]

    note_path = (
        approval_environment
        / "notes"
        / hashlib.sha256(b"agent").hexdigest()
        / "race.md"
    )
    assert note_path.read_text(encoding="utf-8") == "one authorized write"

    audit = [
        json.loads(line)
        for line in (approval_environment / "logs" / "audit.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()
    ]
    assert sum(
        event["action"] == "consumed"
        and event["record"]["id"] == approval_id
        for event in audit
    ) == 1
    assert approval.verify_audit_log()["valid"] is True


def test_execution_success_and_failure_reporting_have_one_terminal_winner(
    approval_environment,
):
    """Concurrent outcome reporters cannot replace each other's terminal result."""
    approval_id = _approved_note("outcome-race.md", "approved")
    consumed = approval.consume_approval_request(
        approval_id, "write_note", requester="agent"
    )
    assert consumed["status"] == "consumed"
    assert consumed["execution_outcome"]["status"] == "started"

    barrier = Barrier(2)

    def report_success():
        barrier.wait(timeout=10)
        return approval.record_execution_success(approval_id)

    def report_failure():
        barrier.wait(timeout=10)
        return approval.record_execution_failure(
            approval_id,
            "SimulatedFailure",
            "concurrent failure report",
            outcome_status="failed",
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        success_future = pool.submit(report_success)
        failure_future = pool.submit(report_failure)
        success = success_future.result(timeout=15)
        failure = failure_future.result(timeout=15)

    results = [success, failure]
    assert sum(
        result.get("status") in {"completed", "consumed"}
        for result in results
    ) == 1
    assert sum(
        result.get("status") == "invalid_transition"
        for result in results
    ) == 1

    record = approval.check_approval(approval_id)
    assert record["status"] == "consumed"
    assert record["execution_outcome"]["status"] in {"completed", "failed"}
    assert record["execution_outcome"]["audit_status"] == "written"

    audit = [
        json.loads(line)
        for line in (approval_environment / "logs" / "audit.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()
    ]
    terminal_events = [
        event for event in audit
        if event["record"]["id"] == approval_id
        and event["action"] in {"execution_succeeded", "execution_failed"}
    ]
    assert len(terminal_events) == 1
    assert approval.verify_audit_log()["valid"] is True


def test_operator_recovery_inspection_is_read_only(
    approval_environment, monkeypatch,
):
    """Inspecting an unresolved execution cannot perform or repeat its write."""
    client = TestClient(app)
    request = write_tools.write_note(
        "needs-review.md", "must remain untouched", requester="agent"
    )
    approval_id = request["approval_id"]
    assert approval.approve(
        approval_id, approver_key=APPROVER_KEY
    )["status"] == "approved"
    assert approval.consume_approval_request(
        approval_id, "write_note", requester="agent"
    )["status"] == "consumed"

    record_before = approval.check_approval(approval_id)
    audit_path = approval_environment / "logs" / "audit.jsonl"
    audit_before = audit_path.read_bytes()
    note_path = (
        approval_environment
        / "notes"
        / hashlib.sha256(b"agent").hexdigest()
        / "needs-review.md"
    )

    def reject_write(*_args, **_kwargs):
        raise AssertionError("recovery inspection must never execute a write")

    monkeypatch.setattr(write_tools, "_atomic_write_note", reject_write)
    response = client.get(
        "/operator/recovery",
        headers={"X-Approver-Key": APPROVER_KEY},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["count"] == 1
    assert body["items"][0]["approval_id"] == approval_id
    assert body["items"][0]["execution_status"] == "started"
    assert not note_path.exists()
    assert approval.check_approval(approval_id) == record_before
    assert audit_path.read_bytes() == audit_before

    replay = write_tools.execute_approved_write(
        approval_id, requester="agent"
    )
    assert replay["status"] == "invalid_transition"
    assert not note_path.exists()


@pytest.mark.parametrize(
    "execution_status",
    [
        "execution_failed",
        "execution_outcome_uncertain",
        "execution_failed_audit_incomplete",
        "execution_failure_recording_failed",
        "execution_outcome_recording_failed",
        "execution_succeeded_audit_incomplete",
        "consumption_audit_incomplete",
        "approval_audit_incomplete",
        "invalid_approved_payload_operator_review",
    ],
)
def test_api_maps_all_recovery_execution_statuses_to_operator_error(
    approval_environment, monkeypatch, execution_status,
):
    """Every unresolved execution result is surfaced as HTTP 500."""
    monkeypatch.setattr(
        write_tools,
        "execute_approved_write",
        lambda *_args, **_kwargs: {
            "status": execution_status,
            "error": execution_status,
        },
    )
    client = TestClient(app)

    response = client.post(
        "/write/execute",
        json={"approval_id": "a" * 32},
        headers={"X-API-Key": API_KEY},
    )

    assert response.status_code == 500
    detail = response.json()["detail"]
    assert detail["error"] == execution_status
    assert detail["approval_id"] == "a" * 32
    assert "operator review required" in detail["recovery"].lower()
