"""Tests for stage2_sdk_ai/logging_setup.py.

These test the JSON formatter directly rather than capturing real
process stdout -- logging handlers bind to a stream reference at
configure time, so fighting pytest's capsys over which stdout object
is "current" is a known source of flaky tests. Testing the formatter
and the logger configuration directly is deterministic.
"""
import json
import logging
import sys

from stage2_sdk_ai.logging_setup import _JsonFormatter, get_logger


def _make_record(level=logging.INFO, msg="hello", request_id=None, exc_info=None, **extra):
    record = logging.LogRecord(
        name="test", level=level, pathname=__file__, lineno=1,
        msg=msg, args=(), exc_info=exc_info,
    )
    if request_id is not None:
        record.request_id = request_id
    for key, value in extra.items():
        setattr(record, key, value)
    return record


def test_formatter_emits_valid_json_with_expected_fields():
    formatter = _JsonFormatter()
    record = _make_record(request_id="abc-123")
    payload = json.loads(formatter.format(record))
    assert payload["message"] == "hello"
    assert payload["level"] == "INFO"
    assert payload["request_id"] == "abc-123"
    assert "timestamp" in payload
    assert payload["logger"] == "test"


def test_formatter_omits_request_id_when_not_set():
    formatter = _JsonFormatter()
    record = _make_record()
    payload = json.loads(formatter.format(record))
    assert "request_id" not in payload


def test_formatter_includes_exception_traceback():
    formatter = _JsonFormatter()
    try:
        raise ValueError("boom")
    except ValueError:
        exc_info = sys.exc_info()
    record = _make_record(level=logging.ERROR, msg="something failed", exc_info=exc_info)
    payload = json.loads(formatter.format(record))
    assert payload["level"] == "ERROR"
    assert "ValueError" in payload["exc_info"]
    assert "boom" in payload["exc_info"]


def test_formatter_includes_arbitrary_extra_fields():
    """Regression test: the formatter used to special-case only
    `request_id` and silently drop every other extra={...} field, so
    api.py's "request completed" log line was missing path, method,
    status_code and duration_ms entirely."""
    formatter = _JsonFormatter()
    record = _make_record(
        request_id="abc-123",
        path="/query",
        method="POST",
        status_code=200,
        duration_ms=12.5,
    )
    payload = json.loads(formatter.format(record))
    assert payload["path"] == "/query"
    assert payload["method"] == "POST"
    assert payload["status_code"] == 200
    assert payload["duration_ms"] == 12.5


def test_get_logger_returns_configured_logger_with_json_formatter():
    logger = get_logger("stage2_sdk_ai.somemodule")
    assert isinstance(logger, logging.Logger)
    root = logging.getLogger()
    assert len(root.handlers) >= 1
    assert isinstance(root.handlers[0].formatter, _JsonFormatter)


def test_get_logger_is_idempotent_single_handler():
    get_logger("a")
    get_logger("b")
    get_logger("c")
    root = logging.getLogger()
    # configure_logging() must not stack a new JSON handler on every call
    # (pytest's own logging plugin may add its own handler to root, so we
    # count only ours rather than asserting the total handler count).
    json_handlers = [h for h in root.handlers if isinstance(h.formatter, _JsonFormatter)]
    assert len(json_handlers) == 1
