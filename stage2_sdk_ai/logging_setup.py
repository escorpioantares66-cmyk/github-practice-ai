"""Structured JSON logging, configured once for the whole process.

Writes one JSON object per line to stdout -- the right target for a
service running under Docker/Render, since those platforms capture
stdout as the log stream rather than a file. A bare `print()` gives
you unstructured text with no level, no timestamp, and nothing to
correlate across a request; this gives every log line a timestamp,
a level, the logger name, and any fields passed via `extra={...}`
(request_id, path, status_code, duration_ms -- whatever the caller
wants to attach) so a failure can be traced end to end.

Usage:
    from stage2_sdk_ai.logging_setup import get_logger
    logger = get_logger(__name__)
    logger.info("request completed", extra={"request_id": rid, "status_code": 200})
    logger.error("request failed", exc_info=exc, extra={"request_id": rid})
"""
from __future__ import annotations

import json
import logging
import sys
import time

# Attributes every LogRecord carries by default. Anything else found on a
# record -- i.e. whatever a caller passed via extra={...} -- is assumed to
# be deliberate structured context and gets included in the JSON output.
_STANDARD_ATTRS = {
    "name", "msg", "args", "levelname", "levelno", "pathname", "filename",
    "module", "exc_info", "exc_text", "stack_info", "lineno", "funcName",
    "created", "msecs", "relativeCreated", "thread", "threadName",
    "processName", "process", "taskName", "message",
}


class _JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(record.created)),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        for key, value in record.__dict__.items():
            if key in _STANDARD_ATTRS or key in payload:
                continue
            payload[key] = value
        return json.dumps(payload, default=str)


_configured = False


def configure_logging(level: int = logging.INFO) -> None:
    """Idempotent: safe to call from every module that wants a logger."""
    global _configured
    if _configured:
        return
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(_JsonFormatter())
    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(level)
    _configured = True


def get_logger(name: str) -> logging.Logger:
    configure_logging()
    return logging.getLogger(name)
