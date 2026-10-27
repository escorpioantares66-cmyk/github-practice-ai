"""Structured JSON logging, configured once for the whole process.

Writes one JSON object per line to stdout -- the right target for a
service running under Docker/Render, since those platforms capture
stdout as the log stream rather than a file. A bare `print()` gives
you unstructured text with no level, no timestamp, and nothing to
correlate across a request; this gives every log line a timestamp,
a level, the logger name, and (when passed via `extra={"request_id": ...}`)
a request id so a failure can be traced end to end.

Usage:
    from stage2_sdk_ai.logging_setup import get_logger
    logger = get_logger(__name__)
    logger.info("agent started", extra={"request_id": rid})
    logger.exception("agent failed", extra={"request_id": rid})
"""
from __future__ import annotations

import json
import logging
import sys
import time


class _JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(record.created)),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        request_id = getattr(record, "request_id", None)
        if request_id:
            payload["request_id"] = request_id
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
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
