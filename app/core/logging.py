"""Structured JSON logging configuration for the auth service.

Produces CloudWatch-friendly log lines:
    {"timestamp", "level", "service", "message", "extra", "trace_id", "span_id", "exc_info"}

Every message, extra field and traceback goes through ``app.core.pii`` as a
safety net so emails/tokens/IPs never ship verbatim.

Call ``setup_logging()`` once at app startup; modules keep using
``logging.getLogger(__name__)``. The ``audit`` logger keeps its own JSON
handler (propagate=False) and is untouched.
"""

import json
import logging
import sys
from datetime import datetime, timezone

from opentelemetry import trace

from app.core.config import settings
from app.core.pii import redact, redact_field

SERVICE_NAME = "auth"

_BUILTIN_ATTRS = logging.LogRecord("", 0, "", 0, "", (), None).__dict__.keys()


class StructuredJsonFormatter(logging.Formatter):
    """Emit each log record as a single, redacted JSON line."""

    def format(self, record: logging.LogRecord) -> str:
        log_entry: dict = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "service": SERVICE_NAME,
            "message": redact(record.getMessage()),
            "extra": {},
        }

        # Correlate CloudWatch lines with OTel traces.
        span_ctx = trace.get_current_span().get_span_context()
        if span_ctx.is_valid:
            log_entry["trace_id"] = format(span_ctx.trace_id, "032x")
            log_entry["span_id"] = format(span_ctx.span_id, "016x")

        # Merge caller-supplied extra fields (skip standard LogRecord attrs)
        for key, value in record.__dict__.items():
            if key not in _BUILTIN_ATTRS and key not in ("message", "msg"):
                log_entry["extra"][key] = redact_field(key, value)

        if not log_entry["extra"]:
            log_entry.pop("extra")

        if record.exc_info:
            log_entry["exc_info"] = redact(self.formatException(record.exc_info))

        return json.dumps(log_entry, default=str)


def setup_logging() -> None:
    """Configure the root logger with structured JSON output at LOG_LEVEL (default INFO)."""
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(StructuredJsonFormatter())

    root = logging.getLogger()
    root.setLevel(settings.LOG_LEVEL.upper())
    # Avoid duplicate handlers on repeated calls
    root.handlers.clear()
    root.addHandler(handler)

    # Quieten noisy third-party loggers
    for noisy in ("botocore", "boto3", "urllib3", "uvicorn.access", "httpx"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
