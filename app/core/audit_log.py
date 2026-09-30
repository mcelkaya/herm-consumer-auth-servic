"""
JSON-structured audit logger for security-relevant auth events.
Emits one JSON line per event — pipe-friendly and parseable by log aggregators.
"""

import json
import logging
import datetime
from typing import Optional

from opentelemetry import trace


class _JSONFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "level": record.levelname,
            "event": record.getMessage(),
        }
        # Correlate CloudWatch lines with OTel traces.
        span_ctx = trace.get_current_span().get_span_context()
        if span_ctx.is_valid:
            payload["trace_id"] = format(span_ctx.trace_id, "032x")
            payload["span_id"] = format(span_ctx.span_id, "016x")
        if hasattr(record, "audit"):
            payload.update(record.audit)
        return json.dumps(payload)


def _build_logger() -> logging.Logger:
    logger = logging.getLogger("audit")
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(_JSONFormatter())
        logger.addHandler(handler)
        logger.propagate = False
    logger.setLevel(logging.INFO)
    return logger


_logger = _build_logger()


def audit(event: str, ip: Optional[str] = None, user_id: Optional[str] = None, **extra) -> None:
    record = _logger.makeRecord("audit", logging.INFO, "", 0, event, (), None)
    record.audit = {"ip": ip, "user_id": user_id, **extra}
    _logger.handle(record)
