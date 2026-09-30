"""Reproduces: the service had no logging setup, so the root logger stayed at
WARNING with no handlers. Every app ``logger.info(...)`` was dropped and
WARNING+ reached stderr only as bare text via Python's last-resort handler;
only the ``audit`` logger emitted JSON.

After startup an app INFO record must be one JSON line on stdout, carry
trace/span ids inside a span, and never ship emails/tokens/IPs verbatim.
"""

import json
import logging
import subprocess
import sys
from pathlib import Path

import pytest
from opentelemetry.sdk.trace import TracerProvider

REPO_ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def unconfigured_root_logger():
    """Put the root logger back to Python's default (WARNING, no handlers)."""
    root = logging.getLogger()
    saved_handlers, saved_level = root.handlers[:], root.level
    root.handlers.clear()
    root.setLevel(logging.WARNING)
    yield
    root.handlers[:] = saved_handlers
    root.setLevel(saved_level)


def _last_json_line(out: str) -> dict:
    lines = [line for line in out.splitlines() if line.strip()]
    assert lines, "nothing was written to stdout"
    return json.loads(lines[-1])


def test_app_startup_emits_app_info_log_as_json_on_stdout():
    # Fresh interpreter: importing app.main is the real startup path.
    code = (
        "import logging, app.main\n"
        "logging.getLogger('app.services.user_service').info("
        "'user signed up', extra={'user_id': 'u-1'})\n"
    )
    proc = subprocess.run(
        [sys.executable, "-c", code],
        cwd=REPO_ROOT, capture_output=True, text=True, timeout=60,
    )
    assert proc.returncode == 0, proc.stderr
    entry = _last_json_line(proc.stdout)
    assert entry["level"] == "INFO"
    assert entry["service"] == "auth"
    assert entry["message"] == "user signed up"
    assert entry["extra"] == {"user_id": "u-1"}
    assert "timestamp" in entry
    assert "trace_id" not in entry


def test_app_log_inside_span_carries_trace_ids(unconfigured_root_logger, capsys):
    from app.core.logging import setup_logging

    setup_logging()
    tracer = TracerProvider().get_tracer(__name__)

    with tracer.start_as_current_span("work") as span:
        logging.getLogger("app.api.oidc").info("inside span")
        ctx = span.get_span_context()

    entry = _last_json_line(capsys.readouterr().out)
    assert entry["trace_id"] == format(ctx.trace_id, "032x")
    assert entry["span_id"] == format(ctx.span_id, "016x")


def test_sensitive_values_are_redacted_in_output(unconfigured_root_logger, capsys):
    from app.core.logging import setup_logging

    setup_logging()
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.c2lnbmF0dXJlc2lnbmF0dXJl"
    logging.getLogger("app.services.forgot_password_service").info(
        "reset for victim@example.com from 203.0.113.9 token=abc123secret "
        "Bearer %s request_id=req-42",
        jwt,
        extra={
            "email": "victim@example.com",
            "refresh_token": "rt-plain",
            "client_ip": "203.0.113.9",
            "user_id": "u-1",
        },
    )

    out = capsys.readouterr().out
    for leaked in ("victim@example.com", "203.0.113.9", "abc123secret", jwt, "req-42", "rt-plain"):
        assert leaked not in out
    entry = _last_json_line(out)
    assert "v***@example.com" in entry["message"]
    assert entry["extra"]["user_id"] == "u-1"


def test_exception_text_is_redacted(unconfigured_root_logger, capsys):
    from app.core.logging import setup_logging

    setup_logging()
    try:
        raise ValueError("bad login for victim@example.com")
    except ValueError:
        logging.getLogger("app.core.error_handlers").exception("boom")

    entry = _last_json_line(capsys.readouterr().out)
    assert "ValueError" in entry["exc_info"]
    assert "victim@example.com" not in entry["exc_info"]


def test_noisy_libraries_are_quietened(unconfigured_root_logger):
    from app.core.logging import setup_logging

    setup_logging()
    for name in ("botocore", "boto3", "urllib3", "uvicorn.access", "httpx"):
        assert logging.getLogger(name).level == logging.WARNING


def test_audit_logger_is_not_double_emitted(unconfigured_root_logger, capsys):
    from app.core.logging import setup_logging

    setup_logging()
    from app.core.audit_log import audit

    audit("login_success", user_id="u-1")

    captured = capsys.readouterr()
    assert "login_success" not in captured.out  # root handler must not see it
    audit_logger = logging.getLogger("audit")
    assert audit_logger.propagate is False
    assert len(audit_logger.handlers) == 1
