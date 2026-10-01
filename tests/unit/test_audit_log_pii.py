"""The ``audit`` JSON logger must not ship raw emails or client IPs to CloudWatch.

Reproduces: ``audit("login_success", ip=..., email=...)`` emitted
``{"event":"login_success","ip":"10.0.3.221","user_id":null,"email":"<raw>"}``.
The audit logger has its own handler (propagate=False), so the structured
formatter's redaction never applied to it.
"""

import io
import json
import logging

import pytest

from app.core.audit_log import audit

EMAIL = "jane.doe@audit-example.org"
DOMAIN = "audit-example.org"
IPV4 = "10.0.3.221"
IPV6 = "2001:db8:abcd:12:34:56:78:9a"


@pytest.fixture
def audit_output():
    """Capture what the audit logger's own handler writes."""
    handler = logging.getLogger("audit").handlers[0]
    stream = io.StringIO()
    original = handler.setStream(stream)
    yield stream
    handler.setStream(original)


def _events(stream: io.StringIO) -> list[dict]:
    return [json.loads(line) for line in stream.getvalue().splitlines() if line]


@pytest.mark.unit
def test_login_success_audit_masks_email_and_ip(audit_output):
    audit("login_success", ip=IPV4, email=EMAIL)

    out = audit_output.getvalue()
    assert EMAIL not in out
    assert "jane.doe" not in out
    assert IPV4 not in out

    (event,) = _events(audit_output)
    assert event["event"] == "login_success"
    assert event["level"] == "INFO"
    assert event["user_id"] is None
    assert event["email"] == f"j***@{DOMAIN}"
    # /24 prefix kept for abuse/credential-stuffing analysis, host part dropped.
    assert event["ip"] == "10.0.3.0/24"


@pytest.mark.unit
def test_audit_masks_ipv6_and_keeps_user_id(audit_output):
    audit("logout", ip=IPV6, user_id="7d3f0c1e-0000-4000-8000-000000000001")

    out = audit_output.getvalue()
    assert IPV6 not in out

    (event,) = _events(audit_output)
    assert event["event"] == "logout"
    assert event["user_id"] == "7d3f0c1e-0000-4000-8000-000000000001"
    assert event["ip"] == "2001:db8:abcd::/48"


@pytest.mark.unit
def test_audit_safety_net_redacts_any_extra_field(audit_output):
    """A future call site passing PII under another key must still be redacted."""
    audit(
        "admin_login_success",
        ip=None,
        admin_email=EMAIL,
        detail=f"login for {EMAIL} from {IPV4}",
        client_ip=IPV4,
        provider="google",
    )

    out = audit_output.getvalue()
    assert EMAIL not in out
    assert IPV4 not in out

    (event,) = _events(audit_output)
    assert event["event"] == "admin_login_success"
    assert event["ip"] is None
    assert event["admin_email"] == f"j***@{DOMAIN}"
    assert event["provider"] == "google"
    assert f"j***@{DOMAIN}" in event["detail"]
