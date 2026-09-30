"""Tests for OpenTelemetry wiring (app/utils/tracing.py and its call sites).

1. The SQS notification producer emits a PRODUCER span and injects the W3C
   ``traceparent`` into MessageAttributes (herm-notification-service continues it).
2. Producer spans never carry PII (emails, names, OTP codes, links).
3. A failed publish marks the span ERROR with the exception type only.
4. The internal consumer-service call carries ``traceparent``; external
   identity-provider calls (Google/Apple/Facebook) never do.
5. FastAPI HTTP spans never export query-string values (OIDC state, nonce,
   request_id, verifier, codes, tokens ...).
6. Health checks are excluded from FastAPI telemetry.
7. Audit JSON log lines carry trace_id/span_id when a span is active.
"""

from __future__ import annotations

import json
import logging
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from opentelemetry.trace import SpanKind, StatusCode

from app.utils.tracing import exclude_health_checks

_exporter = InMemorySpanExporter()
_provider = TracerProvider()
_provider.add_span_processor(SimpleSpanProcessor(_exporter))
trace.set_tracer_provider(_provider)

_QUEUE_URL = "https://sqs.eu-central-1.amazonaws.com/123456789012/prod-notification-queue"
_EMAIL = "victim@example.com"
_SECRET = "s3cr3t-value-123456"


@pytest.fixture(autouse=True)
def _clear_spans():
    _exporter.clear()
    yield
    _exporter.clear()


@pytest.fixture(autouse=True)
def flush_rate_limit_keys():
    """Override the Redis-flushing conftest fixture: these tests use no Redis."""
    yield


def _sqs_client(message_id: str = "m-42") -> MagicMock:
    client = MagicMock()
    client.send_message = MagicMock(return_value={"MessageId": message_id})
    return client


def _producer(client: MagicMock):
    from app.services.sqs_producer import NotificationProducer

    with patch("app.services.sqs_producer.boto3.client", return_value=client), patch(
        "app.services.sqs_producer.settings.NOTIFICATION_QUEUE_URL", _QUEUE_URL
    ):
        return NotificationProducer()


def _all_span_text(span) -> str:
    return json.dumps(
        {
            "name": span.name,
            "attributes": dict(span.attributes or {}),
            "status": span.status.description,
            "events": [
                {"name": e.name, "attributes": dict(e.attributes or {})} for e in span.events
            ],
        },
        default=str,
    )


# ---------------------------------------------------------------------------
# SQS producers
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_sqs_producer_emits_producer_span_and_injects_traceparent():
    client = _sqs_client()
    producer = _producer(client)

    producer.send_email_verification_otp(
        email=_EMAIL, user_name="Victim Name", code="123456",
        expiry_minutes=10, user_id=uuid4(), correlation_id="corr-1",
    )

    (span,) = _exporter.get_finished_spans()
    assert span.name == "send prod-notification-queue"
    assert span.kind == SpanKind.PRODUCER
    assert span.attributes["messaging.system"] == "aws_sqs"
    assert span.attributes["messaging.operation.type"] == "send"
    assert span.attributes["messaging.destination.name"] == "prod-notification-queue"
    assert span.attributes["messaging.message.id"] == "m-42"
    assert span.attributes["herm.correlation_id"] == "corr-1"

    attrs = client.send_message.call_args.kwargs["MessageAttributes"]
    trace_id = format(span.context.trace_id, "032x")
    span_id = format(span.context.span_id, "016x")
    # Consumer's parent is the producer span itself.
    assert attrs["traceparent"]["StringValue"].startswith(f"00-{trace_id}-{span_id}-")
    assert attrs["traceparent"]["DataType"] == "String"
    # Existing attributes are kept.
    assert attrs["template_slug"]["StringValue"] == "email_verification_otp"

    text = _all_span_text(span)
    for pii in (_EMAIL, "Victim Name", "123456"):
        assert pii not in text


@pytest.mark.unit
def test_sqs_producer_failure_marks_span_error_without_message():
    client = _sqs_client()
    client.send_message.side_effect = RuntimeError(f"boom for {_EMAIL}")
    producer = _producer(client)

    with pytest.raises(RuntimeError):
        producer.send_welcome(
            email=_EMAIL, user_name="Victim", login_url="https://x", user_id=uuid4()
        )

    (span,) = _exporter.get_finished_spans()
    assert span.status.status_code == StatusCode.ERROR
    assert span.attributes["error.type"] == "RuntimeError"
    assert _EMAIL not in _all_span_text(span)


@pytest.mark.unit
def test_sqs_producer_keeps_generated_correlation_id():
    client = _sqs_client()
    producer = _producer(client)

    producer.send_password_reset(
        email=_EMAIL, user_name="Victim", reset_link=f"https://app/reset?token={_SECRET}",
        expiry_hours=1, user_id=uuid4(),
    )

    (span,) = _exporter.get_finished_spans()
    body = json.loads(client.send_message.call_args.kwargs["MessageBody"])
    # The generated correlation_id stays in the body and is mirrored on the span.
    assert body["metadata"]["correlation_id"]
    assert span.attributes["herm.correlation_id"] == body["metadata"]["correlation_id"]
    assert _SECRET not in _all_span_text(span)


# ---------------------------------------------------------------------------
# Outgoing HTTP
# ---------------------------------------------------------------------------


def _httpx_client_mock(response: MagicMock) -> MagicMock:
    client = MagicMock()
    client.post = AsyncMock(return_value=response)
    client.get = AsyncMock(return_value=response)
    cm = MagicMock()
    cm.__aenter__ = AsyncMock(return_value=client)
    cm.__aexit__ = AsyncMock(return_value=False)
    return cm, client


@pytest.mark.unit
@pytest.mark.asyncio
async def test_referral_link_call_to_consumer_service_carries_traceparent():
    from app.services.user_service import UserService

    response = MagicMock(status_code=200, text="")
    cm, client = _httpx_client_mock(response)
    tracer = trace.get_tracer("test")

    with patch("app.services.user_service.httpx.AsyncClient", return_value=cm), patch(
        "app.services.user_service.settings.CONSUMER_INTERNAL_BASE_URL",
        "http://prod-consumer:8000/herm-consumer/v1/internal",
    ), patch("app.services.user_service.settings.CONSUMER_INTERNAL_API_KEY", "k"):
        with tracer.start_as_current_span("request") as parent:
            await UserService(MagicMock())._link_referral_signup(uuid4(), _EMAIL, "ABC123")

    headers = client.post.call_args.kwargs["headers"]
    assert headers["X-Internal-API-Key"] == "k"
    trace_id = format(parent.get_span_context().trace_id, "032x")
    assert headers["traceparent"].startswith(f"00-{trace_id}-")

    spans = {s.name: s for s in _exporter.get_finished_spans()}
    client_span = spans["POST /referrals/link-signup"]
    assert client_span.kind == SpanKind.CLIENT
    assert client_span.attributes["http.response.status_code"] == 200
    # The callee's server span is a child of the CLIENT span.
    assert headers["traceparent"].split("-")[2] == format(client_span.context.span_id, "016x")
    text = _all_span_text(client_span)
    assert _EMAIL not in text and "ABC123" not in text


@pytest.mark.unit
@pytest.mark.asyncio
async def test_external_provider_calls_never_carry_traceparent():
    from app.services.social_providers import _JWKSCache

    response = MagicMock()
    response.json = MagicMock(return_value={"keys": [{"kid": "k1"}]})
    response.raise_for_status = MagicMock()
    cm, client = _httpx_client_mock(response)
    tracer = trace.get_tracer("test")

    with patch("app.services.social_providers.httpx.AsyncClient", return_value=cm):
        with tracer.start_as_current_span("request"):
            await _JWKSCache()._fetch("https://www.googleapis.com/oauth2/v3/certs")

    kwargs = client.get.call_args.kwargs
    assert "traceparent" not in (kwargs.get("headers") or {})


# ---------------------------------------------------------------------------
# FastAPI HTTP spans
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_http_spans_never_export_query_string_values():
    from app.main import app

    # Entering the client runs the lifespan, which installs the redaction.
    # Flows off → the route 404s before touching Redis; the span is still recorded.
    with patch("app.api.oidc._flows_enabled", return_value=False), TestClient(app) as http:
        http.get(
            "/herm-auth/oidc/authorize/finish",
            params={"verifier": _SECRET, "state": "st-" + _SECRET, "login_hint": _EMAIL},
        )

    server = [s for s in _exporter.get_finished_spans() if s.kind == SpanKind.SERVER]
    assert server, "FastAPI emitted no server span"
    (span,) = server
    assert span.attributes["url.path"] == "/herm-auth/oidc/authorize/finish"
    assert span.attributes["url.query"] == "REDACTED"
    for s in _exporter.get_finished_spans():
        text = _all_span_text(s)
        assert _SECRET not in text and _EMAIL not in text


@pytest.mark.unit
def test_health_checks_are_excluded():
    assert exclude_health_checks({"path": "/herm-auth/v1/public/health"})
    assert not exclude_health_checks({"path": "/herm-auth/oidc/authorize"})


# ---------------------------------------------------------------------------
# Logs
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_audit_log_lines_carry_trace_ids():
    from app.core.audit_log import _JSONFormatter

    record = logging.LogRecord("audit", logging.INFO, "", 0, "login_success", (), None)
    tracer = trace.get_tracer("test")
    with tracer.start_as_current_span("request") as span:
        line = json.loads(_JSONFormatter().format(record))

    ctx = span.get_span_context()
    assert line["trace_id"] == format(ctx.trace_id, "032x")
    assert line["span_id"] == format(ctx.span_id, "016x")

    # Outside a span: no trace fields.
    assert "trace_id" not in json.loads(_JSONFormatter().format(record))
