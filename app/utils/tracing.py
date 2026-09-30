"""OpenTelemetry helpers.

Provider and OTLP export setup is owned by FastAPI's native telemetry
(``FastAPI(telemetry=...)``): when ``OTEL_EXPORTER_OTLP_ENDPOINT`` is set it
installs the global provider at lifespan startup; when it is unset every span
below is a no-op. This module only adds what FastAPI cannot see — SQS and
internal-HTTP trace propagation — plus query-string redaction.

PII rule (auth service): never put emails, names, passwords, tokens, codes,
OIDC state/nonce/request ids or client secrets in span names, attributes or
status. Use the exception type, never ``str(exc)``.
"""

from typing import Any, MutableMapping, Optional

from opentelemetry import propagate, trace
from opentelemetry.sdk.trace import SpanProcessor
from opentelemetry.trace import Span, Status, StatusCode

_HEALTH_PATH_PREFIX = "/herm-auth/v1/public/health"


def get_tracer(name: str = __name__) -> trace.Tracer:
    """Return a tracer instance."""
    return trace.get_tracer(name)


def exclude_health_checks(scope: MutableMapping[str, Any]) -> bool:
    """FastAPI telemetry ``exclude`` hook: skip ALB/container health probes."""
    return scope.get("path", "").startswith(_HEALTH_PATH_PREFIX)


class RedactQueryStringProcessor(SpanProcessor):
    """Replace FastAPI's ``url.query`` attribute before any exporter sees it.

    FastAPI records the full query string on server spans and only redacts a
    few cloud-signature keys. Here the query carries OIDC state, nonce,
    code_challenge, request_id and finish verifiers — and any client can append
    tokens or emails to any URL — so the whole value (keys included) is dropped.
    """

    def on_start(self, span: Any, parent_context: Any = None) -> None:
        if span.attributes and span.attributes.get("url.query"):
            span.set_attribute("url.query", "REDACTED")


def install_query_redaction() -> None:
    """Attach the redaction processor to the SDK provider FastAPI installed."""
    add_span_processor = getattr(trace.get_tracer_provider(), "add_span_processor", None)
    if callable(add_span_processor):
        add_span_processor(RedactQueryStringProcessor())


def inject_trace_headers(headers: dict[str, str]) -> None:
    """Add ``traceparent`` to headers of a call to ANOTHER HERM SERVICE only.

    Never use this for external providers (Google/Apple/Facebook/Slack).
    """
    propagate.inject(headers)


def inject_sqs_trace_context(attributes: dict[str, Any]) -> None:
    """Add the current trace context (W3C ``traceparent``) to SQS MessageAttributes."""
    carrier: dict[str, str] = {}
    propagate.inject(carrier)
    for key, value in carrier.items():
        attributes[key] = {"DataType": "String", "StringValue": value}


def queue_name(queue_url: Optional[str]) -> str:
    """Return the queue name (last path segment) of an SQS queue URL."""
    return (queue_url or "").rstrip("/").rsplit("/", 1)[-1]


def set_messaging_attributes(
    span: Span, queue_url: Optional[str], operation: str, correlation_id: Optional[str]
) -> None:
    """Set OTel messaging semantic-convention attributes on an SQS span."""
    span.set_attribute("messaging.system", "aws_sqs")
    span.set_attribute("messaging.operation.type", operation)
    span.set_attribute("messaging.destination.name", queue_name(queue_url))
    if correlation_id:
        span.set_attribute("herm.correlation_id", correlation_id)


def mark_span_error(span: Span, exc: BaseException) -> None:
    """Mark a span failed using only the exception type (messages may echo PII)."""
    error_type = type(exc).__name__
    span.set_attribute("error.type", error_type)
    span.set_status(Status(StatusCode.ERROR, error_type))
