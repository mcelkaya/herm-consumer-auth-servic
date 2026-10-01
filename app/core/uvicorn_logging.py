"""uvicorn formatters that redact PII.

uvicorn's loggers (``uvicorn``/``uvicorn.error`` - incl. "Exception in ASGI
application" tracebacks - and ``uvicorn.access`` with the client address and
the full request line + query string) have their own handlers and never reach
setup_logging's redacting root handler. ``uvicorn_log_config.json`` (passed with
``--log-config`` in the Dockerfile CMD, applied in the parent and every worker)
is uvicorn's default ``LOGGING_CONFIG`` with these formatters swapped in.
"""

import logging
import re

from uvicorn.logging import AccessFormatter, DefaultFormatter

from app.core.pii import REDACTED, redact

# OIDC / auth query parameters whose values are never logged, even masked.
_SENSITIVE_QUERY_RE = re.compile(
    r"(?i)([?&](?:login_hint|email|id_token_hint|state|code|code_verifier|verifier"
    r"|code_challenge|request_id|token|access_token|refresh_token|id_token|nonce|otp)=)[^&\s\"]*"
)


class RedactingDefaultFormatter(DefaultFormatter):
    def format(self, record: logging.LogRecord) -> str:
        return redact(super().format(record))


class RedactingAccessFormatter(AccessFormatter):
    def format(self, record: logging.LogRecord) -> str:
        # redact() first: it is not idempotent on an already-"[redacted]" value.
        return _SENSITIVE_QUERY_RE.sub(rf"\1{REDACTED}", redact(super().format(record)))
