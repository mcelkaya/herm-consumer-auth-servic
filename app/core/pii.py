"""Keep PII and credentials out of log lines.

- ``mask_email("someone@example.com")`` -> ``"s***@example.com"`` (domain kept for debugging)
- ``redact(text)``   -> free text with emails masked and JWTs, bearer tokens,
                        ``key=value`` secrets (token, code, verifier, request_id, ...) and IPv4s removed
- ``redact_field(key, value)`` -> value for a structured ``extra`` field; sensitive keys are dropped
- ``validation_summary(errors)`` -> pydantic errors as ``loc:type`` only, never the echoed input
"""

import re
from typing import Any, Iterable, Optional

REDACTED = "[redacted]"

# "@" or its URL-encoded form "%40".
_EMAIL_RE = re.compile(
    r"([A-Za-z0-9._%+-])[A-Za-z0-9._%+-]*?(?:@|%40)([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)"
)
_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")
_BEARER_RE = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+")
_SECRET_KEYS = (
    "password|passwd|client_secret|secret|access_token|refresh_token|id_token|token"
    "|code_verifier|verifier|code|request_id|state|nonce|otp"
)
# key=value / key: value / "key": "value" — the lookbehind keeps e.g. status_code intact.
_KV_RE = re.compile(
    rf"(?i)(?<![A-Za-z0-9_])({_SECRET_KEYS})([\"']?\s*[=:]\s*[\"']?)([^\s,&\"'}}\]]+)"
)
_IPV4_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")

_SENSITIVE_FIELD_PARTS = ("password", "secret", "token", "verifier", "nonce", "otp")
_SENSITIVE_FIELDS = {"ip", "client_ip", "ip_address", "code", "state", "request_id", "authorization"}


def mask_email(email: Optional[str]) -> str:
    """``someone@example.com`` -> ``s***@example.com``."""
    if not email:
        return "-"
    local, sep, domain = str(email).rpartition("@")
    if not sep:
        return REDACTED
    return f"{local[:1]}***@{domain}"


def redact(text: Any) -> str:
    """Return ``str(text)`` with emails masked and tokens/secrets/IPs removed."""
    text = _KV_RE.sub(lambda m: f"{m.group(1)}{m.group(2)}{REDACTED}", str(text))
    text = _JWT_RE.sub(REDACTED, text)
    text = _BEARER_RE.sub(f"Bearer {REDACTED}", text)
    text = _EMAIL_RE.sub(lambda m: f"{m.group(1)}***@{m.group(2)}", text)
    return _IPV4_RE.sub("[ip]", text)


def redact_field(key: str, value: Any) -> Any:
    """Sanitise one structured log field by name, then by content."""
    name = key.lower()
    if name in _SENSITIVE_FIELDS or any(part in name for part in _SENSITIVE_FIELD_PARTS):
        return REDACTED
    if name.endswith("email"):
        return mask_email(value)
    if isinstance(value, str):
        return redact(value)
    return value


def validation_summary(errors: Iterable[dict]) -> str:
    """Summarise pydantic/FastAPI validation errors without the offending input values."""
    return "; ".join(
        f"{'.'.join(str(p) for p in err.get('loc', ()))}:{err.get('type', 'error')}"
        for err in errors
    )
