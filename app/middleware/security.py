"""Security headers middleware for protecting against common web vulnerabilities"""
from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request as StarletteRequest
from starlette.responses import Response
from app.core.config import settings

_UNSAFE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


class SecurityHeadersMiddleware(BaseHTTPMiddleware):

    async def dispatch(self, request: StarletteRequest, call_next):
        if request.headers.get("sec-fetch-site") == "cross-site" and request.method in _UNSAFE_METHODS:
            return JSONResponse(status_code=403, content={"detail": "Cross-site requests are not permitted"})
        response: Response = await call_next(request)

        # Core security headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

        # Content Security Policy
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "font-src 'self'; "
            "connect-src 'self'; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self'"
        )

        # Permissions Policy
        response.headers["Permissions-Policy"] = (
            "camera=(), "
            "microphone=(), "
            "geolocation=(), "
            "payment=(), "
            "usb=()"
        )

        # HTTP Strict Transport Security (always set for production)
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains; preload"
        )

        # Cross-Origin headers for enhanced isolation
        response.headers["Cross-Origin-Embedder-Policy"] = "require-corp"
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        response.headers["Cross-Origin-Resource-Policy"] = "same-origin"

        # OIDC discovery/JWKS are public, cacheable documents — partners and CDNs
        # cache the JWKS (max-age) to verify tokens without hammering us. Preserve
        # the handler's Cache-Control there; force no-store everywhere else.
        if not request.url.path.startswith("/herm-auth/.well-known/"):
            response.headers["Cache-Control"] = "no-store"

        content_type = response.headers.get("content-type", "")
        if response.status_code >= 400 and "application/json" not in content_type:
            response.headers["content-type"] = "application/json"

        return response


class NullByteSanitizerMiddleware(BaseHTTPMiddleware):
    """
    Reject requests containing null bytes in any part of the request.

    Prevents SQL injection, null byte injection, and other
    injection attacks that use \x00 characters.
    """

    async def dispatch(self, request: StarletteRequest, call_next) -> Response:
        # Check query string for null bytes
        if "\x00" in str(request.url.query) or "\x00" in str(request.url.path):
            return JSONResponse(
                status_code=400,
                content={"detail": "Request contains invalid characters"},
            )

        # Check headers for null bytes
        for key, value in request.headers.items():
            if "\x00" in str(key) or "\x00" in str(value):
                return JSONResponse(
                    status_code=400,
                    content={"detail": "Request contains invalid characters"},
                )

        return await call_next(request)
