"""
Refresh-token cookie helpers.

Centralizes how the `refresh_token` cookie is set and cleared so every auth
route uses identical attributes. Keeping set/delete in one place matters:
browsers only clear a cookie when the delete carries the SAME path / samesite /
secure / domain attributes it was set with — a mismatch leaves a stale cookie
behind on logout.

Attributes are driven by settings (see Settings.COOKIE_*). The default is
SameSite=Lax, which is the correct, robust choice for same-origin serving
(Option A) and works on iOS Safari / in-app webviews where SameSite=None
third-party cookies get blocked.
"""

from fastapi import Response

from app.core.config import settings

REFRESH_COOKIE_KEY = "refresh_token"


def set_refresh_cookie(response: Response, token: str) -> None:
    """Set the refresh_token cookie using the configured attributes."""
    response.set_cookie(
        key=REFRESH_COOKIE_KEY,
        value=token,
        httponly=True,
        secure=settings.COOKIE_SECURE,
        samesite=settings.COOKIE_SAMESITE,
        domain=settings.COOKIE_DOMAIN,
        path="/",
        max_age=settings.REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60,
    )


def clear_refresh_cookie(response: Response) -> None:
    """Clear the refresh_token cookie. Must mirror set_refresh_cookie's attrs."""
    response.delete_cookie(
        key=REFRESH_COOKIE_KEY,
        domain=settings.COOKIE_DOMAIN,
        path="/",
        samesite=settings.COOKIE_SAMESITE,
        secure=settings.COOKIE_SECURE,
        httponly=True,
    )
