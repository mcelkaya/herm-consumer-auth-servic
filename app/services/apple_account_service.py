"""Apple-specific account operations beyond sign-in verification.

Two concerns live here, both talking to Apple's servers rather than
verifying a credential handed over by our own frontend:

1. Token revocation on account deletion. App Store guideline 5.1.1(v)
   requires that deleting an in-app account also revokes the user's Sign in
   with Apple tokens. The native flow never gives this backend an Apple
   refresh token, so the app sends a FRESH authorization code with the
   deletion request; we exchange it at /auth/token and immediately revoke
   the resulting token at /auth/revoke. Both calls authenticate with a
   client secret: a short-lived ES256 JWT signed with the .p8 key from the
   developer portal (Keys → Sign in with Apple).

   Revocation is BEST-EFFORT by design: deleting the account must never
   fail because Apple is down or the key is not configured yet, so callers
   get a bool back and failures are logged, never raised.

2. Server-to-server notification verification for
   POST /public/webhooks/apple. Apple POSTs {"payload": "<signed JWT>"};
   we check the signature against the same JWKS used for login tokens and
   require our own client ids as the audience, then hand back the parsed
   `events` claim. Unlike identity tokens these JWTs are not guaranteed to
   carry `exp`, so verification is done here instead of reusing
   social_providers._verify_jwt (which requires it).
"""

from __future__ import annotations

import json
import logging
import time

import httpx
import jwt

from app.core.config import settings
from app.services.social_providers import (
    APPLE_ISSUERS,
    APPLE_JWKS_URL,
    SocialTokenError,
    _jwks,
)

logger = logging.getLogger(__name__)

APPLE_TOKEN_URL = "https://appleid.apple.com/auth/token"
APPLE_REVOKE_URL = "https://appleid.apple.com/auth/revoke"

_HTTP_TIMEOUT = 8.0
# Apple allows client secrets up to 6 months old; we mint one per call, so
# it only needs to outlive the two requests it signs.
_CLIENT_SECRET_TTL_SECONDS = 600


def apple_revocation_configured() -> bool:
    """True when every value needed to call Apple's token endpoints is set."""
    return bool(
        settings.APPLE_TEAM_ID
        and settings.APPLE_KEY_ID
        and settings.APPLE_PRIVATE_KEY
        and settings.APPLE_CLIENT_IDS
        and not settings.APPLE_CLIENT_IDS[0].startswith("TODO_")
    )


def _client_secret() -> str:
    """Mint the ES256 client-secret JWT Apple requires on /auth/token|revoke."""
    # SSM/env commonly stores the .p8 content with literal \n escapes.
    private_key = settings.APPLE_PRIVATE_KEY.replace("\\n", "\n")
    now = int(time.time())
    return jwt.encode(
        {
            "iss": settings.APPLE_TEAM_ID,
            "iat": now,
            "exp": now + _CLIENT_SECRET_TTL_SECONDS,
            "aud": "https://appleid.apple.com",
            # The client id the authorization code was issued for — the
            # app's bundle id, which is first in APPLE_CLIENT_IDS.
            "sub": settings.APPLE_CLIENT_IDS[0],
        },
        private_key,
        algorithm="ES256",
        headers={"kid": settings.APPLE_KEY_ID},
    )


async def revoke_apple_tokens(authorization_code: str) -> bool:
    """Exchange a fresh authorization code and revoke the resulting tokens.

    Returns True when Apple confirmed the revocation, False on any failure
    (missing config, invalid/expired code, network error). Never raises.
    """
    if not apple_revocation_configured():
        logger.warning(
            "Apple revocation skipped: APPLE_TEAM_ID/APPLE_KEY_ID/APPLE_PRIVATE_KEY not configured"
        )
        return False

    try:
        secret = _client_secret()
        client_id = settings.APPLE_CLIENT_IDS[0]
        async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT) as client:
            token_resp = await client.post(
                APPLE_TOKEN_URL,
                data={
                    "client_id": client_id,
                    "client_secret": secret,
                    "code": authorization_code,
                    "grant_type": "authorization_code",
                },
            )
            if token_resp.status_code != 200:
                logger.warning(
                    "Apple code exchange failed (%s): %s",
                    token_resp.status_code,
                    token_resp.text[:200],
                )
                return False
            tokens = token_resp.json()
            token = tokens.get("refresh_token") or tokens.get("access_token")
            if not token:
                logger.warning("Apple code exchange returned no revocable token")
                return False
            hint = "refresh_token" if tokens.get("refresh_token") else "access_token"

            revoke_resp = await client.post(
                APPLE_REVOKE_URL,
                data={
                    "client_id": client_id,
                    "client_secret": secret,
                    "token": token,
                    "token_type_hint": hint,
                },
            )
            if revoke_resp.status_code != 200:
                logger.warning(
                    "Apple revoke failed (%s): %s",
                    revoke_resp.status_code,
                    revoke_resp.text[:200],
                )
                return False
    except Exception:
        logger.exception("Apple token revocation errored")
        return False
    return True


async def verify_apple_webhook(payload: str) -> dict:
    """Verify a server-to-server notification JWT and return its event.

    The decoded JWT carries an `events` claim — a JSON string shaped like
    {"type": "consent-revoked", "sub": "...", "event_time": 1234, ...}.
    Raises SocialTokenError when the signature, issuer, or audience check
    fails or the events claim is missing/malformed.
    """
    if not payload or payload.count(".") != 2:
        raise SocialTokenError("malformed notification payload")

    try:
        header = jwt.get_unverified_header(payload)
    except Exception as exc:
        raise SocialTokenError(f"unreadable notification header: {exc}") from exc
    kid = header.get("kid")
    if not kid:
        raise SocialTokenError("notification missing key id")

    key = await _jwks.get_key(APPLE_JWKS_URL, kid)
    try:
        claims = jwt.decode(
            payload,
            key,
            algorithms=["RS256", "ES256"],
            audience=settings.APPLE_CLIENT_IDS,
            options={"verify_aud": True},
        )
    except jwt.PyJWTError as exc:
        raise SocialTokenError(f"notification rejected: {exc}") from exc

    if claims.get("iss") not in APPLE_ISSUERS:
        raise SocialTokenError("unexpected notification issuer")

    events = claims.get("events")
    if isinstance(events, str):
        try:
            events = json.loads(events)
        except ValueError as exc:
            raise SocialTokenError("unreadable events claim") from exc
    if not isinstance(events, dict) or not events.get("type"):
        raise SocialTokenError("notification carried no event")
    return events
