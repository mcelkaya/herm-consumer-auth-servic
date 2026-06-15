"""Provider-side verification of social login credentials.

Each provider hands the frontend a credential that this module verifies
*server-side* before we trust any identity claim:

  - Google  : an OpenID Connect **ID token** (JWT). Verified against Google's
              JWKS; `aud` must be one of our configured client IDs.
  - Apple   : an **identity token** (JWT) from Sign in with Apple. Verified
              against Apple's JWKS; `aud` must be our bundle id / services id.
  - Facebook: EITHER a Limited Login **OIDC id_token** (JWT, iOS) OR a classic
              **access token** (Android / web). We auto-detect which and verify
              accordingly. The OIDC token is checked against Facebook's JWKS;
              the access token is checked via the Graph API debug_token endpoint
              using an app access token.

Verification only ever produces a `NormalizedIdentity`. It NEVER creates users,
issues sessions, or links accounts — that orchestration lives in
SocialAuthService. Keeping the two apart means the trust boundary (is this
token real and for us?) is in exactly one place.

No new dependencies: PyJWT (+ cryptography) and httpx are already in the
project. JWKS documents are fetched with httpx and cached in-process by URL
with a TTL, refreshing on key rotation (unknown `kid`).
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Iterable, List, Optional

import httpx
import jwt

from app.core.config import settings


# --- provider constants ------------------------------------------------------

GOOGLE_JWKS_URL = "https://www.googleapis.com/oauth2/v3/certs"
GOOGLE_ISSUERS = {"accounts.google.com", "https://accounts.google.com"}

APPLE_JWKS_URL = "https://appleid.apple.com/auth/keys"
APPLE_ISSUERS = {"https://appleid.apple.com"}

# Limited Login (OIDC) token verification for Facebook.
FACEBOOK_JWKS_URL = "https://www.facebook.com/.well-known/oauth/openid/jwks/"
FACEBOOK_ISSUERS = {"https://www.facebook.com", "https://facebook.com"}

FACEBOOK_GRAPH_BASE = "https://graph.facebook.com"

_HTTP_TIMEOUT = 8.0
_JWKS_TTL_SECONDS = 3600
_CLOCK_SKEW_LEEWAY = 10  # seconds


# --- errors ------------------------------------------------------------------


class SocialTokenError(Exception):
    """The provider credential is missing, malformed, expired, or not for us.

    Endpoints map this to HTTP 401 — never reveal which check failed in detail.
    """


class SocialConfigError(Exception):
    """A required provider secret/config value is not set on the server.

    Endpoints map this to HTTP 500 — it is an operator problem, not a caller
    problem.
    """


# --- normalized result -------------------------------------------------------


@dataclass(frozen=True)
class NormalizedIdentity:
    """The trustworthy subset of a verified provider credential.

    `provider_user_id` is the provider's STABLE subject (`sub`) — the only safe
    key for recognising a returning user. `email` may be absent (Apple on
    repeat logins, or when the user declined the email scope). `email_verified`
    is the provider's assertion that it owns/verified that address.
    `is_private_relay` is Apple's "Hide My Email" flag.
    """

    provider: str
    provider_user_id: str
    email: Optional[str]
    email_verified: bool
    is_private_relay: bool = False


# --- JWKS cache --------------------------------------------------------------


class _JWKSCache:
    """In-process JWKS cache keyed by URL, with TTL and rotation refresh."""

    def __init__(self, ttl_seconds: int = _JWKS_TTL_SECONDS):
        self._ttl = ttl_seconds
        # url -> (fetched_at_epoch, {kid: jwk_dict})
        self._cache: dict[str, tuple[float, dict]] = {}

    async def _fetch(self, url: str) -> dict:
        try:
            async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT) as client:
                resp = await client.get(url)
                resp.raise_for_status()
                data = resp.json()
        except Exception as exc:  # network / parse
            raise SocialTokenError(f"could not fetch signing keys: {exc}") from exc
        keys = {k.get("kid"): k for k in data.get("keys", []) if k.get("kid")}
        if not keys:
            raise SocialTokenError("signing key set was empty")
        return keys

    async def get_key(self, url: str, kid: str):
        now = time.time()
        entry = self._cache.get(url)
        fresh = entry is not None and (now - entry[0]) <= self._ttl

        if not fresh or kid not in entry[1]:
            # Stale, or a kid we have not seen (likely rotation) → refetch once.
            keys = await self._fetch(url)
            self._cache[url] = (now, keys)
            entry = self._cache[url]

        jwk = entry[1].get(kid)
        if jwk is None:
            raise SocialTokenError("no matching signing key for token")
        try:
            return jwt.PyJWK.from_dict(jwk, algorithm=jwk.get("alg", "RS256")).key
        except Exception as exc:
            raise SocialTokenError(f"invalid signing key: {exc}") from exc


_jwks = _JWKSCache()


# --- helpers -----------------------------------------------------------------


def _as_bool(value, default: bool = False) -> bool:
    """Coerce a claim that may be a real bool or a "true"/"false" string."""
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() == "true"
    return default


async def _verify_jwt(
    token: str,
    jwks_url: str,
    audiences: List[str],
    allowed_issuers: Iterable[str],
    nonce: Optional[str],
) -> dict:
    if not token or token.count(".") != 2:
        raise SocialTokenError("malformed token")
    if not audiences:
        raise SocialConfigError("no expected audience configured for provider")

    try:
        header = jwt.get_unverified_header(token)
    except Exception as exc:
        raise SocialTokenError(f"unreadable token header: {exc}") from exc

    kid = header.get("kid")
    if not kid:
        raise SocialTokenError("token missing key id")

    key = await _jwks.get_key(jwks_url, kid)

    try:
        payload = jwt.decode(
            token,
            key,
            algorithms=["RS256", "ES256"],
            audience=audiences,  # PyJWT passes if token aud matches any
            leeway=_CLOCK_SKEW_LEEWAY,
            options={"verify_aud": True, "require": ["exp"]},
        )
    except jwt.PyJWTError as exc:
        raise SocialTokenError(f"token rejected: {exc}") from exc

    if payload.get("iss") not in set(allowed_issuers):
        raise SocialTokenError("unexpected token issuer")

    if nonce is not None:
        token_nonce = payload.get("nonce")
        # Only enforce when the token actually carries a nonce.
        if token_nonce is not None and token_nonce != nonce:
            raise SocialTokenError("nonce mismatch")

    return payload


async def _verify_facebook_access_token(token: str) -> NormalizedIdentity:
    """Validate a classic Facebook access token via the Graph API.

    debug_token confirms the token is valid AND was issued for OUR app (so a
    token minted for a different app cannot be replayed here), then /me yields
    the app-scoped user id and email.
    """
    app_id = settings.FACEBOOK_APP_ID
    app_secret = settings.FACEBOOK_APP_SECRET
    if not app_id or not app_secret:
        raise SocialConfigError("Facebook app id/secret not configured")

    app_token = f"{app_id}|{app_secret}"
    try:
        async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT) as client:
            dbg = await client.get(
                f"{FACEBOOK_GRAPH_BASE}/debug_token",
                params={"input_token": token, "access_token": app_token},
            )
            dbg.raise_for_status()
            info = dbg.json().get("data", {})

            if not info.get("is_valid"):
                raise SocialTokenError("facebook token is not valid")
            if str(info.get("app_id")) != str(app_id):
                raise SocialTokenError("facebook token was issued for another app")

            me = await client.get(
                f"{FACEBOOK_GRAPH_BASE}/me",
                params={"fields": "id,name,email", "access_token": token},
            )
            me.raise_for_status()
            profile = me.json()
    except SocialTokenError:
        raise
    except Exception as exc:
        raise SocialTokenError(f"facebook token check failed: {exc}") from exc

    sub = profile.get("id") or info.get("user_id")
    if not sub:
        raise SocialTokenError("facebook token had no user id")

    email = profile.get("email")
    email_verified = settings.FACEBOOK_EMAIL_VERIFIED_DEFAULT if email else False
    return NormalizedIdentity("facebook", str(sub), email, email_verified, False)


# --- public entry point ------------------------------------------------------


async def verify_social_token(
    provider: str,
    credential: str,
    credential_type: Optional[str] = None,
    nonce: Optional[str] = None,
) -> NormalizedIdentity:
    """Verify a provider credential and return the trusted identity.

    Raises SocialTokenError (→ 401) on any verification failure and
    SocialConfigError (→ 500) when server config for the provider is missing.
    """
    provider = (provider or "").lower()

    if provider == "google":
        payload = await _verify_jwt(
            credential, GOOGLE_JWKS_URL, settings.GOOGLE_CLIENT_IDS, GOOGLE_ISSUERS, nonce
        )
        return NormalizedIdentity(
            provider="google",
            provider_user_id=payload["sub"],
            email=payload.get("email"),
            email_verified=_as_bool(payload.get("email_verified")),
        )

    if provider == "apple":
        payload = await _verify_jwt(
            credential, APPLE_JWKS_URL, settings.APPLE_CLIENT_IDS, APPLE_ISSUERS, nonce
        )
        return NormalizedIdentity(
            provider="apple",
            provider_user_id=payload["sub"],
            email=payload.get("email"),
            email_verified=_as_bool(payload.get("email_verified")),
            is_private_relay=_as_bool(payload.get("is_private_email")),
        )

    if provider == "facebook":
        # Auto-detect: a JWT (Limited Login OIDC) has exactly two dots.
        ctype = credential_type or ("id_token" if credential.count(".") == 2 else "access_token")
        if ctype == "id_token":
            payload = await _verify_jwt(
                credential,
                FACEBOOK_JWKS_URL,
                [settings.FACEBOOK_APP_ID],
                FACEBOOK_ISSUERS,
                nonce,
            )
            email = payload.get("email")
            return NormalizedIdentity(
                provider="facebook",
                provider_user_id=payload["sub"],
                email=email,
                email_verified=settings.FACEBOOK_EMAIL_VERIFIED_DEFAULT if email else False,
            )
        return await _verify_facebook_access_token(credential)

    raise SocialTokenError("unsupported provider")