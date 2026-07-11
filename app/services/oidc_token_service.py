"""OIDC token minting for Login with Herm.

Builds and RS256-signs (via KMS, `oidc_key_service.sign`) the partner-facing
id_token and access_token. Two properties are load-bearing for security:

  * `sub` is PAIRWISE (PPID): HMAC(OIDC_PPID_SECRET, client_id | user_uuid) —
    different per partner, and the internal user UUID never leaves the service.
  * id_token and access_token are separated by `aud` AND `typ`:
        id_token      -> aud = client_id,        typ = "JWT"
        access_token  -> aud = "herm-userinfo",  typ = "at+jwt"
    /userinfo enforces the access-token aud+typ so an id_token can't be replayed
    there, and the internal HS256 tokens (alg-pinned) never validate as these.

Token scope is always the per-request granted scope passed by the caller —
never a cumulative consent set.
"""
import base64
import hashlib
import hmac
import json
import secrets
import time
from typing import List, Optional

from app.core.config import settings
from app.services.oidc_key_service import oidc_key_service

ACCESS_TOKEN_AUD = "herm-userinfo"


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _seg(obj: dict) -> str:
    return _b64url(json.dumps(obj, separators=(",", ":")).encode("utf-8"))


def pairwise_sub(client_id: str, user_id: str) -> str:
    """Stable pairwise subject identifier for (client, user)."""
    if not settings.OIDC_PPID_SECRET:
        raise RuntimeError("OIDC_PPID_SECRET is not configured")
    mac = hmac.new(
        settings.OIDC_PPID_SECRET.encode("utf-8"),
        f"{client_id}|{user_id}".encode("utf-8"),
        hashlib.sha256,
    ).digest()
    return _b64url(mac)


class OidcTokenService:
    def _sign(self, header: dict, payload: dict, key_arn: str) -> str:
        signing_input = f"{_seg(header)}.{_seg(payload)}".encode("ascii")
        signature = oidc_key_service.sign(signing_input, key_arn=key_arn)
        return f"{signing_input.decode('ascii')}.{_b64url(signature)}"

    def build_id_token(
        self, *, kid: str, key_arn: str, client_id: str, user_id: str,
        scopes: List[str], email: Optional[str] = None, email_verified: bool = False,
        nonce: Optional[str] = None, auth_time: Optional[int] = None, now: Optional[int] = None,
    ) -> str:
        now = int(now if now is not None else time.time())
        header = {"alg": "RS256", "typ": "JWT", "kid": kid}
        payload = {
            "iss": settings.OIDC_ISSUER,
            "sub": pairwise_sub(client_id, str(user_id)),
            "aud": client_id,
            "iat": now,
            "exp": now + settings.OIDC_ID_TOKEN_TTL_SECONDS,
        }
        if auth_time is not None:
            payload["auth_time"] = int(auth_time)
        if nonce:
            payload["nonce"] = nonce
        if "email" in scopes:
            payload["email"] = email
            payload["email_verified"] = bool(email_verified)
        return self._sign(header, payload, key_arn)

    def build_access_token(
        self, *, kid: str, key_arn: str, client_id: str, user_id: str,
        scopes: List[str], jti: Optional[str] = None, now: Optional[int] = None,
    ) -> str:
        now = int(now if now is not None else time.time())
        header = {"alg": "RS256", "typ": "at+jwt", "kid": kid}
        payload = {
            "iss": settings.OIDC_ISSUER,
            "sub": pairwise_sub(client_id, str(user_id)),
            "aud": ACCESS_TOKEN_AUD,
            "client_id": client_id,
            "scope": " ".join(scopes),
            "iat": now,
            "exp": now + settings.OIDC_ACCESS_TOKEN_TTL_SECONDS,
            "jti": jti or secrets.token_urlsafe(16),
        }
        return self._sign(header, payload, key_arn)


oidc_token_service = OidcTokenService()
