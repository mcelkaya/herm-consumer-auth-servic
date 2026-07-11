"""Short-lived OIDC flow state in Redis (Login with Herm).

Holds the authorization request, the decision->finish verifier, and the
authorization code — all one-time, short-TTL, and stored ENCRYPTED so a
co-resident service sharing the Redis instance cannot read redirect_uri / state
/ nonce / PKCE material. Codes and verifiers are keyed by a hash of the secret
(never the secret itself); the request_id is itself a high-entropy handle.

Consumption uses GETDEL (atomic single-use). A replayed code is caught via a
short-lived `code_used` marker so derived refresh tokens can be revoked.
"""
import base64
import hashlib
import json
import secrets
from typing import Optional

from cryptography.fernet import Fernet, InvalidToken

from app.core.config import settings

_REQ = "oidc:req:"
_VERIFIER = "oidc:verifier:"
_CODE = "oidc:code:"
_CODE_USED = "oidc:code_used:"
_AT = "oidc:at:"


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def new_token() -> str:
    """A high-entropy opaque token (request_id / verifier / code / binding)."""
    return secrets.token_urlsafe(32)


class OidcStateService:
    def __init__(self) -> None:
        self._fernet: Optional[Fernet] = None

    def _f(self) -> Fernet:
        if self._fernet is None:
            if not settings.OIDC_STATE_ENC_KEY:
                raise RuntimeError("OIDC_STATE_ENC_KEY is not configured")
            # Derive a valid Fernet key from any high-entropy secret.
            key = base64.urlsafe_b64encode(
                hashlib.sha256(settings.OIDC_STATE_ENC_KEY.encode("utf-8")).digest()
            )
            self._fernet = Fernet(key)
        return self._fernet

    def _enc(self, data: dict) -> str:
        return self._f().encrypt(json.dumps(data).encode("utf-8")).decode("ascii")

    def _dec(self, token: str) -> Optional[dict]:
        try:
            return json.loads(self._f().decrypt(token.encode("ascii")))
        except (InvalidToken, ValueError):
            return None

    # ---- authorization request ------------------------------------------------
    async def put_request(self, redis, request_id: str, data: dict, ttl: Optional[int] = None) -> None:
        await redis.set(_REQ + request_id, self._enc(data), ex=ttl or settings.OIDC_REQUEST_TTL_SECONDS)

    async def peek_request(self, redis, request_id: str) -> Optional[dict]:
        val = await redis.get(_REQ + request_id)
        return self._dec(val) if val else None

    async def extend_request(self, redis, request_id: str, data: dict) -> None:
        """Lengthen TTL when the flow parks on a pending login/signup detour."""
        await redis.set(_REQ + request_id, self._enc(data), ex=settings.OIDC_REQUEST_PENDING_TTL_SECONDS)

    async def take_request(self, redis, request_id: str) -> Optional[dict]:
        val = await redis.getdel(_REQ + request_id)
        return self._dec(val) if val else None

    # ---- decision -> finish verifier -----------------------------------------
    async def put_verifier(self, redis, verifier: str, data: dict) -> None:
        await redis.set(_VERIFIER + _hash(verifier), self._enc(data), ex=settings.OIDC_VERIFIER_TTL_SECONDS)

    async def take_verifier(self, redis, verifier: str) -> Optional[dict]:
        val = await redis.getdel(_VERIFIER + _hash(verifier))
        return self._dec(val) if val else None

    # ---- authorization code ---------------------------------------------------
    async def put_code(self, redis, code: str, data: dict) -> None:
        await redis.set(_CODE + _hash(code), self._enc(data), ex=settings.OIDC_CODE_TTL_SECONDS)

    async def take_code(self, redis, code: str) -> Optional[dict]:
        val = await redis.getdel(_CODE + _hash(code))
        return self._dec(val) if val else None

    async def mark_code_used(self, redis, code: str) -> None:
        await redis.set(_CODE_USED + _hash(code), "1", ex=settings.OIDC_CODE_USED_TTL_SECONDS)

    async def was_code_used(self, redis, code: str) -> bool:
        return bool(await redis.get(_CODE_USED + _hash(code)))

    # ---- access-token -> user mapping (userinfo lookup; sub is a non-reversible PPID)
    async def put_access(self, redis, jti: str, data: dict) -> None:
        await redis.set(_AT + jti, self._enc(data), ex=settings.OIDC_ACCESS_TOKEN_TTL_SECONDS)

    async def get_access(self, redis, jti: str) -> Optional[dict]:
        val = await redis.get(_AT + jti)
        return self._dec(val) if val else None

    async def del_access(self, redis, jti: str) -> None:
        await redis.delete(_AT + jti)


oidc_state_service = OidcStateService()
