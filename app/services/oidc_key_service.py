"""OIDC signing-key service for Login with Herm.

Turns the KMS asymmetric signing key into a public JWK (for JWKS), keeps a
short-lived in-process cache, and signs JWTs via ``kms:Sign``. Private key
material never leaves KMS.

The ``oauth_signing_keys`` table records the public JWK + KMS ARN + rotation
status; the JWKS endpoint serves every non-dropped key so verification is not
interrupted during rotation. On first use the configured key is registered
lazily (``ensure_active_key``) so no manual seeding step is needed per env.
"""
import base64
import hashlib
import json
import threading
import time
from typing import Optional

import boto3
from cryptography.hazmat.primitives.serialization import load_der_public_key
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models.oauth_signing_key import OAuthSigningKey

# KMS signing algorithm for RS256 (RSASSA-PKCS1-v1_5 with SHA-256).
_KMS_RS256 = "RSASSA_PKCS1_V1_5_SHA_256"


def _b64url_uint(value: int) -> str:
    """Base64url-encode a positive integer (JWK `n`/`e` encoding, no padding)."""
    length = (value.bit_length() + 7) // 8 or 1
    return base64.urlsafe_b64encode(value.to_bytes(length, "big")).rstrip(b"=").decode("ascii")


def _jwk_thumbprint(n: str, e: str) -> str:
    """RFC 7638 JWK thumbprint — a stable, deterministic `kid` for an RSA key."""
    canonical = json.dumps(
        {"e": e, "kty": "RSA", "n": n}, separators=(",", ":"), sort_keys=True
    ).encode("ascii")
    return base64.urlsafe_b64encode(hashlib.sha256(canonical).digest()).rstrip(b"=").decode("ascii")


class OidcKeyService:
    """KMS-backed RS256 signing + JWKS with a thread-safe in-process cache."""

    def __init__(self) -> None:
        self._kms = None
        self._lock = threading.Lock()
        self._jwks_cache: Optional[dict] = None
        self._jwks_expires_at: float = 0.0

    def _client(self):
        if self._kms is None:
            cfg = {"region_name": settings.AWS_REGION}
            if settings.AWS_ENDPOINT_URL:
                cfg["endpoint_url"] = settings.AWS_ENDPOINT_URL
            self._kms = boto3.client("kms", **cfg)
        return self._kms

    def public_jwk_from_kms(self, key_arn: str) -> dict:
        """Fetch the public key from KMS and render it as a signing JWK."""
        resp = self._client().get_public_key(KeyId=key_arn)
        numbers = load_der_public_key(resp["PublicKey"]).public_numbers()
        n = _b64url_uint(numbers.n)
        e = _b64url_uint(numbers.e)
        return {
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "kid": _jwk_thumbprint(n, e),
            "n": n,
            "e": e,
        }

    async def ensure_active_key(self, db: AsyncSession) -> OAuthSigningKey:
        """Register the configured KMS key as the active signing key (idempotent)."""
        if not settings.OIDC_SIGNING_KEY_ARN:
            raise RuntimeError("OIDC_SIGNING_KEY_ARN is not configured")

        result = await db.execute(
            select(OAuthSigningKey).where(OAuthSigningKey.status == "active")
        )
        active = result.scalars().first()
        if active is not None:
            return active

        jwk = self.public_jwk_from_kms(settings.OIDC_SIGNING_KEY_ARN)
        key = OAuthSigningKey(
            kid=jwk["kid"],
            kms_key_arn=settings.OIDC_SIGNING_KEY_ARN,
            algorithm="RS256",
            public_jwk=jwk,
            status="active",
        )
        db.add(key)
        await db.commit()
        await db.refresh(key)
        self.invalidate_cache()
        return key

    async def get_jwks(self, db: AsyncSession) -> dict:
        """Public JWKS document (active + next + retired keys), cached in-process."""
        now = time.time()
        with self._lock:
            if self._jwks_cache is not None and self._jwks_expires_at > now:
                return self._jwks_cache

        result = await db.execute(
            select(OAuthSigningKey).where(
                OAuthSigningKey.status.in_(["active", "next", "retired"])
            )
        )
        jwks = {"keys": [row.public_jwk for row in result.scalars().all()]}

        with self._lock:
            self._jwks_cache = jwks
            self._jwks_expires_at = now + settings.OIDC_SIGNING_KEY_CACHE_TTL_SECONDS
        return jwks

    def invalidate_cache(self) -> None:
        with self._lock:
            self._jwks_cache = None
            self._jwks_expires_at = 0.0

    def sign(self, signing_input: bytes, key_arn: Optional[str] = None) -> bytes:
        """RS256-sign `signing_input` via KMS. Returns the raw signature bytes."""
        resp = self._client().sign(
            KeyId=key_arn or settings.OIDC_SIGNING_KEY_ARN,
            Message=signing_input,
            MessageType="RAW",
            SigningAlgorithm=_KMS_RS256,
        )
        return resp["Signature"]


oidc_key_service = OidcKeyService()
