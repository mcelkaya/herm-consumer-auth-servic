"""
HMAC (HS256) JWT key ring with zero-downtime rotation support.

Platform-wide, consumer/admin access tokens are HS256-signed by
herm-consumer-auth-service with the shared ``prod_secret_key`` and verified by
every service that holds the same key. This module lets one service hold two
keys at once so the key can be rotated without logging anyone out:

  primary    the existing SECRET_KEY / JWT_SECRET_KEY setting. The signer
             (auth service) signs with it; every service verifies with it.
  secondary  the optional JWT_SECONDARY_SECRET_KEY setting. Verify-only. On
             verifiers it holds the NEXT key before the signer switches; on the
             signer it holds the PREVIOUS key right after it switches.

Tokens carry ``kid`` = a fingerprint of the signing key (see ``key_id``), so no
kid has to be configured and every service derives the same id for the same
key. A token whose kid matches no configured key is rejected. A token without
a kid (minted before this code shipped) is tried against every configured key,
unless ``require_kid`` is set.

With only the primary key configured, behaviour is the same as a plain
``jwt.decode(token, key, algorithms=[alg])``, plus a ``kid`` header on new
tokens (which verifiers that predate this module ignore).

This file is copied verbatim into each herm-* service that signs or verifies
these tokens; keep the copies identical.
"""

import hashlib
import logging
from typing import Dict, Optional

import jwt

logger = logging.getLogger(__name__)

# RFC 7518 3.2: a key used with HS256 must be at least as long as the hash output.
MIN_HMAC_KEY_BYTES = 32


def key_id(secret: str) -> str:
    """Stable, non-reversible id for a key: the first 16 hex chars of SHA-256."""
    return hashlib.sha256(b"herm-jwt-kid:" + secret.encode("utf-8")).hexdigest()[:16]


class HmacKeyRing:
    def __init__(
        self,
        primary: Optional[str],
        secondary: Optional[str] = None,
        algorithm: str = "HS256",
        require_kid: bool = False,
    ) -> None:
        self.algorithm = algorithm
        self.require_kid = require_kid
        self._primary = primary or ""
        # Insertion order = try order for kid-less tokens; primary first.
        self._keys: Dict[str, str] = {}
        for secret in (primary, secondary):
            if secret:
                self._keys.setdefault(key_id(secret), secret)

    @property
    def kids(self) -> list:
        return list(self._keys)

    @property
    def signing_kid(self) -> str:
        return key_id(self._primary)

    def encode(self, payload: dict) -> str:
        """Sign with the primary key and stamp its kid in the header."""
        return jwt.encode(
            payload,
            self._primary,
            algorithm=self.algorithm,
            headers={"kid": self.signing_kid},
        )

    def decode(self, token: str, **kwargs) -> dict:
        """
        Verify ``token`` against the configured keys and return its claims.

        Raises a ``jwt.InvalidTokenError`` subclass on any failure, exactly
        like ``jwt.decode``, so existing ``except PyJWTError`` /
        ``except InvalidTokenError`` handlers keep working.
        """
        kid = jwt.get_unverified_header(token).get("kid")
        if kid is not None:
            secret = self._keys.get(kid)
            if secret is None:
                raise jwt.InvalidSignatureError("Unknown signing key id")
            return jwt.decode(token, secret, algorithms=[self.algorithm], **kwargs)

        if self.require_kid:
            raise jwt.InvalidSignatureError("Token has no key id")

        last_error: Optional[jwt.InvalidTokenError] = None
        for secret in self._keys.values():
            try:
                return jwt.decode(token, secret, algorithms=[self.algorithm], **kwargs)
            except jwt.InvalidSignatureError as exc:
                # Wrong key: try the next one. Any other error (expired, bad
                # claims) means the signature matched, so it is final.
                last_error = exc
        raise last_error or jwt.InvalidSignatureError("No verification key configured")

    def check_key_strength(self, enforce: bool = False) -> list:
        """
        Log an ERROR for every configured key shorter than 32 bytes and return
        their kids. With ``enforce`` set, raise ``ValueError`` instead so the
        service refuses to start. Never logs key material, only kid and length.
        """
        weak = [
            kid
            for kid, secret in self._keys.items()
            if len(secret.encode("utf-8")) < MIN_HMAC_KEY_BYTES
        ]
        for kid in weak:
            logger.error(
                "jwt.weak_hmac_key kid=%s bytes=%d min_bytes=%d primary=%s enforce=%s",
                kid,
                len(self._keys[kid].encode("utf-8")),
                MIN_HMAC_KEY_BYTES,
                kid == self.signing_kid,
                enforce,
            )
        if weak and enforce:
            raise ValueError(
                f"JWT HMAC key(s) {weak} shorter than {MIN_HMAC_KEY_BYTES} bytes "
                "and JWT_ENFORCE_MIN_KEY_LENGTH is enabled"
            )
        logger.info(
            "jwt.hmac_keys_loaded count=%d active=%s", len(self._keys), self.signing_kid
        )
        return weak
