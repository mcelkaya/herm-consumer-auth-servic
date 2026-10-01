"""
RS256 key set for consumer/admin access tokens (RS256 migration, step 1).

Access tokens are signed in-process (not via KMS per token) with RSA private
keys loaded once at startup from the ``ACCESS_TOKEN_SIGNING_KEYS`` setting,
which holds JSON injected from Secrets Manager:

    {"active": "<kid>", "keys": {"<kid>": "<PEM private key>", ...}}

``active`` signs; every key in ``keys`` is published in the access-token JWKS
and accepted for verification, so rotation is: add a new kid, switch
``active``, drop the old kid once its tokens expired.

kids must start with ``at-`` so they can never collide with the OIDC signing
key kids (RFC 7638 thumbprints) or the HS256 kids (16 hex chars).

Never log or repr key material: only kids and key sizes.
See docs/rs256-gecis-plani.md (projects/docs) for the full plan.
"""

import json
import re
from typing import Dict

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

ALGORITHM = "RS256"
MIN_RSA_KEY_BITS = 2048
KID_PATTERN = re.compile(r"^at-[A-Za-z0-9._-]{1,64}$")


def _b64url_uint(value: int) -> str:
    raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return jwt.utils.base64url_encode(raw).decode("ascii")


class AccessTokenKeySet:
    def __init__(self, active_kid: str, keys: Dict[str, rsa.RSAPrivateKey]) -> None:
        self.active_kid = active_kid
        self._keys = keys

    def __repr__(self) -> str:
        return f"AccessTokenKeySet(active={self.active_kid!r}, bits={self.key_bits!r})"

    @classmethod
    def from_json(cls, raw: str) -> "AccessTokenKeySet":
        """Parse and validate a keyset. Raises ValueError; messages never contain key material."""
        try:
            doc = json.loads(raw)
        except (TypeError, ValueError):
            raise ValueError("ACCESS_TOKEN_SIGNING_KEYS is not valid JSON") from None
        if not isinstance(doc, dict) or not isinstance(doc.get("keys"), dict) or not doc["keys"]:
            raise ValueError("ACCESS_TOKEN_SIGNING_KEYS must be {'active': kid, 'keys': {kid: pem}} with >= 1 key")
        active = doc.get("active")
        if active not in doc["keys"]:
            raise ValueError(f"ACCESS_TOKEN_SIGNING_KEYS active kid {active!r} is not in keys {sorted(doc['keys'])}")

        keys: Dict[str, rsa.RSAPrivateKey] = {}
        for kid, pem in doc["keys"].items():
            if not isinstance(kid, str) or not KID_PATTERN.match(kid):
                raise ValueError(f"access-token kid {kid!r} must match {KID_PATTERN.pattern}")
            try:
                key = serialization.load_pem_private_key(str(pem).encode("utf-8"), password=None)
            except Exception:
                raise ValueError(f"access-token key {kid!r} is not an unencrypted PEM private key") from None
            if not isinstance(key, rsa.RSAPrivateKey):
                raise ValueError(f"access-token key {kid!r} is not an RSA key")
            if key.key_size < MIN_RSA_KEY_BITS:
                raise ValueError(f"access-token key {kid!r} is {key.key_size} bits; minimum is {MIN_RSA_KEY_BITS}")
            keys[kid] = key
        return cls(active, keys)

    @property
    def kids(self) -> list:
        return list(self._keys)

    @property
    def key_bits(self) -> Dict[str, int]:
        return {kid: key.key_size for kid, key in self._keys.items()}

    def encode(self, payload: dict) -> str:
        """Sign with the active key; header is {alg: RS256, typ: JWT, kid}."""
        return jwt.encode(
            payload,
            self._keys[self.active_kid],
            algorithm=ALGORITHM,
            headers={"kid": self.active_kid},
        )

    def decode(self, token: str, *, audience: str, issuer: str) -> dict:
        """Verify with the key named by kid; RS256 only; exp/iss/aud required."""
        kid = jwt.get_unverified_header(token).get("kid")
        key = self._keys.get(kid) if isinstance(kid, str) else None
        if key is None:
            raise jwt.InvalidSignatureError("Unknown access-token key id")
        return jwt.decode(
            token,
            key.public_key(),
            algorithms=[ALGORITHM],
            audience=audience,
            issuer=issuer,
            options={"require": ["exp", "iss", "aud"]},
        )

    def public_jwks(self) -> dict:
        keys = []
        for kid, key in self._keys.items():
            numbers = key.public_key().public_numbers()
            keys.append(
                {
                    "kty": "RSA",
                    "use": "sig",
                    "alg": ALGORITHM,
                    "kid": kid,
                    "n": _b64url_uint(numbers.n),
                    "e": _b64url_uint(numbers.e),
                }
            )
        return {"keys": keys}
