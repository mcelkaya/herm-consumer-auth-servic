"""Unit tests for the OIDC signing-key service (Login with Herm).

The value here is proving the crypto contract end-to-end without any live AWS:
a KMS RSA key is turned into a JWK, and a JWT signed through ``sign()`` (KMS
mocked to sign locally) verifies against that published JWK — i.e. a partner
doing stateless RS256 verification with our JWKS will accept our tokens.
"""
import base64
import json
from unittest.mock import MagicMock

import jwt
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from app.services.oidc_key_service import OidcKeyService, _b64url_uint, _jwk_thumbprint


def _service_with_mocked_kms():
    """An OidcKeyService whose KMS client is backed by a local RSA key."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    der = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    fake_kms = MagicMock()
    fake_kms.get_public_key.return_value = {"PublicKey": der}

    def _sign(KeyId, Message, MessageType, SigningAlgorithm):
        assert MessageType == "RAW"
        assert SigningAlgorithm == "RSASSA_PKCS1_V1_5_SHA_256"
        return {"Signature": private_key.sign(Message, padding.PKCS1v15(), hashes.SHA256())}

    fake_kms.sign.side_effect = _sign

    svc = OidcKeyService()
    svc._kms = fake_kms
    return svc, private_key


def test_public_jwk_matches_kms_key():
    svc, private_key = _service_with_mocked_kms()
    jwk = svc.public_jwk_from_kms("arn:aws:kms:eu-central-1:0:key/test")

    nums = private_key.public_key().public_numbers()
    assert jwk["kty"] == "RSA"
    assert jwk["use"] == "sig"
    assert jwk["alg"] == "RS256"
    assert jwk["n"] == _b64url_uint(nums.n)
    assert jwk["e"] == _b64url_uint(nums.e)
    # kid is the deterministic RFC 7638 thumbprint of the public key.
    assert jwk["kid"] == _jwk_thumbprint(jwk["n"], jwk["e"])


def test_jwt_signed_via_service_verifies_against_published_jwk():
    svc, _ = _service_with_mocked_kms()
    jwk = svc.public_jwk_from_kms("arn:aws:kms:eu-central-1:0:key/test")

    header = {"alg": "RS256", "typ": "JWT", "kid": jwk["kid"]}
    payload = {"iss": "https://api.herm.lvh.me/herm-auth", "sub": "user-123", "aud": "herm_app_x"}

    def _seg(obj):
        return base64.urlsafe_b64encode(json.dumps(obj, separators=(",", ":")).encode()).rstrip(b"=")

    signing_input = _seg(header) + b"." + _seg(payload)
    signature = svc.sign(signing_input)
    token = (signing_input + b"." + base64.urlsafe_b64encode(signature).rstrip(b"=")).decode()

    # Partner-side: rebuild the public key from the JWK and verify.
    public_key = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(jwk))
    decoded = jwt.decode(token, public_key, algorithms=["RS256"], audience="herm_app_x")
    assert decoded["sub"] == "user-123"
    assert decoded["iss"] == "https://api.herm.lvh.me/herm-auth"
