"""Unit tests for OIDC token minting + state encryption (Login with Herm 2-A)."""
import json
from unittest.mock import MagicMock

import jwt
import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from app.core.config import settings
from app.services.oidc_key_service import OidcKeyService
import app.services.oidc_key_service as key_mod
import app.services.oidc_token_service as tok_mod
from app.services.oidc_token_service import OidcTokenService, pairwise_sub, ACCESS_TOKEN_AUD


@pytest.fixture
def signing(monkeypatch):
    """Wire the token service to a local RSA key standing in for KMS."""
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    der = priv.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    kms = MagicMock()
    kms.get_public_key.return_value = {"PublicKey": der}
    kms.sign.side_effect = lambda **kw: {"Signature": priv.sign(kw["Message"], padding.PKCS1v15(), hashes.SHA256())}
    svc = OidcKeyService()
    svc._kms = kms
    # token service signs via the module-level oidc_key_service singleton
    monkeypatch.setattr(key_mod, "oidc_key_service", svc)
    monkeypatch.setattr(tok_mod, "oidc_key_service", svc)
    monkeypatch.setattr(settings, "OIDC_PPID_SECRET", "ppid-secret", raising=False)
    monkeypatch.setattr(settings, "OIDC_ISSUER", "https://api.herm.io/herm-auth", raising=False)
    jwk = svc.public_jwk_from_kms("arn:test")
    return jwk


def test_pairwise_sub_stable_and_per_client(monkeypatch):
    monkeypatch.setattr(settings, "OIDC_PPID_SECRET", "ppid-secret", raising=False)
    a1 = pairwise_sub("client_A", "user-1")
    a2 = pairwise_sub("client_A", "user-1")
    b = pairwise_sub("client_B", "user-1")
    assert a1 == a2            # stable for same (client, user)
    assert a1 != b             # different per client (no cross-partner correlation)
    assert "user-1" not in a1  # internal uuid not exposed


def test_id_token_verifies_and_has_pairwise_sub(signing):
    jwk = signing
    svc = OidcTokenService()
    token = svc.build_id_token(
        kid=jwk["kid"], key_arn="arn:test", client_id="herm_app_x", user_id="uuid-123",
        scopes=["openid", "email"], email="u@example.com", email_verified=True, nonce="n1",
    )
    pub = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(jwk))
    d = jwt.decode(token, pub, algorithms=["RS256"], audience="herm_app_x")
    assert d["iss"] == "https://api.herm.io/herm-auth"
    assert d["sub"] == pairwise_sub("herm_app_x", "uuid-123")
    assert d["email"] == "u@example.com" and d["email_verified"] is True
    assert d["nonce"] == "n1"
    hdr = jwt.get_unverified_header(token)
    assert hdr["typ"] == "JWT" and hdr["kid"] == jwk["kid"]


def test_access_token_aud_and_typ(signing):
    jwk = signing
    svc = OidcTokenService()
    token = svc.build_access_token(
        kid=jwk["kid"], key_arn="arn:test", client_id="herm_app_x", user_id="uuid-123",
        scopes=["openid", "email"],
    )
    pub = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(jwk))
    d = jwt.decode(token, pub, algorithms=["RS256"], audience=ACCESS_TOKEN_AUD)
    assert d["aud"] == ACCESS_TOKEN_AUD
    assert d["client_id"] == "herm_app_x"
    assert d["scope"] == "openid email"
    assert "jti" in d
    assert jwt.get_unverified_header(token)["typ"] == "at+jwt"


def test_id_token_omits_email_without_scope(signing):
    jwk = signing
    token = OidcTokenService().build_id_token(
        kid=jwk["kid"], key_arn="arn:test", client_id="c", user_id="u",
        scopes=["openid"], email="u@example.com", email_verified=True,
    )
    pub = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(jwk))
    d = jwt.decode(token, pub, algorithms=["RS256"], audience="c")
    assert "email" not in d


def test_state_service_encrypts_and_roundtrips(monkeypatch):
    monkeypatch.setattr(settings, "OIDC_STATE_ENC_KEY", "some-high-entropy-secret", raising=False)
    from app.services.oidc_state_service import OidcStateService
    svc = OidcStateService()
    data = {"client_id": "c", "redirect_uri": "https://p/cb", "state": "s", "nonce": "n"}
    enc = svc._enc(data)
    assert "redirect_uri" not in enc and "https://p/cb" not in enc  # ciphertext, not plaintext
    assert svc._dec(enc) == data
    assert svc._dec("garbage") is None  # tampered/invalid → None, no raise
