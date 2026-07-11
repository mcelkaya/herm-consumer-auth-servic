"""Tests for /oidc/token (Login with Herm 2-D): client auth, code binding, PKCE,
replay, and a happy-path exchange whose id_token verifies against the JWKS."""
import base64
import hashlib
import json
import uuid
from unittest.mock import AsyncMock, MagicMock

import jwt
import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from fastapi.testclient import TestClient

import app.main as m
from app.api import oidc
from app.core.config import settings
from app.db.session import get_db
from app.models.oauth_client import OAuthClient
import app.services.oidc_key_service as key_mod
import app.services.oidc_token_service as tok_mod

SECRET = "client-topsecret"
USER_ID = uuid.uuid4()
VERIFIER = "pkce-verifier-abcdefghijklmnopqrstuvwxyz012345"
CHALLENGE = base64.urlsafe_b64encode(hashlib.sha256(VERIFIER.encode()).digest()).rstrip(b"=").decode()


class FakeClient:
    client_type = "confidential"
    is_usable = True
    redirect_uris = ["https://p.com/cb"]
    allowed_scopes = ["openid", "email"]
    client_secret_hash = OAuthClient.hash_secret(SECRET)


class FakeUser:
    id = USER_ID
    email = "u@example.com"
    is_verified = True


class FakeKey:
    kid = None  # set in fixture
    kms_key_arn = "arn:test"


async def _fake_db():
    yield AsyncMock()


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setattr(settings, "OIDC_PROVIDER_ENABLED", True, raising=False)
    monkeypatch.setattr(settings, "OIDC_FLOWS_ENABLED", True, raising=False)
    monkeypatch.setattr(settings, "OIDC_OFFLINE_ACCESS_ENABLED", False, raising=False)
    monkeypatch.setattr(settings, "OIDC_PPID_SECRET", "ppid", raising=False)
    monkeypatch.setattr(settings, "OIDC_ISSUER", "https://api.herm.io/herm-auth", raising=False)

    # Wire the shared key-service singleton to a local RSA key standing in for KMS.
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    der = priv.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    kms = MagicMock()
    kms.get_public_key.return_value = {"PublicKey": der}
    kms.sign.side_effect = lambda **kw: {"Signature": priv.sign(kw["Message"], padding.PKCS1v15(), hashes.SHA256())}
    key_mod.oidc_key_service._kms = kms
    jwk = key_mod.oidc_key_service.public_jwk_from_kms("arn:test")
    FakeKey.kid = jwk["kid"]
    monkeypatch.setattr(key_mod.oidc_key_service, "ensure_active_key", AsyncMock(return_value=FakeKey()))

    monkeypatch.setattr(oidc.OAuthClientRepository, "get_by_client_id", AsyncMock(return_value=FakeClient()))
    monkeypatch.setattr(oidc.UserRepository, "get_by_id", AsyncMock(return_value=FakeUser()))
    monkeypatch.setattr(oidc.oidc_state_service, "mark_code_used", AsyncMock())
    monkeypatch.setattr(oidc.oidc_state_service, "put_access", AsyncMock())
    monkeypatch.setattr(oidc, "enforce_rate_limit", AsyncMock())

    m.app.dependency_overrides[get_db] = _fake_db
    with TestClient(m.app) as c:
        c._jwk = jwk
        yield c
    m.app.dependency_overrides.clear()


def _code_rec(**over):
    rec = {"client_id": "herm_app_x", "user_id": str(USER_ID), "scopes": ["openid", "email"],
           "redirect_uri": "https://p.com/cb", "code_challenge": CHALLENGE, "code_challenge_method": "S256", "nonce": "n1"}
    rec.update(over)
    return rec


def _post(client, **over):
    body = {"grant_type": "authorization_code", "code": "thecode", "redirect_uri": "https://p.com/cb",
            "code_verifier": VERIFIER, "client_id": "herm_app_x", "client_secret": SECRET}
    body.update(over)
    return client.post("/herm-auth/oidc/token", data=body)


def test_bad_grant_type(client):
    r = _post(client, grant_type="password")
    assert r.status_code == 400 and r.json()["error"] == "unsupported_grant_type"


def test_refresh_grant_disabled(client):
    r = _post(client, grant_type="refresh_token")
    assert r.status_code == 400 and r.json()["error"] == "unsupported_grant_type"


def test_unknown_client(client, monkeypatch):
    monkeypatch.setattr(oidc.OAuthClientRepository, "get_by_client_id", AsyncMock(return_value=None))
    r = _post(client)
    assert r.status_code == 401 and r.json()["error"] == "invalid_client"


def test_wrong_secret(client):
    r = _post(client, client_secret="wrong")
    assert r.status_code == 401 and r.json()["error"] == "invalid_client"


def test_code_substitution_rejected(client, monkeypatch):
    # code was issued to a DIFFERENT client
    monkeypatch.setattr(oidc.oidc_state_service, "take_code", AsyncMock(return_value=_code_rec(client_id="other_client")))
    r = _post(client)
    assert r.status_code == 400 and r.json()["error"] == "invalid_grant"


def test_redirect_uri_mismatch(client, monkeypatch):
    monkeypatch.setattr(oidc.oidc_state_service, "take_code", AsyncMock(return_value=_code_rec()))
    r = _post(client, redirect_uri="https://p.com/other")
    assert r.status_code == 400 and r.json()["error"] == "invalid_grant"


def test_pkce_mismatch(client, monkeypatch):
    monkeypatch.setattr(oidc.oidc_state_service, "take_code", AsyncMock(return_value=_code_rec()))
    r = _post(client, code_verifier="wrong-verifier")
    assert r.status_code == 400 and r.json()["error"] == "invalid_grant"


def test_code_replay_detected(client, monkeypatch):
    monkeypatch.setattr(oidc.oidc_state_service, "take_code", AsyncMock(return_value=None))
    monkeypatch.setattr(oidc.oidc_state_service, "was_code_used", AsyncMock(return_value=True))
    r = _post(client)
    assert r.status_code == 400 and r.json()["error"] == "invalid_grant"


def test_happy_path_issues_verifiable_tokens(client, monkeypatch):
    monkeypatch.setattr(oidc.oidc_state_service, "take_code", AsyncMock(return_value=_code_rec()))
    r = _post(client)
    assert r.status_code == 200
    body = r.json()
    assert body["token_type"] == "Bearer" and body["scope"] == "openid email"
    assert r.headers.get("cache-control") == "no-store"
    pub = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(client._jwk))
    idt = jwt.decode(body["id_token"], pub, algorithms=["RS256"], audience="herm_app_x")
    assert idt["email"] == "u@example.com" and idt["iss"] == "https://api.herm.io/herm-auth"
    at = jwt.decode(body["access_token"], pub, algorithms=["RS256"], audience="herm-userinfo")
    assert at["client_id"] == "herm_app_x" and at["scope"] == "openid email"
