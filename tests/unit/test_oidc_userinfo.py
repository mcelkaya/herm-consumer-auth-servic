"""Tests for /oidc/userinfo + /oidc/revoke (Login with Herm 2-E)."""
import json
import uuid
from unittest.mock import AsyncMock, MagicMock

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
from app.services.oidc_token_service import oidc_token_service, pairwise_sub

SECRET = "client-topsecret"
UID = uuid.uuid4()
JTI = "jti-abc"


class FakeClient:
    client_type = "confidential"
    is_usable = True
    client_secret_hash = OAuthClient.hash_secret(SECRET)


class FakeUser:
    id = UID
    email = "u@example.com"
    is_verified = True


class FakeKey:
    kid = None
    kms_key_arn = "arn:test"
    public_jwk = None


async def _fake_db():
    yield AsyncMock()


@pytest.fixture
def ctx(monkeypatch):
    monkeypatch.setattr(settings, "OIDC_PROVIDER_ENABLED", True, raising=False)
    monkeypatch.setattr(settings, "OIDC_FLOWS_ENABLED", True, raising=False)
    monkeypatch.setattr(settings, "OIDC_PPID_SECRET", "ppid", raising=False)
    monkeypatch.setattr(settings, "OIDC_ISSUER", "https://api.herm.io/herm-auth", raising=False)

    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    der = priv.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    kms = MagicMock()
    kms.get_public_key.return_value = {"PublicKey": der}
    kms.sign.side_effect = lambda **kw: {"Signature": priv.sign(kw["Message"], padding.PKCS1v15(), hashes.SHA256())}
    key_mod.oidc_key_service._kms = kms
    jwk = key_mod.oidc_key_service.public_jwk_from_kms("arn:test")
    FakeKey.kid, FakeKey.public_jwk = jwk["kid"], jwk
    monkeypatch.setattr(key_mod.oidc_key_service, "ensure_active_key", AsyncMock(return_value=FakeKey()))
    monkeypatch.setattr(oidc, "enforce_rate_limit", AsyncMock())

    access = oidc_token_service.build_access_token(
        kid=jwk["kid"], key_arn="arn:test", client_id="herm_app_x", user_id=str(UID),
        scopes=["openid", "email"], jti=JTI,
    )
    id_token = oidc_token_service.build_id_token(
        kid=jwk["kid"], key_arn="arn:test", client_id="herm_app_x", user_id=str(UID),
        scopes=["openid", "email"], email="u@example.com", email_verified=True,
    )
    m.app.dependency_overrides[get_db] = _fake_db
    with TestClient(m.app) as c:
        yield c, access, id_token
    m.app.dependency_overrides.clear()


def test_userinfo_valid(ctx, monkeypatch):
    c, access, _ = ctx
    monkeypatch.setattr(oidc.oidc_state_service, "get_access", AsyncMock(return_value={
        "user_id": str(UID), "scopes": ["openid", "email"], "client_id": "herm_app_x"}))
    monkeypatch.setattr(oidc.UserRepository, "get_by_id", AsyncMock(return_value=FakeUser()))
    r = c.get("/herm-auth/oidc/userinfo", headers={"Authorization": f"Bearer {access}"})
    assert r.status_code == 200
    body = r.json()
    assert body["sub"] == pairwise_sub("herm_app_x", str(UID))
    assert body["email"] == "u@example.com" and body["email_verified"] is True


def test_userinfo_rejects_id_token(ctx, monkeypatch):
    c, _, id_token = ctx
    monkeypatch.setattr(oidc.oidc_state_service, "get_access", AsyncMock(return_value={"user_id": str(UID), "scopes": ["openid"], "client_id": "herm_app_x"}))
    r = c.get("/herm-auth/oidc/userinfo", headers={"Authorization": f"Bearer {id_token}"})
    assert r.status_code == 401  # aud=client_id / typ=JWT → not an access token


def test_userinfo_no_mapping_unauthorized(ctx, monkeypatch):
    c, access, _ = ctx
    monkeypatch.setattr(oidc.oidc_state_service, "get_access", AsyncMock(return_value=None))
    r = c.get("/herm-auth/oidc/userinfo", headers={"Authorization": f"Bearer {access}"})
    assert r.status_code == 401  # revoked/expired mapping


def test_userinfo_no_bearer(ctx):
    c, _, _ = ctx
    r = c.get("/herm-auth/oidc/userinfo")
    assert r.status_code == 401


def test_revoke_access_token_ok(ctx, monkeypatch):
    c, access, _ = ctx
    monkeypatch.setattr(oidc.OAuthClientRepository, "get_by_client_id", AsyncMock(return_value=FakeClient()))
    del_access = AsyncMock()
    monkeypatch.setattr(oidc.oidc_state_service, "del_access", del_access)
    r = c.post("/herm-auth/oidc/revoke", data={"token": access, "client_id": "herm_app_x", "client_secret": SECRET})
    assert r.status_code == 200
    del_access.assert_awaited_once()


def test_revoke_wrong_secret(ctx, monkeypatch):
    c, access, _ = ctx
    monkeypatch.setattr(oidc.OAuthClientRepository, "get_by_client_id", AsyncMock(return_value=FakeClient()))
    r = c.post("/herm-auth/oidc/revoke", data={"token": access, "client_id": "herm_app_x", "client_secret": "wrong"})
    assert r.status_code == 401


def test_revoke_unknown_token_still_200(ctx, monkeypatch):
    c, _, _ = ctx
    monkeypatch.setattr(oidc.OAuthClientRepository, "get_by_client_id", AsyncMock(return_value=FakeClient()))
    monkeypatch.setattr(oidc.oidc_state_service, "del_access", AsyncMock())
    r = c.post("/herm-auth/oidc/revoke", data={"token": "garbage", "client_id": "herm_app_x", "client_secret": SECRET})
    assert r.status_code == 200
