"""Unit tests for OAuth client registration foundation (Login with Herm Faz 1-A)."""
import uuid

import pytest
from pydantic import ValidationError

from app.models.oauth_client import OAuthClient
from app.schemas.oauth_client import OAuthClientCreate


def test_client_id_and_secret_generation():
    cid = OAuthClient.generate_client_id()
    assert cid.startswith("herm_app_")
    assert len(cid) > len("herm_app_") + 10

    secret, digest = OAuthClient.generate_client_secret()
    assert len(secret) >= 32
    assert digest == OAuthClient.hash_secret(secret)
    assert len(digest) == 64  # sha256 hex
    # Different each call.
    assert OAuthClient.generate_client_secret()[0] != secret


def _base(**over):
    data = dict(
        client_name="Acme",
        redirect_uris=["https://acme.com/callback"],
        allowed_scopes=["openid", "email"],
        brand_id=uuid.uuid4(),
        company_id=uuid.uuid4(),
    )
    data.update(over)
    return data


def test_valid_client_create():
    m = OAuthClientCreate(**_base())
    assert m.redirect_uris == ["https://acme.com/callback"]


def test_rejects_non_https_redirect():
    with pytest.raises(ValidationError):
        OAuthClientCreate(**_base(redirect_uris=["http://acme.com/callback"]))


def test_rejects_fragment_in_redirect():
    with pytest.raises(ValidationError):
        OAuthClientCreate(**_base(redirect_uris=["https://acme.com/cb#x"]))


def test_localhost_only_allowed_for_sandbox():
    # Non-sandbox: loopback http rejected.
    with pytest.raises(ValidationError):
        OAuthClientCreate(**_base(redirect_uris=["http://localhost:3000/cb"], is_sandbox=False))
    # Sandbox: loopback http allowed.
    m = OAuthClientCreate(**_base(redirect_uris=["http://localhost:3000/cb"], is_sandbox=True))
    assert m.is_sandbox is True


def test_scope_must_be_supported_and_include_openid():
    with pytest.raises(ValidationError):
        OAuthClientCreate(**_base(allowed_scopes=["openid", "payments"]))
    with pytest.raises(ValidationError):
        OAuthClientCreate(**_base(allowed_scopes=["email"]))  # missing openid


def test_invalid_client_type_rejected():
    with pytest.raises(ValidationError):
        OAuthClientCreate(**_base(client_type="implicit"))


@pytest.mark.asyncio
async def test_wizard_auth_key_verification(monkeypatch):
    from fastapi import HTTPException
    from app.core.config import settings
    from app.api.v1.internal_oauth import verify_wizard_auth_key

    # Unset → fail closed (503).
    monkeypatch.setattr(settings, "WIZARD_AUTH_KEY", None)
    with pytest.raises(HTTPException) as e:
        await verify_wizard_auth_key(x_internal_api_key="anything")
    assert e.value.status_code == 503

    # Configured: wrong / missing key → 403; correct → ok.
    monkeypatch.setattr(settings, "WIZARD_AUTH_KEY", "the-secret")
    with pytest.raises(HTTPException) as e:
        await verify_wizard_auth_key(x_internal_api_key="wrong")
    assert e.value.status_code == 403
    with pytest.raises(HTTPException):
        await verify_wizard_auth_key(x_internal_api_key=None)
    assert await verify_wizard_auth_key(x_internal_api_key="the-secret") is True
