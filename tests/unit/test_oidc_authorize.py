"""Tests for /oidc/authorize (Login with Herm 2-B): validation + binding cookie."""
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi.testclient import TestClient

import app.main as m
from app.api import oidc
from app.core.config import settings
from app.db.session import get_db
from app.middleware.rate_limit import rate_limit_oidc_authorize


class _FakeClient:
    is_usable = True
    redirect_uris = ["https://p.com/cb"]
    allowed_scopes = ["openid", "email"]


async def _fake_db():
    yield MagicMock()


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setattr(settings, "OIDC_PROVIDER_ENABLED", True, raising=False)
    monkeypatch.setattr(settings, "OIDC_FLOWS_ENABLED", True, raising=False)
    monkeypatch.setattr(settings, "OIDC_CONSENT_URL", "https://app.herm.io/connect/consent", raising=False)
    monkeypatch.setattr(settings, "OIDC_ERROR_URL", "https://app.herm.io/connect/error", raising=False)
    # Avoid Redis on the valid path.
    monkeypatch.setattr(oidc.oidc_state_service, "put_request", AsyncMock())
    m.app.dependency_overrides[get_db] = _fake_db
    m.app.dependency_overrides[rate_limit_oidc_authorize] = lambda: None
    with TestClient(m.app) as c:
        yield c
    m.app.dependency_overrides.clear()


def _authorize(client, **params):
    base = {
        "response_type": "code", "client_id": "herm_app_x",
        "redirect_uri": "https://p.com/cb", "scope": "openid email",
        "state": "st1", "code_challenge": "abc", "code_challenge_method": "S256",
    }
    base.update(params)
    base = {k: v for k, v in base.items() if v is not None}
    return client.get("/herm-auth/oidc/authorize", params=base, follow_redirects=False)


def _found(client, present=True):
    oidc.OAuthClientRepository.get_by_client_id = AsyncMock(return_value=_FakeClient() if present else None)


def test_flag_off_goes_to_error(client, monkeypatch):
    monkeypatch.setattr(settings, "OIDC_FLOWS_ENABLED", False, raising=False)
    r = _authorize(client)
    assert r.status_code == 302 and "/connect/error" in r.headers["location"]


def test_unknown_client_error_page(client):
    _found(client, present=False)
    r = _authorize(client)
    assert r.status_code == 302
    assert "/connect/error" in r.headers["location"] and "unauthorized_client" in r.headers["location"]


def test_bad_redirect_uri_never_redirects_to_it(client):
    _found(client)
    r = _authorize(client, redirect_uri="https://evil.com/cb")
    loc = r.headers["location"]
    assert "/connect/error" in loc and "invalid_redirect_uri" in loc
    assert "evil.com" not in loc


def test_missing_state_returns_error_to_client(client):
    _found(client)
    r = _authorize(client, state=None)
    loc = r.headers["location"]
    assert loc.startswith("https://p.com/cb") and "error=invalid_request" in loc


def test_missing_pkce_returns_error_to_client(client):
    _found(client)
    r = _authorize(client, code_challenge=None)
    loc = r.headers["location"]
    assert loc.startswith("https://p.com/cb") and "error=invalid_request" in loc and "state=st1" in loc


def test_scope_without_openid_rejected(client):
    _found(client)
    r = _authorize(client, scope="email")
    assert "error=invalid_scope" in r.headers["location"]


def test_scope_escalation_rejected(client):
    _found(client)
    r = _authorize(client, scope="openid email profile")  # profile not allowed
    assert "error=invalid_scope" in r.headers["location"]


def test_valid_sets_binding_cookie_and_hands_off(client):
    _found(client)
    r = _authorize(client)
    loc = r.headers["location"]
    assert r.status_code == 302
    assert loc.startswith("https://app.herm.io/connect/consent#request_id=")
    sc = r.headers.get("set-cookie", "")
    assert "__Host-oidc_bind=" in sc and "Secure" in sc and "HttpOnly" in sc
    assert "Domain" not in sc  # __Host- requires no Domain
