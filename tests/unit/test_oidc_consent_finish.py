"""Tests for OIDC consent decision + authorize/finish (Login with Herm 2-C).

Focus: the browser-binding defense at /finish (forced-login / verifier replay)
and that /consent/decision never returns an authorization code.
"""
import uuid
from unittest.mock import AsyncMock

import pytest
from fastapi.testclient import TestClient

import app.main as m
from app.api import oidc
from app.core.config import settings
from app.api.dependencies import get_current_user
from app.db.session import get_db


class _User:
    id = uuid.uuid4()


async def _fake_db():
    yield AsyncMock()


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setattr(settings, "OIDC_PROVIDER_ENABLED", True, raising=False)
    monkeypatch.setattr(settings, "OIDC_FLOWS_ENABLED", True, raising=False)
    monkeypatch.setattr(settings, "OIDC_ISSUER", "https://api.herm.io/herm-auth", raising=False)
    monkeypatch.setattr(settings, "OIDC_ERROR_URL", "https://app.herm.io/connect/error", raising=False)
    m.app.dependency_overrides[get_db] = _fake_db
    with TestClient(m.app) as c:
        yield c
    m.app.dependency_overrides.clear()


APPROVED = {
    "approved": True, "redirect_uri": "https://p.com/cb", "state": "st1",
    "browser_binding": "BIND", "client_id": "herm_app_x", "user_id": "u-1",
    "scopes": ["openid", "email"], "code_challenge": "cc", "code_challenge_method": "S256", "nonce": "n1",
}


def _finish(client, verifier="v", cookie="BIND"):
    cookies = {oidc.BINDING_COOKIE: cookie} if cookie is not None else {}
    return client.get("/herm-auth/oidc/authorize/finish", params={"verifier": verifier},
                      cookies=cookies, follow_redirects=False)


def test_finish_missing_verifier_error(client, monkeypatch):
    monkeypatch.setattr(oidc.oidc_state_service, "take_verifier", AsyncMock(return_value=None))
    r = _finish(client)
    assert r.status_code == 302 and "/connect/error" in r.headers["location"]


def test_finish_binding_mismatch_rejected(client, monkeypatch):
    monkeypatch.setattr(oidc.oidc_state_service, "take_verifier", AsyncMock(return_value=dict(APPROVED)))
    monkeypatch.setattr(oidc.oidc_state_service, "put_code", AsyncMock())
    r = _finish(client, cookie="WRONG")
    assert r.status_code == 302 and "/connect/error" in r.headers["location"]
    assert "access_denied" in r.headers["location"]


def test_finish_missing_cookie_rejected(client, monkeypatch):
    monkeypatch.setattr(oidc.oidc_state_service, "take_verifier", AsyncMock(return_value=dict(APPROVED)))
    r = _finish(client, cookie=None)
    assert r.status_code == 302 and "/connect/error" in r.headers["location"]


def test_finish_valid_issues_code(client, monkeypatch):
    put_code = AsyncMock()
    monkeypatch.setattr(oidc.oidc_state_service, "take_verifier", AsyncMock(return_value=dict(APPROVED)))
    monkeypatch.setattr(oidc.oidc_state_service, "put_code", put_code)
    r = _finish(client, cookie="BIND")
    loc = r.headers["location"]
    assert r.status_code == 302 and loc.startswith("https://p.com/cb?")
    assert "code=" in loc and "state=st1" in loc and "iss=https" in loc
    put_code.assert_awaited_once()  # code persisted server-side, not returned to JS


def test_finish_denied_redirects_with_error(client, monkeypatch):
    denied = {"approved": False, "redirect_uri": "https://p.com/cb", "state": "st1", "browser_binding": "BIND"}
    monkeypatch.setattr(oidc.oidc_state_service, "take_verifier", AsyncMock(return_value=denied))
    r = _finish(client, cookie="BIND")
    loc = r.headers["location"]
    assert loc.startswith("https://p.com/cb") and "error=access_denied" in loc and "state=st1" in loc
    assert "code=" not in loc


def test_decision_returns_finish_url_not_code(client, monkeypatch):
    m.app.dependency_overrides[get_current_user] = lambda: _User()
    monkeypatch.setattr(oidc.oidc_state_service, "take_request", AsyncMock(return_value={
        "client_id": "herm_app_x", "redirect_uri": "https://p.com/cb", "scopes": ["openid", "email"],
        "state": "st1", "code_challenge": "cc", "code_challenge_method": "S256", "nonce": "n1",
        "browser_binding": "BIND",
    }))
    monkeypatch.setattr(oidc.OAuthConsentRepository, "upsert", AsyncMock())
    monkeypatch.setattr(oidc.oidc_state_service, "put_verifier", AsyncMock())
    r = client.post("/herm-auth/oidc/consent/decision", json={"request_id": "rid", "approved": True})
    assert r.status_code == 200
    body = r.json()
    assert "finish_url" in body and "/oidc/authorize/finish?verifier=" in body["finish_url"]
    assert "code" not in body  # code is never handed to the SPA


def test_decision_expired_request_400(client, monkeypatch):
    m.app.dependency_overrides[get_current_user] = lambda: _User()
    monkeypatch.setattr(oidc.oidc_state_service, "take_request", AsyncMock(return_value=None))
    r = client.post("/herm-auth/oidc/consent/decision", json={"request_id": "rid", "approved": True})
    assert r.status_code == 400
