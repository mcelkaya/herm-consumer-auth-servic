"""Tests for consumer Connected Apps endpoints (Login with Herm 5-A)."""
import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock

import pytest
from fastapi.testclient import TestClient

import app.main as m
from app.api.v1 import pii_oauth
from app.core.config import settings
from app.api.dependencies import get_current_user
from app.db.session import get_db

UID = uuid.uuid4()


class _User:
    id = UID


class _Consent:
    def __init__(self, client_id, revoked_at=None):
        self.client_id = client_id
        self.granted_scopes = ["openid", "email"]
        self.granted_at = datetime(2026, 7, 1, tzinfo=timezone.utc)
        self.last_used_at = None
        self.revoked_at = revoked_at


class _Client:
    def __init__(self, client_id, name):
        self.client_id = client_id
        self.client_name = name
        self.logo_url = None


async def _fake_db():
    yield AsyncMock()


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setattr(settings, "OIDC_PROVIDER_ENABLED", True, raising=False)
    m.app.dependency_overrides[get_db] = _fake_db
    m.app.dependency_overrides[get_current_user] = lambda: _User()
    with TestClient(m.app) as c:
        yield c
    m.app.dependency_overrides.clear()


def test_list_consents_joins_client(client, monkeypatch):
    monkeypatch.setattr(pii_oauth.OAuthConsentRepository, "list_for_user",
                        AsyncMock(return_value=[_Consent("herm_app_a"), _Consent("herm_app_b")]))
    monkeypatch.setattr(pii_oauth.OAuthClientRepository, "get_by_client_ids",
                        AsyncMock(return_value=[_Client("herm_app_a", "Acme"), _Client("herm_app_b", "Beta")]))
    r = client.get("/herm-auth/v1/pii/oauth/consents")
    assert r.status_code == 200
    apps = r.json()
    assert {a["client_name"] for a in apps} == {"Acme", "Beta"}
    assert apps[0]["granted_scopes"] == ["openid", "email"]


def test_list_skips_orphaned_consent(client, monkeypatch):
    # Consent references a client that no longer exists → skipped.
    monkeypatch.setattr(pii_oauth.OAuthConsentRepository, "list_for_user",
                        AsyncMock(return_value=[_Consent("herm_app_gone")]))
    monkeypatch.setattr(pii_oauth.OAuthClientRepository, "get_by_client_ids", AsyncMock(return_value=[]))
    r = client.get("/herm-auth/v1/pii/oauth/consents")
    assert r.status_code == 200 and r.json() == []


def test_revoke_consent(client, monkeypatch):
    consent = _Consent("herm_app_a")
    monkeypatch.setattr(pii_oauth.OAuthConsentRepository, "get", AsyncMock(return_value=consent))
    r = client.delete("/herm-auth/v1/pii/oauth/consents/herm_app_a")
    assert r.status_code == 204
    assert consent.revoked_at is not None  # marked revoked


def test_revoke_unknown_404(client, monkeypatch):
    monkeypatch.setattr(pii_oauth.OAuthConsentRepository, "get", AsyncMock(return_value=None))
    r = client.delete("/herm-auth/v1/pii/oauth/consents/nope")
    assert r.status_code == 404


def test_flag_off_404(client, monkeypatch):
    monkeypatch.setattr(settings, "OIDC_PROVIDER_ENABLED", False, raising=False)
    assert client.get("/herm-auth/v1/pii/oauth/consents").status_code == 404
