"""Tests for POST /public/webhooks/apple (server-to-server notifications)."""
import uuid
from unittest.mock import AsyncMock

import pytest
from fastapi.testclient import TestClient

import app.main as m
from app.api.v1 import apple_webhooks
from app.db.session import get_db
from app.services import apple_account_service
from app.services.social_providers import SocialTokenError

URL = "/herm-auth/v1/public/webhooks/apple"
USER_ID = uuid.uuid4()


class _Link:
    user_id = USER_ID
    provider = "apple"
    provider_user_id = "apple-sub-1"


async def _fake_db():
    yield AsyncMock()


@pytest.fixture
def client():
    m.app.dependency_overrides[get_db] = _fake_db
    with TestClient(m.app) as c:
        yield c
    m.app.dependency_overrides.clear()


@pytest.fixture
def repo_and_tokens(monkeypatch):
    get_link = AsyncMock(return_value=_Link())
    delete_link = AsyncMock()
    revoke_all = AsyncMock()
    monkeypatch.setattr(
        apple_webhooks.UserOAuthAccountRepository, "get_by_provider_identity", get_link
    )
    monkeypatch.setattr(apple_webhooks.UserOAuthAccountRepository, "delete", delete_link)
    monkeypatch.setattr(apple_webhooks.TokenService, "revoke_all_user_tokens", revoke_all)
    return get_link, delete_link, revoke_all


def _event(event_type, sub="apple-sub-1"):
    return {"type": event_type, "sub": sub, "event_time": 1752969600}


def test_invalid_signature_rejected(client, monkeypatch):
    monkeypatch.setattr(
        apple_account_service,
        "verify_apple_webhook",
        AsyncMock(side_effect=SocialTokenError("bad")),
    )
    r = client.post(URL, json={"payload": "not.a.jwt"})
    assert r.status_code == 401


def test_consent_revoked_signs_user_out_but_keeps_link(client, monkeypatch, repo_and_tokens):
    _, delete_link, revoke_all = repo_and_tokens
    monkeypatch.setattr(
        apple_account_service,
        "verify_apple_webhook",
        AsyncMock(return_value=_event("consent-revoked")),
    )
    r = client.post(URL, json={"payload": "a.b.c"})
    assert r.status_code == 200
    revoke_all.assert_awaited_once_with(USER_ID)
    delete_link.assert_not_awaited()


def test_account_delete_drops_link_and_signs_out(client, monkeypatch, repo_and_tokens):
    _, delete_link, revoke_all = repo_and_tokens
    monkeypatch.setattr(
        apple_account_service,
        "verify_apple_webhook",
        AsyncMock(return_value=_event("account-delete")),
    )
    r = client.post(URL, json={"payload": "a.b.c"})
    assert r.status_code == 200
    revoke_all.assert_awaited_once_with(USER_ID)
    delete_link.assert_awaited_once()


def test_email_disabled_is_informational(client, monkeypatch, repo_and_tokens):
    _, delete_link, revoke_all = repo_and_tokens
    monkeypatch.setattr(
        apple_account_service,
        "verify_apple_webhook",
        AsyncMock(return_value=_event("email-disabled")),
    )
    r = client.post(URL, json={"payload": "a.b.c"})
    assert r.status_code == 200
    revoke_all.assert_not_awaited()
    delete_link.assert_not_awaited()


def test_unknown_sub_still_acknowledged(client, monkeypatch, repo_and_tokens):
    get_link, delete_link, revoke_all = repo_and_tokens
    get_link.return_value = None
    monkeypatch.setattr(
        apple_account_service,
        "verify_apple_webhook",
        AsyncMock(return_value=_event("account-delete", sub="gone")),
    )
    r = client.post(URL, json={"payload": "a.b.c"})
    assert r.status_code == 200
    revoke_all.assert_not_awaited()
    delete_link.assert_not_awaited()
