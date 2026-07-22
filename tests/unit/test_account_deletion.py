"""Tests for DELETE /pii/auth/me (account deletion, guideline 5.1.1(v))."""
import uuid
from unittest.mock import AsyncMock

import pytest
from fastapi.testclient import TestClient

import app.main as m
from app.api.v1 import pii_auth
from app.api.dependencies import get_blocklist, get_current_user
from app.db.session import get_db
from app.services import apple_account_service

UID = uuid.uuid4()
URL = "/herm-auth/v1/pii/auth/me"


class _User:
    def __init__(self, hashed_password=None):
        self.id = UID
        self.hashed_password = hashed_password
        self.is_active = True


async def _fake_db():
    yield AsyncMock()


def _client(user):
    m.app.dependency_overrides[get_db] = _fake_db
    m.app.dependency_overrides[get_current_user] = lambda: user
    m.app.dependency_overrides[get_blocklist] = lambda: AsyncMock()
    return TestClient(m.app)


@pytest.fixture(autouse=True)
def _cleanup(monkeypatch):
    delete_mock = AsyncMock()
    monkeypatch.setattr(pii_auth.UserService, "delete_account", delete_mock)
    yield delete_mock
    m.app.dependency_overrides.clear()


def test_social_only_user_deletes_without_password(_cleanup):
    with _client(_User(hashed_password=None)) as c:
        r = c.request("DELETE", URL)
    assert r.status_code == 200
    _cleanup.assert_awaited_once()


def test_password_user_requires_password(_cleanup):
    with _client(_User(hashed_password="$hash")) as c:
        r = c.request("DELETE", URL)
    assert r.status_code == 400
    assert r.json()["detail"]["error_key"] == "auth.account.passwordRequired"
    _cleanup.assert_not_awaited()


def test_wrong_password_rejected(_cleanup, monkeypatch):
    monkeypatch.setattr(
        pii_auth.security_service, "verify_password", lambda p, h: False
    )
    with _client(_User(hashed_password="$hash")) as c:
        r = c.request("DELETE", URL, json={"password": "nope"})
    assert r.status_code == 401
    assert r.json()["detail"]["error_key"] == "auth.account.invalidPassword"
    _cleanup.assert_not_awaited()


def test_correct_password_deletes(_cleanup, monkeypatch):
    monkeypatch.setattr(
        pii_auth.security_service, "verify_password", lambda p, h: True
    )
    with _client(_User(hashed_password="$hash")) as c:
        r = c.request("DELETE", URL, json={"password": "right"})
    assert r.status_code == 200
    _cleanup.assert_awaited_once()


def test_apple_code_triggers_best_effort_revocation(_cleanup, monkeypatch):
    revoke = AsyncMock(return_value=True)
    monkeypatch.setattr(apple_account_service, "revoke_apple_tokens", revoke)
    with _client(_User(hashed_password=None)) as c:
        r = c.request("DELETE", URL, json={"apple_authorization_code": "c0de"})
    assert r.status_code == 200
    revoke.assert_awaited_once_with("c0de")
    _cleanup.assert_awaited_once()


def test_apple_revocation_failure_does_not_block_deletion(_cleanup, monkeypatch):
    monkeypatch.setattr(
        apple_account_service, "revoke_apple_tokens", AsyncMock(return_value=False)
    )
    with _client(_User(hashed_password=None)) as c:
        r = c.request("DELETE", URL, json={"apple_authorization_code": "expired"})
    assert r.status_code == 200
    _cleanup.assert_awaited_once()
