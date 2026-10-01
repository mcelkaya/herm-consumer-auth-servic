"""RS256 migration step 4b: auth accepts RS256 access tokens only.

The old shared HS256 key (SSM prod_secret_key, kid 592b15f8567f47e7) is
treated as leaked. Before this change auth's own decode_token fell back to
the HS256 key ring for any non-RS256 token, so a forged HS256 token (admin
included) was accepted by /pii/auth/*, the admin dependency and logout.

``leaked_secret`` models the attacker's knowledge: on code that still has a
SECRET_KEY setting it is pointed at the test secret the forgeries are signed
with (so the old fallback would accept them); on RS256-only code the setting
no longer exists and there is nothing to point.
"""

import base64
import hashlib
import hmac
import json
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings, settings
from app.core.security import check_access_token_keys, security_service
from app.models.admin_user import AdminUser
from app.models.user import User
from app.services.admin_token_service import create_admin_access_token
from app.services.token_service import create_access_token
from tests.conftest import TEST_ACCESS_TOKEN_KEY, TEST_ACCESS_TOKEN_KID

REPO_ROOT = Path(__file__).resolve().parents[2]
TEST_SECRET = "test-only-hs256-secret-0123456789abcdef0123456789"  # gitleaks:allow
PROD_HS256_KID = "592b15f8567f47e7"  # kid of the retired prod_secret_key (a public value)

ME = "/herm-auth/v1/pii/auth/me"
LOGOUT = "/herm-auth/v1/pii/auth/logout"
ADMIN_ME = "/herm-auth/v1/admin/auth/me"


def _test_secret_kid() -> str:
    # Same derivation the removed HmacKeyRing used, so the old code would look
    # the forged token's kid up and find the (leaked) key.
    return hashlib.sha256(b"herm-jwt-kid:" + TEST_SECRET.encode()).hexdigest()[:16]


@pytest.fixture
def leaked_secret(monkeypatch):
    if "SECRET_KEY" in type(settings).model_fields:
        monkeypatch.setattr(settings, "SECRET_KEY", TEST_SECRET)
        monkeypatch.setattr(settings, "JWT_SECONDARY_SECRET_KEY", None)
    return TEST_SECRET


def _claims(sub: str, **extra) -> dict:
    now = datetime.now(timezone.utc)
    return {
        "sub": sub,
        "type": "access",
        "jti": str(uuid.uuid4()),
        "iss": settings.OIDC_ISSUER,
        "aud": settings.ACCESS_TOKEN_AUDIENCE,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=10)).timestamp()),
        **extra,
    }


def _forge_hs256(claims: dict, kid) -> str:
    # Shaped like the real HS256 tokens auth used to issue: no iss/aud.
    claims = {k: v for k, v in claims.items() if k not in ("iss", "aud")}
    headers = {"kid": kid} if kid else None
    return jwt.encode(claims, TEST_SECRET, algorithm="HS256", headers=headers)


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _unsigned(header: dict, claims: dict, sig: bytes = b"") -> str:
    head = _b64(json.dumps(header).encode()) + "." + _b64(json.dumps(claims).encode())
    return head + "." + _b64(sig)


HS256_KIDS = pytest.mark.parametrize(
    "kid", ["test-secret-kid", PROD_HS256_KID, None], ids=["kid-of-key", "prod-kid", "no-kid"]
)


def _kid(kid):
    return _test_secret_kid() if kid == "test-secret-kid" else kid


async def _admin(db: AsyncSession) -> AdminUser:
    admin = AdminUser(
        email="super_admin@example.com",
        hashed_password=security_service.get_password_hash("correct_password"),
        role="super_admin",
        is_active=True,
    )
    db.add(admin)
    await db.commit()
    await db.refresh(admin)
    return admin


# --- forged HS256 tokens are rejected through the real endpoints -----------------------


@pytest.mark.asyncio
@HS256_KIDS
async def test_forged_hs256_consumer_token_is_401_on_pii_endpoints(
    client: AsyncClient, test_user: User, leaked_secret, kid
):
    token = _forge_hs256(
        _claims(str(test_user.id), email=test_user.email, is_verified=True, role="user"), _kid(kid)
    )
    headers = {"Authorization": f"Bearer {token}"}
    assert (await client.get(ME, headers=headers)).status_code == 401
    assert (await client.post(LOGOUT, headers=headers)).status_code == 401


@pytest.mark.asyncio
@HS256_KIDS
async def test_forged_hs256_admin_token_is_401_on_admin_endpoints(
    client: AsyncClient, db_session: AsyncSession, leaked_secret, kid
):
    admin = await _admin(db_session)
    token = _forge_hs256(
        _claims(str(admin.id), email=admin.email, role="super_admin", is_admin=True), _kid(kid)
    )
    resp = await client.get(ADMIN_ME, headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_rs256_tokens_still_work_on_the_same_endpoints(
    client: AsyncClient, db_session: AsyncSession, test_user: User
):
    token = create_access_token(test_user)
    assert jwt.get_unverified_header(token) == {"alg": "RS256", "typ": "JWT", "kid": TEST_ACCESS_TOKEN_KID}
    resp = await client.get(ME, headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200 and resp.json()["email"] == test_user.email

    admin = await _admin(db_session)
    admin_token = create_admin_access_token(admin)
    assert jwt.get_unverified_header(admin_token)["alg"] == "RS256"
    resp = await client.get(ADMIN_ME, headers={"Authorization": f"Bearer {admin_token}"})
    assert resp.status_code == 200 and resp.json()["email"] == admin.email


@pytest.mark.asyncio
async def test_alg_none_and_alg_confusion_are_401(
    client: AsyncClient, db_session: AsyncSession, test_user: User
):
    admin = await _admin(db_session)
    public_pem = TEST_ACCESS_TOKEN_KEY.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    for sub, extra, url in (
        (str(test_user.id), {"email": test_user.email}, ME),
        (str(admin.id), {"is_admin": True, "role": "super_admin"}, ADMIN_ME),
    ):
        claims = _claims(sub, **extra)
        forged = [
            _unsigned({"alg": "none", "typ": "JWT"}, claims),
            _unsigned({"alg": "none", "typ": "JWT", "kid": TEST_ACCESS_TOKEN_KID}, claims),
        ]
        # alg confusion: HMAC-SHA256 keyed with the *public* PEM, header lying either way
        for alg in ("HS256", "RS256"):
            header = {"alg": alg, "typ": "JWT", "kid": TEST_ACCESS_TOKEN_KID}
            signing_input = _unsigned(header, claims).rsplit(".", 1)[0]
            sig = hmac.new(public_pem, signing_input.encode(), hashlib.sha256).digest()
            forged.append(signing_input + "." + _b64(sig))
        for token in forged:
            assert security_service.decode_token(token) is None
            resp = await client.get(url, headers={"Authorization": f"Bearer {token}"})
            assert resp.status_code == 401, (url, jwt.get_unverified_header(token))


@HS256_KIDS
def test_decode_token_rejects_hs256_even_with_valid_claims(leaked_secret, kid):
    token = _forge_hs256(_claims("1", is_admin=True, role="super_admin"), _kid(kid))
    assert security_service.decode_token(token) is None


def test_decode_token_rejects_everything_when_keyset_missing(monkeypatch):
    token = security_service.create_access_token({"sub": "1"})
    assert security_service.decode_token(token)["sub"] == "1"
    monkeypatch.setattr(settings, "ACCESS_TOKEN_SIGNING_KEYS", None)
    assert security_service.decode_token(token) is None


# --- signing / startup -----------------------------------------------------------------


def test_access_token_algorithm_defaults_to_rs256_and_rejects_hs256():
    assert Settings.model_fields["ACCESS_TOKEN_ALGORITHM"].default == "RS256"
    with pytest.raises(ValueError):
        Settings(ACCESS_TOKEN_ALGORITHM="HS256")


def test_startup_refuses_non_rs256_mode(monkeypatch):
    monkeypatch.setattr(settings, "ACCESS_TOKEN_ALGORITHM", "HS256")
    with pytest.raises(ValueError):
        check_access_token_keys()


@pytest.mark.parametrize("raw", [None, "", "   ", "{not json"])
def test_startup_refuses_missing_or_invalid_keyset(monkeypatch, raw):
    monkeypatch.setattr(settings, "ACCESS_TOKEN_SIGNING_KEYS", raw)
    with pytest.raises(ValueError):
        check_access_token_keys()


@pytest.mark.asyncio
@pytest.mark.parametrize("algorithm,keys", [("HS256", "conftest"), ("RS256", None)])
async def test_lifespan_refuses_to_boot(monkeypatch, algorithm, keys):
    from app.main import app, lifespan

    monkeypatch.setattr(settings, "ACCESS_TOKEN_ALGORITHM", algorithm)
    if keys is None:
        monkeypatch.setattr(settings, "ACCESS_TOKEN_SIGNING_KEYS", None)
    with pytest.raises(ValueError):
        async with lifespan(app):
            pass


def test_settings_need_no_shared_secret(monkeypatch, tmp_path):
    for name in ("SECRET_KEY", "JWT_SECONDARY_SECRET_KEY", "ALGORITHM", "JWT_ENFORCE_MIN_KEY_LENGTH"):
        monkeypatch.delenv(name, raising=False)
    fresh = Settings(_env_file=None, DATABASE_URL="postgresql+asyncpg://u@localhost/db")
    assert not hasattr(fresh, "SECRET_KEY")

    # a stale local .env that still carries the old HS256 settings must not break boot
    stale = tmp_path / ".env"
    stale.write_text(
        "DATABASE_URL=postgresql+asyncpg://u@localhost/db\n"
        "SECRET_KEY=stale-local-value\nALGORITHM=HS256\nJWT_ENFORCE_MIN_KEY_LENGTH=true\n"
    )
    assert not hasattr(Settings(_env_file=str(stale)), "SECRET_KEY")


def test_production_task_definition_no_longer_injects_the_hs256_secret():
    task_def = json.loads((REPO_ROOT / "ecs-task-definitions" / "production.json").read_text())
    (container,) = [c for c in task_def["containerDefinitions"] if c["name"] == "prod-auth"]
    env = {e["name"]: e["value"] for e in container["environment"]}
    secrets = {s["name"]: s["valueFrom"] for s in container["secrets"]}
    assert "SECRET_KEY" not in secrets
    assert not [v for v in secrets.values() if v.endswith("parameter/prod_secret_key")]
    assert not {"ALGORITHM", "JWT_ENFORCE_MIN_KEY_LENGTH", "JWT_SECONDARY_SECRET_KEY"} & env.keys()
    assert env["ACCESS_TOKEN_ALGORITHM"] == "RS256"
    assert "ACCESS_TOKEN_SIGNING_KEYS" in secrets
