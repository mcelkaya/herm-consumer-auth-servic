"""RS256 access tokens, step 1 (signer side only).

Contract under test:

* ``ACCESS_TOKEN_ALGORITHM=HS256`` (default): every token auth issues is
  byte-for-byte identical to what origin/main issues, and still verifies with
  the verifier code deployed in herm-consumer-service today. No communication
  changes.
* ``ACCESS_TOKEN_ALGORITHM=RS256``: access tokens (consumer + admin) are signed
  in-process with the active key from ``ACCESS_TOKEN_SIGNING_KEYS`` and carry
  kid/iss/aud; they verify against the published JWKS with pinned
  algorithms; alg-confusion and unknown kids are rejected.
* /herm-auth/.well-known/jwks.json is byte-identical to origin/main while no
  keyset is configured, and lists the ``at-*`` keys after the OIDC keys once
  one is. OIDC tokens can never carry the internal ``aud``.

All RSA keys are generated at test time; no key material is committed.
"""

import base64
import hashlib
import hmac
import json
import logging
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from httpx import ASGITransport, AsyncClient

import app.core.security as security_module
from app.core import access_token_keys
from app.core.access_token_keys import AccessTokenKeySet
from app.core.config import Settings, settings
from app.core.security import check_access_token_keys, security_service
from app.services.admin_token_service import create_admin_access_token
from app.services.token_service import create_access_token
from tests._frozen import auth_main_security as main_security
from tests._frozen import consumer_service_security as consumer_verifier

REPO_ROOT = Path(__file__).resolve().parents[2]
FROZEN_NOW = datetime(2026, 10, 1, 12, 0, 0)
FROZEN_UUID = "11111111-2222-4333-8444-555555555555"
ISSUER = "https://api.herm.test/herm-auth"
AUDIENCE = "herm-api"


# --- helpers -------------------------------------------------------------------


def _pem(private_key) -> str:
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()


def _keyset_json(active: str, keys: dict) -> str:
    return json.dumps({"active": active, "keys": {kid: _pem(k) for kid, k in keys.items()}})


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _segments(token: str):
    header, payload, _ = token.split(".")
    pad = lambda s: s + "=" * (-len(s) % 4)  # noqa: E731
    return (
        json.loads(base64.urlsafe_b64decode(pad(header))),
        json.loads(base64.urlsafe_b64decode(pad(payload))),
    )


def _verify_with_jwks(token: str, jwks: dict, **kwargs) -> dict:
    """What a correct step-2 verifier does: kid lookup in JWKS, pinned RS256."""
    kid = jwt.get_unverified_header(token).get("kid")
    jwk = next((k for k in jwks["keys"] if k["kid"] == kid), None)
    if jwk is None:
        raise jwt.InvalidSignatureError("unknown kid")
    public_key = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(jwk))
    return jwt.decode(
        token, public_key, algorithms=["RS256"], audience=AUDIENCE, issuer=ISSUER, **kwargs
    )


class _FrozenDatetime(datetime):
    @classmethod
    def utcnow(cls):
        return FROZEN_NOW


@pytest.fixture(scope="module")
def rsa_old():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="module")
def rsa_new():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture
def frozen(monkeypatch):
    """Freeze time and jti in both the new signer and the frozen origin/main one."""
    for module in (security_module, main_security):
        monkeypatch.setattr(module, "datetime", _FrozenDatetime)
        monkeypatch.setattr(module, "uuid4", lambda: FROZEN_UUID)


@pytest.fixture
def mode(monkeypatch):
    def configure(algorithm="HS256", keyset=None):
        monkeypatch.setattr(settings, "ACCESS_TOKEN_ALGORITHM", algorithm)
        monkeypatch.setattr(settings, "ACCESS_TOKEN_SIGNING_KEYS", keyset)
        monkeypatch.setattr(settings, "ACCESS_TOKEN_AUDIENCE", AUDIENCE)
        monkeypatch.setattr(settings, "OIDC_ISSUER", ISSUER)

    configure()
    return configure


CONSUMER_USER = SimpleNamespace(id=42, email="u@example.com", is_verified=True, role="user")
ADMIN_USER = SimpleNamespace(id=7, email="admin@example.com", role="super_admin")


def _main_consumer_token():
    return main_security.security_service.create_access_token(
        data={
            "sub": str(CONSUMER_USER.id),
            "email": CONSUMER_USER.email,
            "is_verified": CONSUMER_USER.is_verified,
            "role": CONSUMER_USER.role,
        }
    )


def _main_admin_token():
    return main_security.security_service.create_access_token(
        data={
            "sub": str(ADMIN_USER.id),
            "email": ADMIN_USER.email,
            "role": ADMIN_USER.role,
            "is_admin": True,
        }
    )


# --- (1) HS256 default: no change on the wire -------------------------------------


def test_settings_default_is_hs256_without_keyset():
    fresh = Settings()
    assert fresh.ACCESS_TOKEN_ALGORITHM == "HS256"
    assert not fresh.ACCESS_TOKEN_SIGNING_KEYS
    assert fresh.ACCESS_TOKEN_AUDIENCE == "herm-api"


def test_invalid_algorithm_setting_is_rejected():
    with pytest.raises(ValueError):
        Settings(ACCESS_TOKEN_ALGORITHM="none")


@pytest.mark.parametrize("with_keyset", [False, True])
def test_hs256_tokens_are_byte_identical_to_origin_main(frozen, mode, rsa_old, with_keyset):
    # A configured keyset must not change anything while the mode is HS256.
    mode("HS256", _keyset_json("at-old", {"at-old": rsa_old}) if with_keyset else None)

    pairs = [
        (create_access_token(CONSUMER_USER), _main_consumer_token()),
        (create_admin_access_token(ADMIN_USER), _main_admin_token()),
        (
            security_service.create_access_token({"sub": "1"}, timedelta(minutes=5)),
            main_security.security_service.create_access_token({"sub": "1"}, timedelta(minutes=5)),
        ),
        (
            security_service.create_refresh_token({"sub": "1"}),
            main_security.security_service.create_refresh_token({"sub": "1"}),
        ),
    ]
    for new, old in pairs:
        assert new == old  # same header, same claims, same signature
        header, claims = _segments(new)
        assert header == {"alg": "HS256", "typ": "JWT", "kid": header["kid"]}
        assert not {"iss", "aud"} & claims.keys()


def test_hs256_tokens_verify_with_deployed_consumer_service_verifier(mode):
    mode("HS256")
    for token in (create_access_token(CONSUMER_USER), create_admin_access_token(ADMIN_USER)):
        claims = consumer_verifier.security_service.decode_token(token)
        assert claims is not None
        assert claims["type"] == "access"
    assert consumer_verifier.security_service.get_user_id_from_token(
        create_access_token(CONSUMER_USER)
    ) == "42"


def test_rs256_tokens_are_rejected_by_todays_verifiers(mode, rsa_old):
    # Documents why step 2 (verifier dual-mode) MUST ship before RS256 is enabled.
    mode("RS256", _keyset_json("at-old", {"at-old": rsa_old}))
    assert consumer_verifier.security_service.decode_token(create_access_token(CONSUMER_USER)) is None


# --- (2) RS256 mode ------------------------------------------------------------------


@pytest.fixture
def rs256(mode, rsa_old):
    mode("RS256", _keyset_json("at-old", {"at-old": rsa_old}))
    return AccessTokenKeySet.from_json(settings.ACCESS_TOKEN_SIGNING_KEYS).public_jwks()


@pytest.mark.parametrize("mint", [lambda: create_access_token(CONSUMER_USER), lambda: create_admin_access_token(ADMIN_USER)])
def test_rs256_token_shape_and_jwks_verification(rs256, mint):
    token = mint()
    header, claims = _segments(token)
    assert header == {"alg": "RS256", "typ": "JWT", "kid": "at-old"}
    assert claims["iss"] == ISSUER
    assert claims["aud"] == AUDIENCE
    assert claims["type"] == "access"
    verified = _verify_with_jwks(token, rs256)
    assert verified["sub"] in ("42", "7")
    # auth's own verification path (/me, logout, admin deps) accepts it too
    assert security_service.decode_token(token)["sub"] == verified["sub"]


def test_rs256_admin_token_keeps_admin_marker(rs256):
    claims = _verify_with_jwks(create_admin_access_token(ADMIN_USER), rs256)
    assert claims["is_admin"] is True and claims["role"] == "super_admin"


def test_refresh_tokens_stay_hs256_in_rs256_mode(frozen, rs256):
    token = security_service.create_refresh_token({"sub": "1"})
    assert token == main_security.security_service.create_refresh_token({"sub": "1"})
    assert security_service.decode_token(token)["type"] == "refresh"


def test_rs256_unknown_kid_is_rejected(rs256, rsa_new):
    claims = {"sub": "1", "iss": ISSUER, "aud": AUDIENCE, "exp": datetime.now(timezone.utc) + timedelta(minutes=5)}
    forged = jwt.encode(claims, rsa_new, algorithm="RS256", headers={"kid": "at-unknown"})
    assert security_service.decode_token(forged) is None
    with pytest.raises(jwt.InvalidTokenError):
        _verify_with_jwks(forged, rs256)
    # known kid, wrong key
    forged_known_kid = jwt.encode(claims, rsa_new, algorithm="RS256", headers={"kid": "at-old"})
    assert security_service.decode_token(forged_known_kid) is None
    with pytest.raises(jwt.InvalidSignatureError):
        _verify_with_jwks(forged_known_kid, rs256)


def test_rs256_alg_confusion_public_key_as_hmac_secret_is_rejected(rs256, rsa_old):
    public_pem = rsa_old.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    claims = {"sub": "1", "iss": ISSUER, "aud": AUDIENCE, "type": "access",
              "exp": int((datetime.now(timezone.utc) + timedelta(minutes=5)).timestamp())}
    for alg in ("HS256", "RS256"):  # header lies either way; signature is HMAC(public key)
        signing_input = _b64(json.dumps({"alg": alg, "typ": "JWT", "kid": "at-old"}).encode()) + "." + _b64(json.dumps(claims).encode())
        sig = hmac.new(public_pem, signing_input.encode(), hashlib.sha256).digest()
        forged = signing_input + "." + _b64(sig)
        assert security_service.decode_token(forged) is None
        with pytest.raises(jwt.InvalidTokenError):
            _verify_with_jwks(forged, rs256)


def test_rs256_wrong_audience_issuer_or_expired_rejected(rs256, rsa_old):
    base = {"sub": "1", "iss": ISSUER, "aud": AUDIENCE, "exp": datetime.now(timezone.utc) + timedelta(minutes=5)}
    bad = [
        {**base, "aud": "herm-userinfo"},
        {**base, "iss": "https://evil.example/herm-auth"},
        {**base, "exp": datetime.now(timezone.utc) - timedelta(minutes=1)},
        {k: v for k, v in base.items() if k != "aud"},
        {k: v for k, v in base.items() if k != "iss"},
    ]
    for claims in bad:
        token = jwt.encode(claims, rsa_old, algorithm="RS256", headers={"kid": "at-old"})
        assert security_service.decode_token(token) is None


def test_hs256_mode_still_accepts_outstanding_rs256_tokens_when_keyset_present(mode, rsa_old):
    # Rollback RS256 -> HS256: tokens already issued keep working on auth.
    keyset = _keyset_json("at-old", {"at-old": rsa_old})
    mode("RS256", keyset)
    token = create_access_token(CONSUMER_USER)
    mode("HS256", keyset)
    assert security_service.decode_token(token)["sub"] == "42"
    mode("HS256", None)
    assert security_service.decode_token(token) is None


def test_hs256_tokens_still_verify_in_rs256_mode(mode, rsa_old):
    hs_token = create_access_token(CONSUMER_USER)
    mode("RS256", _keyset_json("at-old", {"at-old": rsa_old}))
    assert security_service.decode_token(hs_token)["sub"] == "42"


# --- (3) JWKS: one document, /herm-auth/.well-known/jwks.json -------------------------

JWKS_PATH = "/herm-auth/.well-known/jwks.json"
OIDC_KID = "oidcThumbprintKid0123456789abcdefghijklmnopq"


async def _get(path, app=None, base_url="http://test"):
    if app is None:
        from app.main import app
    async with AsyncClient(transport=ASGITransport(app=app), base_url=base_url) as c:
        return await c.get(path)


def _main_app():
    """origin/main's discovery/JWKS router, mounted exactly as app.main mounts it."""
    from fastapi import FastAPI
    from tests._frozen import auth_main_well_known

    frozen = FastAPI()
    frozen.include_router(auth_main_well_known.router, prefix="/herm-auth")
    return frozen


@pytest.fixture
def oidc_stub(monkeypatch):
    """Stub the KMS/DB-backed OIDC key service (same singleton both routers use)."""
    from app.db.session import get_db
    from app.main import app
    from app.services.oidc_key_service import oidc_key_service

    oidc_jwks = {"keys": [{"kty": "RSA", "use": "sig", "alg": "RS256", "kid": OIDC_KID, "n": "AQAB", "e": "AQAB"}]}

    async def ensure_active_key(db):
        return None

    async def get_jwks(db):
        return json.loads(json.dumps(oidc_jwks))

    async def fake_db():
        yield None

    monkeypatch.setattr(oidc_key_service, "ensure_active_key", ensure_active_key)
    monkeypatch.setattr(oidc_key_service, "get_jwks", get_jwks)
    frozen = _main_app()
    for a in (app, frozen):
        a.dependency_overrides[get_db] = fake_db
    yield SimpleNamespace(jwks=oidc_jwks, frozen=frozen)
    app.dependency_overrides.pop(get_db, None)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "oidc_enabled,key_arn",
    [(True, "arn:aws:kms:eu-central-1:0:key/test"), (True, None), (False, "arn:aws:kms:eu-central-1:0:key/test"), (False, None)],
)
async def test_jwks_without_keyset_is_identical_to_origin_main(mode, oidc_stub, monkeypatch, oidc_enabled, key_arn):
    mode("HS256", None)
    monkeypatch.setattr(settings, "OIDC_PROVIDER_ENABLED", oidc_enabled)
    monkeypatch.setattr(settings, "OIDC_SIGNING_KEY_ARN", key_arn)
    for path in (JWKS_PATH, "/herm-auth/.well-known/openid-configuration"):
        new = await _get(path)
        old = await _get(path, app=oidc_stub.frozen)
        assert (new.status_code, new.content, new.headers.get("cache-control")) == (
            old.status_code, old.content, old.headers.get("cache-control"),
        ), path


@pytest.mark.asyncio
async def test_jwks_includes_access_token_keys_alongside_oidc_keys(mode, oidc_stub, monkeypatch, rsa_old, rsa_new):
    monkeypatch.setattr(settings, "OIDC_PROVIDER_ENABLED", True)
    monkeypatch.setattr(settings, "OIDC_SIGNING_KEY_ARN", "arn:aws:kms:eu-central-1:0:key/test")
    mode("HS256", _keyset_json("at-new", {"at-old": rsa_old, "at-new": rsa_new}))
    resp = await _get(JWKS_PATH)
    assert resp.status_code == 200
    assert resp.headers["cache-control"] == "public, max-age=3600"  # same as today
    keys = resp.json()["keys"]
    assert keys[0] == oidc_stub.jwks["keys"][0]  # OIDC key first, untouched
    access = keys[1:]
    assert [k["kid"] for k in access] == ["at-old", "at-new"]
    for k in access:
        assert set(k) == {"kty", "use", "alg", "kid", "n", "e"}  # no private parts
        assert (k["kty"], k["use"], k["alg"]) == ("RSA", "sig", "RS256")
    assert len({k["kid"] for k in keys}) == len(keys)  # no kid collisions
    # discovery document unchanged
    disc = await _get("/herm-auth/.well-known/openid-configuration")
    disc_main = await _get("/herm-auth/.well-known/openid-configuration", app=oidc_stub.frozen)
    assert disc.content == disc_main.content


@pytest.mark.asyncio
async def test_jwks_serves_access_keys_even_when_oidc_disabled(mode, oidc_stub, monkeypatch, rsa_old):
    monkeypatch.setattr(settings, "OIDC_PROVIDER_ENABLED", False)
    monkeypatch.setattr(settings, "OIDC_SIGNING_KEY_ARN", None)
    mode("RS256", _keyset_json("at-old", {"at-old": rsa_old}))
    resp = await _get(JWKS_PATH)
    assert resp.status_code == 200
    assert [k["kid"] for k in resp.json()["keys"]] == ["at-old"]


@pytest.mark.asyncio
async def test_jwks_over_plain_internal_http_and_token_verifies_against_it(mode, oidc_stub, monkeypatch, rsa_old):
    # Verifiers fetch http://prod-auth:8000/herm-auth/.well-known/jwks.json via Service Connect.
    monkeypatch.setattr(settings, "OIDC_PROVIDER_ENABLED", True)
    monkeypatch.setattr(settings, "OIDC_SIGNING_KEY_ARN", "arn:aws:kms:eu-central-1:0:key/test")
    mode("RS256", _keyset_json("at-old", {"at-old": rsa_old}))
    resp = await _get(JWKS_PATH, base_url="http://prod-auth:8000")
    assert resp.status_code == 200 and not resp.is_redirect
    assert resp.headers["content-type"].startswith("application/json")
    token = create_access_token(CONSUMER_USER)
    assert _verify_with_jwks(token, resp.json())["sub"] == "42"
    # an OIDC-kid lookup never resolves an access token and vice versa
    assert jwt.get_unverified_header(token)["kid"] != OIDC_KID


# --- OIDC tokens can never carry the internal access-token audience --------------------


def test_oidc_audiences_never_equal_access_token_audience():
    from app.models.oauth_client import OAuthClient
    from app.services.oidc_token_service import ACCESS_TOKEN_AUD

    assert ACCESS_TOKEN_AUD != settings.ACCESS_TOKEN_AUDIENCE
    assert all(OAuthClient.generate_client_id() != "herm-api" for _ in range(100))
    assert OAuthClient.CLIENT_ID_PREFIX == "herm_app_"


def test_oidc_token_builders_refuse_access_token_audience(monkeypatch):
    from app.services import oidc_token_service as ots

    signed = []
    monkeypatch.setattr(settings, "OIDC_PPID_SECRET", "ppid-test-secret-0123456789abcdef")  # gitleaks:allow
    monkeypatch.setattr(ots.oidc_key_service, "sign", lambda data, key_arn=None: signed.append(data) or b"sig")
    common = dict(kid="k", key_arn="arn", user_id="1", scopes=["openid"])

    with pytest.raises(ValueError):
        ots.oidc_token_service.build_id_token(client_id=settings.ACCESS_TOKEN_AUDIENCE, **common)
    monkeypatch.setattr(ots, "ACCESS_TOKEN_AUD", settings.ACCESS_TOKEN_AUDIENCE)
    with pytest.raises(ValueError):
        ots.oidc_token_service.build_access_token(client_id="herm_app_x", **common)
    assert signed == []  # refused before anything was sent to KMS

    monkeypatch.setattr(ots, "ACCESS_TOKEN_AUD", "herm-userinfo")
    ots.oidc_token_service.build_id_token(client_id="herm_app_x", **common)
    ots.oidc_token_service.build_access_token(client_id="herm_app_x", **common)
    assert len(signed) == 2


@pytest.mark.parametrize("audience", ["herm-userinfo", "herm_app_abc"])
def test_startup_rejects_access_audience_that_collides_with_oidc(mode, monkeypatch, audience):
    mode("HS256", None)
    monkeypatch.setattr(settings, "ACCESS_TOKEN_AUDIENCE", audience)
    with pytest.raises(ValueError):
        check_access_token_keys()


# --- (4) startup validation + rotation -----------------------------------------------


@pytest.mark.parametrize("raw", [None, "", "   "])
def test_hs256_without_keyset_starts_silently(mode, caplog, raw):
    mode("HS256", raw)
    with caplog.at_level(logging.DEBUG):
        check_access_token_keys()
    assert not [r for r in caplog.records if r.levelno >= logging.WARNING]


def test_hs256_with_invalid_keyset_logs_error_but_starts(mode, caplog, rsa_old):
    pem = _pem(rsa_old)
    mode("HS256", json.dumps({"active": "at-missing", "keys": {"at-old": pem}}))
    with caplog.at_level(logging.INFO):
        check_access_token_keys()
    assert "jwt.access_token_keys_invalid" in caplog.text
    assert "PRIVATE KEY" not in caplog.text


def test_rs256_startup_logs_kids_and_sizes_only(mode, caplog, rsa_old, rsa_new):
    mode("RS256", _keyset_json("at-new", {"at-old": rsa_old, "at-new": rsa_new}))
    with caplog.at_level(logging.INFO):
        check_access_token_keys()
    assert "jwt.access_token_keys_loaded" in caplog.text
    assert "at-new" in caplog.text and "2048" in caplog.text
    assert "PRIVATE KEY" not in caplog.text and "MII" not in caplog.text


def _invalid_keysets(rsa_old):
    weak = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    ec_key = ec.generate_private_key(ec.SECP256R1())
    good = _pem(rsa_old)
    return {
        "missing": None,
        "empty": "",
        "not-json": "{not json",
        "no-keys": json.dumps({"active": "at-a", "keys": {}}),
        "active-missing": json.dumps({"active": "at-b", "keys": {"at-a": good}}),
        "no-active": json.dumps({"keys": {"at-a": good}}),
        "bad-kid-prefix": json.dumps({"active": "k1", "keys": {"k1": good}}),
        "weak-1024": json.dumps({"active": "at-a", "keys": {"at-a": _pem(weak)}}),
        "not-rsa": json.dumps({"active": "at-a", "keys": {"at-a": _pem(ec_key)}}),
        "garbage-pem": json.dumps({"active": "at-a", "keys": {"at-a": "-----BEGIN nope"}}),
        "public-only": json.dumps({"active": "at-a", "keys": {"at-a": rsa_old.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()}}),
    }


def test_rs256_startup_fails_fast_on_invalid_keyset(mode, rsa_old):
    for name, raw in _invalid_keysets(rsa_old).items():
        mode("RS256", raw)
        with pytest.raises(ValueError) as exc:
            check_access_token_keys()
        assert "PRIVATE KEY" not in str(exc.value), name
        assert "MII" not in str(exc.value), name


@pytest.mark.asyncio
async def test_lifespan_refuses_to_start_in_rs256_without_keys(mode):
    from app.main import app, lifespan

    mode("RS256", None)
    with pytest.raises(ValueError):
        async with lifespan(app):
            pass


def test_rs256_signing_without_keyset_raises_instead_of_falling_back(mode):
    mode("RS256", None)
    with pytest.raises(Exception):
        create_access_token(CONSUMER_USER)


def test_rotation_old_kid_token_verifies_while_new_key_signs(mode, rsa_old, rsa_new):
    mode("RS256", _keyset_json("at-old", {"at-old": rsa_old}))
    old_token = create_access_token(CONSUMER_USER)

    # rotate: add new key, switch active, keep old for verification
    mode("RS256", _keyset_json("at-new", {"at-old": rsa_old, "at-new": rsa_new}))
    jwks = AccessTokenKeySet.from_json(settings.ACCESS_TOKEN_SIGNING_KEYS).public_jwks()
    new_token = create_access_token(CONSUMER_USER)
    assert jwt.get_unverified_header(new_token)["kid"] == "at-new"
    assert _verify_with_jwks(old_token, jwks)["sub"] == "42"
    assert _verify_with_jwks(new_token, jwks)["sub"] == "42"
    assert security_service.decode_token(old_token)["sub"] == "42"

    # later: drop the old key
    mode("RS256", _keyset_json("at-new", {"at-new": rsa_new}))
    jwks = AccessTokenKeySet.from_json(settings.ACCESS_TOKEN_SIGNING_KEYS).public_jwks()
    with pytest.raises(jwt.InvalidTokenError):
        _verify_with_jwks(old_token, jwks)
    assert security_service.decode_token(old_token) is None
    assert security_service.decode_token(new_token)["sub"] == "42"


def test_keyset_repr_never_contains_key_material(rsa_old):
    ks = AccessTokenKeySet.from_json(_keyset_json("at-old", {"at-old": rsa_old}))
    assert "PRIVATE" not in repr(ks) and "MII" not in repr(ks)
    assert ks.active_kid == "at-old" and ks.key_bits == {"at-old": 2048}
    assert access_token_keys.MIN_RSA_KEY_BITS == 2048


# --- operator helper script ------------------------------------------------------------


def _run_script(*args, stdin=None):
    return subprocess.run(
        [sys.executable, str(REPO_ROOT / "scripts" / "generate_access_token_keypair.py"), *args],
        input=stdin, capture_output=True, text=True, check=True, cwd=REPO_ROOT,
    )


def test_generator_prints_only_a_valid_keyset():
    out = _run_script("--bits", "2048").stdout
    keyset = json.loads(out)  # stdout is exactly one JSON document
    assert set(keyset) == {"active", "keys"} and list(keyset["keys"]) == [keyset["active"]]
    ks = AccessTokenKeySet.from_json(out)
    assert ks.active_kid.startswith("at-") and ks.key_bits[ks.active_kid] == 2048


def test_generator_two_phase_rotation():
    first = _run_script("--bits", "2048").stdout
    old_kid = json.loads(first)["active"]

    # phase A: publish new key, old stays active
    phase_a = json.loads(_run_script("--bits", "2048", "--add-to", "-", "--no-activate", stdin=first).stdout)
    (new_kid,) = set(phase_a["keys"]) - {old_kid}
    assert phase_a["active"] == old_kid
    assert phase_a["keys"][old_kid] == json.loads(first)["keys"][old_kid]
    AccessTokenKeySet.from_json(json.dumps(phase_a))

    # phase B: activate new key
    phase_b = json.loads(_run_script("--add-to", "-", "--no-new", "--set-active", new_kid, stdin=json.dumps(phase_a)).stdout)
    assert phase_b["active"] == new_kid and set(phase_b["keys"]) == {old_kid, new_kid}

    # phase C: drop old key; dropping the active key is refused
    phase_c = json.loads(_run_script("--add-to", "-", "--no-new", "--drop", old_kid, stdin=json.dumps(phase_b)).stdout)
    assert phase_c == {"active": new_kid, "keys": {new_kid: phase_a["keys"][new_kid]}}
    with pytest.raises(subprocess.CalledProcessError):
        _run_script("--add-to", "-", "--no-new", "--drop", new_kid, stdin=json.dumps(phase_c))
