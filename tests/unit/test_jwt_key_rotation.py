"""Zero-downtime HS256 key rotation: multi-key verification, kid, weak-key guard."""

import logging
from datetime import datetime, timedelta, timezone

import jwt
import pytest

from app.core import jwt_keys
from app.core.config import settings
from app.core.jwt_keys import HmacKeyRing, key_id
from app.core.security import security_service

OLD_KEY = "old-31-byte-legacy-signing-key!"  # gitleaks:allow
NEW_KEY = "new-strong-rotation-key-0123456789abcdefghijklmnopqrstuvwxyz-ABCDEFGH"  # gitleaks:allow
OTHER_KEY = "attacker-controlled-key-0123456789abcdefghijklmnop"  # gitleaks:allow


def _claims(**extra):
    claims = {
        "sub": "user-1",
        "type": "access",
        "exp": datetime.now(timezone.utc) + timedelta(minutes=5),
    }
    claims.update(extra)
    return claims


def _legacy_token(secret, **extra):
    """A token as minted before kid support: no kid header."""
    return jwt.encode(_claims(**extra), secret, algorithm="HS256")


def _token_with_kid(secret, kid, **extra):
    return jwt.encode(_claims(**extra), secret, algorithm="HS256", headers={"kid": kid})


# --- HmacKeyRing --------------------------------------------------------------


def test_old_key_token_without_kid_verifies_with_single_key():
    ring = HmacKeyRing(OLD_KEY)
    assert ring.decode(_legacy_token(OLD_KEY))["sub"] == "user-1"


def test_signer_emits_kid_of_primary_key():
    ring = HmacKeyRing(NEW_KEY, OLD_KEY)
    token = ring.encode(_claims())
    assert jwt.get_unverified_header(token)["kid"] == key_id(NEW_KEY)
    assert ring.decode(token)["sub"] == "user-1"


def test_token_signed_by_second_configured_key_verifies():
    ring = HmacKeyRing(OLD_KEY, NEW_KEY)
    assert ring.decode(_token_with_kid(NEW_KEY, key_id(NEW_KEY)))["sub"] == "user-1"
    # and without kid (fallback tries every key)
    assert ring.decode(_legacy_token(NEW_KEY))["sub"] == "user-1"


def test_unknown_kid_is_rejected_even_if_signature_is_valid():
    ring = HmacKeyRing(OLD_KEY, NEW_KEY)
    with pytest.raises(jwt.InvalidTokenError):
        ring.decode(_token_with_kid(OLD_KEY, "not-a-known-kid"))


def test_wrong_key_is_rejected():
    ring = HmacKeyRing(OLD_KEY, NEW_KEY)
    with pytest.raises(jwt.InvalidSignatureError):
        ring.decode(_legacy_token(OTHER_KEY))
    # forged token claiming a known kid
    with pytest.raises(jwt.InvalidSignatureError):
        ring.decode(_token_with_kid(OTHER_KEY, key_id(OLD_KEY)))


def test_require_kid_rejects_legacy_tokens():
    ring = HmacKeyRing(OLD_KEY, require_kid=True)
    with pytest.raises(jwt.InvalidTokenError):
        ring.decode(_legacy_token(OLD_KEY))
    assert ring.decode(_token_with_kid(OLD_KEY, key_id(OLD_KEY)))["sub"] == "user-1"


def test_expired_token_is_rejected_not_retried_with_other_keys():
    ring = HmacKeyRing(OLD_KEY, NEW_KEY)
    expired = _legacy_token(OLD_KEY, exp=datetime.now(timezone.utc) - timedelta(minutes=1))
    with pytest.raises(jwt.ExpiredSignatureError):
        ring.decode(expired)


def test_rotation_sequence_never_rejects_a_live_token():
    # (a) everyone on OLD only
    signer_a = HmacKeyRing(OLD_KEY)
    # (b) verifiers accept OLD + NEW, signer still OLD
    verifier_b = HmacKeyRing(OLD_KEY, NEW_KEY)
    # (c) signer switches to NEW, keeps OLD as secondary
    signer_c = HmacKeyRing(NEW_KEY, OLD_KEY)
    # (d) everyone on NEW only
    verifier_d = HmacKeyRing(NEW_KEY)

    token_a = signer_a.encode(_claims())
    token_c = signer_c.encode(_claims())
    assert verifier_b.decode(token_a)["sub"] == "user-1"
    assert verifier_b.decode(token_c)["sub"] == "user-1"
    assert signer_c.decode(token_a)["sub"] == "user-1"
    assert verifier_d.decode(token_c)["sub"] == "user-1"
    with pytest.raises(jwt.InvalidTokenError):
        verifier_d.decode(token_a)  # old key retired


def test_weak_key_logs_error_but_does_not_raise_by_default(caplog):
    ring = HmacKeyRing(OLD_KEY)
    with caplog.at_level(logging.ERROR, logger=jwt_keys.logger.name):
        weak = ring.check_key_strength(enforce=False)
    assert weak == [key_id(OLD_KEY)]
    assert "jwt.weak_hmac_key" in caplog.text
    assert OLD_KEY not in caplog.text


def test_weak_key_raises_when_enforced():
    with pytest.raises(ValueError):
        HmacKeyRing(OLD_KEY).check_key_strength(enforce=True)


def test_strong_keys_pass_enforcement():
    assert HmacKeyRing(NEW_KEY).check_key_strength(enforce=True) == []


# --- SecurityService wiring ----------------------------------------------------


@pytest.fixture
def keys(monkeypatch):
    def configure(primary, secondary=None, require_kid=False):
        monkeypatch.setattr(settings, "SECRET_KEY", primary)
        monkeypatch.setattr(settings, "JWT_SECONDARY_SECRET_KEY", secondary)
        monkeypatch.setattr(settings, "JWT_REQUIRE_KID", require_kid)

    return configure


def test_settings_defaults_keep_single_key_behaviour():
    assert settings.JWT_SECONDARY_SECRET_KEY in (None, "")
    assert settings.JWT_REQUIRE_KID is False
    assert settings.JWT_ENFORCE_MIN_KEY_LENGTH is False


def test_access_token_carries_kid_and_verifies(keys):
    keys(OLD_KEY)
    token = security_service.create_access_token({"sub": "user-1"})
    assert jwt.get_unverified_header(token)["kid"] == key_id(OLD_KEY)
    assert security_service.decode_token(token)["sub"] == "user-1"


def test_decode_token_accepts_legacy_and_secondary_and_rejects_unknown(keys):
    keys(NEW_KEY, OLD_KEY)
    assert security_service.decode_token(_legacy_token(OLD_KEY))["sub"] == "user-1"
    assert security_service.decode_token(_token_with_kid(OLD_KEY, key_id(OLD_KEY)))
    assert security_service.decode_token(_token_with_kid(OLD_KEY, "bogus")) is None
    assert security_service.decode_token(_legacy_token(OTHER_KEY)) is None
    assert security_service.decode_token("not-a-jwt") is None


def test_signer_switch_signs_with_primary(keys):
    keys(NEW_KEY, OLD_KEY)
    token = security_service.create_access_token({"sub": "user-1"})
    assert jwt.get_unverified_header(token)["kid"] == key_id(NEW_KEY)
    jwt.decode(token, NEW_KEY, algorithms=["HS256"])  # verifies with NEW alone


def test_check_jwt_keys_respects_enforce_setting(keys, monkeypatch):
    from app.core.security import check_jwt_keys

    keys(OLD_KEY)
    monkeypatch.setattr(settings, "JWT_ENFORCE_MIN_KEY_LENGTH", False)
    check_jwt_keys()  # warning only
    monkeypatch.setattr(settings, "JWT_ENFORCE_MIN_KEY_LENGTH", True)
    with pytest.raises(ValueError):
        check_jwt_keys()
