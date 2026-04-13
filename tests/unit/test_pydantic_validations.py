"""
Tests for Pydantic input validation gaps.

Reproduces two bugs:
  1. UserLogin.password has no max_length — arbitrarily large payloads accepted.
  2. language field is a free string — injection values like SQL/template
     fragments pass through to SQS and email templates.
"""

import pytest
from pydantic import ValidationError

from app.schemas.user import UserLogin, UserSignup, ForgotPasswordRequest


# ---------------------------------------------------------------------------
# BUG 1 — UserLogin.password missing max_length
# ---------------------------------------------------------------------------

class TestLoginPasswordValidation:

    @pytest.mark.unit
    def test_login_rejects_oversized_password(self):
        """
        BUG: UserLogin.password has no max_length constraint.
        A 10 000-char password payload is accepted, wasting CPU on bcrypt.

        FIX: Add max_length=100 (matching UserSignup) to UserLogin.password.
        """
        with pytest.raises(ValidationError) as exc_info:
            UserLogin(email="test@example.com", password="x" * 10_000)

        errors = exc_info.value.errors()
        password_errors = [e for e in errors if "password" in str(e.get("loc", ""))]
        assert password_errors, (
            "BUG: UserLogin accepted a 10 000-char password. "
            "max_length constraint is missing."
        )

    @pytest.mark.unit
    def test_login_accepts_valid_password(self):
        """Passwords within the allowed range must still be accepted."""
        user = UserLogin(email="test@example.com", password="ValidPass123")
        assert user.password == "ValidPass123"

    @pytest.mark.unit
    def test_login_rejects_empty_password(self):
        """Empty password must be rejected (min_length=1 at minimum)."""
        with pytest.raises(ValidationError):
            UserLogin(email="test@example.com", password="")


# ---------------------------------------------------------------------------
# BUG 2 — language field accepts arbitrary strings
# ---------------------------------------------------------------------------

INVALID_LANGUAGES = [
    "'; DROP TABLE users--",          # SQL injection
    "<script>alert(1)</script>",      # XSS
    "en" * 100,                       # Oversized
    "../../../etc/passwd",            # Path traversal
    "{{7*7}}",                        # Template injection
]

VALID_LANGUAGES = ["en", "tr", "de", "fr", "es"]


class TestLanguageFieldValidation:

    @pytest.mark.unit
    @pytest.mark.parametrize("bad_lang", INVALID_LANGUAGES)
    def test_signup_rejects_invalid_language(self, bad_lang: str):
        """
        BUG: language is Optional[str] with no validation.
        Malicious values flow directly into SQS messages and email templates.

        FIX: Validate language against an allowed list or enforce
        max_length=10 + regex pattern ^[a-z]{2,5}$.
        """
        with pytest.raises(ValidationError) as exc_info:
            UserSignup(
                email="test@example.com",
                password="ValidPass123",
                language=bad_lang,
            )

        errors = exc_info.value.errors()
        lang_errors = [e for e in errors if "language" in str(e.get("loc", ""))]
        assert lang_errors, (
            f"BUG: UserSignup accepted invalid language={bad_lang!r}. "
            "No validation on the language field."
        )

    @pytest.mark.unit
    @pytest.mark.parametrize("good_lang", VALID_LANGUAGES)
    def test_signup_accepts_valid_language(self, good_lang: str):
        """Valid ISO language codes must be accepted."""
        user = UserSignup(
            email="test@example.com",
            password="ValidPass123",
            language=good_lang,
        )
        assert user.language == good_lang

    @pytest.mark.unit
    @pytest.mark.parametrize("bad_lang", INVALID_LANGUAGES)
    def test_forgot_password_rejects_invalid_language(self, bad_lang: str):
        """ForgotPasswordRequest.language must enforce the same constraint."""
        with pytest.raises(ValidationError) as exc_info:
            ForgotPasswordRequest(email="test@example.com", language=bad_lang)

        errors = exc_info.value.errors()
        lang_errors = [e for e in errors if "language" in str(e.get("loc", ""))]
        assert lang_errors, (
            f"BUG: ForgotPasswordRequest accepted invalid language={bad_lang!r}."
        )


# ---------------------------------------------------------------------------
# BUG 3 - signup drops referral code metadata
# ---------------------------------------------------------------------------


class TestReferralCodeValidation:

    @pytest.mark.unit
    def test_signup_keeps_referral_code(self):
        """
        BUG: signup payload has no referral_code field, so referral attribution is lost.

        FIX: UserSignup must accept optional referral_code and preserve it.
        """
        signup = UserSignup(
            email="test@example.com",
            password="ValidPass123",
            referral_code="ABC123",
        )

        assert signup.referral_code == "ABC123"

