"""
Tests for PII leakage in log output.

OWASP ASVS 7.1.1: The application must not log sensitive data such as
passwords, session tokens, or PII that could expose personal information.

Reproduces: user.email logged in plaintext in user_service.py and
reset_password_service.py — should use user.id (UUID) instead.
"""

import logging
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_user(email: str = "victim@example.com") -> MagicMock:
    user = MagicMock()
    user.id = uuid4()
    user.email = email
    user.hashed_password = "hashed"
    user.is_active = True
    user.is_verified = False
    user.role = "user"
    return user


# ---------------------------------------------------------------------------
# BUG: user_service — email logged in signup path
# ---------------------------------------------------------------------------

class TestUserServiceLogging:

    @pytest.mark.asyncio
    @pytest.mark.unit
    async def test_signup_does_not_log_email(self):
        """
        BUG: user_service.py:61  logger.info(f"...user: {user.email}...")
             user_service.py:71  logger.error(f"...user {user.email}...")

        FIX: Replace user.email with str(user.id) in both log calls.
        """
        from app.services.user_service import UserService
        from app.schemas.user import UserSignup

        mock_db = AsyncMock()
        service = UserService(mock_db)

        user = _make_user("victim@example.com")
        mock_repo = AsyncMock()
        mock_repo.get_by_email.return_value = None
        mock_repo.create.return_value = user
        service.user_repo = mock_repo

        mock_token_service = AsyncMock()
        mock_token_service.create_refresh_token.return_value = MagicMock(token="rt")
        service.token_service = mock_token_service

        mock_verification = AsyncMock()
        mock_verification.send_verification_email = AsyncMock(
            side_effect=Exception("smtp error")   # forces fallback error log path
        )
        service.verification_service = mock_verification

        captured_logs: list[str] = []

        class EmailCapture(logging.Handler):
            def emit(self, record):
                captured_logs.append(record.getMessage())

        handler = EmailCapture()
        logger = logging.getLogger("app.services.user_service")
        logger.addHandler(handler)
        logger.setLevel(logging.DEBUG)

        try:
            with patch("app.services.user_service.create_access_token", return_value="at"):
                await service.signup(
                    UserSignup(email="victim@example.com", password="ValidPass1"),
                    background_tasks=None,
                )
        except Exception:
            pass
        finally:
            logger.removeHandler(handler)

        email = "victim@example.com"
        pii_logs = [msg for msg in captured_logs if email in msg]

        assert not pii_logs, (
            f"BUG: Email address found in log output:\n"
            + "\n".join(f"  {m}" for m in pii_logs)
            + "\nFIX: Replace user.email with str(user.id) in log statements."
        )


# ---------------------------------------------------------------------------
# BUG: reset_password_service — email logged in two places
# ---------------------------------------------------------------------------

class TestResetPasswordServiceLogging:

    @pytest.mark.asyncio
    @pytest.mark.unit
    async def test_reset_password_does_not_log_email_on_success(self):
        """
        BUG: reset_password_service.py:115
             logger.info(f"Password successfully reset for user: {user.email} ...")

        FIX: Replace user.email with str(user.id).
        """
        from app.services.reset_password_service import ResetPasswordService

        user = _make_user("victim@example.com")

        mock_reset_token = MagicMock()
        mock_reset_token.user_id = user.id
        mock_reset_token.is_valid.return_value = True
        mock_reset_token.is_expired.return_value = False
        mock_reset_token.is_used = False

        mock_db = AsyncMock()
        mock_db.execute = AsyncMock()

        # verify_reset_token result
        scalar1 = MagicMock()
        scalar1.scalar_one_or_none.return_value = mock_reset_token
        # get user result
        scalar2 = MagicMock()
        scalar2.scalar_one_or_none.return_value = user

        mock_db.execute.side_effect = [scalar1, scalar2]
        mock_db.add = MagicMock()
        mock_db.commit = AsyncMock()

        service = ResetPasswordService(mock_db)
        mock_ts = AsyncMock()
        service.token_service = mock_ts

        captured_logs: list[str] = []

        class EmailCapture(logging.Handler):
            def emit(self, record):
                captured_logs.append(record.getMessage())

        handler = EmailCapture()
        logger = logging.getLogger("app.services.reset_password_service")
        logger.addHandler(handler)
        logger.setLevel(logging.DEBUG)

        try:
            await service.reset_password(
                token="valid-token",
                new_password="NewPass123!",
                ip_address="1.2.3.4",
            )
        finally:
            logger.removeHandler(handler)

        email = "victim@example.com"
        pii_logs = [msg for msg in captured_logs if email in msg]

        assert not pii_logs, (
            f"BUG: Email address found in log output:\n"
            + "\n".join(f"  {m}" for m in pii_logs)
            + "\nFIX: Replace user.email with str(user.id) in log statements."
        )

    @pytest.mark.asyncio
    @pytest.mark.unit
    async def test_reset_password_does_not_log_email_for_inactive_user(self):
        """
        BUG: reset_password_service.py:91
             logger.warning(f"Password reset attempted for inactive user: {user.email}")

        FIX: Replace user.email with str(user.id).
        """
        from app.services.reset_password_service import ResetPasswordService
        from fastapi import HTTPException

        user = _make_user("victim@example.com")
        user.is_active = False  # triggers the warning log

        mock_reset_token = MagicMock()
        mock_reset_token.user_id = user.id
        mock_reset_token.is_valid.return_value = True
        mock_reset_token.is_expired.return_value = False
        mock_reset_token.is_used = False

        mock_db = AsyncMock()
        scalar1 = MagicMock()
        scalar1.scalar_one_or_none.return_value = mock_reset_token
        scalar2 = MagicMock()
        scalar2.scalar_one_or_none.return_value = user
        mock_db.execute.side_effect = [scalar1, scalar2]

        service = ResetPasswordService(mock_db)

        captured_logs: list[str] = []

        class EmailCapture(logging.Handler):
            def emit(self, record):
                captured_logs.append(record.getMessage())

        handler = EmailCapture()
        logger = logging.getLogger("app.services.reset_password_service")
        logger.addHandler(handler)
        logger.setLevel(logging.DEBUG)

        try:
            await service.reset_password(
                token="valid-token",
                new_password="NewPass123!",
            )
        except HTTPException:
            pass
        finally:
            logger.removeHandler(handler)

        email = "victim@example.com"
        pii_logs = [msg for msg in captured_logs if email in msg]

        assert not pii_logs, (
            f"BUG: Email address found in log output:\n"
            + "\n".join(f"  {m}" for m in pii_logs)
            + "\nFIX: Replace user.email with str(user.id) in log statements."
        )
