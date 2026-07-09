"""Integration tests for email OTP verification API endpoints"""

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession
from datetime import datetime, timedelta

from app.models.user import User
from app.models.email_otp_code import EmailOtpCode, OTP_MAX_ATTEMPTS
from app.core.security import security_service


@pytest.mark.asyncio
class TestSignupCreatesOtpCode:
    """Signup should automatically create an EmailOtpCode row for the new
    user, so the client can immediately prompt for OTP verification without
    a separate /send-otp call. Bug report: signing up does not insert a row
    into email_otp_codes."""

    async def test_signup_creates_otp_code_for_new_user(
        self,
        client: AsyncClient,
        db_session: AsyncSession,
    ):
        response = await client.post(
            "/herm-auth/v1/public/auth/signup",
            json={
                "email": "newsignupuser@example.com",
                "password": "TestPassword123!",
            },
        )

        assert response.status_code == 201

        from sqlalchemy import select
        result = await db_session.execute(
            select(User).where(User.email == "newsignupuser@example.com")
        )
        user = result.scalar_one_or_none()
        assert user is not None

        otp_result = await db_session.execute(
            select(EmailOtpCode).where(EmailOtpCode.user_id == user.id)
        )
        otp_code = otp_result.scalar_one_or_none()

        assert otp_code is not None
        assert otp_code.is_used is False
        assert otp_code.is_valid() is True


@pytest.mark.asyncio
class TestSendOtpEndpoint:
    """Tests for /herm-auth/v1/public/auth/send-otp endpoint"""

    async def test_send_otp_with_existing_unverified_user_returns_200(
        self,
        client: AsyncClient,
        test_user: User,
    ):
        response = await client.post(
            "/herm-auth/v1/public/auth/send-otp",
            json={"email": test_user.email},
        )

        assert response.status_code == 200
        data = response.json()
        assert "message" in data

    async def test_send_otp_with_nonexistent_user_returns_200(self, client: AsyncClient):
        """Same response for unknown email, to avoid email enumeration."""
        response = await client.post(
            "/herm-auth/v1/public/auth/send-otp",
            json={"email": "nonexistent@example.com"},
        )

        assert response.status_code == 200

    async def test_send_otp_with_invalid_email_returns_422(self, client: AsyncClient):
        response = await client.post(
            "/herm-auth/v1/public/auth/send-otp",
            json={"email": "not-an-email"},
        )

        assert response.status_code == 422

    async def test_send_otp_creates_otp_code(
        self,
        client: AsyncClient,
        db_session: AsyncSession,
        test_user: User,
    ):
        response = await client.post(
            "/herm-auth/v1/public/auth/send-otp",
            json={"email": test_user.email},
        )

        assert response.status_code == 200

        from sqlalchemy import select
        result = await db_session.execute(
            select(EmailOtpCode).where(EmailOtpCode.user_id == test_user.id)
        )
        code = result.scalar_one_or_none()

        assert code is not None
        assert code.is_used is False
        assert code.is_valid() is True

    async def test_send_otp_revokes_old_codes(
        self,
        client: AsyncClient,
        db_session: AsyncSession,
        test_user: User,
    ):
        old_code = EmailOtpCode(
            code_hash=security_service.get_password_hash("111111"),
            user_id=test_user.id,
            expires_at=datetime.utcnow() + timedelta(minutes=10),
            is_used=False,
        )
        db_session.add(old_code)
        await db_session.commit()

        response = await client.post(
            "/herm-auth/v1/public/auth/send-otp",
            json={"email": test_user.email},
        )

        assert response.status_code == 200

        await db_session.refresh(old_code)
        assert old_code.revoked_at is not None

    async def test_send_otp_rate_limit(self, client: AsyncClient, test_user: User):
        for _ in range(3):
            response = await client.post(
                "/herm-auth/v1/public/auth/send-otp",
                json={"email": test_user.email},
            )
            assert response.status_code == 200

        response = await client.post(
            "/herm-auth/v1/public/auth/send-otp",
            json={"email": test_user.email},
        )

        assert response.status_code == 429


@pytest.mark.asyncio
class TestVerifyOtpEndpoint:
    """Tests for /herm-auth/v1/public/auth/verify-otp endpoint"""

    async def test_verify_otp_with_valid_code_returns_200_and_tokens(
        self,
        client: AsyncClient,
        db_session: AsyncSession,
        test_user: User,
    ):
        code_plaintext = "123456"
        otp_code = EmailOtpCode(
            code_hash=security_service.get_password_hash(code_plaintext),
            user_id=test_user.id,
            expires_at=datetime.utcnow() + timedelta(minutes=10),
            is_used=False,
        )
        db_session.add(otp_code)
        await db_session.commit()

        response = await client.post(
            "/herm-auth/v1/public/auth/verify-otp",
            json={"email": test_user.email, "code": code_plaintext},
        )

        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert "refresh_token" in data
        assert data["expires_in"] > 0

    async def test_verify_otp_marks_user_verified_and_code_used(
        self,
        client: AsyncClient,
        db_session: AsyncSession,
        test_user: User,
    ):
        code_plaintext = "654321"
        otp_code = EmailOtpCode(
            code_hash=security_service.get_password_hash(code_plaintext),
            user_id=test_user.id,
            expires_at=datetime.utcnow() + timedelta(minutes=10),
            is_used=False,
        )
        db_session.add(otp_code)
        await db_session.commit()

        response = await client.post(
            "/herm-auth/v1/public/auth/verify-otp",
            json={"email": test_user.email, "code": code_plaintext},
        )

        assert response.status_code == 200

        await db_session.refresh(test_user)
        await db_session.refresh(otp_code)
        assert test_user.is_verified is True
        assert otp_code.is_used is True
        assert otp_code.used_at is not None

    async def test_verify_otp_with_wrong_code_returns_400_and_increments_attempts(
        self,
        client: AsyncClient,
        db_session: AsyncSession,
        test_user: User,
    ):
        otp_code = EmailOtpCode(
            code_hash=security_service.get_password_hash("123456"),
            user_id=test_user.id,
            expires_at=datetime.utcnow() + timedelta(minutes=10),
            is_used=False,
        )
        db_session.add(otp_code)
        await db_session.commit()

        response = await client.post(
            "/herm-auth/v1/public/auth/verify-otp",
            json={"email": test_user.email, "code": "000000"},
        )

        assert response.status_code == 400

        await db_session.refresh(otp_code)
        assert otp_code.attempt_count == 1
        assert otp_code.is_used is False

    async def test_verify_otp_locks_out_after_five_wrong_attempts(
        self,
        client: AsyncClient,
        db_session: AsyncSession,
        test_user: User,
    ):
        otp_code = EmailOtpCode(
            code_hash=security_service.get_password_hash("123456"),
            user_id=test_user.id,
            expires_at=datetime.utcnow() + timedelta(minutes=10),
            is_used=False,
        )
        db_session.add(otp_code)
        await db_session.commit()

        for _ in range(OTP_MAX_ATTEMPTS):
            response = await client.post(
                "/herm-auth/v1/public/auth/verify-otp",
                json={"email": test_user.email, "code": "000000"},
            )
            assert response.status_code == 400

        # 6th attempt (even with the correct code) is rejected: locked out.
        response = await client.post(
            "/herm-auth/v1/public/auth/verify-otp",
            json={"email": test_user.email, "code": "123456"},
        )

        assert response.status_code == 429

        await db_session.refresh(otp_code)
        assert otp_code.attempt_count == OTP_MAX_ATTEMPTS
        assert otp_code.is_used is False

    async def test_verify_otp_with_expired_code_returns_400(
        self,
        client: AsyncClient,
        db_session: AsyncSession,
        test_user: User,
    ):
        otp_code = EmailOtpCode(
            code_hash=security_service.get_password_hash("123456"),
            user_id=test_user.id,
            expires_at=datetime.utcnow() - timedelta(minutes=1),
            is_used=False,
        )
        db_session.add(otp_code)
        await db_session.commit()

        response = await client.post(
            "/herm-auth/v1/public/auth/verify-otp",
            json={"email": test_user.email, "code": "123456"},
        )

        assert response.status_code == 400

    async def test_verify_otp_with_no_active_code_returns_400(
        self,
        client: AsyncClient,
        test_user: User,
    ):
        response = await client.post(
            "/herm-auth/v1/public/auth/verify-otp",
            json={"email": test_user.email, "code": "123456"},
        )

        assert response.status_code == 400

    async def test_verify_otp_with_nonexistent_user_returns_400(self, client: AsyncClient):
        response = await client.post(
            "/herm-auth/v1/public/auth/verify-otp",
            json={"email": "nonexistent@example.com", "code": "123456"},
        )

        assert response.status_code == 400

    async def test_verify_otp_with_malformed_code_returns_422(
        self,
        client: AsyncClient,
        test_user: User,
    ):
        response = await client.post(
            "/herm-auth/v1/public/auth/verify-otp",
            json={"email": test_user.email, "code": "12"},
        )

        assert response.status_code == 422

    async def test_verify_otp_resend_invalidates_previous_code(
        self,
        client: AsyncClient,
        db_session: AsyncSession,
        test_user: User,
    ):
        """Sending a new code (resend) must revoke the old one, so it can no
        longer be used even if the user still has it."""
        old_plaintext = "111111"
        old_code = EmailOtpCode(
            code_hash=security_service.get_password_hash(old_plaintext),
            user_id=test_user.id,
            expires_at=datetime.utcnow() + timedelta(minutes=10),
            is_used=False,
        )
        db_session.add(old_code)
        await db_session.commit()

        resend_response = await client.post(
            "/herm-auth/v1/public/auth/send-otp",
            json={"email": test_user.email},
        )
        assert resend_response.status_code == 200

        response = await client.post(
            "/herm-auth/v1/public/auth/verify-otp",
            json={"email": test_user.email, "code": old_plaintext},
        )

        assert response.status_code == 400
