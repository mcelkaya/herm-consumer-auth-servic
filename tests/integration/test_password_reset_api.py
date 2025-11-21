"""Integration tests for password reset API endpoints"""

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession
from datetime import datetime, timedelta

from app.models.user import User
from app.models.password_reset_token import PasswordResetToken
from app.core.security import security_service


@pytest.mark.asyncio
class TestForgotPasswordEndpoint:
    """Tests for /api/v1/auth/forgot-password endpoint"""

    async def test_forgot_password_with_existing_user_returns_200(
        self,
        client: AsyncClient,
        test_user: User
    ):
        """Test forgot password with existing user returns 200"""
        response = await client.post(
            "/api/v1/auth/forgot-password",
            json={"email": test_user.email}
        )

        assert response.status_code == 200
        data = response.json()
        assert "message" in data
        assert "password reset link has been sent" in data["message"].lower()

    async def test_forgot_password_with_nonexistent_user_returns_200(
        self,
        client: AsyncClient
    ):
        """Test forgot password with non-existent user still returns 200 (security)"""
        response = await client.post(
            "/api/v1/auth/forgot-password",
            json={"email": "nonexistent@example.com"}
        )

        assert response.status_code == 200
        data = response.json()
        assert "message" in data
        # Same message to prevent email enumeration
        assert "password reset link has been sent" in data["message"].lower()

    async def test_forgot_password_with_invalid_email_returns_422(
        self,
        client: AsyncClient
    ):
        """Test forgot password with invalid email format returns 422"""
        response = await client.post(
            "/api/v1/auth/forgot-password",
            json={"email": "not-an-email"}
        )

        assert response.status_code == 422

    async def test_forgot_password_creates_reset_token(
        self,
        client: AsyncClient,
        db_session: AsyncSession,
        test_user: User
    ):
        """Test that forgot password creates a password reset token"""
        response = await client.post(
            "/api/v1/auth/forgot-password",
            json={"email": test_user.email}
        )

        assert response.status_code == 200

        # Verify token was created in database
        from sqlalchemy import select
        result = await db_session.execute(
            select(PasswordResetToken).where(
                PasswordResetToken.user_id == test_user.id
            )
        )
        token = result.scalar_one_or_none()

        assert token is not None
        assert token.is_used is False
        assert token.is_valid() is True

    async def test_forgot_password_invalidates_old_tokens(
        self,
        client: AsyncClient,
        db_session: AsyncSession,
        test_user: User
    ):
        """Test that forgot password invalidates old unused tokens"""
        # Create an old token
        old_token = PasswordResetToken(
            token=PasswordResetToken.generate_token(),
            user_id=test_user.id,
            expires_at=datetime.utcnow() + timedelta(hours=24),
            is_used=False
        )
        db_session.add(old_token)
        await db_session.commit()

        # Request new token
        response = await client.post(
            "/api/v1/auth/forgot-password",
            json={"email": test_user.email}
        )

        assert response.status_code == 200

        # Verify old token is marked as used
        await db_session.refresh(old_token)
        assert old_token.is_used is True

    async def test_forgot_password_rate_limit(
        self,
        client: AsyncClient,
        test_user: User
    ):
        """Test that forgot password endpoint is rate limited"""
        # Make 3 requests (the limit)
        for _ in range(3):
            response = await client.post(
                "/api/v1/auth/forgot-password",
                json={"email": test_user.email}
            )
            assert response.status_code == 200

        # 4th request should be rate limited
        response = await client.post(
            "/api/v1/auth/forgot-password",
            json={"email": test_user.email}
        )

        assert response.status_code == 429
        data = response.json()
        assert "rate limit" in data["detail"].lower()


@pytest.mark.asyncio
class TestResetPasswordEndpoint:
    """Tests for /api/v1/auth/reset-password endpoint"""

    async def test_reset_password_with_valid_token_returns_200(
        self,
        client: AsyncClient,
        db_session: AsyncSession,
        test_user: User
    ):
        """Test reset password with valid token returns 200"""
        # Create valid token
        token = PasswordResetToken(
            token=PasswordResetToken.generate_token(),
            user_id=test_user.id,
            expires_at=datetime.utcnow() + timedelta(hours=1),
            is_used=False
        )
        db_session.add(token)
        await db_session.commit()

        response = await client.post(
            "/api/v1/auth/reset-password",
            json={
                "token": token.token,
                "new_password": "NewSecurePassword123!"
            }
        )

        assert response.status_code == 200
        data = response.json()
        assert "message" in data
        assert "reset successfully" in data["message"].lower()

    async def test_reset_password_with_invalid_token_returns_400(
        self,
        client: AsyncClient
    ):
        """Test reset password with invalid token returns 400"""
        response = await client.post(
            "/api/v1/auth/reset-password",
            json={
                "token": "invalid_token",
                "new_password": "NewSecurePassword123!"
            }
        )

        assert response.status_code == 400
        data = response.json()
        assert "invalid" in data["detail"].lower() or "expired" in data["detail"].lower()

    async def test_reset_password_with_expired_token_returns_400(
        self,
        client: AsyncClient,
        db_session: AsyncSession,
        test_user: User
    ):
        """Test reset password with expired token returns 400"""
        # Create expired token
        token = PasswordResetToken(
            token=PasswordResetToken.generate_token(),
            user_id=test_user.id,
            expires_at=datetime.utcnow() - timedelta(hours=1),  # Expired
            is_used=False
        )
        db_session.add(token)
        await db_session.commit()

        response = await client.post(
            "/api/v1/auth/reset-password",
            json={
                "token": token.token,
                "new_password": "NewSecurePassword123!"
            }
        )

        assert response.status_code == 400

    async def test_reset_password_with_used_token_returns_400(
        self,
        client: AsyncClient,
        db_session: AsyncSession,
        test_user: User
    ):
        """Test reset password with used token returns 400"""
        # Create used token
        token = PasswordResetToken(
            token=PasswordResetToken.generate_token(),
            user_id=test_user.id,
            expires_at=datetime.utcnow() + timedelta(hours=1),
            is_used=True  # Already used
        )
        db_session.add(token)
        await db_session.commit()

        response = await client.post(
            "/api/v1/auth/reset-password",
            json={
                "token": token.token,
                "new_password": "NewSecurePassword123!"
            }
        )

        assert response.status_code == 400

    async def test_reset_password_actually_changes_password(
        self,
        client: AsyncClient,
        db_session: AsyncSession,
        test_user: User
    ):
        """Test that reset password actually changes the user's password"""
        old_hashed_password = test_user.hashed_password

        # Create valid token
        token = PasswordResetToken(
            token=PasswordResetToken.generate_token(),
            user_id=test_user.id,
            expires_at=datetime.utcnow() + timedelta(hours=1),
            is_used=False
        )
        db_session.add(token)
        await db_session.commit()

        new_password = "NewSecurePassword123!"

        response = await client.post(
            "/api/v1/auth/reset-password",
            json={
                "token": token.token,
                "new_password": new_password
            }
        )

        assert response.status_code == 200

        # Verify password was changed
        await db_session.refresh(test_user)
        assert test_user.hashed_password != old_hashed_password

        # Verify new password works
        assert security_service.verify_password(new_password, test_user.hashed_password)

    async def test_reset_password_marks_token_as_used(
        self,
        client: AsyncClient,
        db_session: AsyncSession,
        test_user: User
    ):
        """Test that reset password marks token as used"""
        # Create valid token
        token = PasswordResetToken(
            token=PasswordResetToken.generate_token(),
            user_id=test_user.id,
            expires_at=datetime.utcnow() + timedelta(hours=1),
            is_used=False
        )
        db_session.add(token)
        await db_session.commit()

        response = await client.post(
            "/api/v1/auth/reset-password",
            json={
                "token": token.token,
                "new_password": "NewSecurePassword123!"
            }
        )

        assert response.status_code == 200

        # Verify token is marked as used
        await db_session.refresh(token)
        assert token.is_used is True
        assert token.used_at is not None

    async def test_reset_password_revokes_all_refresh_tokens(
        self,
        client: AsyncClient,
        db_session: AsyncSession,
        test_user: User
    ):
        """Test that reset password revokes all user's refresh tokens"""
        from app.models.refresh_token import RefreshToken

        # Create some refresh tokens
        refresh_token1 = RefreshToken(
            token=RefreshToken.generate_token(),
            user_id=test_user.id,
            expires_at=datetime.utcnow() + timedelta(days=30),
            is_revoked=False
        )
        refresh_token2 = RefreshToken(
            token=RefreshToken.generate_token(),
            user_id=test_user.id,
            expires_at=datetime.utcnow() + timedelta(days=30),
            is_revoked=False
        )
        db_session.add_all([refresh_token1, refresh_token2])

        # Create password reset token
        reset_token = PasswordResetToken(
            token=PasswordResetToken.generate_token(),
            user_id=test_user.id,
            expires_at=datetime.utcnow() + timedelta(hours=1),
            is_used=False
        )
        db_session.add(reset_token)
        await db_session.commit()

        # Reset password
        response = await client.post(
            "/api/v1/auth/reset-password",
            json={
                "token": reset_token.token,
                "new_password": "NewSecurePassword123!"
            }
        )

        assert response.status_code == 200

        # Verify all refresh tokens are revoked
        await db_session.refresh(refresh_token1)
        await db_session.refresh(refresh_token2)
        assert refresh_token1.is_revoked is True
        assert refresh_token2.is_revoked is True

    async def test_reset_password_with_weak_password_returns_422(
        self,
        client: AsyncClient,
        db_session: AsyncSession,
        test_user: User
    ):
        """Test reset password with weak password returns 422"""
        # Create valid token
        token = PasswordResetToken(
            token=PasswordResetToken.generate_token(),
            user_id=test_user.id,
            expires_at=datetime.utcnow() + timedelta(hours=1),
            is_used=False
        )
        db_session.add(token)
        await db_session.commit()

        # Try with password that's too short
        response = await client.post(
            "/api/v1/auth/reset-password",
            json={
                "token": token.token,
                "new_password": "short"  # Less than 8 characters
            }
        )

        assert response.status_code == 422

    async def test_reset_password_rate_limit(
        self,
        client: AsyncClient,
        db_session: AsyncSession,
        test_user: User
    ):
        """Test that reset password endpoint is rate limited"""
        # Create tokens for testing rate limit
        tokens = []
        for _ in range(6):  # Limit is 5
            token = PasswordResetToken(
                token=PasswordResetToken.generate_token(),
                user_id=test_user.id,
                expires_at=datetime.utcnow() + timedelta(hours=1),
                is_used=False
            )
            db_session.add(token)
            tokens.append(token)

        await db_session.commit()

        # Make 5 requests (the limit)
        for i in range(5):
            response = await client.post(
                "/api/v1/auth/reset-password",
                json={
                    "token": tokens[i].token,
                    "new_password": f"NewPassword{i}123!"
                }
            )
            assert response.status_code == 200

        # 6th request should be rate limited
        response = await client.post(
            "/api/v1/auth/reset-password",
            json={
                "token": tokens[5].token,
                "new_password": "NewPassword6123!"
            }
        )

        assert response.status_code == 429
        data = response.json()
        assert "rate limit" in data["detail"].lower()
