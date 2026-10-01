"""Unit tests for password reset functionality"""

import json
import pytest
from datetime import datetime, timedelta
from uuid import uuid4
from unittest.mock import AsyncMock, MagicMock, patch
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.password_reset_token import PasswordResetToken
from app.models.user import User
from app.services.forgot_password_service import ForgotPasswordService
from app.services.reset_password_service import ResetPasswordService
from fastapi import HTTPException


class TestPasswordResetTokenModel:
    """Tests for PasswordResetToken model"""

    def test_generate_token_returns_string(self):
        """Test that generate_token returns a string"""
        token = PasswordResetToken.generate_token()
        assert isinstance(token, str)
        assert len(token) == 64  # URL-safe 48 bytes = 64 characters

    def test_generate_token_is_unique(self):
        """Test that generated tokens are unique"""
        tokens = [PasswordResetToken.generate_token() for _ in range(100)]
        assert len(tokens) == len(set(tokens))  # All tokens should be unique

    def test_is_expired_returns_true_for_expired_token(self):
        """Test that is_expired returns True for expired tokens"""
        token = PasswordResetToken(
            token="test_token",
            user_id=uuid4(),
            expires_at=datetime.utcnow() - timedelta(hours=1)  # Expired 1 hour ago
        )
        assert token.is_expired() is True

    def test_is_expired_returns_false_for_valid_token(self):
        """Test that is_expired returns False for valid tokens"""
        token = PasswordResetToken(
            token="test_token",
            user_id=uuid4(),
            expires_at=datetime.utcnow() + timedelta(hours=1)  # Expires in 1 hour
        )
        assert token.is_expired() is False

    def test_is_valid_returns_true_for_valid_token(self):
        """Test that is_valid returns True for valid tokens"""
        token = PasswordResetToken(
            token="test_token",
            user_id=uuid4(),
            expires_at=datetime.utcnow() + timedelta(hours=1),
            is_used=False
        )
        assert token.is_valid() is True

    def test_is_valid_returns_false_for_expired_token(self):
        """Test that is_valid returns False for expired tokens"""
        token = PasswordResetToken(
            token="test_token",
            user_id=uuid4(),
            expires_at=datetime.utcnow() - timedelta(hours=1),
            is_used=False
        )
        assert token.is_valid() is False

    def test_is_valid_returns_false_for_used_token(self):
        """Test that is_valid returns False for used tokens"""
        token = PasswordResetToken(
            token="test_token",
            user_id=uuid4(),
            expires_at=datetime.utcnow() + timedelta(hours=1),
            is_used=True
        )
        assert token.is_valid() is False

    def test_is_valid_returns_false_for_expired_and_used_token(self):
        """Test that is_valid returns False for expired and used tokens"""
        token = PasswordResetToken(
            token="test_token",
            user_id=uuid4(),
            expires_at=datetime.utcnow() - timedelta(hours=1),
            is_used=True
        )
        assert token.is_valid() is False


class TestForgotPasswordService:
    """Tests for ForgotPasswordService"""

    @pytest.fixture
    def mock_db(self):
        """Mock database session"""
        db = AsyncMock(spec=AsyncSession)
        db.execute = AsyncMock()
        db.commit = AsyncMock()
        db.add = MagicMock()
        return db

    @pytest.fixture
    def service(self, mock_db):
        """ForgotPasswordService instance"""
        return ForgotPasswordService(mock_db)

    @pytest.mark.asyncio
    async def test_process_forgot_password_queues_reset_email_in_request_language(
        self, service, mock_db, stub_notification_sqs
    ):
        """The reset email goes out as the notification service's "password_reset"
        template, in the language the client sent, carrying the new token's link.

        (Replaces the old get_user_language_code / get_email_template placeholder
        tests: language now comes from the request and templates live in
        herm-notification-service, selected by template_slug.)
        """
        user = User(id=uuid4(), email="reset@example.com", is_active=True)
        user_result = MagicMock()
        user_result.scalar_one_or_none = MagicMock(return_value=user)
        old_tokens_result = MagicMock()
        old_tokens_result.scalars = MagicMock(return_value=MagicMock(all=MagicMock(return_value=[])))
        mock_db.execute.side_effect = [user_result, old_tokens_result]
        mock_db.refresh = AsyncMock()

        assert await service.process_forgot_password("reset@example.com", language="tr") is True

        (created_token,) = [c.args[0] for c in mock_db.add.call_args_list]
        kwargs = stub_notification_sqs.send_message.call_args.kwargs
        assert kwargs["MessageAttributes"]["template_slug"]["StringValue"] == "password_reset"
        assert kwargs["MessageAttributes"]["language"]["StringValue"] == "tr"
        body = json.loads(kwargs["MessageBody"])
        assert body["recipient"]["email"] == "reset@example.com"
        assert body["variables"]["reset_link"].endswith(f"/reset-password?token={created_token.token}")

    @pytest.mark.asyncio
    async def test_create_reset_token_generates_valid_token(self, service, mock_db):
        """Test that create_reset_token generates a valid token"""
        user_id = uuid4()
        ip_address = "192.168.1.1"

        # Mock empty result for existing tokens query
        mock_result = AsyncMock()
        mock_result.scalars = MagicMock(return_value=MagicMock(all=MagicMock(return_value=[])))
        mock_db.execute.return_value = mock_result

        # Emulate INSERT + refresh: the DB fills the PK and the column defaults
        # (is_used=False, created_at) that SQLAlchemy only applies at flush time.
        async def mock_refresh(obj):
            obj.id = uuid4()
            obj.created_at = datetime.utcnow()
            if obj.is_used is None:
                obj.is_used = PasswordResetToken.__table__.c.is_used.default.arg

        mock_db.refresh = mock_refresh

        token = await service.create_reset_token(user_id, ip_address, expiry_hours=24)

        assert token.user_id == user_id
        assert len(token.token) == 64
        assert token.ip_address == ip_address
        assert token.is_used is False
        assert token.expires_at > datetime.utcnow()

    @pytest.mark.asyncio
    async def test_process_forgot_password_returns_false_for_nonexistent_user(self, service, mock_db):
        """Test that process_forgot_password returns False for non-existent users"""
        # Mock empty result (user not found)
        mock_result = AsyncMock()
        mock_result.scalar_one_or_none = MagicMock(return_value=None)
        mock_db.execute.return_value = mock_result

        result = await service.process_forgot_password("nonexistent@example.com")

        assert result is False


class TestResetPasswordService:
    """Tests for ResetPasswordService"""

    @pytest.fixture
    def mock_db(self):
        """Mock database session"""
        db = AsyncMock(spec=AsyncSession)
        db.execute = AsyncMock()
        db.commit = AsyncMock()
        db.add = MagicMock()
        return db

    @pytest.fixture
    def service(self, mock_db):
        """ResetPasswordService instance"""
        return ResetPasswordService(mock_db)

    @pytest.mark.asyncio
    async def test_verify_reset_token_returns_none_for_nonexistent_token(self, service, mock_db):
        """Test that verify_reset_token returns None for non-existent token"""
        # Mock empty result
        mock_result = AsyncMock()
        mock_result.scalar_one_or_none = MagicMock(return_value=None)
        mock_db.execute.return_value = mock_result

        result = await service.verify_reset_token("invalid_token")

        assert result is None

    @pytest.mark.asyncio
    async def test_verify_reset_token_returns_none_for_expired_token(self, service, mock_db):
        """Test that verify_reset_token returns None for expired token"""
        expired_token = PasswordResetToken(
            id=uuid4(),
            token="expired_token",
            user_id=uuid4(),
            expires_at=datetime.utcnow() - timedelta(hours=1),
            is_used=False
        )

        # Mock result with expired token
        mock_result = AsyncMock()
        mock_result.scalar_one_or_none = MagicMock(return_value=expired_token)
        mock_db.execute.return_value = mock_result

        result = await service.verify_reset_token("expired_token")

        assert result is None

    @pytest.mark.asyncio
    async def test_verify_reset_token_returns_none_for_used_token(self, service, mock_db):
        """Test that verify_reset_token returns None for used token"""
        used_token = PasswordResetToken(
            id=uuid4(),
            token="used_token",
            user_id=uuid4(),
            expires_at=datetime.utcnow() + timedelta(hours=1),
            is_used=True
        )

        # Mock result with used token
        mock_result = AsyncMock()
        mock_result.scalar_one_or_none = MagicMock(return_value=used_token)
        mock_db.execute.return_value = mock_result

        result = await service.verify_reset_token("used_token")

        assert result is None

    @pytest.mark.asyncio
    async def test_verify_reset_token_returns_token_for_valid_token(self, service, mock_db):
        """Test that verify_reset_token returns token for valid token"""
        valid_token = PasswordResetToken(
            id=uuid4(),
            token="valid_token",
            user_id=uuid4(),
            expires_at=datetime.utcnow() + timedelta(hours=1),
            is_used=False
        )

        # Mock result with valid token
        mock_result = AsyncMock()
        mock_result.scalar_one_or_none = MagicMock(return_value=valid_token)
        mock_db.execute.return_value = mock_result

        result = await service.verify_reset_token("valid_token")

        assert result is not None
        assert result.token == "valid_token"
        assert result.is_valid() is True

    @pytest.mark.asyncio
    async def test_reset_password_raises_exception_for_invalid_token(self, service, mock_db):
        """Test that reset_password raises HTTPException for invalid token"""
        # Mock empty result (token not found)
        mock_result = AsyncMock()
        mock_result.scalar_one_or_none = MagicMock(return_value=None)
        mock_db.execute.return_value = mock_result

        with pytest.raises(HTTPException) as exc_info:
            await service.reset_password("invalid_token", "NewPassword123")

        assert exc_info.value.status_code == 400
        assert "Invalid or expired" in exc_info.value.detail

    @pytest.mark.asyncio
    async def test_reset_password_raises_exception_for_inactive_user(self, service, mock_db):
        """Test that reset_password raises HTTPException for inactive user"""
        user_id = uuid4()
        valid_token = PasswordResetToken(
            id=uuid4(),
            token="valid_token",
            user_id=user_id,
            expires_at=datetime.utcnow() + timedelta(hours=1),
            is_used=False
        )

        inactive_user = User(
            id=user_id,
            email="test@example.com",
            hashed_password="hashed",
            is_active=False
        )

        # reset_password looks up the token first, then the user it belongs to
        token_result = MagicMock()
        token_result.scalar_one_or_none = MagicMock(return_value=valid_token)
        user_result = MagicMock()
        user_result.scalar_one_or_none = MagicMock(return_value=inactive_user)
        mock_db.execute.side_effect = [token_result, user_result]

        with pytest.raises(HTTPException) as exc_info:
            await service.reset_password("valid_token", "NewPassword123")

        assert exc_info.value.status_code == 403
        assert "inactive" in exc_info.value.detail.lower()
