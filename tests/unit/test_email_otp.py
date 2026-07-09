"""Unit tests for email OTP verification functionality"""

import pytest
from datetime import datetime, timedelta
from uuid import uuid4
from unittest.mock import AsyncMock, MagicMock
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.email_otp_code import EmailOtpCode, OTP_MAX_ATTEMPTS
from app.models.user import User
from app.core.security import security_service
from app.services.email_otp_service import EmailOtpService
from fastapi import HTTPException


class TestEmailOtpCodeModel:
    """Tests for EmailOtpCode model"""

    def test_generate_code_returns_six_digit_string(self):
        """Test that generate_code returns a zero-padded 6-digit string"""
        code = EmailOtpCode.generate_code()
        assert isinstance(code, str)
        assert len(code) == 6
        assert code.isdigit()

    def test_generate_code_zero_pads(self):
        """Test that codes below 100000 are zero-padded to 6 digits"""
        codes = [EmailOtpCode.generate_code() for _ in range(200)]
        assert all(len(c) == 6 for c in codes)

    def test_is_expired_returns_true_for_expired_code(self):
        code = EmailOtpCode(
            code_hash="hash",
            user_id=uuid4(),
            expires_at=datetime.utcnow() - timedelta(minutes=1),
        )
        assert code.is_expired() is True

    def test_is_expired_returns_false_for_valid_code(self):
        code = EmailOtpCode(
            code_hash="hash",
            user_id=uuid4(),
            expires_at=datetime.utcnow() + timedelta(minutes=10),
        )
        assert code.is_expired() is False

    def test_is_revoked_returns_true_when_revoked_at_set(self):
        code = EmailOtpCode(
            code_hash="hash",
            user_id=uuid4(),
            expires_at=datetime.utcnow() + timedelta(minutes=10),
            revoked_at=datetime.utcnow(),
        )
        assert code.is_revoked() is True

    def test_is_revoked_returns_false_when_not_revoked(self):
        code = EmailOtpCode(
            code_hash="hash",
            user_id=uuid4(),
            expires_at=datetime.utcnow() + timedelta(minutes=10),
        )
        assert code.is_revoked() is False

    def test_is_locked_out_returns_false_below_max_attempts(self):
        code = EmailOtpCode(
            code_hash="hash",
            user_id=uuid4(),
            expires_at=datetime.utcnow() + timedelta(minutes=10),
            attempt_count=OTP_MAX_ATTEMPTS - 1,
        )
        assert code.is_locked_out() is False

    def test_is_locked_out_returns_true_at_max_attempts(self):
        code = EmailOtpCode(
            code_hash="hash",
            user_id=uuid4(),
            expires_at=datetime.utcnow() + timedelta(minutes=10),
            attempt_count=OTP_MAX_ATTEMPTS,
        )
        assert code.is_locked_out() is True

    def test_is_valid_returns_true_for_fresh_code(self):
        code = EmailOtpCode(
            code_hash="hash",
            user_id=uuid4(),
            expires_at=datetime.utcnow() + timedelta(minutes=10),
            is_used=False,
            attempt_count=0,
        )
        assert code.is_valid() is True

    def test_is_valid_returns_false_for_used_code(self):
        code = EmailOtpCode(
            code_hash="hash",
            user_id=uuid4(),
            expires_at=datetime.utcnow() + timedelta(minutes=10),
            is_used=True,
        )
        assert code.is_valid() is False

    def test_is_valid_returns_false_for_expired_code(self):
        code = EmailOtpCode(
            code_hash="hash",
            user_id=uuid4(),
            expires_at=datetime.utcnow() - timedelta(minutes=1),
        )
        assert code.is_valid() is False

    def test_is_valid_returns_false_for_revoked_code(self):
        code = EmailOtpCode(
            code_hash="hash",
            user_id=uuid4(),
            expires_at=datetime.utcnow() + timedelta(minutes=10),
            revoked_at=datetime.utcnow(),
        )
        assert code.is_valid() is False

    def test_is_valid_returns_false_for_locked_out_code(self):
        code = EmailOtpCode(
            code_hash="hash",
            user_id=uuid4(),
            expires_at=datetime.utcnow() + timedelta(minutes=10),
            attempt_count=OTP_MAX_ATTEMPTS,
        )
        assert code.is_valid() is False


class TestEmailOtpServiceCreateAndSend:
    """Tests for EmailOtpService.create_otp_code / send_otp_email"""

    @pytest.fixture
    def mock_db(self):
        db = AsyncMock(spec=AsyncSession)
        db.execute = AsyncMock()
        db.commit = AsyncMock()
        db.add = MagicMock()
        db.delete = AsyncMock()
        return db

    @pytest.fixture
    def service(self, mock_db):
        return EmailOtpService(mock_db)

    @pytest.mark.asyncio
    async def test_create_otp_code_generates_hashed_code(self, service, mock_db):
        """The stored row's code_hash must not equal the plaintext code, and
        verifying the plaintext against the hash must succeed."""
        user_id = uuid4()

        mock_result = AsyncMock()
        mock_result.scalars = MagicMock(return_value=MagicMock(all=MagicMock(return_value=[])))
        mock_db.execute.return_value = mock_result

        async def mock_refresh(obj):
            obj.id = uuid4()
            obj.created_at = datetime.utcnow()
            # Simulate DB-applied column defaults (default=... only applies on
            # a real flush, not on bare Python construction).
            if obj.is_used is None:
                obj.is_used = False
            if obj.attempt_count is None:
                obj.attempt_count = 0

        mock_db.refresh = mock_refresh

        otp_code, plaintext_code = await service.create_otp_code(user_id, "192.168.1.1")

        assert len(plaintext_code) == 6
        assert plaintext_code.isdigit()
        assert otp_code.code_hash != plaintext_code
        assert security_service.verify_password(plaintext_code, otp_code.code_hash)
        assert otp_code.user_id == user_id
        assert otp_code.ip_address == "192.168.1.1"
        assert otp_code.is_used is False
        assert otp_code.attempt_count == 0
        assert otp_code.expires_at > datetime.utcnow()

    @pytest.mark.asyncio
    async def test_create_otp_code_revokes_prior_active_codes(self, service, mock_db):
        """Requesting a new code (e.g. resend) must revoke old active codes."""
        user_id = uuid4()
        old_code = EmailOtpCode(
            id=uuid4(),
            code_hash="oldhash",
            user_id=user_id,
            expires_at=datetime.utcnow() + timedelta(minutes=10),
            is_used=False,
        )

        mock_result = AsyncMock()
        mock_result.scalars = MagicMock(return_value=MagicMock(all=MagicMock(return_value=[old_code])))
        mock_db.execute.return_value = mock_result

        async def mock_refresh(obj):
            obj.id = uuid4()
            obj.created_at = datetime.utcnow()
            if obj.is_used is None:
                obj.is_used = False
            if obj.attempt_count is None:
                obj.attempt_count = 0

        mock_db.refresh = mock_refresh

        await service.create_otp_code(user_id, None)

        assert old_code.revoked_at is not None
        assert old_code.is_used is False  # revoked, not consumed


class TestEmailOtpServiceVerify:
    """Tests for EmailOtpService.verify_otp_code"""

    @pytest.fixture
    def mock_db(self):
        db = AsyncMock(spec=AsyncSession)
        db.execute = AsyncMock()
        db.commit = AsyncMock()
        db.add = MagicMock()
        db.refresh = AsyncMock()
        return db

    @pytest.fixture
    def service(self, mock_db):
        return EmailOtpService(mock_db)

    def _user(self, **overrides):
        defaults = dict(
            id=uuid4(),
            email="user@example.com",
            hashed_password="x",
            is_active=True,
            is_verified=False,
            role="user",
        )
        defaults.update(overrides)
        return User(**defaults)

    @pytest.mark.asyncio
    async def test_verify_otp_code_raises_for_unknown_email(self, service, mock_db):
        mock_result = AsyncMock()
        mock_result.scalar_one_or_none = MagicMock(return_value=None)
        mock_db.execute.return_value = mock_result

        with pytest.raises(HTTPException) as exc_info:
            await service.verify_otp_code("nobody@example.com", "123456")

        assert exc_info.value.status_code == 400

    @pytest.mark.asyncio
    async def test_verify_otp_code_raises_for_no_active_code(self, service, mock_db):
        user = self._user()

        user_result = AsyncMock()
        user_result.scalar_one_or_none = MagicMock(return_value=user)

        code_result = AsyncMock()
        code_result.scalars = MagicMock(return_value=MagicMock(first=MagicMock(return_value=None)))

        mock_db.execute.side_effect = [user_result, code_result]

        with pytest.raises(HTTPException) as exc_info:
            await service.verify_otp_code(user.email, "123456")

        assert exc_info.value.status_code == 400

    @pytest.mark.asyncio
    async def test_verify_otp_code_raises_for_expired_code(self, service, mock_db):
        user = self._user()
        expired_code = EmailOtpCode(
            id=uuid4(),
            code_hash=security_service.get_password_hash("123456"),
            user_id=user.id,
            expires_at=datetime.utcnow() - timedelta(minutes=1),
        )

        user_result = AsyncMock()
        user_result.scalar_one_or_none = MagicMock(return_value=user)
        code_result = AsyncMock()
        code_result.scalars = MagicMock(return_value=MagicMock(first=MagicMock(return_value=expired_code)))
        mock_db.execute.side_effect = [user_result, code_result]

        with pytest.raises(HTTPException) as exc_info:
            await service.verify_otp_code(user.email, "123456")

        assert exc_info.value.status_code == 400

    @pytest.mark.asyncio
    async def test_verify_otp_code_raises_for_revoked_code(self, service, mock_db):
        user = self._user()
        revoked_code = EmailOtpCode(
            id=uuid4(),
            code_hash=security_service.get_password_hash("123456"),
            user_id=user.id,
            expires_at=datetime.utcnow() + timedelta(minutes=10),
            revoked_at=datetime.utcnow(),
        )

        user_result = AsyncMock()
        user_result.scalar_one_or_none = MagicMock(return_value=user)
        code_result = AsyncMock()
        code_result.scalars = MagicMock(return_value=MagicMock(first=MagicMock(return_value=revoked_code)))
        mock_db.execute.side_effect = [user_result, code_result]

        with pytest.raises(HTTPException) as exc_info:
            await service.verify_otp_code(user.email, "123456")

        assert exc_info.value.status_code == 400

    @pytest.mark.asyncio
    async def test_verify_otp_code_wrong_code_increments_attempt_count(self, service, mock_db):
        user = self._user()
        otp_code = EmailOtpCode(
            id=uuid4(),
            code_hash=security_service.get_password_hash("123456"),
            user_id=user.id,
            expires_at=datetime.utcnow() + timedelta(minutes=10),
            attempt_count=0,
            is_used=False,
        )

        user_result = AsyncMock()
        user_result.scalar_one_or_none = MagicMock(return_value=user)
        code_result = AsyncMock()
        code_result.scalars = MagicMock(return_value=MagicMock(first=MagicMock(return_value=otp_code)))
        mock_db.execute.side_effect = [user_result, code_result]

        with pytest.raises(HTTPException) as exc_info:
            await service.verify_otp_code(user.email, "000000")

        assert exc_info.value.status_code == 400
        assert otp_code.attempt_count == 1
        assert otp_code.is_used is False

    @pytest.mark.asyncio
    async def test_verify_otp_code_locks_out_on_fifth_wrong_attempt(self, service, mock_db):
        """The code becomes locked out once attempt_count reaches OTP_MAX_ATTEMPTS
        (5) after this wrong guess; the current call itself still reports the
        wrong-code failure (400), but any subsequent call must see the lockout."""
        user = self._user()
        otp_code = EmailOtpCode(
            id=uuid4(),
            code_hash=security_service.get_password_hash("123456"),
            user_id=user.id,
            expires_at=datetime.utcnow() + timedelta(minutes=10),
            attempt_count=OTP_MAX_ATTEMPTS - 1,
        )

        user_result = AsyncMock()
        user_result.scalar_one_or_none = MagicMock(return_value=user)
        code_result = AsyncMock()
        code_result.scalars = MagicMock(return_value=MagicMock(first=MagicMock(return_value=otp_code)))
        mock_db.execute.side_effect = [user_result, code_result]

        with pytest.raises(HTTPException) as exc_info:
            await service.verify_otp_code(user.email, "000000")

        assert exc_info.value.status_code == 400
        assert otp_code.attempt_count == OTP_MAX_ATTEMPTS
        assert otp_code.is_locked_out() is True

        # A further attempt against the now-locked-out code is rejected with 429.
        user_result2 = AsyncMock()
        user_result2.scalar_one_or_none = MagicMock(return_value=user)
        code_result2 = AsyncMock()
        code_result2.scalars = MagicMock(return_value=MagicMock(first=MagicMock(return_value=otp_code)))
        mock_db.execute.side_effect = [user_result2, code_result2]

        with pytest.raises(HTTPException) as exc_info2:
            await service.verify_otp_code(user.email, "123456")

        assert exc_info2.value.status_code == 429

    @pytest.mark.asyncio
    async def test_verify_otp_code_success_marks_used_and_verifies_user(self, service, mock_db):
        user = self._user()
        otp_code = EmailOtpCode(
            id=uuid4(),
            code_hash=security_service.get_password_hash("123456"),
            user_id=user.id,
            expires_at=datetime.utcnow() + timedelta(minutes=10),
            attempt_count=0,
        )

        user_result = AsyncMock()
        user_result.scalar_one_or_none = MagicMock(return_value=user)
        code_result = AsyncMock()
        code_result.scalars = MagicMock(return_value=MagicMock(first=MagicMock(return_value=otp_code)))
        mock_db.execute.side_effect = [user_result, code_result]

        refresh_token_obj = MagicMock()
        refresh_token_obj.token = "refresh-token-value"

        from unittest.mock import patch
        with patch(
            "app.services.email_otp_service.TokenService.create_refresh_token",
            new=AsyncMock(return_value=refresh_token_obj),
        ), patch(
            "app.services.email_otp_service.create_access_token",
            return_value="access-token-value",
        ):
            result = await service.verify_otp_code(user.email, "123456", ip_address="1.2.3.4")

        assert otp_code.is_used is True
        assert otp_code.used_at is not None
        assert user.is_verified is True
        assert result.access_token == "access-token-value"
        assert result.refresh_token == "refresh-token-value"
        assert result.expires_in > 0
