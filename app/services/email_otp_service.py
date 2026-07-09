from dataclasses import dataclass
from typing import Optional
from uuid import UUID, uuid4
from sqlalchemy import select, and_
from sqlalchemy.ext.asyncio import AsyncSession
from datetime import datetime, timedelta
from fastapi import HTTPException, status
from app.models.user import User
from app.models.email_otp_code import EmailOtpCode
from app.core.security import security_service
from app.services.sqs_producer import notification_producer
from app.services.token_service import TokenService, create_access_token
from app.core.config import settings
import logging

logger = logging.getLogger(__name__)


@dataclass
class VerifyOtpResult:
    """Outcome of a successful verify_otp_code call."""
    user: "User"
    access_token: str
    refresh_token: str
    expires_in: int


class EmailOtpService:
    """Service for handling 6-digit OTP email verification.

    Mirrors EmailVerificationService's token flow, but the code is short
    enough (1,000,000 possibilities) that it must be hashed at rest and
    guarded against brute-force guessing (attempt_count / is_locked_out).
    """

    def __init__(self, db: AsyncSession):
        self.db = db

    async def create_otp_code(
        self,
        user_id: UUID,
        ip_address: Optional[str],
        expiry_minutes: int = 10,
    ) -> tuple[EmailOtpCode, str]:
        """
        Create a new OTP code for a user.

        Any existing active (unused, unrevoked) codes for this user are
        REVOKED (superseded), not marked as used — same distinction as
        EmailVerificationToken: is_used means successfully consumed,
        revoked_at means superseded by a newer request (e.g. resend).

        Returns the persisted (hashed) row plus the plaintext code, since
        the plaintext is only ever needed once, to send the email.
        """
        scope = and_(
            EmailOtpCode.user_id == user_id,
            EmailOtpCode.is_used == False,  # noqa: E712
            EmailOtpCode.revoked_at.is_(None),
        )
        result = await self.db.execute(select(EmailOtpCode).where(scope))
        old_codes = result.scalars().all()

        now = datetime.utcnow()
        for old_code in old_codes:
            old_code.revoked_at = now

        plaintext_code = EmailOtpCode.generate_code()

        otp_code = EmailOtpCode(
            code_hash=security_service.get_password_hash(plaintext_code),
            user_id=user_id,
            expires_at=now + timedelta(minutes=expiry_minutes),
            ip_address=ip_address,
        )

        self.db.add(otp_code)
        await self.db.commit()
        await self.db.refresh(otp_code)

        return otp_code, plaintext_code

    async def send_otp_email(
        self,
        user: User,
        language: str = "en",
        ip_address: Optional[str] = None,
        expiry_minutes: int = 10,
    ) -> bool:
        """
        Create and send a 6-digit OTP code to the user's email.

        Returns:
            True if email queued successfully
        """
        _, plaintext_code = await self.create_otp_code(
            user.id, ip_address, expiry_minutes
        )

        user_name = user.email.split("@")[0]

        message_id = notification_producer.send_email_verification_otp(
            email=user.email,
            user_name=user_name,
            code=plaintext_code,
            expiry_minutes=expiry_minutes,
            user_id=user.id,
            language=language,
            correlation_id=str(uuid4()),
        )

        logger.info(
            f"Queued email verification OTP notification: {message_id} "
            f"for user: {user.email} (language: {language}, expires in {expiry_minutes} minutes)"
        )

        return True

    async def _get_active_code(self, user_id: UUID) -> Optional[EmailOtpCode]:
        """Look up the most recent non-superseded, unused code for a user."""
        result = await self.db.execute(
            select(EmailOtpCode)
            .where(
                and_(
                    EmailOtpCode.user_id == user_id,
                    EmailOtpCode.is_used == False,  # noqa: E712
                    EmailOtpCode.revoked_at.is_(None),
                )
            )
            .order_by(EmailOtpCode.created_at.desc())
        )
        return result.scalars().first()

    async def verify_otp_code(
        self,
        email: str,
        code: str,
        ip_address: Optional[str] = None,
        device_info: Optional[str] = None,
    ) -> VerifyOtpResult:
        """
        Verify a 6-digit OTP code for the user identified by email.

        State machine:
          - user not found                          → 400 invalid code
          - no active code for user                  → 400 invalid or expired
          - code revoked (superseded by resend)       → 400 use latest code
          - code expired                              → 400 invalid or expired
          - code locked out (>= 5 wrong attempts)      → 429 too many attempts
          - hash mismatch                             → increment attempt_count, 400
          - match                                     → mark used, verify user, mint tokens

        Raises:
            HTTPException: with appropriate status and message
        """
        result = await self.db.execute(select(User).where(User.email == email))
        user = result.scalar_one_or_none()

        if not user:
            logger.warning(f"OTP verification attempted for non-existent email: {email}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired verification code",
            )

        otp_code = await self._get_active_code(user.id)

        if not otp_code:
            logger.warning(f"OTP verification attempted with no active code for user {user.id}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired verification code",
            )

        if otp_code.is_revoked():
            logger.info(
                f"OTP verification: superseded code for user {user.id} "
                f"- user likely requested a resend"
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="This code has been replaced. Please use the most recent code.",
            )

        if otp_code.is_expired():
            logger.warning(f"OTP verification attempted with expired code for user {user.id}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired verification code",
            )

        if otp_code.is_locked_out():
            logger.warning(f"OTP verification attempted on locked-out code for user {user.id}")
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many incorrect attempts. Please request a new code.",
            )

        if not security_service.verify_password(code, otp_code.code_hash):
            otp_code.attempt_count += 1
            await self.db.commit()
            logger.warning(
                f"OTP verification: wrong code for user {user.id} "
                f"(attempt {otp_code.attempt_count})"
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired verification code",
            )

        # Match. Mark code used and verify the user (login-on-verify parity
        # with EmailVerificationService.verify_email for kind="primary").
        now = datetime.utcnow()
        otp_code.is_used = True
        otp_code.used_at = now
        self.db.add(otp_code)

        user.is_verified = True
        self.db.add(user)

        await self.db.commit()
        await self.db.refresh(user)

        access_token = create_access_token(user)

        token_service = TokenService(self.db)
        refresh_token_obj = await token_service.create_refresh_token(
            user=user,
            device_info=device_info,
            ip_address=ip_address,
        )

        logger.info(
            f"Email successfully verified via OTP for user: {user.email} "
            f"(from IP: {ip_address or 'unknown'})"
        )

        return VerifyOtpResult(
            user=user,
            access_token=access_token,
            refresh_token=refresh_token_obj.token,
            expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        )

    async def cleanup_expired_codes(self) -> int:
        """
        Delete expired email OTP codes.

        Returns:
            Number of codes deleted
        """
        result = await self.db.execute(
            select(EmailOtpCode).where(EmailOtpCode.expires_at < datetime.utcnow())
        )
        expired_codes = result.scalars().all()

        for code in expired_codes:
            await self.db.delete(code)

        await self.db.commit()

        logger.info(f"Cleaned up {len(expired_codes)} expired email OTP codes")
        return len(expired_codes)
