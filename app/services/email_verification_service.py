from typing import Optional
from uuid import UUID, uuid4
from sqlalchemy import select, and_
from sqlalchemy.ext.asyncio import AsyncSession
from datetime import datetime, timedelta
from fastapi import HTTPException, status
from app.models.user import User
from app.models.email_verification_token import EmailVerificationToken
from app.services.sqs_producer import notification_producer
from app.core.config import settings
import logging

logger = logging.getLogger(__name__)


class EmailVerificationService:
    """Service for handling email verification functionality"""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def create_verification_token(
        self,
        user_id: UUID,
        ip_address: Optional[str],
        expiry_hours: int = 24,
    ) -> EmailVerificationToken:
        """
        Create a new email verification token for a user.

        Any existing active tokens for this user are REVOKED (superseded),
        not marked as used. This preserves the distinction between two
        very different states:

          - is_used=True       → token was successfully consumed by verification
          - revoked_at IS NOT NULL → token was superseded by a newer one (resend)

        Without this distinction, clicking an older verification email after
        requesting a resend was being misclassified as suspicious activity
        and rejected.
        """
        # Revoke (supersede) any existing active tokens for this user
        result = await self.db.execute(
            select(EmailVerificationToken).where(
                and_(
                    EmailVerificationToken.user_id == user_id,
                    EmailVerificationToken.is_used == False,  # noqa: E712
                    EmailVerificationToken.revoked_at.is_(None),
                )
            )
        )
        old_tokens = result.scalars().all()

        now = datetime.utcnow()
        for old_token in old_tokens:
            old_token.revoked_at = now

        # Create new token
        token = EmailVerificationToken(
            token=EmailVerificationToken.generate_token(),
            user_id=user_id,
            expires_at=now + timedelta(hours=expiry_hours),
            ip_address=ip_address,
        )

        self.db.add(token)
        await self.db.commit()
        await self.db.refresh(token)

        return token

    async def send_verification_email(
        self,
        user: User,
        language: str = "en",
        ip_address: Optional[str] = None,
        expiry_hours: int = 24,
    ) -> bool:
        """
        Send email verification to user.

        Args:
            user: User object
            language: Language code from frontend (e.g., 'en', 'tr')
            ip_address: IP address of requester for audit
            expiry_hours: Token expiry time in hours

        Returns:
            True if email queued successfully, False otherwise
        """
        # Create verification token (revokes any existing active ones)
        verification_token = await self.create_verification_token(
            user.id, ip_address, expiry_hours
        )

        # Build verification link
        verification_link = (
            f"{settings.FRONTEND_URL}/verify-email?token={verification_token.token}"
        )

        # Prepare user name (simple fallback since User model doesn't have name fields)
        user_name = user.email.split("@")[0]

        # Send email verification notification via SQS
        message_id = notification_producer.send_email_verification(
            email=user.email,
            user_name=user_name,
            verification_link=verification_link,
            user_id=user.id,
            language=language,
            correlation_id=str(uuid4()),
        )

        logger.info(
            f"Queued email verification notification: {message_id} "
            f"for user: {user.email} (language: {language}, expires in {expiry_hours} hours)"
        )

        return True

    async def verify_token(self, token: str) -> Optional[EmailVerificationToken]:
        """
        Look up a verification token by its string value.

        Returns None for tokens that don't exist or are expired.
        Returns the token object even if it is used or revoked — the caller
        (verify_email) decides how to handle each state.
        """
        result = await self.db.execute(
            select(EmailVerificationToken).where(EmailVerificationToken.token == token)
        )
        verification_token = result.scalar_one_or_none()

        if not verification_token:
            logger.warning("Email verification attempted with non-existent token")
            return None

        if verification_token.is_expired():
            logger.warning(
                f"Email verification attempted with expired token "
                f"for user {verification_token.user_id}"
            )
            return None

        if verification_token.is_used:
            logger.info(
                f"Email verification attempted with already-used token "
                f"for user {verification_token.user_id} (allowing for idempotency check)"
            )

        if verification_token.is_revoked():
            logger.info(
                f"Email verification attempted with revoked (superseded) token "
                f"for user {verification_token.user_id}"
            )

        return verification_token

    async def verify_email(
        self,
        token: str,
        ip_address: Optional[str] = None,
    ) -> User:
        """
        Verify user's email using a token.

        Idempotent: returns success even if user already verified (handles
        duplicate calls e.g. from React StrictMode).

        Token states handled:
          - not found / expired                     → 400 invalid/expired
          - revoked (superseded by resend)          → 400 with "use the latest email"
          - already used + user already verified    → success (idempotency)
          - already used + user NOT verified        → 400 (genuine replay/race)
          - active + first-time use                 → mark used, mark user verified

        Raises:
            HTTPException: with appropriate status and message
        """
        verification_token = await self.verify_token(token)

        if not verification_token:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired verification token",
            )

        # Get user
        result = await self.db.execute(
            select(User).where(User.id == verification_token.user_id)
        )
        user = result.scalar_one_or_none()

        if not user:
            logger.error(f"User not found for valid token: {verification_token.user_id}")
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found",
            )

        # IDEMPOTENT: If already verified, return success regardless of token state.
        # Handles duplicate calls (e.g. React StrictMode) and the case where the user
        # clicks the same link twice.
        if user.is_verified:
            logger.info(
                f"Email verification: User already verified: {user.email} "
                f"(token used: {verification_token.is_used}, "
                f"revoked: {verification_token.is_revoked()}) "
                f"- returning success for idempotency"
            )
            if not verification_token.is_used:
                verification_token.is_used = True
                verification_token.used_at = datetime.utcnow()
                await self.db.commit()
            return user

        # User is NOT verified yet. Reject if the token is unusable:

        # REVOKED: user clicked an older email after requesting a resend.
        # This is normal user behavior, not malicious. Tell them to use the latest email.
        if verification_token.is_revoked():
            logger.info(
                f"Email verification: Superseded token for unverified user {user.email} "
                f"- user likely clicked an older email after requesting a resend"
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="This verification link has been replaced. Please use the most recent email.",
            )

        # USED but not revoked, on an unverified user → genuine replay/race.
        # The token was successfully consumed once but verification didn't complete.
        # Reject for safety.
        if verification_token.is_used:
            logger.warning(
                f"Email verification: Token already used but user NOT verified: {user.email} "
                f"(suspicious activity detected) - rejecting"
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired verification token",
            )

        # FIRST-TIME VERIFICATION: Update user status
        user.is_verified = True
        self.db.add(user)

        # Mark token as used
        verification_token.is_used = True
        verification_token.used_at = datetime.utcnow()
        self.db.add(verification_token)

        # Commit changes
        await self.db.commit()

        # Refresh user to get updated data
        await self.db.refresh(user)

        logger.info(
            f"Email successfully verified for user: {user.email} "
            f"(from IP: {ip_address or 'unknown'})"
        )

        return user

    async def cleanup_expired_tokens(self) -> int:
        """
        Delete expired email verification tokens.

        Returns:
            Number of tokens deleted
        """
        result = await self.db.execute(
            select(EmailVerificationToken).where(
                EmailVerificationToken.expires_at < datetime.utcnow()
            )
        )
        expired_tokens = result.scalars().all()

        for token in expired_tokens:
            await self.db.delete(token)

        await self.db.commit()

        logger.info(
            f"Cleaned up {len(expired_tokens)} expired email verification tokens"
        )
        return len(expired_tokens)