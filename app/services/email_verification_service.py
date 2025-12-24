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
        expiry_hours: int = 24
    ) -> EmailVerificationToken:
        """Create email verification token and invalidate old ones"""
        # Invalidate existing unused tokens for this user
        result = await self.db.execute(
            select(EmailVerificationToken).where(
                and_(
                    EmailVerificationToken.user_id == user_id,
                    EmailVerificationToken.is_used == False
                )
            )
        )
        old_tokens = result.scalars().all()

        for old_token in old_tokens:
            old_token.is_used = True

        # Create new token
        token = EmailVerificationToken(
            token=EmailVerificationToken.generate_token(),
            user_id=user_id,
            expires_at=datetime.utcnow() + timedelta(hours=expiry_hours),
            ip_address=ip_address
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
        expiry_hours: int = 24
    ) -> bool:
        """
        Send email verification to user

        Args:
            user: User object
            language: Language code from frontend (e.g., 'en', 'tr')
            ip_address: IP address of requester for audit
            expiry_hours: Token expiry time in hours

        Returns:
            True if email queued successfully, False otherwise
        """
        # Create verification token
        verification_token = await self.create_verification_token(
            user.id, ip_address, expiry_hours
        )

        # Build verification link
        verification_link = f"{settings.FRONTEND_URL}/verify-email?token={verification_token.token}"

        # Prepare user name (simple fallback since User model doesn't have name fields)
        user_name = user.email.split('@')[0]

        # Send email verification notification via SQS
        message_id = notification_producer.send_email_verification(
            email=user.email,
            user_name=user_name,
            verification_link=verification_link,
            user_id=user.id,
            language=language,
            correlation_id=str(uuid4())
        )

        logger.info(
            f"Queued email verification notification: {message_id} "
            f"for user: {user.email} (language: {language}, expires in {expiry_hours} hours)"
        )

        return True

    async def verify_token(self, token: str) -> Optional[EmailVerificationToken]:
        """
        Verify email verification token

        Returns:
            EmailVerificationToken if valid, None otherwise
            
        Note: Returns token even if already used to support idempotent verification
        (e.g., duplicate calls from frontend). The verify_email method will check
        if user is already verified and handle accordingly.
        """
        result = await self.db.execute(
            select(EmailVerificationToken).where(EmailVerificationToken.token == token)
        )
        verification_token = result.scalar_one_or_none()

        if not verification_token:
            logger.warning("Email verification attempted with non-existent token")
            return None

        # Check if expired (but allow used tokens for idempotency)
        if verification_token.is_expired():
            logger.warning(
                f"Email verification attempted with expired token for user {verification_token.user_id}"
            )
            return None

        # ✅ CHANGED: Don't reject used tokens here
        # The verify_email method will check if user is already verified
        # This allows idempotent verification (duplicate calls return same result)
        if verification_token.is_used:
            logger.info(
                f"Email verification attempted with already-used token for user {verification_token.user_id} "
                f"(allowing for idempotency check)"
            )

        return verification_token

    async def verify_email(
        self,
        token: str,
        ip_address: Optional[str] = None
    ) -> User:
        """
        Verify user's email using token
        
        Idempotent: Returns success even if user already verified (for duplicate calls)

        Args:
            token: Email verification token
            ip_address: IP address of requester for audit

        Returns:
            User object with updated is_verified status

        Raises:
            HTTPException: If token is invalid, expired, or user not found
        """
        # Verify token (allows already-used tokens for idempotency)
        verification_token = await self.verify_token(token)

        if not verification_token:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired verification token"
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
                detail="User not found"
            )

        # ✅ IDEMPOTENT: If already verified, just return success
        # This handles duplicate calls from frontend (e.g., React StrictMode)
        if user.is_verified:
            logger.info(
                f"Email verification: User already verified: {user.email} "
                f"(token already used: {verification_token.is_used}) - returning success for idempotency"
            )
            # Mark token as used if not already (shouldn't happen but safety check)
            if not verification_token.is_used:
                verification_token.is_used = True
                verification_token.used_at = datetime.utcnow()
                await self.db.commit()
            
            # Return user so endpoint can generate fresh JWT token
            return user

        # ✅ SECURITY CHECK: If token is already used but user NOT verified, reject
        # This catches suspicious activity (token reuse after partial failure)
        if verification_token.is_used:
            logger.warning(
                f"Email verification: Token already used but user NOT verified: {user.email} "
                f"(suspicious activity detected) - rejecting"
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired verification token"
            )

        # ✅ FIRST-TIME VERIFICATION: Update user status
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
        Delete expired email verification tokens

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

        logger.info(f"Cleaned up {len(expired_tokens)} expired email verification tokens")
        return len(expired_tokens)