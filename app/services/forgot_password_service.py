from typing import Optional
from uuid import UUID, uuid4
from sqlalchemy import select, and_
from sqlalchemy.ext.asyncio import AsyncSession
from datetime import datetime, timedelta
from app.models.user import User
from app.models.password_reset_token import PasswordResetToken
from app.services.sqs_producer import notification_producer
from app.core.config import settings
import logging

logger = logging.getLogger(__name__)


class ForgotPasswordService:
    """Service for handling forgot password functionality"""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def create_reset_token(
        self,
        user_id: UUID,
        ip_address: Optional[str],
        expiry_hours: int = 24
    ) -> PasswordResetToken:
        """Create password reset token and invalidate old ones"""
        # Invalidate existing unused tokens for this user
        result = await self.db.execute(
            select(PasswordResetToken).where(
                and_(
                    PasswordResetToken.user_id == user_id,
                    PasswordResetToken.is_used == False
                )
            )
        )
        old_tokens = result.scalars().all()

        for old_token in old_tokens:
            old_token.is_used = True

        # Create new token
        token = PasswordResetToken(
            token=PasswordResetToken.generate_token(),
            user_id=user_id,
            expires_at=datetime.utcnow() + timedelta(hours=expiry_hours),
            ip_address=ip_address
        )

        self.db.add(token)
        await self.db.commit()
        await self.db.refresh(token)

        return token

    async def process_forgot_password(
        self,
        email: str,
        language: str = "en",
        ip_address: Optional[str] = None,
        expiry_hours: int = 24
    ) -> bool:
        """
        Main method - returns True if email queued, False if user not found

        NOTE: Always returns success to frontend to prevent email enumeration

        Args:
            email: User's email address
            language: Language code from frontend (e.g., 'en', 'tr')
            ip_address: IP address for audit trail
            expiry_hours: Token expiry time in hours
        """
        # Check if user exists
        result = await self.db.execute(
            select(User).where(User.email == email)
        )
        user = result.scalar_one_or_none()

        if not user:
            # Don't reveal that user doesn't exist (security)
            logger.info(f"Password reset requested for non-existent email: {email}")
            return False

        # Create reset token
        reset_token = await self.create_reset_token(user.id, ip_address, expiry_hours)

        # Build reset link
        reset_link = f"{settings.FRONTEND_URL}/reset-password?token={reset_token.token}"

        # Prepare user name (simple fallback since User model doesn't have name fields)
        user_name = email.split('@')[0]

        # Send password reset notification via SQS
        message_id = notification_producer.send_password_reset(
            email=email,
            user_name=user_name,
            reset_link=reset_link,
            expiry_hours=expiry_hours,
            user_id=user.id,
            language=language,  # Use language from request
            correlation_id=str(uuid4())
        )

        logger.info(
            f"Queued password reset notification: {message_id} "
            f"for user: {email} (language: {language}, expires in {expiry_hours} hours)"
        )

        return True