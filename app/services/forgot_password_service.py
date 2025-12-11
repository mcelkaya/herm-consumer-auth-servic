from typing import Optional
from uuid import UUID, uuid4
from sqlalchemy import select, and_
from sqlalchemy.ext.asyncio import AsyncSession
from datetime import datetime, timedelta
from app.models.user import User
from app.models.password_reset_token import PasswordResetToken
from app.core.config import settings
import logging

from app.services.sqs_producer import notification_producer

logger = logging.getLogger(__name__)


class ForgotPasswordService:
    """Service for handling forgot password functionality"""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def get_user_language_code(self, user_id: UUID) -> str:
        """
        Get user's language code via user_settings → languages join

        NOTE: This is a placeholder. When user_settings and languages tables exist:
        - Query user_settings by user_id
        - Join with languages table
        - Return language code
        - Default to 'en' if not found
        """
        # TODO: Implement when user_settings and languages tables are created
        # Example query:
        # result = await self.db.execute(
        #     select(Language.code)
        #     .join(UserSettings, UserSettings.language_id == Language.id)
        #     .where(UserSettings.user_id == user_id)
        # )
        # language = result.scalar_one_or_none()
        # return language if language else 'en'

        return 'en'  # Default to English for now

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
        ip_address: Optional[str] = None,
        expiry_hours: int = 24
    ) -> bool:
        """
        Main method - returns True if email queued, False if user not found

        NOTE: Always returns success to frontend to prevent email enumeration
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

        # Get user's language
        language_code = await self.get_user_language_code(user.id)

        # Create reset token
        reset_token = await self.create_reset_token(user.id, ip_address, expiry_hours)

        # Build reset link
        reset_link = f"{settings.FRONTEND_URL}/reset-password?token={reset_token.token}"

        # Prepare template variables
        # Note: user.first_name and user.last_name don't exist in current User model
        # Using email as fallback
        user_name = email.split('@')[0]  # Simple fallback

        message_id = notification_producer.send_password_reset(
            email=email,
            user_name=user_name,
            reset_link=reset_link,
            expiry_hours=expiry_hours,
            user_id=user.id,
            language="en",  # Turkish language_code
            correlation_id=str(uuid4())
        )

        logger.info(f"Queued password reset notification: {message_id}")


        logger.info(f"Password reset token created for user: {email} (expires in {expiry_hours} hours)")

        return True
