from typing import Optional
from uuid import UUID
from sqlalchemy import select, and_
from sqlalchemy.ext.asyncio import AsyncSession
from datetime import datetime, timedelta
from app.models.user import User
from app.models.password_reset_token import PasswordResetToken
from app.core.config import settings
import logging

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

    async def get_email_template(self, email_type_name: str, language_code: str):
        """
        Get template by email_type name and language, fallback to English

        NOTE: This is a placeholder. When email_types and email_templates tables exist:
        - Query email_types by name (e.g., 'forget_password')
        - Query email_templates by email_type_id and language_code
        - Fallback to English if user's language not found
        - Return template with id, subject, and content
        """
        # TODO: Implement when email_types and email_templates tables are created
        # Example query:
        # email_type = await self.db.execute(
        #     select(EmailType).where(EmailType.name == email_type_name)
        # )
        # email_type = email_type.scalar_one_or_none()
        #
        # if not email_type:
        #     return None
        #
        # template = await self.db.execute(
        #     select(EmailTemplate)
        #     .where(and_(
        #         EmailTemplate.email_type_id == email_type.id,
        #         EmailTemplate.language_code == language_code
        #     ))
        # )
        # template = template.scalar_one_or_none()
        #
        # if not template:
        #     # Fallback to English
        #     template = await self.db.execute(
        #         select(EmailTemplate)
        #         .where(and_(
        #             EmailTemplate.email_type_id == email_type.id,
        #             EmailTemplate.language_code == 'en'
        #         ))
        #     )
        #     template = template.scalar_one_or_none()
        #
        # return template

        # Return a mock template for now
        class MockTemplate:
            id = 1
            subject = "Password Reset Request"
            content = "Click the link to reset your password: {reset_link}"

        return MockTemplate()

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

    async def create_pending_email(
        self,
        template_id: int,
        recipient_email: str,
        language_code: str,
        template_variables: dict
    ):
        """
        Queue email for background worker

        NOTE: This is a placeholder. When pending_emails table exists:
        - Create a record in pending_emails table
        - Include template_id, recipient_email, language_code
        - Store template_variables as JSONB
        - Set status to 'pending'
        - Background worker will pick it up and send
        """
        # TODO: Implement when pending_emails table is created
        # Example:
        # pending_email = PendingEmail(
        #     email_templates_id=template_id,
        #     recipient_email=recipient_email,
        #     language_code=language_code,
        #     template_variables=template_variables,
        #     status='pending'
        # )
        # self.db.add(pending_email)
        # await self.db.commit()
        # return pending_email

        # For now, just log that we would send an email
        logger.info(
            f"[SIMULATED EMAIL] Would send password reset email to: {recipient_email}\n"
            f"Language: {language_code}\n"
            f"Template ID: {template_id}\n"
            f"Variables: {template_variables}"
        )

        return True

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

        # Get email template
        template = await self.get_email_template('forget_password', language_code)

        if not template:
            logger.error(f"Email template 'forget_password' not found for language: {language_code}")
            return False

        # Create reset token
        reset_token = await self.create_reset_token(user.id, ip_address, expiry_hours)

        # Build reset link
        reset_link = f"{settings.FRONTEND_URL}/reset-password?token={reset_token.token}"

        # Prepare template variables
        # Note: user.first_name and user.last_name don't exist in current User model
        # Using email as fallback
        user_name = email.split('@')[0]  # Simple fallback
        template_variables = {
            "reset_link": reset_link,
            "user_name": user_name,
            "expiry_hours": expiry_hours
        }

        # Queue email
        await self.create_pending_email(
            template_id=template.id,
            recipient_email=email,
            language_code=language_code,
            template_variables=template_variables
        )

        logger.info(f"Password reset token created for user: {email} (expires in {expiry_hours} hours)")

        return True
