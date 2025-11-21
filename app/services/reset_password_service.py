from typing import Optional
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from datetime import datetime
from fastapi import HTTPException, status
from app.models.password_reset_token import PasswordResetToken
from app.models.user import User
from app.core.security import security_service
from app.services.token_service import TokenService
import logging

logger = logging.getLogger(__name__)


class ResetPasswordService:
    """Service for handling password reset functionality"""

    def __init__(self, db: AsyncSession):
        self.db = db
        self.token_service = TokenService(db)

    async def verify_reset_token(self, token: str) -> Optional[PasswordResetToken]:
        """
        Verify password reset token

        Returns:
            PasswordResetToken if valid, None otherwise
        """
        result = await self.db.execute(
            select(PasswordResetToken).where(PasswordResetToken.token == token)
        )
        reset_token = result.scalar_one_or_none()

        if not reset_token:
            logger.warning(f"Password reset attempted with non-existent token")
            return None

        if not reset_token.is_valid():
            logger.warning(
                f"Password reset attempted with invalid token for user {reset_token.user_id} "
                f"(expired: {reset_token.is_expired()}, used: {reset_token.is_used})"
            )
            return None

        return reset_token

    async def reset_password(
        self,
        token: str,
        new_password: str,
        ip_address: Optional[str] = None
    ) -> bool:
        """
        Reset user password using token

        Args:
            token: Password reset token
            new_password: New password (plain text, will be hashed)
            ip_address: IP address of requester for audit

        Returns:
            True if password was reset successfully

        Raises:
            HTTPException: If token is invalid or expired
        """
        # Verify token
        reset_token = await self.verify_reset_token(token)

        if not reset_token:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired password reset token"
            )

        # Get user
        result = await self.db.execute(
            select(User).where(User.id == reset_token.user_id)
        )
        user = result.scalar_one_or_none()

        if not user:
            logger.error(f"User not found for valid token: {reset_token.user_id}")
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )

        # Check if user is active
        if not user.is_active:
            logger.warning(f"Password reset attempted for inactive user: {user.email}")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="User account is inactive"
            )

        # Hash new password
        hashed_password = security_service.get_password_hash(new_password)

        # Update user password
        user.hashed_password = hashed_password
        self.db.add(user)

        # Mark token as used
        reset_token.is_used = True
        reset_token.used_at = datetime.utcnow()
        self.db.add(reset_token)

        # Revoke all refresh tokens for security (user needs to login again)
        await self.token_service.revoke_all_user_tokens(user.id)

        # Commit all changes
        await self.db.commit()

        logger.info(
            f"Password successfully reset for user: {user.email} "
            f"(from IP: {ip_address or 'unknown'})"
        )

        return True

    async def cleanup_expired_tokens(self) -> int:
        """
        Delete expired password reset tokens

        Returns:
            Number of tokens deleted
        """
        result = await self.db.execute(
            select(PasswordResetToken).where(
                PasswordResetToken.expires_at < datetime.utcnow()
            )
        )
        expired_tokens = result.scalars().all()

        for token in expired_tokens:
            await self.db.delete(token)

        await self.db.commit()

        logger.info(f"Cleaned up {len(expired_tokens)} expired password reset tokens")
        return len(expired_tokens)
