from typing import Optional
from sqlalchemy import select, update
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
        # Consume the token atomically: the conditional UPDATE row-locks it, so
        # of N concurrent requests with the same token exactly one matches
        # `is_used = false`; the rest re-check after it commits and get 0 rows.
        now = datetime.utcnow()
        consumed = await self.db.execute(
            update(PasswordResetToken)
            .where(
                PasswordResetToken.token_hash == PasswordResetToken.hash_token(token),
                PasswordResetToken.is_used == False,  # noqa: E712
                PasswordResetToken.expires_at > now,
            )
            .values(is_used=True, used_at=now)
            .returning(PasswordResetToken.user_id)
            .execution_options(synchronize_session=False)
        )
        user_id = consumed.scalar_one_or_none()

        if user_id is None:
            logger.warning("Password reset attempted with invalid, expired or used token")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired password reset token"
            )

        # Get user
        result = await self.db.execute(
            select(User).where(User.id == user_id)
        )
        user = result.scalar_one_or_none()

        if not user:
            await self.db.rollback()
            logger.error(f"User not found for valid token: {user_id}")
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )

        # Check if user is active (roll back so the token is not consumed)
        if not user.is_active:
            await self.db.rollback()
            logger.warning(f"Password reset attempted for inactive user_id={user_id}")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="User account is inactive"
            )

        # Hash new password
        hashed_password = security_service.get_password_hash(new_password)

        # Update user password
        user.hashed_password = hashed_password
        self.db.add(user)

        # Revoke all refresh tokens for security (user needs to login again)
        await self.token_service.revoke_all_user_tokens(user.id)

        # Commit all changes
        await self.db.commit()

        logger.info(
            f"Password successfully reset for user_id={user.id}"
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
