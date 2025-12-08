from datetime import datetime, timedelta
from typing import Optional
from uuid import UUID
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.security import security_service
from app.models.refresh_token import RefreshToken
from app.models.user import User
from app.core.config import settings


class TokenService:
    """Service for managing refresh tokens"""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def create_refresh_token(
        self,
        user: User,
        device_info: Optional[str] = None,
        ip_address: Optional[str] = None
    ) -> RefreshToken:
        """Create a new refresh token for a user"""
        expires_delta = timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)

        refresh_token = RefreshToken(
            token=RefreshToken.generate_token(),
            user_id=user.id,
            expires_at=datetime.utcnow() + expires_delta,
            device_info=device_info,
            ip_address=ip_address
        )

        self.db.add(refresh_token)
        await self.db.commit()
        await self.db.refresh(refresh_token)

        return refresh_token

    async def verify_refresh_token(self, token: str) -> Optional[RefreshToken]:
        """Verify and return a refresh token if valid"""
        result = await self.db.execute(
            select(RefreshToken).where(RefreshToken.token == token)
        )
        refresh_token = result.scalar_one_or_none()

        if not refresh_token or not refresh_token.is_valid():
            return None

        return refresh_token

    async def revoke_refresh_token(self, token: str) -> bool:
        """Revoke a specific refresh token"""
        result = await self.db.execute(
            select(RefreshToken).where(RefreshToken.token == token)
        )
        refresh_token = result.scalar_one_or_none()

        if refresh_token:
            refresh_token.is_revoked = True
            await self.db.commit()
            return True

        return False

    async def revoke_all_user_tokens(self, user_id: UUID):
        """Revoke all refresh tokens for a user"""
        result = await self.db.execute(
            select(RefreshToken).where(
                RefreshToken.user_id == user_id,
                RefreshToken.is_revoked == False
            )
        )
        tokens = result.scalars().all()

        for token in tokens:
            token.is_revoked = True

        await self.db.commit()

    async def cleanup_expired_tokens(self):
        """Delete expired refresh tokens"""
        result = await self.db.execute(
            select(RefreshToken).where(
                RefreshToken.expires_at < datetime.utcnow()
            )
        )
        expired_tokens = result.scalars().all()

        for token in expired_tokens:
            await self.db.delete(token)

        await self.db.commit()
        return len(expired_tokens)


def create_access_token(user: User) -> str:
    """Create an access token for a user"""
    return security_service.create_access_token(
        data={"sub": str(user.id), "email": user.email, "role": user.role}
    )
