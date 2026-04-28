from datetime import datetime, timedelta
from typing import Optional
from uuid import UUID
from sqlalchemy import delete, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.config import settings
from app.core.security import security_service
from app.models.admin_user import AdminUser
from app.models.admin_refresh_token import AdminRefreshToken


class AdminTokenService:
    """Manages refresh tokens scoped to AdminUser sessions."""

    def __init__(self, db: AsyncSession) -> None:
        self.db = db

    async def create_refresh_token(
        self,
        admin_user: AdminUser,
        device_info: Optional[str] = None,
        ip_address: Optional[str] = None,
    ) -> AdminRefreshToken:
        """Issue a new refresh token for an admin user."""
        expires_delta = timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)

        refresh_token = AdminRefreshToken(
            token=AdminRefreshToken.generate_token(),
            admin_user_id=admin_user.id,
            expires_at=datetime.utcnow() + expires_delta,
            device_info=device_info,
            ip_address=ip_address,
        )

        self.db.add(refresh_token)
        await self.db.commit()
        await self.db.refresh(refresh_token)
        return refresh_token

    async def verify_refresh_token(self, token: str) -> Optional[AdminRefreshToken]:
        """Return the AdminRefreshToken if it exists and is valid, else None."""
        result = await self.db.execute(
            select(AdminRefreshToken)
            .options(selectinload(AdminRefreshToken.admin_user))
            .where(AdminRefreshToken.token == token)
        )
        refresh_token = result.scalar_one_or_none()

        if not refresh_token or not refresh_token.is_valid():
            return None

        return refresh_token

    async def revoke_refresh_token(self, token: str) -> bool:
        """Mark a single refresh token as revoked. Returns True if found."""
        result = await self.db.execute(
            select(AdminRefreshToken).where(AdminRefreshToken.token == token)
        )
        refresh_token = result.scalar_one_or_none()

        if refresh_token:
            refresh_token.is_revoked = True
            await self.db.commit()
            return True

        return False

    async def revoke_all_tokens_for_user(self, admin_user_id: UUID) -> None:
        """Revoke every active refresh token for the given admin user."""
        result = await self.db.execute(
            select(AdminRefreshToken).where(
                AdminRefreshToken.admin_user_id == admin_user_id,
                AdminRefreshToken.is_revoked == False,  # noqa: E712
            )
        )
        for token in result.scalars().all():
            token.is_revoked = True

        await self.db.commit()

    async def cleanup_stale_tokens(self) -> int:
        """Delete revoked and expired admin refresh tokens in a single bulk query."""
        result = await self.db.execute(
            delete(AdminRefreshToken).where(
                or_(
                    AdminRefreshToken.is_revoked == True,  # noqa: E712
                    AdminRefreshToken.expires_at < datetime.utcnow(),
                )
            )
        )
        await self.db.commit()
        return result.rowcount


def create_admin_access_token(admin_user: AdminUser) -> str:
    """
    Mint a JWT access token for an admin user.

    The payload includes `role` so downstream services can gate on it
    without an extra DB call, and `is_admin=True` as an explicit marker
    that makes it impossible to accidentally accept this token in the
    consumer auth dependency.
    """
    return security_service.create_access_token(
        data={
            "sub": str(admin_user.id),
            "email": admin_user.email,
            "role": admin_user.role,
            "is_admin": True,  # hard marker — consumer dep will reject this token
        }
    )