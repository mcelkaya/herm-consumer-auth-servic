from typing import Optional
from uuid import UUID
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.admin_user import AdminUser


class AdminUserRepository:
    """Repository for AdminUser database operations."""

    def __init__(self, db: AsyncSession) -> None:
        self.db = db

    async def get_by_id(self, admin_id: UUID) -> Optional[AdminUser]:
        """Fetch an admin user by primary key."""
        result = await self.db.execute(
            select(AdminUser).where(AdminUser.id == admin_id)
        )
        return result.scalar_one_or_none()

    async def get_by_email(self, email: str) -> Optional[AdminUser]:
        """Fetch an admin user by email address."""
        result = await self.db.execute(
            select(AdminUser).where(AdminUser.email == email)
        )
        return result.scalar_one_or_none()

    async def update(self, admin_user: AdminUser) -> AdminUser:
        """Persist changes to an AdminUser and return the refreshed instance."""
        self.db.add(admin_user)
        await self.db.flush()
        await self.db.refresh(admin_user)
        return admin_user