from datetime import datetime, timedelta, timezone
from typing import Optional
from uuid import UUID
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.user import User


class UserRepository:
    """Repository for User database operations"""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def get_registration_counts(self) -> dict:
        """User registration counts for the last 24h / 7d / 30d and total (rolling window)."""
        now = datetime.now(timezone.utc)
        result = await self.db.execute(
            select(
                func.count().filter(User.created_at >= now - timedelta(days=1)).label("daily"),
                func.count().filter(User.created_at >= now - timedelta(days=7)).label("weekly"),
                func.count().filter(User.created_at >= now - timedelta(days=30)).label("monthly"),
                func.count().label("total"),
            )
        )
        row = result.one()
        return {"daily": row.daily, "weekly": row.weekly, "monthly": row.monthly, "total": row.total}

    async def create(
        self,
        email: str,
        hashed_password: str,
        marketing_consent: bool = False,
        utm_source: Optional[str] = None,
        utm_medium: Optional[str] = None,
        utm_campaign: Optional[str] = None,
        utm_term: Optional[str] = None,
        utm_content: Optional[str] = None,
    ) -> User:
        """Create a new user"""
        user = User(
            email=email,
            hashed_password=hashed_password,
            marketing_consent=marketing_consent,
            utm_source=utm_source,
            utm_medium=utm_medium,
            utm_campaign=utm_campaign,
            utm_term=utm_term,
            utm_content=utm_content,
        )
        self.db.add(user)
        await self.db.flush()
        await self.db.refresh(user)
        return user
    
    async def get_by_id(self, user_id: UUID) -> Optional[User]:
        """Get user by ID"""
        result = await self.db.execute(
            select(User).where(User.id == user_id)
        )
        return result.scalar_one_or_none()
    
    async def get_by_email(self, email: str) -> Optional[User]:
        """Get user by email"""
        result = await self.db.execute(
            select(User).where(User.email == email)
        )
        return result.scalar_one_or_none()
    
    async def update(self, user: User) -> User:
        """Update user"""
        self.db.add(user)
        await self.db.flush()
        await self.db.refresh(user)
        return user
    
    async def delete(self, user: User) -> None:
        """Delete user"""
        await self.db.delete(user)
        await self.db.flush()