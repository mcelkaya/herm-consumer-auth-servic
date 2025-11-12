from typing import Optional
from uuid import UUID
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.user import User


class UserRepository:
    """Repository for User database operations"""
    
    def __init__(self, db: AsyncSession):
        self.db = db
    
    async def create(self, email: str, hashed_password: str) -> User:
        """Create a new user"""
        user = User(email=email, hashed_password=hashed_password)
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
