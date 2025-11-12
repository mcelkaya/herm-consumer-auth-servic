from typing import List, Optional
from uuid import UUID
from datetime import datetime
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.connected_app import ConnectedApp


class ConnectedAppRepository:
    """Repository for ConnectedApp database operations"""
    
    def __init__(self, db: AsyncSession):
        self.db = db
    
    async def create(
        self,
        user_id: UUID,
        provider: str,
        provider_email: str,
        access_token: str,
        refresh_token: Optional[str] = None,
        token_expires_at: Optional[datetime] = None
    ) -> ConnectedApp:
        """Create a new connected app"""
        connected_app = ConnectedApp(
            user_id=user_id,
            provider=provider,
            provider_email=provider_email,
            access_token=access_token,
            refresh_token=refresh_token,
            token_expires_at=token_expires_at
        )
        self.db.add(connected_app)
        await self.db.flush()
        await self.db.refresh(connected_app)
        return connected_app
    
    async def get_by_id(self, app_id: UUID) -> Optional[ConnectedApp]:
        """Get connected app by ID"""
        result = await self.db.execute(
            select(ConnectedApp).where(ConnectedApp.id == app_id)
        )
        return result.scalar_one_or_none()
    
    async def get_by_user_id(self, user_id: UUID) -> List[ConnectedApp]:
        """Get all connected apps for a user"""
        result = await self.db.execute(
            select(ConnectedApp).where(ConnectedApp.user_id == user_id)
        )
        return list(result.scalars().all())
    
    async def get_by_user_and_provider(
        self, user_id: UUID, provider: str
    ) -> Optional[ConnectedApp]:
        """Get connected app by user and provider"""
        result = await self.db.execute(
            select(ConnectedApp).where(
                ConnectedApp.user_id == user_id,
                ConnectedApp.provider == provider
            )
        )
        return result.scalar_one_or_none()
    
    async def update(self, connected_app: ConnectedApp) -> ConnectedApp:
        """Update connected app"""
        self.db.add(connected_app)
        await self.db.flush()
        await self.db.refresh(connected_app)
        return connected_app
    
    async def delete(self, connected_app: ConnectedApp) -> None:
        """Delete connected app"""
        await self.db.delete(connected_app)
        await self.db.flush()
