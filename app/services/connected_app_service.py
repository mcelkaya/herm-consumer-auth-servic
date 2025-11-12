from typing import List
from uuid import UUID
from fastapi import HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from app.repositories.connected_app_repository import ConnectedAppRepository
from app.schemas.user import ConnectedAppCreate, ConnectedAppResponse, ConnectedAppsList
from app.models.connected_app import ConnectedApp


class ConnectedAppService:
    """Service for connected app business logic"""
    
    def __init__(self, db: AsyncSession):
        self.db = db
        self.connected_app_repo = ConnectedAppRepository(db)
    
    async def connect_app(
        self, user_id: UUID, app_data: ConnectedAppCreate
    ) -> ConnectedAppResponse:
        """Connect a new email provider app"""
        # Check if app already connected for this provider
        existing_app = await self.connected_app_repo.get_by_user_and_provider(
            user_id, app_data.provider
        )
        
        if existing_app:
            # Update existing connection
            existing_app.provider_email = app_data.provider_email
            existing_app.access_token = app_data.access_token
            existing_app.refresh_token = app_data.refresh_token
            existing_app.token_expires_at = app_data.token_expires_at
            
            connected_app = await self.connected_app_repo.update(existing_app)
        else:
            # Create new connection
            connected_app = await self.connected_app_repo.create(
                user_id=user_id,
                provider=app_data.provider,
                provider_email=app_data.provider_email,
                access_token=app_data.access_token,
                refresh_token=app_data.refresh_token,
                token_expires_at=app_data.token_expires_at
            )
        
        return ConnectedAppResponse.model_validate(connected_app)
    
    async def list_connected_apps(self, user_id: UUID) -> ConnectedAppsList:
        """List all connected apps for a user"""
        apps = await self.connected_app_repo.get_by_user_id(user_id)
        
        return ConnectedAppsList(
            apps=[ConnectedAppResponse.model_validate(app) for app in apps],
            total=len(apps)
        )
    
    async def delete_connected_app(self, user_id: UUID, app_id: UUID) -> None:
        """Delete a connected app"""
        connected_app = await self.connected_app_repo.get_by_id(app_id)
        
        if not connected_app:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Connected app not found"
            )
        
        # Verify ownership
        if connected_app.user_id != user_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not authorized to delete this app"
            )
        
        await self.connected_app_repo.delete(connected_app)
