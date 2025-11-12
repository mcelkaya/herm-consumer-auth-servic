from fastapi import APIRouter, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession
from uuid import UUID
from app.db.session import get_db
from app.schemas.user import (
    ConnectedAppCreate,
    ConnectedAppResponse,
    ConnectedAppsList,
    MessageResponse
)
from app.services.connected_app_service import ConnectedAppService
from app.api.dependencies import get_current_user
from app.models.user import User

router = APIRouter(prefix="/connected-apps", tags=["Connected Apps"])


@router.post("", response_model=ConnectedAppResponse, status_code=status.HTTP_201_CREATED)
async def connect_app(
    app_data: ConnectedAppCreate,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
) -> ConnectedAppResponse:
    """
    Connect an email provider app (Gmail, Outlook, Yahoo)
    
    - **provider**: Email provider (gmail, outlook, yahoo)
    - **provider_email**: Email address for the provider
    - **access_token**: OAuth access token
    - **refresh_token**: OAuth refresh token (optional)
    - **token_expires_at**: Token expiration timestamp (optional)
    """
    service = ConnectedAppService(db)
    return await service.connect_app(current_user.id, app_data)


@router.get("", response_model=ConnectedAppsList)
async def list_connected_apps(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
) -> ConnectedAppsList:
    """
    Get list of all connected apps for the current user
    """
    service = ConnectedAppService(db)
    return await service.list_connected_apps(current_user.id)


@router.delete("/{app_id}", response_model=MessageResponse)
async def delete_connected_app(
    app_id: UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
) -> MessageResponse:
    """
    Delete a connected app
    
    - **app_id**: UUID of the connected app to delete
    """
    service = ConnectedAppService(db)
    await service.delete_connected_app(current_user.id, app_id)
    return MessageResponse(message="Connected app deleted successfully")
