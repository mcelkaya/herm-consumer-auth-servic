from fastapi import APIRouter, Depends, Query, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from datetime import datetime, timedelta
from app.db.session import get_db
from app.schemas.user import ConnectedAppResponse, ConnectedAppCreate
from app.services.oauth_service import oauth_service
from app.services.connected_app_service import ConnectedAppService
from app.api.dependencies import get_current_user
from app.models.user import User

router = APIRouter(prefix="/oauth", tags=["OAuth"])


@router.get("/google/authorize")
async def google_authorize():
    """
    Get Google OAuth authorization URL
    
    Redirects user to Google for authentication
    """
    auth_url = oauth_service.get_google_auth_url()
    return {"authorization_url": auth_url}


@router.get("/google/callback", response_model=ConnectedAppResponse)
async def google_callback(
    code: str = Query(..., description="Authorization code from Google"),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
) -> ConnectedAppResponse:
    """
    Handle Google OAuth callback
    
    Exchanges authorization code for access token and connects the app
    """
    # Exchange code for tokens
    token_data = await oauth_service.exchange_google_code(code)
    
    # Get user info
    user_info = await oauth_service.get_google_user_info(token_data["access_token"])
    
    # Calculate token expiration
    expires_in = token_data.get("expires_in", 3600)
    token_expires_at = datetime.utcnow() + timedelta(seconds=expires_in)
    
    # Create connected app
    app_data = ConnectedAppCreate(
        provider="gmail",
        provider_email=user_info["email"],
        access_token=token_data["access_token"],
        refresh_token=token_data.get("refresh_token"),
        token_expires_at=token_expires_at
    )
    
    service = ConnectedAppService(db)
    return await service.connect_app(current_user.id, app_data)


@router.get("/microsoft/authorize")
async def microsoft_authorize():
    """
    Get Microsoft OAuth authorization URL
    
    Redirects user to Microsoft for authentication
    """
    auth_url = oauth_service.get_microsoft_auth_url()
    return {"authorization_url": auth_url}


@router.get("/microsoft/callback", response_model=ConnectedAppResponse)
async def microsoft_callback(
    code: str = Query(..., description="Authorization code from Microsoft"),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
) -> ConnectedAppResponse:
    """
    Handle Microsoft OAuth callback
    
    Exchanges authorization code for access token and connects the app
    """
    # Exchange code for tokens
    token_data = await oauth_service.exchange_microsoft_code(code)
    
    # Get user info
    user_info = await oauth_service.get_microsoft_user_info(token_data["access_token"])
    
    # Calculate token expiration
    expires_in = token_data.get("expires_in", 3600)
    token_expires_at = datetime.utcnow() + timedelta(seconds=expires_in)
    
    # Create connected app
    app_data = ConnectedAppCreate(
        provider="outlook",
        provider_email=user_info.get("mail") or user_info.get("userPrincipalName"),
        access_token=token_data["access_token"],
        refresh_token=token_data.get("refresh_token"),
        token_expires_at=token_expires_at
    )
    
    service = ConnectedAppService(db)
    return await service.connect_app(current_user.id, app_data)


@router.get("/yahoo/authorize")
async def yahoo_authorize():
    """
    Get Yahoo OAuth authorization URL
    
    Redirects user to Yahoo for authentication
    """
    auth_url = oauth_service.get_yahoo_auth_url()
    return {"authorization_url": auth_url}


@router.get("/yahoo/callback", response_model=ConnectedAppResponse)
async def yahoo_callback(
    code: str = Query(..., description="Authorization code from Yahoo"),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
) -> ConnectedAppResponse:
    """
    Handle Yahoo OAuth callback
    
    Exchanges authorization code for access token and connects the app
    """
    # Exchange code for tokens
    token_data = await oauth_service.exchange_yahoo_code(code)
    
    # Get user info
    user_info = await oauth_service.get_yahoo_user_info(token_data["access_token"])
    
    # Calculate token expiration
    expires_in = token_data.get("expires_in", 3600)
    token_expires_at = datetime.utcnow() + timedelta(seconds=expires_in)
    
    # Create connected app
    app_data = ConnectedAppCreate(
        provider="yahoo",
        provider_email=user_info["email"],
        access_token=token_data["access_token"],
        refresh_token=token_data.get("refresh_token"),
        token_expires_at=token_expires_at
    )
    
    service = ConnectedAppService(db)
    return await service.connect_app(current_user.id, app_data)
