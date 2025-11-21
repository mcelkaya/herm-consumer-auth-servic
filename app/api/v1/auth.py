from fastapi import APIRouter, Depends, status, Request, Response, Cookie
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Optional
from app.db.session import get_db
from app.schemas.user import (
    UserSignup, UserLogin, TokenResponse, UserResponse,
    RefreshTokenRequest, ForgotPasswordRequest, ForgotPasswordResponse
)
from app.services.user_service import UserService
from app.services.token_service import TokenService, create_access_token
from app.services.forgot_password_service import ForgotPasswordService
from app.api.dependencies import get_current_user
from app.models.user import User
from app.core.config import settings

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post("/signup", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
async def signup(
    signup_data: UserSignup,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db)
) -> TokenResponse:
    """
    Register a new user account

    - **email**: Valid email address
    - **password**: Password (minimum 8 characters)
    """
    # Get device info and IP
    device_info = request.headers.get("User-Agent")
    ip_address = request.client.host if request.client else None

    user_service = UserService(db)
    token_response = await user_service.signup(
        signup_data,
        device_info=device_info,
        ip_address=ip_address
    )

    # Set refresh token as HttpOnly cookie (RECOMMENDED for security)
    response.set_cookie(
        key="refresh_token",
        value=token_response.refresh_token,
        httponly=True,  # Cannot be accessed by JavaScript
        secure=True,    # Only sent over HTTPS
        samesite="lax", # CSRF protection
        max_age=settings.REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60
    )

    return token_response


@router.post("/login", response_model=TokenResponse)
async def login(
    login_data: UserLogin,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db)
) -> TokenResponse:
    """
    Authenticate user and get access tokens

    - **email**: User's email address
    - **password**: User's password
    """
    # Get device info and IP
    device_info = request.headers.get("User-Agent")
    ip_address = request.client.host if request.client else None

    user_service = UserService(db)
    token_response = await user_service.login(
        login_data,
        device_info=device_info,
        ip_address=ip_address
    )

    # Set refresh token as HttpOnly cookie (RECOMMENDED for security)
    response.set_cookie(
        key="refresh_token",
        value=token_response.refresh_token,
        httponly=True,  # Cannot be accessed by JavaScript
        secure=True,    # Only sent over HTTPS
        samesite="lax", # CSRF protection
        max_age=settings.REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60
    )

    return token_response


@router.get("/me", response_model=UserResponse)
async def get_current_user_info(
    current_user: User = Depends(get_current_user)
) -> UserResponse:
    """
    Get current authenticated user information
    """
    return UserResponse.model_validate(current_user)


@router.post("/refresh", response_model=TokenResponse)
async def refresh_access_token(
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
    refresh_token_cookie: Optional[str] = Cookie(None, alias="refresh_token"),
    body: Optional[RefreshTokenRequest] = None
) -> TokenResponse:
    """
    Refresh access token using refresh token

    Accepts refresh token from:
    1. HttpOnly cookie (recommended for web apps)
    2. Request body (for mobile apps)
    """
    from fastapi import HTTPException

    # Get refresh token from cookie or body
    token = refresh_token_cookie or (body.refresh_token if body else None)

    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token required"
        )

    # Verify refresh token
    token_service = TokenService(db)
    refresh_token_obj = await token_service.verify_refresh_token(token)

    if not refresh_token_obj:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token"
        )

    user = refresh_token_obj.user

    # Create new access token
    access_token = create_access_token(user)

    # Optional: Token Rotation (RECOMMENDED for security)
    if settings.REFRESH_TOKEN_ROTATION_ENABLED:
        # Revoke old refresh token
        await token_service.revoke_refresh_token(token)

        # Create new refresh token
        device_info = request.headers.get("User-Agent")
        ip_address = request.client.host if request.client else None

        new_refresh_token = await token_service.create_refresh_token(
            user=user,
            device_info=device_info,
            ip_address=ip_address
        )

        # Set new refresh token cookie
        response.set_cookie(
            key="refresh_token",
            value=new_refresh_token.token,
            httponly=True,
            secure=True,
            samesite="lax",
            max_age=settings.REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60
        )

        return TokenResponse(
            access_token=access_token,
            refresh_token=new_refresh_token.token,
            expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
        )
    else:
        # Reuse same refresh token
        return TokenResponse(
            access_token=access_token,
            refresh_token=token,
            expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
        )


@router.post("/logout")
async def logout(
    response: Response,
    db: AsyncSession = Depends(get_db),
    refresh_token_cookie: Optional[str] = Cookie(None, alias="refresh_token"),
    body: Optional[RefreshTokenRequest] = None,
    current_user: User = Depends(get_current_user)
):
    """
    Logout user by revoking refresh token

    Accepts refresh token from cookie or body
    """
    token = refresh_token_cookie or (body.refresh_token if body else None)

    if token:
        token_service = TokenService(db)
        await token_service.revoke_refresh_token(token)

    # Clear refresh token cookie
    response.delete_cookie(key="refresh_token")

    return {"message": "Logged out successfully"}


@router.post("/logout-all")
async def logout_all_devices(
    response: Response,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Logout from all devices by revoking all user's refresh tokens
    """
    token_service = TokenService(db)
    await token_service.revoke_all_user_tokens(current_user.id)

    # Clear refresh token cookie
    response.delete_cookie(key="refresh_token")

    return {"message": "Logged out from all devices"}


@router.post("/forgot-password", response_model=ForgotPasswordResponse, status_code=status.HTTP_200_OK)
async def forgot_password(
    request_data: ForgotPasswordRequest,
    request: Request,
    db: AsyncSession = Depends(get_db)
) -> ForgotPasswordResponse:
    """
    Send password reset email if account exists.

    SECURITY NOTE: Always returns 200 to prevent email enumeration.
    Never reveals whether an email exists in the system.

    - **email**: Email address to send reset link to
    """
    # Get client IP for audit trail
    ip_address = request.client.host if request.client else None

    # Process request (returns True/False but we ignore it for security)
    service = ForgotPasswordService(db)
    await service.process_forgot_password(
        email=request_data.email,
        ip_address=ip_address,
        expiry_hours=24  # Token valid for 24 hours
    )

    # ALWAYS return success message (don't reveal if email exists)
    return ForgotPasswordResponse()
