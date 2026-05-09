from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Cookie, Depends, HTTPException, Request, Response, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.dependencies import get_blocklist, get_current_user
from app.core.config import settings
from app.core.security import security_service
from app.core.audit_log import audit
from app.db.session import get_db
from app.models.user import User
from app.schemas.user import TokenResponse, UserResponse, RefreshTokenRequest
from app.services.token_service import TokenService, create_access_token
from app.services.email_verification_service import EmailVerificationService
from app.services.token_blocklist_service import TokenBlocklistService
from app.middleware.rate_limit import rate_limit_resend_verification

router = APIRouter(prefix="/pii/auth", tags=["Authentication"])


def _blocklist_access_token(payload: dict | None, blocklist: TokenBlocklistService):
    async def _add():
        if not payload:
            return
        jti = payload.get("jti")
        exp = payload.get("exp")
        if not jti or not exp:
            return
        remaining = int(exp - datetime.now(timezone.utc).timestamp())
        if remaining > 0:
            await blocklist.add(jti, ttl_seconds=remaining)
    return _add()


@router.get("/me", response_model=UserResponse)
async def get_current_user_info(
    current_user: User = Depends(get_current_user)
) -> UserResponse:
    return UserResponse.model_validate(current_user)


@router.post("/refresh", response_model=TokenResponse)
async def refresh_access_token(
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
    refresh_token_cookie: Optional[str] = Cookie(None, alias="refresh_token"),
    body: Optional[RefreshTokenRequest] = None
) -> TokenResponse:
    token = refresh_token_cookie or (body.refresh_token if body else None)

    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token required"
        )

    token_service = TokenService(db)
    refresh_token_obj = await token_service.verify_refresh_token(token)

    if not refresh_token_obj:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token"
        )

    user = await db.get(User, refresh_token_obj.user_id)

    if not user:
        await token_service.revoke_refresh_token(token)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token"
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is inactive"
        )

    access_token = create_access_token(user)

    if settings.REFRESH_TOKEN_ROTATION_ENABLED:
        await token_service.revoke_refresh_token(token)

        device_info = request.headers.get("User-Agent")
        ip_address = request.client.host if request.client else None

        new_refresh_token = await token_service.create_refresh_token(
            user=user,
            device_info=device_info,
            ip_address=ip_address
        )

        response.set_cookie(
            key="refresh_token",
            value=new_refresh_token.token,
            httponly=True,
            secure=True,
            samesite="none",
            max_age=settings.REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60
        )

        return TokenResponse(
            access_token=access_token,
            refresh_token=new_refresh_token.token,
            expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
        )

    return TokenResponse(
        access_token=access_token,
        refresh_token=token,
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
    )


@router.post("/logout")
async def logout(
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
    refresh_token_cookie: Optional[str] = Cookie(None, alias="refresh_token"),
    body: Optional[RefreshTokenRequest] = None,
    current_user: User = Depends(get_current_user),
    blocklist: TokenBlocklistService = Depends(get_blocklist),
):
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        payload = security_service.decode_token(auth_header[7:])
        await _blocklist_access_token(payload, blocklist)

    token = refresh_token_cookie or (body.refresh_token if body else None)
    if token:
        token_service = TokenService(db)
        await token_service.revoke_refresh_token(token)

    ip_address = request.client.host if request.client else None
    audit("logout", ip=ip_address, user_id=str(current_user.id))
    response.delete_cookie(key="refresh_token")
    return {"message": "Logged out successfully"}


@router.post("/logout-all")
async def logout_all_devices(
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    blocklist: TokenBlocklistService = Depends(get_blocklist),
):
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        payload = security_service.decode_token(auth_header[7:])
        await _blocklist_access_token(payload, blocklist)

    token_service = TokenService(db)
    await token_service.revoke_all_user_tokens(current_user.id)

    ip_all = request.client.host if request.client else None
    audit("logout_all_devices", ip=ip_all, user_id=str(current_user.id))
    response.delete_cookie(key="refresh_token")
    return {"message": "Logged out from all devices"}


@router.post("/resend-verification")
async def resend_verification(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    _: None = Depends(rate_limit_resend_verification)
):
    if current_user.is_verified:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email is already verified"
        )

    ip_address = request.client.host if request.client else None
    accept_language = request.headers.get("Accept-Language", "en")
    language = accept_language.split(',')[0].split('-')[0]

    service = EmailVerificationService(db)
    await service.send_verification_email(
        user=current_user,
        language=language,
        ip_address=ip_address
    )

    from app.schemas.user import ResendVerificationResponse
    return ResendVerificationResponse()
