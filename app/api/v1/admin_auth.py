from typing import Optional

from fastapi import APIRouter, Cookie, Depends, HTTPException, Request, Response, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.dependencies import get_blocklist
from app.core.config import settings
from app.core.security import security_service
from app.db.session import get_db
from app.models.admin_user import AdminUser
from app.schemas.admin import (
    AdminLogin,
    AdminRefreshTokenRequest,
    AdminTokenResponse,
    AdminUserResponse,
)
from app.services.admin_auth_service import AdminAuthService
from app.services.admin_token_service import AdminTokenService, create_admin_access_token
from app.services.token_blocklist_service import TokenBlocklistService

router = APIRouter(prefix="/admin/auth", tags=["Admin Authentication"])

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

_COOKIE_KEY = "admin_refresh_token"


def _set_refresh_cookie(response: Response, token: str) -> None:
    """Write the admin refresh token as a secure HttpOnly cookie."""
    response.set_cookie(
        key=_COOKIE_KEY,
        value=token,
        httponly=True,
        secure=True,
        samesite="none",
        max_age=settings.REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60,
    )


async def _blocklist_access_token(
    raw_token: str,
    blocklist: TokenBlocklistService,
) -> None:
    """Add a JWT's jti to the Redis blocklist for its remaining TTL."""
    from datetime import datetime, timezone

    payload = security_service.decode_token(raw_token)
    if not payload:
        return

    jti = payload.get("jti")
    exp = payload.get("exp")
    if not jti or not exp:
        return

    remaining = int(exp - datetime.now(timezone.utc).timestamp())
    if remaining > 0:
        await blocklist.add(jti, ttl_seconds=remaining)


# ---------------------------------------------------------------------------
# Dependency: resolve the current admin from a Bearer token
# ---------------------------------------------------------------------------

async def get_current_admin(
    request: Request,
    db: AsyncSession = Depends(get_db),
    blocklist: TokenBlocklistService = Depends(get_blocklist),
) -> AdminUser:
    """
    Validate the Bearer token in Authorization header and return the AdminUser.

    Rejects tokens that:
    - are missing or malformed
    - have been blocklisted (logout)
    - belong to a non-admin (consumer token accidentally used here)
    - reference a deleted or deactivated admin account
    """
    from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
    from uuid import UUID
    from app.repositories.admin_user_repository import AdminUserRepository

    credentials_exc = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate admin credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        raise credentials_exc

    raw_token = auth_header[7:]
    payload = security_service.decode_token(raw_token)
    if not payload:
        raise credentials_exc

    # Blocklist check
    jti = payload.get("jti")
    if jti and await blocklist.is_blocked(jti):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has been revoked",
        )

    # Reject consumer tokens passed to admin endpoints
    if not payload.get("is_admin"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required",
        )

    admin_id = payload.get("sub")
    if not admin_id:
        raise credentials_exc

    repo = AdminUserRepository(db)
    admin_user = await repo.get_by_id(UUID(admin_id))

    if not admin_user or not admin_user.is_active:
        raise credentials_exc

    return admin_user


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("/login", response_model=AdminTokenResponse)
async def admin_login(
    credentials: AdminLogin,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
) -> AdminTokenResponse:
    """
    Authenticate an admin user and issue a token pair.

    - **email**: Admin's email address
    - **password**: Admin's password

    The refresh token is set as a secure HttpOnly cookie **and** returned
    in the body so CLI / non-browser clients can store it themselves.

    No registration or password-reset flow exists here; admin accounts
    are managed directly in the database.
    """
    device_info = request.headers.get("User-Agent")
    ip_address = request.client.host if request.client else None

    service = AdminAuthService(db)
    token_response = await service.login(
        credentials,
        device_info=device_info,
        ip_address=ip_address,
    )

    _set_refresh_cookie(response, token_response.refresh_token)

    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
    return token_response


@router.post("/refresh", response_model=AdminTokenResponse)
async def admin_refresh(
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
    refresh_token_cookie: Optional[str] = Cookie(None, alias=_COOKIE_KEY),
    body: Optional[AdminRefreshTokenRequest] = None,
) -> AdminTokenResponse:
    """
    Issue a new access token (and optionally rotate the refresh token).

    Accepts the refresh token from:
    1. HttpOnly cookie — recommended for browser-based dashboards
    2. Request body — for CLI or mobile admin clients
    """
    token = refresh_token_cookie or (body.refresh_token if body else None)

    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token required",
        )

    token_service = AdminTokenService(db)
    refresh_token_obj = await token_service.verify_refresh_token(token)

    if not refresh_token_obj:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token",
        )

    admin_user = refresh_token_obj.admin_user

    # Ensure the admin account is still active at refresh time.
    if not admin_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin account is deactivated",
        )

    access_token = create_admin_access_token(admin_user)

    if settings.REFRESH_TOKEN_ROTATION_ENABLED:
        await token_service.revoke_refresh_token(token)

        device_info = request.headers.get("User-Agent")
        ip_address = request.client.host if request.client else None

        new_refresh_token = await token_service.create_refresh_token(
            admin_user=admin_user,
            device_info=device_info,
            ip_address=ip_address,
        )

        _set_refresh_cookie(response, new_refresh_token.token)

        return AdminTokenResponse(
            access_token=access_token,
            refresh_token=new_refresh_token.token,
            expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        )
    else:
        return AdminTokenResponse(
            access_token=access_token,
            refresh_token=token,
            expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        )


@router.post("/logout")
async def admin_logout(
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
    refresh_token_cookie: Optional[str] = Cookie(None, alias=_COOKIE_KEY),
    body: Optional[AdminRefreshTokenRequest] = None,
    current_admin: AdminUser = Depends(get_current_admin),
    blocklist: TokenBlocklistService = Depends(get_blocklist),
):
    """
    Logout the current admin session.

    - Blocklists the current access token for its remaining TTL.
    - Revokes the refresh token (cookie or body).
    - Clears the refresh token cookie.
    """
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        await _blocklist_access_token(auth_header[7:], blocklist)

    token = refresh_token_cookie or (body.refresh_token if body else None)
    if token:
        token_service = AdminTokenService(db)
        await token_service.revoke_refresh_token(token)

    response.delete_cookie(key=_COOKIE_KEY)
    return {"message": "Logged out successfully"}


@router.get("/me", response_model=AdminUserResponse)
async def admin_me(
    current_admin: AdminUser = Depends(get_current_admin),
) -> AdminUserResponse:
    """
    Return the profile of the currently authenticated admin user.
    """
    return AdminUserResponse.model_validate(current_admin)