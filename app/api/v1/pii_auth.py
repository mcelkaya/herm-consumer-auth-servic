from datetime import datetime, timezone
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Cookie, Depends, HTTPException, Request, Response, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.dependencies import get_blocklist, get_current_user
from app.core.config import settings
from app.core.security import security_service
from app.core.audit_log import audit
from app.db.session import get_db
from app.models.user import User
from app.schemas.user import (
    EmailAliasAddRequest,
    EmailAliasResponse,
    EmailEntryResponse,
    EmailListResponse,
    LanguagePreference,
    RefreshTokenRequest,
    ResendAliasVerificationResponse,
    TokenResponse,
    UserResponse,
)
from app.services.email_alias_service import EmailAliasService
from app.services.email_verification_service import EmailVerificationService
from app.services.token_blocklist_service import TokenBlocklistService
from app.services.token_service import TokenService, create_access_token
from app.middleware.rate_limit import (
    assert_alias_add_quota,
    assert_alias_resend_quota,
    rate_limit_resend_verification,
    record_alias_add,
)

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
    body: Optional[LanguagePreference] = None,
    _: None = Depends(rate_limit_resend_verification)
):
    if current_user.is_verified:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email is already verified"
        )

    ip_address = request.client.host if request.client else None
    language = (body.language if body else None) or "en"

    service = EmailVerificationService(db)
    await service.send_verification_email(
        user=current_user,
        language=language,
        ip_address=ip_address
    )

    from app.schemas.user import ResendVerificationResponse
    return ResendVerificationResponse()


# =============================================================================
# Email aliases — secondary emails on the current user's account
#
# All endpoints require a Bearer JWT (get_current_user). The user can only see
# and mutate their own aliases. The primary email (users.email) is exposed
# read-only in the list endpoint; it cannot be changed or removed here.
#
#   GET    /pii/auth/emails
#     → list of all emails on the account (primary + aliases) with status
#
#   POST   /pii/auth/emails
#     → add a new alias and send a verification email to it.
#       Body: {email, language?}
#       Limit: at most 3 new aliases per user per rolling 24h (only successful
#       adds count). 429 when exceeded.
#
#   POST   /pii/auth/emails/{alias_id}/resend-verification
#     → re-send the verification email for an unverified alias.
#       Body: {language?}
#       Limit: per-alias (3 / 15 min, keyed by alias id) AND the shared IP
#       resend limit. 429 when exceeded.
#
#   DELETE /pii/auth/emails/{alias_id}
#     → remove an alias from the account. Primary cannot be removed (it has
#       no alias_id). 404 if the alias doesn't belong to the caller.
# =============================================================================


@router.get("/emails", response_model=EmailListResponse)
async def list_emails(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> EmailListResponse:
    service = EmailAliasService(db)
    aliases = await service.list_for_user(current_user)

    entries: list[EmailEntryResponse] = [
        EmailEntryResponse(
            id=None,
            email=current_user.email,
            is_verified=current_user.is_verified,
            is_primary=True,
            verified_at=None,
            created_at=current_user.created_at,
        )
    ]
    for alias in aliases:
        entries.append(
            EmailEntryResponse(
                id=alias.id,
                email=alias.email,
                is_verified=alias.is_verified,
                is_primary=False,
                verified_at=alias.verified_at,
                created_at=alias.created_at,
            )
        )
    return EmailListResponse(emails=entries)


@router.post(
    "/emails",
    response_model=EmailAliasResponse,
    status_code=status.HTTP_201_CREATED,
)
async def add_email_alias(
    payload: EmailAliasAddRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> EmailAliasResponse:
    await assert_alias_add_quota(request, str(current_user.id))

    ip_address = request.client.host if request.client else None
    service = EmailAliasService(db)
    alias = await service.add_alias(
        user=current_user,
        email=str(payload.email),
        language=payload.language or "en",
        ip_address=ip_address,
    )
    # Count only after a successful create + queued email.
    await record_alias_add(request, str(current_user.id))
    audit("email_alias_added", ip=ip_address, user_id=str(current_user.id))
    return EmailAliasResponse.model_validate(alias)


@router.post(
    "/emails/{alias_id}/resend-verification",
    response_model=ResendAliasVerificationResponse,
)
async def resend_alias_verification(
    alias_id: UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    body: Optional[LanguagePreference] = None,
    _: None = Depends(rate_limit_resend_verification),
) -> ResendAliasVerificationResponse:
    ip_address = request.client.host if request.client else None
    language = (body.language if body else None) or "en"

    service = EmailAliasService(db)
    # Confirm ownership BEFORE counting against the per-alias quota, so a
    # guessed alias id can't be used to drain another user's resend budget.
    alias = await service.get_for_user(current_user, alias_id)
    if alias.is_verified:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="This email is already verified",
        )

    await assert_alias_resend_quota(request, str(alias_id))

    await service.verification_service.send_alias_verification_email(
        user=current_user,
        alias=alias,
        language=language,
        ip_address=ip_address,
    )
    return ResendAliasVerificationResponse()


@router.delete("/emails/{alias_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_email_alias(
    alias_id: UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    service = EmailAliasService(db)
    await service.remove_alias(current_user, alias_id)
    ip_address = request.client.host if request.client else None
    audit("email_alias_removed", ip=ip_address, user_id=str(current_user.id))
    return Response(status_code=status.HTTP_204_NO_CONTENT)