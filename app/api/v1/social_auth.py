"""Public social sign-in / sign-up.

    POST /public/auth/social/{provider}
        Body: SocialAuthRequest
        - Verifies the provider credential server-side.
        - Logs in a returning social user, auto-links to a verified existing
          account, or creates a new account — see SocialAuthService.authenticate.
        - On success returns the same TokenResponse as password login and sets
          the refresh_token cookie identically.

    Error responses (JSON `detail` carries a stable `error_key`):
        401 auth.social.invalidToken          — credential failed verification
        409 auth.social.accountExistsNeedsLink — email belongs to an account we
            can't auto-link; user must log in with their existing method and
            link from settings. `provider` and `email` included for the UI.
        403                                    — account inactive
        500 auth.social.providerMisconfigured  — server-side provider config
"""

from fastapi import APIRouter, Depends, Request, Response, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.audit_log import audit
from app.core.config import settings
from app.db.session import get_db
from app.middleware.rate_limit import rate_limit_login
from app.schemas.social import SocialAuthRequest, SocialProvider
from app.schemas.user import TokenResponse
from app.services.social_auth_service import (
    AccountNeedsLinkingError,
    SocialAuthService,
)
from app.services.social_providers import SocialConfigError, SocialTokenError
from fastapi import HTTPException

router = APIRouter(prefix="/public/auth/social", tags=["Social Authentication"])


@router.post("/{provider}", response_model=TokenResponse)
async def social_auth(
    provider: SocialProvider,
    body: SocialAuthRequest,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
    _: None = Depends(rate_limit_login),
) -> TokenResponse:
    device_info = request.headers.get("User-Agent")
    ip_address = request.client.host if request.client else None

    service = SocialAuthService(db)
    try:
        result = await service.authenticate(
            provider=provider.value,
            credential=body.credential,
            credential_type=body.credential_type.value if body.credential_type else None,
            nonce=body.nonce,
            referral_code=body.referral_code,
            marketing_consent=body.marketing_consent,
            utm=body.utm_dict(),
            device_info=device_info,
            ip_address=ip_address,
        )
    except SocialTokenError:
        audit("social_auth_invalid_token", ip=ip_address, provider=provider.value)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error_key": "auth.social.invalidToken"},
        )
    except SocialConfigError:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error_key": "auth.social.providerMisconfigured"},
        )
    except AccountNeedsLinkingError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "error_key": "auth.social.accountExistsNeedsLink",
                "provider": exc.provider,
                "email": exc.email,
            },
        )

    response.set_cookie(
        key="refresh_token",
        value=result.tokens.refresh_token,
        httponly=True,
        secure=True,
        samesite="none",
        max_age=settings.REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60,
    )

    audit(
        "social_signup_success" if result.created else "social_login_success",
        ip=ip_address,
        provider=provider.value,
        user_id=str(result.user.id),
    )
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
    return result.tokens