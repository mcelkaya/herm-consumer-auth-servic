from fastapi import APIRouter, Depends, status, Request, Response, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from app.db.session import get_db
from app.schemas.user import (
    UserSignup, UserLogin, TokenResponse,
    ForgotPasswordRequest, ForgotPasswordResponse,
    ResetPasswordRequest, ResetPasswordResponse,
    VerifyEmailRequest, VerifyEmailResponse,
)
from app.services.user_service import UserService
from app.services.token_service import TokenService, create_access_token
from app.services.forgot_password_service import ForgotPasswordService
from app.services.reset_password_service import ResetPasswordService
from app.services.email_verification_service import EmailVerificationService
from app.core.config import settings
from app.core.cookies import set_refresh_cookie
from app.core.audit_log import audit
from app.middleware.rate_limit import (
    rate_limit_forgot_password,
    rate_limit_reset_password,
    rate_limit_login,
    rate_limit_signup,
    rate_limit_verify_email,
)

router = APIRouter(prefix="/public/auth", tags=["Authentication"])


@router.post("/signup", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
async def signup(
    signup_data: UserSignup,
    request: Request,
    response: Response,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    _: None = Depends(rate_limit_signup)
) -> TokenResponse:
    device_info = request.headers.get("User-Agent")
    ip_address = request.client.host if request.client else None

    user_service = UserService(db)
    token_response = await user_service.signup(
        signup_data,
        device_info=device_info,
        ip_address=ip_address,
        background_tasks=background_tasks
    )

    set_refresh_cookie(response, token_response.refresh_token)

    return token_response


@router.post("/login", response_model=TokenResponse)
async def login(
    login_data: UserLogin,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
    _: None = Depends(rate_limit_login)
) -> TokenResponse:
    device_info = request.headers.get("User-Agent")
    ip_address = request.client.host if request.client else None

    user_service = UserService(db)
    token_response = await user_service.login(
        login_data,
        device_info=device_info,
        ip_address=ip_address
    )

    set_refresh_cookie(response, token_response.refresh_token)

    audit("login_success", ip=ip_address, email=login_data.email)
    response.headers["Content-Type"] = "application/json"
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"

    return token_response


@router.post("/forgot-password", response_model=ForgotPasswordResponse, status_code=status.HTTP_200_OK)
async def forgot_password(
    request_data: ForgotPasswordRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    _: None = Depends(rate_limit_forgot_password)
) -> ForgotPasswordResponse:
    import asyncio
    ip_address = request.client.host if request.client else None
    language = request_data.language or "en"

    service = ForgotPasswordService(db)
    await service.process_forgot_password(
        email=request_data.email,
        language=language,
        ip_address=ip_address,
        expiry_hours=24
    )

    await asyncio.sleep(0.5)
    return ForgotPasswordResponse()


@router.post("/reset-password", response_model=ResetPasswordResponse, status_code=status.HTTP_200_OK)
async def reset_password(
    request_data: ResetPasswordRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    _: None = Depends(rate_limit_reset_password)
) -> ResetPasswordResponse:
    ip_address = request.client.host if request.client else None

    service = ResetPasswordService(db)
    await service.reset_password(
        token=request_data.token,
        new_password=request_data.new_password,
        ip_address=ip_address
    )

    return ResetPasswordResponse()


@router.post("/verify-email", response_model=VerifyEmailResponse, status_code=status.HTTP_200_OK)
async def verify_email(
    body: VerifyEmailRequest,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
    _: None = Depends(rate_limit_verify_email),
) -> VerifyEmailResponse:
    ip_address = request.client.host if request.client else None
    device_info = request.headers.get("User-Agent")

    service = EmailVerificationService(db)
    result = await service.verify_email(
        token=body.token,
        ip_address=ip_address
    )

    # Alias verification → confirm ownership only, do not log the user in.
    # The user might be clicking the link from a different device or while
    # already signed in elsewhere; minting a new session would surprise them.
    if result.kind == "alias":
        return VerifyEmailResponse(
            kind="alias",
            alias_email=result.alias_email,
            message_key="auth.verifyEmail.aliasSuccess",
            message="Email address verified.",
        )

    user = result.user
    access_token = create_access_token(user)

    token_service = TokenService(db)
    refresh_token_obj = await token_service.create_refresh_token(
        user=user,
        device_info=device_info,
        ip_address=ip_address
    )

    set_refresh_cookie(response, refresh_token_obj.token)

    return VerifyEmailResponse(
        kind="primary",
        access_token=access_token,
        refresh_token=refresh_token_obj.token,
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
    )
