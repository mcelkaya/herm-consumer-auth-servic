from typing import Optional
from uuid import UUID
from fastapi import HTTPException, status, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
import httpx
from app.repositories.user_repository import UserRepository
from app.core.security import security_service
from app.schemas.user import UserSignup, UserLogin, TokenResponse
from app.models.user import User
from app.services.token_service import TokenService, create_access_token
from app.services.email_verification_service import EmailVerificationService
from app.services.email_otp_service import EmailOtpService
from app.core.config import settings
import logging

logger = logging.getLogger(__name__)


class UserService:
    """Service for user business logic"""
    
    def __init__(self, db: AsyncSession):
        self.db = db
        self.user_repo = UserRepository(db)
        self.token_service = TokenService(db)
        self.otp_service = EmailOtpService(db)

    async def signup(
        self,
        signup_data: UserSignup,
        device_info: Optional[str] = None,
        ip_address: Optional[str] = None,
        background_tasks: Optional[BackgroundTasks] = None
    ) -> TokenResponse:
        """Register a new user"""
        # Check if user already exists
        existing_user = await self.user_repo.get_by_email(signup_data.email)
        if existing_user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email already registered"
            )

        # Hash password and create user
        hashed_password = security_service.get_password_hash(signup_data.password)
        user = await self.user_repo.create(
            email=signup_data.email,
            hashed_password=hashed_password,
            marketing_consent=signup_data.marketing_consent,
            utm_source=signup_data.utm_source,
            utm_medium=signup_data.utm_medium,
            utm_campaign=signup_data.utm_campaign,
            utm_term=signup_data.utm_term,
            utm_content=signup_data.utm_content,
        )

        # Get language from signup data (default to 'en' if not provided)
        language = signup_data.language or "en"

        # Link referral signup in consumer-service if referral_code was provided.
        if signup_data.referral_code:
            await self._link_referral_signup(
                user_id=user.id,
                email=user.email,
                referral_code=signup_data.referral_code,
            )

        # Send OTP verification email asynchronously
        if background_tasks:
            background_tasks.add_task(
                self.otp_service.send_otp_email,
                user=user,
                language=language,  # Pass language to email service
                ip_address=ip_address
            )
            logger.info(f"OTP email queued for user_id={user.id} (language: {language})")
        else:
            # Fallback to synchronous if background_tasks not available
            try:
                await self.otp_service.send_otp_email(
                    user=user,
                    language=language,  # Pass language to email service
                    ip_address=ip_address
                )
            except Exception as e:
                logger.error(f"Failed to send OTP email for user_id={user.id}: {str(e)}")

        # Generate tokens (is_verified will be false initially)
        access_token = create_access_token(user)
        refresh_token = await self.token_service.create_refresh_token(
            user=user,
            device_info=device_info,
            ip_address=ip_address
        )

        return TokenResponse(
            access_token=access_token,
            refresh_token=refresh_token.token,
            expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
        )

    async def _link_referral_signup(self, user_id: UUID, email: str, referral_code: str) -> None:
        """Notify consumer-service to mark referral as signed_up for this user."""
        if not settings.CONSUMER_INTERNAL_BASE_URL or not settings.CONSUMER_INTERNAL_API_KEY:
            logger.warning(
                "Referral code provided but consumer internal API is not configured",
                extra={"user_id": str(user_id)}
            )
            return

        url = f"{settings.CONSUMER_INTERNAL_BASE_URL.rstrip('/')}/referrals/link-signup"
        payload = {
            "user_id": str(user_id),
            "email": email,
            "referral_code": referral_code,
        }
        headers = {"X-Internal-API-Key": settings.CONSUMER_INTERNAL_API_KEY}

        try:
            async with httpx.AsyncClient(timeout=settings.CONSUMER_INTERNAL_TIMEOUT_SECONDS) as client:
                response = await client.post(url, json=payload, headers=headers)
                if response.status_code >= 400:
                    logger.warning(
                        "Referral signup linking request failed",
                        extra={
                            "user_id": str(user_id),
                            "status_code": response.status_code,
                            "response": response.text,
                        },
                    )
        except Exception as exc:
            logger.warning(
                "Referral signup linking request errored",
                extra={"user_id": str(user_id), "error": str(exc)},
            )

    async def login(
        self,
        login_data: UserLogin,
        device_info: Optional[str] = None,
        ip_address: Optional[str] = None
    ) -> TokenResponse:
        """Authenticate user and return tokens"""
        # Get user by email
        user = await self.user_repo.get_by_email(login_data.email)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect email or password"
            )

        # Social-only accounts have no password (hashed_password is NULL).
        # Treat a password login attempt against one exactly like a wrong
        # password — never reveal that the account exists but is social-only,
        # and never hand a NULL hash to passlib (which would raise).
        if not user.hashed_password:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect email or password"
            )

        # Verify password
        if not security_service.verify_password(login_data.password, user.hashed_password):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect email or password"
            )

        # Check if user is active
        if not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="User account is inactive"
            )

        # Generate tokens (is_verified is included in JWT)
        access_token = create_access_token(user)
        refresh_token = await self.token_service.create_refresh_token(
            user=user,
            device_info=device_info,
            ip_address=ip_address
        )

        return TokenResponse(
            access_token=access_token,
            refresh_token=refresh_token.token,
            expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
        )
    
    async def get_user_by_id(self, user_id: UUID) -> Optional[User]:
        """Get user by ID"""
        return await self.user_repo.get_by_id(user_id)

    async def delete_account(self, user: User) -> None:
        """Hard-delete the user's account and every dependent row.

        Refresh tokens, social links, email aliases, OTP/verification/reset
        tokens, and Login-with-Herm consents all go with the row (ORM
        cascades plus DB-level ON DELETE CASCADE), so no PII-bearing data
        survives the account.
        """
        await self.user_repo.delete(user)
    
    async def get_current_user(self, token: str) -> User:
        """Get current authenticated user from token"""
        payload = security_service.decode_token(token)
        if not payload:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials"
            )
        
        user_id = payload.get("sub")
        if not user_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials"
            )
        
        user = await self.user_repo.get_by_id(UUID(user_id))
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        if not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="User account is inactive"
            )
        
        return user