from typing import Optional
from fastapi import HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import security_service
from app.models.admin_user import AdminUser
from app.repositories.admin_user_repository import AdminUserRepository
from app.schemas.admin import AdminLogin, AdminTokenResponse
from app.services.admin_token_service import AdminTokenService, create_admin_access_token
from app.core.config import settings


class AdminAuthService:
    """Business logic for admin authentication flows."""

    # Generic error message — never reveal whether the email exists.
    _INVALID_CREDENTIALS = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid email or password",
        headers={"WWW-Authenticate": "Bearer"},
    )

    def __init__(self, db: AsyncSession) -> None:
        self.db = db
        self.repo = AdminUserRepository(db)
        self.token_service = AdminTokenService(db)

    async def login(
        self,
        credentials: AdminLogin,
        device_info: Optional[str] = None,
        ip_address: Optional[str] = None,
    ) -> AdminTokenResponse:
        """
        Validate credentials and return a token pair.

        Raises 401 for any credential problem so callers cannot enumerate
        which admin emails exist in the system.
        Raises 403 when the account exists but has been deactivated.
        """
        admin_user = await self.repo.get_by_email(credentials.email)

        # Constant-time path: always verify even on miss to prevent
        # timing-based email enumeration.
        if not admin_user:
            # Run a dummy verify so timing is similar to the real path.
            security_service.verify_password("dummy", "dummy_hash_placeholder")
            raise self._INVALID_CREDENTIALS

        if not security_service.verify_password(
            credentials.password, admin_user.hashed_password
        ):
            raise self._INVALID_CREDENTIALS

        # Deactivated accounts get a distinct 403 (not 401) because the
        # credentials were correct — the account is just disabled.
        if not admin_user.is_active:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Admin account is deactivated",
            )

        access_token = create_admin_access_token(admin_user)
        refresh_token_obj = await self.token_service.create_refresh_token(
            admin_user=admin_user,
            device_info=device_info,
            ip_address=ip_address,
        )

        return AdminTokenResponse(
            access_token=access_token,
            refresh_token=refresh_token_obj.token,
            expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        )