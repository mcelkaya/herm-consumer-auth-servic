from typing import Optional
from uuid import UUID, uuid4
from fastapi import HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from app.repositories.user_repository import UserRepository
from app.core.security import security_service
from app.schemas.user import UserSignup, UserLogin, TokenResponse, UserResponse
from app.models.user import User
from app.services.sqs_producer import notification_producer
from app.services.token_service import TokenService, create_access_token
from app.core.config import settings


class UserService:
    """Service for user business logic"""
    
    def __init__(self, db: AsyncSession):
        self.db = db
        self.user_repo = UserRepository(db)
        self.token_service = TokenService(db)
    
    async def signup(
        self,
        signup_data: UserSignup,
        device_info: Optional[str] = None,
        ip_address: Optional[str] = None
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
            hashed_password=hashed_password
        )

        # Generate tokens
        access_token = create_access_token(user)
        refresh_token = await self.token_service.create_refresh_token(
            user=user,
            device_info=device_info,
            ip_address=ip_address
        )

        message_id = notification_producer.send_welcome(
            email=signup_data.email,
            user_name="hello world",
            login_url="https://github.com/erimerturk/herm-notification-service/settings/access",
            user_id=user.id,
            language="en",  # Turkish language_code
            correlation_id=str(uuid4())
        )

        # logger.info(f"Queued password reset notification: {message_id}")

        return TokenResponse(
            access_token=access_token,
            refresh_token=refresh_token.token,
            expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
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

        # Generate tokens
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
