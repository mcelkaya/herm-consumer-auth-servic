from typing import Optional
from uuid import UUID
from fastapi import HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from app.repositories.user_repository import UserRepository
from app.core.security import security_service
from app.schemas.user import UserSignup, UserLogin, TokenResponse, UserResponse
from app.models.user import User


class UserService:
    """Service for user business logic"""
    
    def __init__(self, db: AsyncSession):
        self.db = db
        self.user_repo = UserRepository(db)
    
    async def signup(self, signup_data: UserSignup) -> TokenResponse:
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
        access_token = security_service.create_access_token(
            data={"sub": str(user.id), "email": user.email}
        )
        refresh_token = security_service.create_refresh_token(
            data={"sub": str(user.id)}
        )
        
        return TokenResponse(
            access_token=access_token,
            refresh_token=refresh_token
        )
    
    async def login(self, login_data: UserLogin) -> TokenResponse:
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
        access_token = security_service.create_access_token(
            data={"sub": str(user.id), "email": user.email}
        )
        refresh_token = security_service.create_refresh_token(
            data={"sub": str(user.id)}
        )
        
        return TokenResponse(
            access_token=access_token,
            refresh_token=refresh_token
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
