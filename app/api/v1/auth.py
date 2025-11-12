from fastapi import APIRouter, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession
from app.db.session import get_db
from app.schemas.user import UserSignup, UserLogin, TokenResponse, UserResponse
from app.services.user_service import UserService
from app.api.dependencies import get_current_user
from app.models.user import User

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post("/signup", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
async def signup(
    signup_data: UserSignup,
    db: AsyncSession = Depends(get_db)
) -> TokenResponse:
    """
    Register a new user account
    
    - **email**: Valid email address
    - **password**: Password (minimum 8 characters)
    """
    user_service = UserService(db)
    return await user_service.signup(signup_data)


@router.post("/login", response_model=TokenResponse)
async def login(
    login_data: UserLogin,
    db: AsyncSession = Depends(get_db)
) -> TokenResponse:
    """
    Authenticate user and get access tokens
    
    - **email**: User's email address
    - **password**: User's password
    """
    user_service = UserService(db)
    return await user_service.login(login_data)


@router.get("/me", response_model=UserResponse)
async def get_current_user_info(
    current_user: User = Depends(get_current_user)
) -> UserResponse:
    """
    Get current authenticated user information
    """
    return UserResponse.model_validate(current_user)
