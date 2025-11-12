import pytest
from fastapi import HTTPException
from app.services.user_service import UserService
from app.schemas.user import UserSignup, UserLogin


@pytest.mark.asyncio
async def test_user_signup_success(db_session):
    """Test successful user signup"""
    user_service = UserService(db_session)
    signup_data = UserSignup(
        email="test@example.com",
        password="testpassword123"
    )
    
    result = await user_service.signup(signup_data)
    
    assert result.access_token is not None
    assert result.refresh_token is not None
    assert result.token_type == "bearer"


@pytest.mark.asyncio
async def test_user_signup_duplicate_email(db_session):
    """Test user signup with duplicate email"""
    user_service = UserService(db_session)
    signup_data = UserSignup(
        email="test@example.com",
        password="testpassword123"
    )
    
    # First signup should succeed
    await user_service.signup(signup_data)
    
    # Second signup with same email should fail
    with pytest.raises(HTTPException) as exc_info:
        await user_service.signup(signup_data)
    
    assert exc_info.value.status_code == 400
    assert "already registered" in exc_info.value.detail.lower()


@pytest.mark.asyncio
async def test_user_login_success(db_session):
    """Test successful user login"""
    user_service = UserService(db_session)
    
    # Create user
    signup_data = UserSignup(
        email="test@example.com",
        password="testpassword123"
    )
    await user_service.signup(signup_data)
    
    # Login
    login_data = UserLogin(
        email="test@example.com",
        password="testpassword123"
    )
    result = await user_service.login(login_data)
    
    assert result.access_token is not None
    assert result.refresh_token is not None
    assert result.token_type == "bearer"


@pytest.mark.asyncio
async def test_user_login_wrong_password(db_session):
    """Test user login with wrong password"""
    user_service = UserService(db_session)
    
    # Create user
    signup_data = UserSignup(
        email="test@example.com",
        password="testpassword123"
    )
    await user_service.signup(signup_data)
    
    # Try login with wrong password
    login_data = UserLogin(
        email="test@example.com",
        password="wrongpassword"
    )
    
    with pytest.raises(HTTPException) as exc_info:
        await user_service.login(login_data)
    
    assert exc_info.value.status_code == 401


@pytest.mark.asyncio
async def test_user_login_nonexistent_user(db_session):
    """Test user login with nonexistent user"""
    user_service = UserService(db_session)
    
    login_data = UserLogin(
        email="nonexistent@example.com",
        password="testpassword123"
    )
    
    with pytest.raises(HTTPException) as exc_info:
        await user_service.login(login_data)
    
    assert exc_info.value.status_code == 401
