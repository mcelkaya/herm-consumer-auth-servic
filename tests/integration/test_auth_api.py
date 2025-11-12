import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_signup_endpoint(client: AsyncClient):
    """Test signup endpoint"""
    response = await client.post(
        "/api/v1/auth/signup",
        json={
            "email": "test@example.com",
            "password": "testpassword123"
        }
    )
    
    assert response.status_code == 201
    data = response.json()
    assert "access_token" in data
    assert "refresh_token" in data
    assert data["token_type"] == "bearer"


@pytest.mark.asyncio
async def test_signup_invalid_email(client: AsyncClient):
    """Test signup with invalid email"""
    response = await client.post(
        "/api/v1/auth/signup",
        json={
            "email": "invalid-email",
            "password": "testpassword123"
        }
    )
    
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_signup_short_password(client: AsyncClient):
    """Test signup with short password"""
    response = await client.post(
        "/api/v1/auth/signup",
        json={
            "email": "test@example.com",
            "password": "short"
        }
    )
    
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_login_endpoint(client: AsyncClient):
    """Test login endpoint"""
    # First signup
    await client.post(
        "/api/v1/auth/signup",
        json={
            "email": "test@example.com",
            "password": "testpassword123"
        }
    )
    
    # Then login
    response = await client.post(
        "/api/v1/auth/login",
        json={
            "email": "test@example.com",
            "password": "testpassword123"
        }
    )
    
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert "refresh_token" in data


@pytest.mark.asyncio
async def test_get_current_user(client: AsyncClient):
    """Test get current user endpoint"""
    # Signup
    signup_response = await client.post(
        "/api/v1/auth/signup",
        json={
            "email": "test@example.com",
            "password": "testpassword123"
        }
    )
    
    token = signup_response.json()["access_token"]
    
    # Get current user
    response = await client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {token}"}
    )
    
    assert response.status_code == 200
    data = response.json()
    assert data["email"] == "test@example.com"
    assert "id" in data
    assert data["is_active"] is True


@pytest.mark.asyncio
async def test_get_current_user_invalid_token(client: AsyncClient):
    """Test get current user with invalid token"""
    response = await client.get(
        "/api/v1/auth/me",
        headers={"Authorization": "Bearer invalid_token"}
    )
    
    assert response.status_code == 401
