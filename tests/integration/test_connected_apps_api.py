import pytest
from httpx import AsyncClient


async def get_auth_token(client: AsyncClient) -> str:
    """Helper to get authentication token"""
    response = await client.post(
        "/api/v1/auth/signup",
        json={
            "email": "test@example.com",
            "password": "testpassword123"
        }
    )
    return response.json()["access_token"]


@pytest.mark.asyncio
async def test_connect_app(client: AsyncClient):
    """Test connecting an email app"""
    token = await get_auth_token(client)
    
    response = await client.post(
        "/api/v1/connected-apps",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "provider": "gmail",
            "provider_email": "user@gmail.com",
            "access_token": "test_access_token",
            "refresh_token": "test_refresh_token"
        }
    )
    
    assert response.status_code == 201
    data = response.json()
    assert data["provider"] == "gmail"
    assert data["provider_email"] == "user@gmail.com"
    assert "id" in data


@pytest.mark.asyncio
async def test_connect_app_invalid_provider(client: AsyncClient):
    """Test connecting app with invalid provider"""
    token = await get_auth_token(client)
    
    response = await client.post(
        "/api/v1/connected-apps",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "provider": "invalid_provider",
            "provider_email": "user@example.com",
            "access_token": "test_access_token"
        }
    )
    
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_list_connected_apps(client: AsyncClient):
    """Test listing connected apps"""
    token = await get_auth_token(client)
    
    # Connect two apps
    await client.post(
        "/api/v1/connected-apps",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "provider": "gmail",
            "provider_email": "user@gmail.com",
            "access_token": "test_access_token"
        }
    )
    
    await client.post(
        "/api/v1/connected-apps",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "provider": "outlook",
            "provider_email": "user@outlook.com",
            "access_token": "test_access_token"
        }
    )
    
    # List apps
    response = await client.get(
        "/api/v1/connected-apps",
        headers={"Authorization": f"Bearer {token}"}
    )
    
    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 2
    assert len(data["apps"]) == 2


@pytest.mark.asyncio
async def test_delete_connected_app(client: AsyncClient):
    """Test deleting a connected app"""
    token = await get_auth_token(client)
    
    # Connect an app
    connect_response = await client.post(
        "/api/v1/connected-apps",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "provider": "gmail",
            "provider_email": "user@gmail.com",
            "access_token": "test_access_token"
        }
    )
    
    app_id = connect_response.json()["id"]
    
    # Delete the app
    response = await client.delete(
        f"/api/v1/connected-apps/{app_id}",
        headers={"Authorization": f"Bearer {token}"}
    )
    
    assert response.status_code == 200
    assert "deleted successfully" in response.json()["message"]
    
    # Verify it's deleted
    list_response = await client.get(
        "/api/v1/connected-apps",
        headers={"Authorization": f"Bearer {token}"}
    )
    
    assert list_response.json()["total"] == 0


@pytest.mark.asyncio
async def test_delete_connected_app_not_found(client: AsyncClient):
    """Test deleting non-existent app"""
    token = await get_auth_token(client)
    
    # Try to delete non-existent app
    response = await client.delete(
        "/api/v1/connected-apps/00000000-0000-0000-0000-000000000000",
        headers={"Authorization": f"Bearer {token}"}
    )
    
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_update_existing_provider(client: AsyncClient):
    """Test updating an existing provider connection"""
    token = await get_auth_token(client)
    
    # Connect Gmail first time
    first_response = await client.post(
        "/api/v1/connected-apps",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "provider": "gmail",
            "provider_email": "old@gmail.com",
            "access_token": "old_token"
        }
    )
    
    first_id = first_response.json()["id"]
    
    # Connect Gmail again with different email
    second_response = await client.post(
        "/api/v1/connected-apps",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "provider": "gmail",
            "provider_email": "new@gmail.com",
            "access_token": "new_token"
        }
    )
    
    # Should update existing, not create new
    assert second_response.status_code == 201
    assert second_response.json()["provider_email"] == "new@gmail.com"
    assert second_response.json()["id"] == first_id
    
    # Verify only one Gmail connection exists
    list_response = await client.get(
        "/api/v1/connected-apps",
        headers={"Authorization": f"Bearer {token}"}
    )
    
    assert list_response.json()["total"] == 1
