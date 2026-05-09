"""
URL Migration Test — herm-consumer-auth-service

BEFORE migration: TestOldPaths* testler pass, TestNewPaths* testler fail (404)
AFTER migration:  TestNewPaths* testler pass, TestOldPaths* testler fail (404)
"""
import pytest
from unittest.mock import AsyncMock, MagicMock
from httpx import AsyncClient
from app.main import app


@pytest.fixture(autouse=True)
def mock_app_redis():
    """app.state.redis'i mock'la — lifespan olmadan test için."""
    redis_mock = MagicMock()
    redis_mock.get = AsyncMock(return_value=None)
    redis_mock.set = AsyncMock(return_value=True)
    redis_mock.setex = AsyncMock(return_value=True)
    redis_mock.incr = AsyncMock(return_value=1)
    redis_mock.expire = AsyncMock(return_value=True)
    redis_mock.ttl = AsyncMock(return_value=-1)
    redis_mock.delete = AsyncMock(return_value=0)
    app.state.redis = redis_mock
    yield
    if hasattr(app.state, "redis"):
        del app.state.redis


# ---------------------------------------------------------------------------
# YENİ URL'ler — migration SONRASI çalışması gereken path'ler
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_new_health_path(client: AsyncClient):
    response = await client.get("/herm-auth/v1/public/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"


@pytest.mark.asyncio
async def test_new_signup_path_reachable(client: AsyncClient):
    response = await client.post(
        "/herm-auth/v1/public/auth/signup",
        json={"email": "migration_test@example.com", "password": "testpassword123"},
    )
    # 404 = route yok (migration tamamlanmadı), diğerleri = route kayıtlı
    assert response.status_code != 404, f"Route not registered: {response.status_code}"


@pytest.mark.asyncio
async def test_new_login_path_reachable(client: AsyncClient):
    response = await client.post(
        "/herm-auth/v1/public/auth/login",
        json={"email": "notexist@example.com", "password": "wrongpass"},
    )
    assert response.status_code != 404, f"Route not registered: {response.status_code}"


@pytest.mark.asyncio
async def test_new_forgot_password_path_reachable(client: AsyncClient):
    response = await client.post(
        "/herm-auth/v1/public/auth/forgot-password",
        json={"email": "test@example.com"},
    )
    assert response.status_code != 404, f"Route not registered: {response.status_code}"


@pytest.mark.asyncio
async def test_new_reset_password_path_reachable(client: AsyncClient):
    response = await client.post(
        "/herm-auth/v1/public/auth/reset-password",
        json={"token": "invalid_token", "new_password": "newpassword123"},
    )
    assert response.status_code != 404, f"Route not registered: {response.status_code}"


@pytest.mark.asyncio
async def test_new_verify_email_path_reachable(client: AsyncClient):
    response = await client.post(
        "/herm-auth/v1/public/auth/verify-email",
        json={"token": "invalid_token"},
    )
    assert response.status_code != 404, f"Route not registered: {response.status_code}"


@pytest.mark.asyncio
async def test_new_me_path_requires_auth(client: AsyncClient):
    response = await client.get("/herm-auth/v1/pii/auth/me")
    assert response.status_code != 404, f"Route not registered: {response.status_code}"


@pytest.mark.asyncio
async def test_new_refresh_path_requires_token(client: AsyncClient):
    response = await client.post("/herm-auth/v1/pii/auth/refresh")
    assert response.status_code in (401, 422)


@pytest.mark.asyncio
async def test_new_logout_path_requires_auth(client: AsyncClient):
    response = await client.post("/herm-auth/v1/pii/auth/logout")
    assert response.status_code != 404, f"Route not registered: {response.status_code}"


@pytest.mark.asyncio
async def test_new_logout_all_path_requires_auth(client: AsyncClient):
    response = await client.post("/herm-auth/v1/pii/auth/logout-all")
    assert response.status_code != 404, f"Route not registered: {response.status_code}"


@pytest.mark.asyncio
async def test_new_resend_verification_path_requires_auth(client: AsyncClient):
    response = await client.post("/herm-auth/v1/pii/auth/resend-verification")
    assert response.status_code != 404, f"Route not registered: {response.status_code}"


@pytest.mark.asyncio
async def test_new_admin_login_path_reachable(client: AsyncClient):
    response = await client.post(
        "/herm-auth/v1/admin/auth/login",
        json={"email": "admin@example.com", "password": "wrongpass"},
    )
    assert response.status_code != 404, f"Route not registered: {response.status_code}"


@pytest.mark.asyncio
async def test_new_admin_me_path_requires_auth(client: AsyncClient):
    response = await client.get("/herm-auth/v1/admin/auth/me")
    assert response.status_code != 404, f"Route not registered: {response.status_code}"


# ---------------------------------------------------------------------------
# ESKİ URL'ler — migration SONRASI 404 dönmeli
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_old_health_path_gone(client: AsyncClient):
    response = await client.get("/herm-auth/health")
    assert response.status_code == 404, \
        "Eski /herm-auth/health path'i hâlâ aktif — migration tamamlanmadı"


@pytest.mark.asyncio
async def test_old_signup_path_gone(client: AsyncClient):
    response = await client.post(
        "/herm-auth/api/v1/auth/signup",
        json={"email": "test@example.com", "password": "testpassword123"},
    )
    assert response.status_code == 404, \
        "Eski /herm-auth/api/v1/auth/signup path'i hâlâ aktif — migration tamamlanmadı"


@pytest.mark.asyncio
async def test_old_login_path_gone(client: AsyncClient):
    response = await client.post(
        "/herm-auth/api/v1/auth/login",
        json={"email": "test@example.com", "password": "pass"},
    )
    assert response.status_code == 404, \
        "Eski /herm-auth/api/v1/auth/login path'i hâlâ aktif — migration tamamlanmadı"


@pytest.mark.asyncio
async def test_old_me_path_gone(client: AsyncClient):
    response = await client.get("/herm-auth/api/v1/auth/me")
    assert response.status_code == 404, \
        "Eski /herm-auth/api/v1/auth/me path'i hâlâ aktif — migration tamamlanmadı"


@pytest.mark.asyncio
async def test_old_admin_login_path_gone(client: AsyncClient):
    response = await client.post(
        "/herm-auth/api/v1/admin/auth/login",
        json={"email": "admin@example.com", "password": "pass"},
    )
    assert response.status_code == 404, \
        "Eski /herm-auth/api/v1/admin/auth/login path'i hâlâ aktif — migration tamamlanmadı"
