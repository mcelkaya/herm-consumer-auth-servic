"""Integration tests for admin authentication API endpoints"""

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.admin_user import AdminUser
from app.core.security import security_service


@pytest.mark.asyncio
class TestAdminLoginNonExistentUser:
    """Admin login must return 401 (not 500) for non-existent accounts."""

    async def test_unknown_email_returns_401_not_500(self, client: AsyncClient):
        """
        BUG: verify_password("dummy", "dummy_hash_placeholder") throws because
        "dummy_hash_placeholder" is not a valid bcrypt hash. The exception
        propagates as HTTP 500 instead of 401.

        FIX: Use a pre-hashed dummy value so the timing-constant path never
        crashes.
        """
        response = await client.post(
            "/herm-auth/api/v1/admin/auth/login",
            json={"email": "nobody@example.com", "password": "anything"},
        )
        assert response.status_code == 401, (
            f"BUG: expected 401 for unknown admin email, got {response.status_code}. "
            "The dummy bcrypt hash in AdminAuthService.login is invalid and throws."
        )


@pytest.mark.asyncio
class TestAdminLoginRateLimit:
    """Tests that admin login endpoint is rate limited."""

    async def test_admin_login_rate_limit(
        self,
        client: AsyncClient,
        db_session: AsyncSession,
    ):
        """Admin login must return 429 after exceeding the rate limit."""
        admin = AdminUser(
            email="ratelimit_admin@example.com",
            hashed_password=security_service.get_password_hash("correct_password"),
            is_active=True,
        )
        db_session.add(admin)
        await db_session.commit()

        # Make 5 requests (the allowed limit)
        for _ in range(5):
            await client.post(
                "/herm-auth/api/v1/admin/auth/login",
                json={"email": "ratelimit_admin@example.com", "password": "correct_password"},
            )

        # 6th request must be rate-limited
        response = await client.post(
            "/herm-auth/api/v1/admin/auth/login",
            json={"email": "ratelimit_admin@example.com", "password": "correct_password"},
        )

        assert response.status_code == 429
        assert "rate limit" in response.json()["detail"].lower()
