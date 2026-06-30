"""Integration tests for admin authentication API endpoints"""

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.admin_user import AdminUser
from app.models.user import User
from app.core.security import security_service
from app.services.admin_token_service import create_admin_access_token


async def _admin_auth_header(db_session: AsyncSession, role: str = "admin") -> dict:
    """Persist an active admin with the given role and return an auth header."""
    admin = AdminUser(
        email=f"{role}_admin@example.com",
        hashed_password=security_service.get_password_hash("correct_password"),
        role=role,
        is_active=True,
    )
    db_session.add(admin)
    await db_session.commit()
    await db_session.refresh(admin)
    token = create_admin_access_token(admin)
    return {"Authorization": f"Bearer {token}"}


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
            "/herm-auth/v1/admin/auth/login",
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
                "/herm-auth/v1/admin/auth/login",
                json={"email": "ratelimit_admin@example.com", "password": "correct_password"},
            )

        # 6th request must be rate-limited
        response = await client.post(
            "/herm-auth/v1/admin/auth/login",
            json={"email": "ratelimit_admin@example.com", "password": "correct_password"},
        )

        assert response.status_code == 429
        assert "rate limit" in response.json()["detail"].lower()


@pytest.mark.asyncio
class TestRegistrationUtmBreakdown:
    """Tests for GET /admin/auth/stats/registrations/utm."""

    _URL = "/herm-auth/v1/admin/auth/stats/registrations/utm"

    async def test_requires_admin_auth(self, client: AsyncClient):
        """Endpoint must reject unauthenticated callers."""
        response = await client.get(self._URL)
        assert response.status_code == 401

    async def test_marketing_role_can_view_breakdown(
        self,
        client: AsyncClient,
        db_session: AsyncSession,
    ):
        """Reporting-only 'marketing' admins are allowed on the stats endpoints."""
        headers = await _admin_auth_header(db_session, role="marketing")
        response = await client.get(self._URL, headers=headers)
        assert response.status_code == 200

    async def test_groups_signups_by_utm_dimension(
        self,
        client: AsyncClient,
        db_session: AsyncSession,
    ):
        """Signups are aggregated per dimension with a '(none)' bucket."""
        headers = await _admin_auth_header(db_session)

        # 2 google signups, 1 facebook signup, 1 with no source at all.
        db_session.add_all([
            User(email="g1@example.com", hashed_password="x", utm_source="google"),
            User(email="g2@example.com", hashed_password="x", utm_source="google"),
            User(email="f1@example.com", hashed_password="x", utm_source="facebook"),
            User(email="d1@example.com", hashed_password="x", utm_source=None),
        ])
        await db_session.commit()

        response = await client.get(self._URL, headers=headers)
        assert response.status_code == 200

        body = response.json()
        assert body["window_days"] == 30
        assert body["total"] == 4

        sources = {row["value"]: row["count"] for row in body["utm_source"]}
        assert sources["google"] == 2
        assert sources["facebook"] == 1
        assert sources["(none)"] == 1

        # A dimension never set still appears as a single "(none)" bucket.
        medium = {row["value"]: row["count"] for row in body["utm_medium"]}
        assert medium == {"(none)": 4}

    async def test_rejects_out_of_range_days(
        self,
        client: AsyncClient,
        db_session: AsyncSession,
    ):
        """days must be within 1..365 (FastAPI query validation -> 422)."""
        headers = await _admin_auth_header(db_session)

        assert (await client.get(f"{self._URL}?days=0", headers=headers)).status_code == 422
        assert (await client.get(f"{self._URL}?days=366", headers=headers)).status_code == 422
