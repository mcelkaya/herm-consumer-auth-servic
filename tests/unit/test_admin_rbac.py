"""Unit tests for admin role-based access control."""

import pytest
from fastapi import HTTPException

from app.api.v1.admin_auth import require_full_admin
from app.core.roles import ROLE_ADMIN, ROLE_MARKETING, is_reporting_only
from app.models.admin_user import AdminUser


def _admin(role: str) -> AdminUser:
    return AdminUser(
        email=f"{role}@example.com",
        hashed_password="x",
        role=role,
        is_active=True,
    )


class TestIsReportingOnly:
    def test_marketing_is_reporting_only(self):
        assert is_reporting_only(ROLE_MARKETING) is True

    def test_full_admin_is_not_reporting_only(self):
        assert is_reporting_only(ROLE_ADMIN) is False

    def test_unknown_or_missing_role_is_not_reporting_only(self):
        # Fail closed on access (treated as a normal role here), never crash.
        assert is_reporting_only("support") is False
        assert is_reporting_only(None) is False


class TestRequireFullAdmin:
    def test_rejects_reporting_only_role(self):
        with pytest.raises(HTTPException) as exc:
            require_full_admin(current_admin=_admin(ROLE_MARKETING))
        assert exc.value.status_code == 403

    def test_allows_full_admin(self):
        admin = _admin(ROLE_ADMIN)
        assert require_full_admin(current_admin=admin) is admin
