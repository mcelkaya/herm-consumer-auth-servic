"""Admin RBAC role definitions and helpers.

The admin dashboard issues a single JWT per admin whose ``role`` claim comes
from ``admin_users.role``. Most admins are full back-office operators
(``ROLE_ADMIN``). Some roles are intentionally limited to read-only reporting
— e.g. ``ROLE_MARKETING`` users may only view signup/UTM statistics so they can
track ad performance, and must never reach management/privileged endpoints.

This module is the single source of truth for that policy so every endpoint
gates on the same rule rather than scattering string comparisons.
"""

# Known admin roles. ``role`` is a free-form column, so treat these as the
# canonical, documented values rather than an exhaustive enum.
ROLE_ADMIN = "admin"
ROLE_MARKETING = "marketing"

# Roles whose access is limited to read-only reporting/stats endpoints. They
# must be rejected from any management or privileged admin endpoint.
REPORTING_ONLY_ROLES = frozenset({ROLE_MARKETING})


def is_reporting_only(role: str | None) -> bool:
    """Whether the given admin role is restricted to reporting endpoints."""
    return role in REPORTING_ONLY_ROLES
