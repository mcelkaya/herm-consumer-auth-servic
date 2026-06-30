from datetime import datetime
from typing import Optional
from uuid import UUID
from pydantic import BaseModel, EmailStr


# ---------------------------------------------------------------------------
# Request schemas
# ---------------------------------------------------------------------------

class AdminLogin(BaseModel):
    """Credentials submitted to POST /admin/auth/login."""

    email: EmailStr
    password: str


class AdminRefreshTokenRequest(BaseModel):
    """Optional body payload for token refresh (used by non-browser clients)."""

    refresh_token: str


# ---------------------------------------------------------------------------
# Response schemas
# ---------------------------------------------------------------------------

class AdminTokenResponse(BaseModel):
    """Returned on successful login or token refresh."""

    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int  # seconds until access token expires


class AdminUserResponse(BaseModel):
    """Public representation of an admin user (no hashed_password)."""

    id: UUID
    email: str
    role: str
    is_active: bool
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    model_config = {"from_attributes": True}


class RegistrationStatsResponse(BaseModel):
    """User registration counts over rolling windows."""

    daily: int  # last 24 hours
    weekly: int  # last 7 days
    monthly: int  # last 30 days
    total: int


class UtmDimensionCount(BaseModel):
    """One value of a UTM dimension and how many signups carried it.

    ``value`` is "(none)" for signups with a missing/empty value on this
    dimension (direct / unattributed traffic).
    """

    value: str
    count: int


class UtmBreakdownResponse(BaseModel):
    """Signup counts grouped by each UTM dimension over a rolling window.

    Each dimension lists its top values (descending by count). ``total`` is the
    number of signups in the same window, so the share of attributed vs.
    "(none)" traffic can be computed per dimension.
    """

    window_days: int
    total: int
    utm_source: list[UtmDimensionCount]
    utm_medium: list[UtmDimensionCount]
    utm_campaign: list[UtmDimensionCount]
    utm_term: list[UtmDimensionCount]
    utm_content: list[UtmDimensionCount]