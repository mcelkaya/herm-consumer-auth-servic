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