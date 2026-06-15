"""Request/response schemas for social login & account linking.

Kept in its own module so the large app/schemas/user.py is left untouched. The
success response for sign-in reuses TokenResponse from app.schemas.user, so the
frontend gets the exact same shape as password login.
"""

from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field, field_serializer, field_validator

from app.schemas.user import _to_utc_iso, _validate_language


class SocialProvider(str, Enum):
    google = "google"
    apple = "apple"
    facebook = "facebook"


class CredentialType(str, Enum):
    """What kind of credential the frontend obtained from the provider SDK.

    - id_token     : an OIDC/identity JWT (Google always; Apple always;
                     Facebook iOS Limited Login).
    - access_token : a classic OAuth access token (Facebook Android / web).

    Optional: if omitted, the backend infers it (Facebook is the only
    ambiguous case, and a JWT is detected by structure).
    """

    id_token = "id_token"
    access_token = "access_token"


class SocialAuthRequest(BaseModel):
    """Body for POST /public/auth/social/{provider}.

    `credential` is the provider token from the native SDK. The signup-only
    fields (referral_code, marketing_consent, utm_*) are applied only when this
    call results in a brand-new account being created; they're ignored on
    sign-in or auto-link.
    """

    model_config = ConfigDict(extra="forbid")

    credential: str = Field(..., min_length=1, description="Provider token (id_token or access_token)")
    credential_type: Optional[CredentialType] = None
    nonce: Optional[str] = Field(default=None, description="Nonce supplied to the provider, if any")

    # New-account passthrough (mirrors UserSignup).
    referral_code: Optional[str] = Field(default=None)
    marketing_consent: bool = Field(default=False)
    language: Optional[str] = Field(default="en")

    utm_source: Optional[str] = Field(default=None, max_length=255)
    utm_medium: Optional[str] = Field(default=None, max_length=255)
    utm_campaign: Optional[str] = Field(default=None, max_length=255)
    utm_term: Optional[str] = Field(default=None, max_length=255)
    utm_content: Optional[str] = Field(default=None, max_length=255)

    @field_validator("language", mode="before")
    @classmethod
    def _v_language(cls, v):
        return _validate_language(v)

    @field_validator("referral_code", mode="before")
    @classmethod
    def _v_referral(cls, v):
        if v is None:
            return v
        import re

        code = str(v).strip().upper()
        if not re.match(r"^[A-Z0-9]{6,20}$", code):
            raise ValueError("referral_code must be 6-20 uppercase alphanumeric characters")
        return code

    def utm_dict(self) -> dict:
        return {
            "utm_source": self.utm_source,
            "utm_medium": self.utm_medium,
            "utm_campaign": self.utm_campaign,
            "utm_term": self.utm_term,
            "utm_content": self.utm_content,
        }


class SocialLinkRequest(BaseModel):
    """Body for POST /pii/auth/social/{provider}/link (authenticated)."""

    model_config = ConfigDict(extra="forbid")

    credential: str = Field(..., min_length=1)
    credential_type: Optional[CredentialType] = None
    nonce: Optional[str] = None


class LinkedAccountResponse(BaseModel):
    """One linked provider in the settings list / link responses."""

    model_config = ConfigDict(from_attributes=True)

    provider: str
    email_at_link: Optional[str] = None
    created_at: datetime

    @field_serializer("created_at", when_used="json")
    def _ser_created(self, value: Optional[datetime]) -> Optional[str]:
        return _to_utc_iso(value)


class LinkedAccountsListResponse(BaseModel):
    accounts: list[LinkedAccountResponse]