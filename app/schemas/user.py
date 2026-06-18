from enum import Enum
from pydantic import BaseModel, EmailStr, Field, ConfigDict, field_validator, field_serializer
from typing import Optional, Any
from datetime import datetime, timezone
from uuid import UUID
import re


def _validate_language(v):
    if v is None:
        return v
    v = str(v).strip().lower()
    if not v:
        return None
    # Browsers send BCP-47 locales like "tr-TR" / "en_US". Keep only the primary
    # language subtag (ISO 639, 2-3 letters) and drop any region/script suffix.
    primary = re.split(r'[-_]', v, maxsplit=1)[0]
    if not re.match(r'^[a-z]{2,3}$', primary):
        raise ValueError("language must be a valid ISO 639 language code (e.g. 'en', 'tr')")
    return primary


def _to_utc_iso(value: Optional[datetime]) -> Optional[str]:
    """Serialize a datetime as RFC 3339 UTC with a trailing 'Z'.

    Some source columns are timezone-aware (users.created_at) and some are
    naive UTC (alias timestamps written with datetime.utcnow()). Normalizing
    on the way out guarantees every datetime in a response uses one identical
    format regardless of which column it came from, so the frontend never has
    to handle a mix of offset-bearing and offset-less timestamps.
    """
    if value is None:
        return None
    if value.tzinfo is None:
        # Stored naive == UTC by convention in this service.
        value = value.replace(tzinfo=timezone.utc)
    else:
        value = value.astimezone(timezone.utc)
    return value.isoformat().replace("+00:00", "Z")


class UserSignup(BaseModel):
    """Schema for user signup"""
    model_config = ConfigDict(extra="forbid")

    email: EmailStr
    password: str = Field(..., min_length=8, max_length=100)
    language: Optional[str] = Field(default="en", description="User's preferred language code (e.g., 'en', 'tr')")
    referral_code: Optional[str] = Field(default=None, description="Optional referral code (e.g., ABC123)")
    marketing_consent: bool = Field(default=False, description="User opted in to marketing emails")

    # UTM tracking fields (all optional)
    utm_source: Optional[str] = Field(default=None, max_length=255, description="UTM source parameter")
    utm_medium: Optional[str] = Field(default=None, max_length=255, description="UTM medium parameter")
    utm_campaign: Optional[str] = Field(default=None, max_length=255, description="UTM campaign parameter")
    utm_term: Optional[str] = Field(default=None, max_length=255, description="UTM term parameter")
    utm_content: Optional[str] = Field(default=None, max_length=255, description="UTM content parameter")

    @field_validator("language", mode="before")
    @classmethod
    def validate_language(cls, v):
        return _validate_language(v)

    @field_validator("referral_code", mode="before")
    @classmethod
    def validate_referral_code(cls, v):
        if v is None:
            return v
        code = str(v).strip().upper()
        if not re.match(r"^[A-Z0-9]{6,20}$", code):
            raise ValueError("referral_code must be 6-20 uppercase alphanumeric characters")
        return code


class UserLogin(BaseModel):
    """Schema for user login"""
    email: EmailStr
    password: str = Field(..., min_length=1, max_length=100)


class TokenResponse(BaseModel):
    """Schema for token response"""
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int  # seconds until access token expires


class RefreshTokenRequest(BaseModel):
    """Schema for refresh token request"""
    refresh_token: str


class UserResponse(BaseModel):
    """Schema for user response"""
    id: UUID
    email: str
    is_active: bool
    is_verified: bool
    created_at: datetime
    
    class Config:
        from_attributes = True


class MessageResponse(BaseModel):
    """Generic message response with translation key"""
    message_key: str
    message: Optional[str] = None  # Optional fallback for backward compatibility


class ErrorResponse(BaseModel):
    """Error response schema with translation key"""
    error_key: str
    detail: Optional[str] = None  # Optional fallback for backward compatibility


# Password Reset Schemas
class ForgotPasswordRequest(BaseModel):
    """Schema for forgot password request"""
    email: EmailStr
    language: Optional[str] = Field(default="en", description="User's preferred language code")

    @field_validator("language", mode="before")
    @classmethod
    def validate_language(cls, v):
        return _validate_language(v)


class ForgotPasswordResponse(BaseModel):
    """Schema for forgot password response"""
    message_key: str = "auth.forgotPassword.emailSent"
    message: str = "If an account exists with this email, a password reset link has been sent."


_SQL_INJECTION_PATTERN = re.compile(
    r"(--|/\*|\*/|;\s*--|'\s*(or|and)\s*'|'\s*(or|and)\s+\d|union\s+select|drop\s+table|insert\s+into|delete\s+from|update\s+\w+\s+set)",
    re.IGNORECASE,
)


class ResetPasswordRequest(BaseModel):
    """Schema for reset password request"""
    token: str = Field(..., min_length=1, description="Password reset token from email")
    new_password: str = Field(..., min_length=8, max_length=100, description="New password")

    @field_validator("new_password", mode="before")
    @classmethod
    def sanitize_password(cls, v):
        if v is None:
            return v
        v = str(v)
        if "\x00" in v:
            raise ValueError("password contains invalid characters")
        if not v.isprintable():
            raise ValueError("password must contain only printable characters")
        if _SQL_INJECTION_PATTERN.search(v):
            raise ValueError("password contains invalid character sequences")
        return v


class ResetPasswordResponse(BaseModel):
    """Schema for reset password response"""
    message_key: str = "auth.resetPassword.success"
    message: str = "Password has been reset successfully."


# Email Verification Schemas
class VerifyEmailRequest(BaseModel):
    """Schema for email verification request"""
    token: str = Field(..., min_length=1, description="Email verification token from email")


class VerifyEmailResponse(BaseModel):
    """Response shape for /public/auth/verify-email.

    `kind` discriminates between:

      - "primary": the user's signup email was verified. The user is logged
        in as part of the flow, so access_token / refresh_token / expires_in
        are populated and a refresh_token cookie is set.

      - "alias": a secondary email was verified. No session is issued —
        alias verification only proves email ownership. The token fields
        are null and `alias_email` is set so the frontend can show
        "{alias} is now verified." The user keeps whatever session they
        already had (if any).
    """
    message_key: str = "auth.verifyEmail.success"
    message: str = "Email has been verified successfully."
    kind: str = "primary"  # "primary" | "alias"
    alias_email: Optional[str] = None
    access_token: Optional[str] = None
    refresh_token: Optional[str] = None
    expires_in: Optional[int] = None


class ResendVerificationRequest(BaseModel):
    """Schema for resend verification request"""
    email: EmailStr
    language: Optional[str] = Field(default="en", description="User's preferred language code")

    @field_validator("language", mode="before")
    @classmethod
    def validate_language(cls, v):
        return _validate_language(v)


class ResendVerificationResponse(BaseModel):
    """Schema for resend verification response"""
    message_key: str = "auth.verifyEmail.emailSent"
    message: str = "If an account exists with this email, a verification link has been sent."


class LanguagePreference(BaseModel):
    """Optional request body carrying just the caller's preferred language.

    Used by authenticated endpoints that send an email but otherwise take no
    input (primary resend-verification, alias resend) so the language source
    is the request body everywhere — the same pattern as signup / forgot
    password — and is validated identically (_validate_language). The body is
    optional; an absent body falls back to "en".
    """
    model_config = ConfigDict(extra="forbid")

    language: Optional[str] = Field(
        default="en",
        description="Preferred language code for the outbound email (e.g. 'en', 'tr')",
    )

    @field_validator("language", mode="before")
    @classmethod
    def _v_language(cls, v):
        return _validate_language(v)


# SQS Notification Schemas
class BaseSchema(BaseModel):
    """Base schema with common configuration."""

    model_config = ConfigDict(
        from_attributes=True,
        populate_by_name=True,
        str_strip_whitespace=True,
    )


class Channel(str, Enum):
    """Notification channels."""

    EMAIL = "email"
    SMS = "sms"  # Future
    PUSH = "push"  # Future


class Priority(str, Enum):
    """Notification priority levels."""

    HIGH = "high"
    STANDARD = "standard"
    LOW = "low"


class RecipientSchema(BaseSchema):
    """Recipient schema for SQS messages."""

    email: EmailStr
    user_id: Optional[str] = None
    name: Optional[str] = None


class NotificationMessage(BaseSchema):
    """SQS notification message schema."""

    channel: Channel = Field(default=Channel.EMAIL)
    template_slug: str = Field(..., min_length=1, max_length=100)
    recipient: RecipientSchema
    language: str = Field(default="en", min_length=2, max_length=5)
    variables: dict[str, Any] = Field(default_factory=dict)
    priority: Priority = Field(default=Priority.STANDARD)
    metadata: dict[str, Any] = Field(default_factory=dict)

# =============================================================================
# Email aliases (secondary emails) — /pii/auth/emails
# =============================================================================


class EmailAliasAddRequest(BaseModel):
    """Add a new secondary email to the current user's account."""
    model_config = ConfigDict(extra="forbid")

    email: EmailStr
    language: Optional[str] = Field(
        default="en",
        description="Language code for the verification email body (e.g. 'en', 'tr')",
    )

    @field_validator("language", mode="before")
    @classmethod
    def _v_language(cls, v):
        return _validate_language(v)


class EmailAliasResponse(BaseModel):
    """One alias row in /pii/auth/emails responses."""
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    email: EmailStr
    is_verified: bool
    verified_at: Optional[datetime] = None
    created_at: datetime

    @field_serializer("verified_at", "created_at", when_used="json")
    def _serialize_datetimes(self, value: Optional[datetime]) -> Optional[str]:
        return _to_utc_iso(value)


class EmailEntryResponse(BaseModel):
    """Unified shape for primary email + aliases in the list endpoint.

    `id` is null and `is_primary` is true for the user's primary email row,
    which lives on `users.email` and has no alias UUID.

    Note: the primary row's `verified_at` is always null (the users table has
    no such column); read `is_verified` for the primary's status. All datetime
    fields are serialized as UTC ISO 8601 with a trailing 'Z'.
    """
    model_config = ConfigDict(from_attributes=True)

    id: Optional[UUID] = None
    email: EmailStr
    is_verified: bool
    is_primary: bool
    verified_at: Optional[datetime] = None
    created_at: Optional[datetime] = None

    @field_serializer("verified_at", "created_at", when_used="json")
    def _serialize_datetimes(self, value: Optional[datetime]) -> Optional[str]:
        return _to_utc_iso(value)


class EmailListResponse(BaseModel):
    """All emails (primary + aliases) on the current user's account."""
    emails: list[EmailEntryResponse]


class ResendAliasVerificationResponse(BaseModel):
    message: str = "Verification email sent. Please check your inbox."