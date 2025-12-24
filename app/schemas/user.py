from enum import Enum
from pydantic import BaseModel, EmailStr, Field, ConfigDict
from typing import Optional, Any
from datetime import datetime
from uuid import UUID


class UserSignup(BaseModel):
    """Schema for user signup"""
    email: EmailStr
    password: str = Field(..., min_length=8, max_length=100)
    language: Optional[str] = Field(default="en", description="User's preferred language code (e.g., 'en', 'tr')")


class UserLogin(BaseModel):
    """Schema for user login"""
    email: EmailStr
    password: str


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


class ForgotPasswordResponse(BaseModel):
    """Schema for forgot password response"""
    message_key: str = "auth.forgotPassword.emailSent"
    message: str = "If an account exists with this email, a password reset link has been sent."


class ResetPasswordRequest(BaseModel):
    """Schema for reset password request"""
    token: str = Field(..., min_length=1, description="Password reset token from email")
    new_password: str = Field(..., min_length=8, max_length=100, description="New password")


class ResetPasswordResponse(BaseModel):
    """Schema for reset password response"""
    message_key: str = "auth.resetPassword.success"
    message: str = "Password has been reset successfully."


# Email Verification Schemas
class VerifyEmailRequest(BaseModel):
    """Schema for email verification request"""
    token: str = Field(..., min_length=1, description="Email verification token from email")


class VerifyEmailResponse(BaseModel):
    """Schema for email verification response with new access token"""
    message_key: str = "auth.verifyEmail.success"
    message: str = "Email has been verified successfully."
    access_token: str  # New JWT token with is_verified=true
    expires_in: int  # Token expiration in seconds


class ResendVerificationRequest(BaseModel):
    """Schema for resend verification request"""
    email: EmailStr
    language: Optional[str] = Field(default="en", description="User's preferred language code")


class ResendVerificationResponse(BaseModel):
    """Schema for resend verification response"""
    message_key: str = "auth.verifyEmail.emailSent"
    message: str = "If an account exists with this email, a verification link has been sent."


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