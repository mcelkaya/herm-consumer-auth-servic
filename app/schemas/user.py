from pydantic import BaseModel, EmailStr, Field
from typing import Optional, List
from datetime import datetime
from uuid import UUID


class UserSignup(BaseModel):
    """Schema for user signup"""
    email: EmailStr
    password: str = Field(..., min_length=8, max_length=100)


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


class ConnectedAppCreate(BaseModel):
    """Schema for creating connected app"""
    provider: str = Field(..., pattern="^(gmail|outlook|yahoo)$")
    provider_email: EmailStr
    access_token: str
    refresh_token: Optional[str] = None
    token_expires_at: Optional[datetime] = None


class ConnectedAppResponse(BaseModel):
    """Schema for connected app response"""
    id: UUID
    provider: str
    provider_email: str
    created_at: datetime
    updated_at: Optional[datetime] = None
    
    class Config:
        from_attributes = True


class ConnectedAppsList(BaseModel):
    """Schema for list of connected apps"""
    apps: List[ConnectedAppResponse]
    total: int


class MessageResponse(BaseModel):
    """Generic message response"""
    message: str


class ErrorResponse(BaseModel):
    """Error response schema"""
    detail: str


class ForgotPasswordRequest(BaseModel):
    """Schema for forgot password request"""
    email: EmailStr


class ForgotPasswordResponse(BaseModel):
    """Schema for forgot password response"""
    message: str = "If an account exists with this email, a password reset link has been sent."
