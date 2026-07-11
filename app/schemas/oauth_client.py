"""Schemas for partner OAuth client registration (Login with Herm).

Used by the internal client-registry endpoints (wizard-service is the caller
that has already enforced brand ownership). Validation here is the last line of
defense on the registration payload: redirect URIs must be exact https URLs
(loopback only for sandbox clients), and scopes must be a subset of what the
provider supports and include `openid`.
"""
from datetime import datetime
from typing import List, Optional
from urllib.parse import urlparse
from uuid import UUID

from pydantic import BaseModel, Field, field_validator, model_validator

SUPPORTED_SCOPES = {"openid", "email", "profile"}
CLIENT_TYPES = {"confidential", "public"}


class OAuthClientCreate(BaseModel):
    client_name: str = Field(min_length=1, max_length=255)
    logo_url: Optional[str] = Field(default=None, max_length=1024)
    client_type: str = "confidential"
    redirect_uris: List[str] = Field(min_length=1)
    allowed_scopes: List[str] = Field(default_factory=lambda: ["openid", "email"])
    is_sandbox: bool = False

    # Wizard-asserted tenant ownership (wizard enforces ADMIN + brand assignment
    # before calling; recorded here for audit / orphan reconciliation).
    brand_id: UUID
    company_id: UUID
    created_by_user_id: Optional[UUID] = None

    @field_validator("client_type")
    @classmethod
    def _check_type(cls, v: str) -> str:
        if v not in CLIENT_TYPES:
            raise ValueError(f"client_type must be one of {sorted(CLIENT_TYPES)}")
        return v

    @field_validator("allowed_scopes")
    @classmethod
    def _check_scopes(cls, v: List[str]) -> List[str]:
        unknown = set(v) - SUPPORTED_SCOPES
        if unknown:
            raise ValueError(f"unsupported scopes: {sorted(unknown)}")
        if "openid" not in v:
            raise ValueError("allowed_scopes must include 'openid'")
        return v

    @model_validator(mode="after")
    def _check_redirect_uris(self):
        for uri in self.redirect_uris:
            parsed = urlparse(uri)
            if parsed.fragment:
                raise ValueError(f"redirect_uri must not contain a fragment: {uri}")
            if not parsed.netloc:
                raise ValueError(f"redirect_uri must be an absolute URL: {uri}")
            is_loopback = parsed.hostname in ("localhost", "127.0.0.1", "::1")
            if parsed.scheme == "https":
                continue
            if parsed.scheme == "http" and is_loopback and self.is_sandbox:
                continue  # loopback http allowed only for sandbox clients
            raise ValueError(
                f"redirect_uri must be https (http loopback allowed only for sandbox): {uri}"
            )
        return self


class OAuthClientUpdate(BaseModel):
    """Partial update from the brand developer dashboard (via wizard)."""
    client_name: Optional[str] = Field(default=None, min_length=1, max_length=255)
    logo_url: Optional[str] = Field(default=None, max_length=1024)
    redirect_uris: Optional[List[str]] = None
    allowed_scopes: Optional[List[str]] = None
    status: Optional[str] = None
    # Needed to validate loopback redirect URIs against the client's sandbox flag.
    is_sandbox: bool = False

    @field_validator("status")
    @classmethod
    def _check_status(cls, v):
        if v is not None and v not in {"active", "suspended", "revoked"}:
            raise ValueError("status must be active | suspended | revoked")
        return v

    @field_validator("allowed_scopes")
    @classmethod
    def _check_scopes(cls, v):
        if v is None:
            return v
        unknown = set(v) - SUPPORTED_SCOPES
        if unknown:
            raise ValueError(f"unsupported scopes: {sorted(unknown)}")
        if "openid" not in v:
            raise ValueError("allowed_scopes must include 'openid'")
        return v

    @model_validator(mode="after")
    def _check_redirect_uris(self):
        for uri in self.redirect_uris or []:
            parsed = urlparse(uri)
            if parsed.fragment or not parsed.netloc:
                raise ValueError(f"invalid redirect_uri: {uri}")
            is_loopback = parsed.hostname in ("localhost", "127.0.0.1", "::1")
            if parsed.scheme == "https":
                continue
            if parsed.scheme == "http" and is_loopback and self.is_sandbox:
                continue
            raise ValueError(f"redirect_uri must be https (http loopback only for sandbox): {uri}")
        return self


class OAuthClientPublic(BaseModel):
    """Client as returned on reads — never includes the secret."""
    id: UUID
    client_id: str
    client_type: str
    client_name: str
    logo_url: Optional[str]
    brand_id: UUID
    company_id: UUID
    redirect_uris: List[str]
    allowed_scopes: List[str]
    is_sandbox: bool
    status: str
    created_at: datetime

    model_config = {"from_attributes": True}


class OAuthClientCreated(OAuthClientPublic):
    """Creation/regenerate response — carries the plaintext secret exactly once."""
    client_secret: Optional[str] = None
