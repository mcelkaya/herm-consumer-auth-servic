from sqlalchemy import Column, String, DateTime, Boolean
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.sql import func
import uuid
import secrets
import hashlib

from app.db.session import Base
from app.core.config import settings


class OAuthClient(Base):
    """A partner "Login with Herm" OAuth2/OIDC client registration.

    Owned by a brand: `brand_id`/`company_id` reference the wizard-service tenant.
    That is a different database, so there is no FK — ownership is enforced by
    wizard-service before registration and recorded here for audit and orphan
    reconciliation.

    The client secret is never stored in plaintext: only its SHA-256 hash is
    kept (the secret is high-entropy random and shown once at creation). Public
    clients (SPA-only partners) have no secret and rely on PKCE.
    """

    __tablename__ = "oauth_clients"
    __table_args__ = {"schema": settings.DATABASE_SCHEMA}

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    client_id = Column(String(64), unique=True, index=True, nullable=False)
    # SHA-256 hex of the client secret; NULL for public clients.
    client_secret_hash = Column(String(64), nullable=True)
    client_type = Column(String(16), nullable=False, default="confidential")  # confidential | public

    client_name = Column(String(255), nullable=False)
    logo_url = Column(String(1024), nullable=True)

    # Wizard-side tenant ownership (cross-DB — no FK; wizard-asserted).
    brand_id = Column(UUID(as_uuid=True), nullable=False, index=True)
    company_id = Column(UUID(as_uuid=True), nullable=False, index=True)
    created_by_user_id = Column(UUID(as_uuid=True), nullable=True)

    redirect_uris = Column(JSONB, nullable=False, default=list)
    allowed_scopes = Column(JSONB, nullable=False, default=list)
    is_sandbox = Column(Boolean, nullable=False, default=False)

    status = Column(String(16), nullable=False, default="active")  # active | suspended | revoked

    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    revoked_at = Column(DateTime(timezone=True), nullable=True)

    CLIENT_ID_PREFIX = "herm_app_"

    @staticmethod
    def generate_client_id() -> str:
        """Public client identifier, e.g. `herm_app_<22 url-safe chars>`."""
        return f"{OAuthClient.CLIENT_ID_PREFIX}{secrets.token_urlsafe(16)}"

    @staticmethod
    def generate_client_secret() -> tuple[str, str]:
        """Generate a confidential-client secret.

        Returns (plaintext_secret, sha256_hash). The plaintext is returned to
        the caller exactly once (creation/regenerate); only the hash is stored.
        """
        secret = secrets.token_urlsafe(32)  # ~256 bits of entropy
        return secret, OAuthClient.hash_secret(secret)

    @staticmethod
    def hash_secret(secret: str) -> str:
        return hashlib.sha256(secret.encode()).hexdigest()

    @property
    def is_usable(self) -> bool:
        """Active and not revoked — eligible to start/redeem an OAuth flow."""
        return self.status == "active" and self.revoked_at is None

    def __repr__(self):
        return f"<OAuthClient client_id={self.client_id} brand={self.brand_id} status={self.status}>"
