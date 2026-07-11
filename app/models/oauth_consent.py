from sqlalchemy import Column, String, DateTime, ForeignKey, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.sql import func
import uuid

from app.db.session import Base
from app.core.config import settings


class OAuthConsent(Base):
    """A consumer's standing consent for a partner "Login with Herm" client.

    `granted_scopes` is cumulative (used only to decide whether the consent
    screen can be skipped); the scopes minted into tokens are always the
    per-request set, bounded by this grant. Revocation sets `revoked_at` and
    invalidates the client's refresh tokens for this user.
    """

    __tablename__ = "oauth_consents"
    __table_args__ = (
        UniqueConstraint("user_id", "client_id", name="uq_oauth_consents_user_client"),
        {"schema": settings.DATABASE_SCHEMA},
    )

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey(f"{settings.DATABASE_SCHEMA}.users.id", ondelete="CASCADE"), nullable=False, index=True)
    client_id = Column(String(64), nullable=False, index=True)
    granted_scopes = Column(JSONB, nullable=False, default=list)
    granted_at = Column(DateTime(timezone=True), server_default=func.now())
    last_used_at = Column(DateTime(timezone=True), nullable=True)
    revoked_at = Column(DateTime(timezone=True), nullable=True)

    def __repr__(self):
        return f"<OAuthConsent user={self.user_id} client={self.client_id}>"
