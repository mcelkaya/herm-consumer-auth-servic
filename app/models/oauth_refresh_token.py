from sqlalchemy import Column, String, DateTime, ForeignKey
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.sql import func
import uuid

from app.db.session import Base
from app.core.config import settings


class OAuthRefreshToken(Base):
    """Partner refresh token (offline_access) — hashed at rest, rotating.

    Issued only to confidential clients that were granted `offline_access`
    (feature-flagged off in v1). `code_hash` records the authorization code the
    token chain originated from, so a code-replay can revoke the whole chain.
    """

    __tablename__ = "oauth_refresh_tokens"
    __table_args__ = {"schema": settings.DATABASE_SCHEMA}

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    token_hash = Column(String(64), unique=True, index=True, nullable=False)  # sha256 hex
    client_id = Column(String(64), nullable=False, index=True)
    user_id = Column(UUID(as_uuid=True), ForeignKey(f"{settings.DATABASE_SCHEMA}.users.id", ondelete="CASCADE"), nullable=False, index=True)
    scopes = Column(JSONB, nullable=False, default=list)
    code_hash = Column(String(64), nullable=True, index=True)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    revoked_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    def __repr__(self):
        return f"<OAuthRefreshToken client={self.client_id} user={self.user_id}>"
