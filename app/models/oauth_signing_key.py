from sqlalchemy import Column, String, DateTime
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.sql import func
import uuid

from app.db.session import Base
from app.core.config import settings


class OAuthSigningKey(Base):
    """Registry of OIDC (Login with Herm) RS256 signing keys.

    Private key material lives in AWS KMS (non-exportable) — only the public
    JWK and the KMS ARN are stored here. `status` drives rotation: the JWKS
    endpoint serves every non-dropped key so partner token verification stays
    uninterrupted across a rotation.
        active  — currently signing
        next    — published ahead of a rotation so partner caches warm up
        retired — no longer signing, kept in JWKS during the grace window
    """

    __tablename__ = "oauth_signing_keys"
    __table_args__ = {"schema": settings.DATABASE_SCHEMA}

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    kid = Column(String(255), unique=True, index=True, nullable=False)
    kms_key_arn = Column(String(512), nullable=False)
    algorithm = Column(String(16), nullable=False, default="RS256")
    public_jwk = Column(JSONB, nullable=False)
    status = Column(String(16), nullable=False, default="active")  # active | next | retired
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    def __repr__(self):
        return f"<OAuthSigningKey kid={self.kid} status={self.status}>"
