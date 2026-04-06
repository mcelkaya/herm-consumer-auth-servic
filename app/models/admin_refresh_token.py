import secrets
from datetime import datetime
from sqlalchemy import Column, String, Boolean, DateTime, ForeignKey, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
import uuid
from app.db.session import Base
from app.core.config import settings


class AdminRefreshToken(Base):
    """Refresh tokens scoped exclusively to AdminUser sessions."""

    __tablename__ = "admin_refresh_tokens"
    __table_args__ = {"schema": settings.DATABASE_SCHEMA}

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    token = Column(String(255), unique=True, nullable=False, index=True)
    admin_user_id = Column(
        UUID(as_uuid=True),
        ForeignKey(f"{settings.DATABASE_SCHEMA}.admin_users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    expires_at = Column(DateTime(timezone=False), nullable=False)
    is_revoked = Column(Boolean, default=False, nullable=False)
    device_info = Column(Text, nullable=True)
    ip_address = Column(String(45), nullable=True)
    created_at = Column(DateTime(timezone=False), server_default=func.now())

    admin_user = relationship("AdminUser", back_populates="refresh_tokens")

    @staticmethod
    def generate_token() -> str:
        return secrets.token_urlsafe(64)

    def is_valid(self) -> bool:
        return not self.is_revoked and self.expires_at > datetime.utcnow()