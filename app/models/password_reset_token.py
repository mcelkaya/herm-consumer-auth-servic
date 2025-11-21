from sqlalchemy import Column, String, DateTime, ForeignKey, Boolean
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from datetime import datetime, timedelta
import uuid
import secrets
from app.db.session import Base
from app.core.config import settings


class PasswordResetToken(Base):
    """Password reset token model for forgot password functionality"""

    __tablename__ = "password_reset_tokens"
    __table_args__ = {"schema": settings.DATABASE_SCHEMA}

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    token = Column(String(64), unique=True, nullable=False, index=True)
    user_id = Column(UUID(as_uuid=True), ForeignKey(f"{settings.DATABASE_SCHEMA}.users.id", ondelete="CASCADE"), nullable=False)
    expires_at = Column(DateTime(timezone=False), nullable=False)
    is_used = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime(timezone=False), default=datetime.utcnow)
    used_at = Column(DateTime(timezone=False), nullable=True)
    ip_address = Column(String(45), nullable=True)

    # Relationship with user
    user = relationship("User", back_populates="password_reset_tokens")

    @staticmethod
    def generate_token() -> str:
        """Generate secure URL-safe token (64 characters)"""
        return secrets.token_urlsafe(48)

    def is_expired(self) -> bool:
        """Check if token is expired"""
        return datetime.utcnow() > self.expires_at

    def is_valid(self) -> bool:
        """Check if token is valid (not used and not expired)"""
        return not self.is_used and not self.is_expired()

    def __repr__(self):
        return f"<PasswordResetToken {self.id} for user {self.user_id}>"
