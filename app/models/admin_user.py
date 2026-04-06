from sqlalchemy import Column, String, Boolean, DateTime
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
import uuid
from app.db.session import Base
from app.core.config import settings


class AdminUser(Base):
    """AdminUser model for dashboard/back-office accounts.

    Intentionally kept separate from the consumer `users` table so that
    admin auth logic never bleeds into consumer flows and the two
    populations can be managed independently at the DB level.
    """

    __tablename__ = "admin_users"
    __table_args__ = {"schema": settings.DATABASE_SCHEMA}

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email = Column(String(255), unique=True, nullable=False, index=True)
    hashed_password = Column(String(255), nullable=False)
    # Fine-grained role for future RBAC (e.g. "super_admin", "support")
    role = Column(String(50), default="admin", nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    # Admin users get their own refresh token rows so revocation is
    # completely isolated from consumer sessions.
    refresh_tokens = relationship(
        "AdminRefreshToken",
        back_populates="admin_user",
        cascade="all, delete-orphan",
    )

    def __repr__(self) -> str:
        return f"<AdminUser {self.email}>"