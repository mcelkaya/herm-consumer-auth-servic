from sqlalchemy import Column, String, Boolean, DateTime, ForeignKey
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
import uuid
from app.db.session import Base
from app.core.config import settings


class UserEmailAlias(Base):
    """A secondary email address claimed by a user.

    The primary email lives on `users.email`. Aliases are separate addresses
    the same user wants to associate with their account (e.g. inbound receipt
    matching). Aliases are NOT login identifiers.

    Verification reuses `email_verification_tokens` with `alias_email_id` set.
    """

    __tablename__ = "user_email_aliases"
    __table_args__ = {"schema": settings.DATABASE_SCHEMA}

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(
        UUID(as_uuid=True),
        ForeignKey(f"{settings.DATABASE_SCHEMA}.users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    email = Column(String(255), nullable=False, index=True)
    is_verified = Column(Boolean, default=False, nullable=False)
    verified_at = Column(DateTime(timezone=False), nullable=True)
    created_at = Column(DateTime(timezone=False), server_default=func.now(), nullable=False)
    updated_at = Column(
        DateTime(timezone=False),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )

    verification_tokens = relationship(
        "EmailVerificationToken",
        back_populates="alias",
        cascade="all, delete-orphan",
        foreign_keys="EmailVerificationToken.alias_email_id",
    )

    def __repr__(self) -> str:
        return f"<UserEmailAlias {self.email} user={self.user_id} verified={self.is_verified}>"
