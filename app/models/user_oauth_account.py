from sqlalchemy import Column, String, DateTime, ForeignKey, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
import uuid
from app.db.session import Base
from app.core.config import settings


class UserOAuthAccount(Base):
    """A social-login identity linked to a user.

    Each row links exactly one provider identity (e.g. a specific Google
    account, identified by its stable `sub`) to one local user. A user may
    have several rows — at most one per provider — so the same person can
    sign in with Google, Apple, or Facebook and land on the same profile.

    Links are created either:
      - automatically during social sign-in, when the provider asserts a
        VERIFIED email that matches a VERIFIED local email (primary or alias),
        or
      - explicitly from the settings page, where the already-authenticated
        user links a provider regardless of email — this is the only path that
        works for Apple "Hide My Email" relay addresses, which never match a
        local email.

    `provider_user_id` is the provider's stable subject identifier (the `sub`
    claim), NOT the email. Emails can change or be hidden; the sub does not, so
    it is the only safe key for recognising a returning social user.

    `email_at_link` records the email the provider asserted when the link was
    created. It is for audit/debugging only and is never used as a login key.
    """

    __tablename__ = "user_oauth_accounts"
    __table_args__ = (
        UniqueConstraint(
            "provider",
            "provider_user_id",
            name="uq_user_oauth_provider_identity",
        ),
        UniqueConstraint(
            "user_id",
            "provider",
            name="uq_user_oauth_user_provider",
        ),
        {"schema": settings.DATABASE_SCHEMA},
    )

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(
        UUID(as_uuid=True),
        ForeignKey(f"{settings.DATABASE_SCHEMA}.users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    # 'google' | 'apple' | 'facebook'
    provider = Column(String(32), nullable=False)
    provider_user_id = Column(String(255), nullable=False, index=True)
    email_at_link = Column(String(255), nullable=True)
    created_at = Column(
        DateTime(timezone=False), server_default=func.now(), nullable=False
    )
    updated_at = Column(
        DateTime(timezone=False),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )

    user = relationship("User", back_populates="oauth_accounts")

    def __repr__(self) -> str:
        return f"<UserOAuthAccount {self.provider} user={self.user_id}>"