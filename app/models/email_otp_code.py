from sqlalchemy import Column, String, DateTime, ForeignKey, Boolean, Integer
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from datetime import datetime
import uuid
import secrets
from app.db.session import Base
from app.core.config import settings

# Number of wrong attempts allowed before a code is locked out. A 6-digit
# code only has 1,000,000 possibilities (unlike the 64-char email
# verification token), so brute-force lockout is required.
OTP_MAX_ATTEMPTS = 5


class EmailOtpCode(Base):
    """6-digit OTP code model for email verification.

    Unlike EmailVerificationToken (a high-entropy 64-char token that is safe
    to store plaintext), a 6-digit code must be hashed at rest (code_hash)
    and needs brute-force protection via attempt_count/is_locked_out.
    """

    __tablename__ = "email_otp_codes"
    __table_args__ = {"schema": settings.DATABASE_SCHEMA}

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    code_hash = Column(String(255), nullable=False)
    user_id = Column(
        UUID(as_uuid=True),
        ForeignKey(f"{settings.DATABASE_SCHEMA}.users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    expires_at = Column(DateTime(timezone=False), nullable=False)
    is_used = Column(Boolean, default=False, nullable=False)
    used_at = Column(DateTime(timezone=False), nullable=True)
    attempt_count = Column(Integer, default=0, nullable=False)
    # Set when this code is superseded by a newer one (e.g. user requested
    # a resend), mirroring EmailVerificationToken.revoked_at.
    revoked_at = Column(DateTime(timezone=False), nullable=True)
    created_at = Column(DateTime(timezone=False), default=datetime.utcnow)
    ip_address = Column(String(45), nullable=True)

    # Relationship with user
    user = relationship("User", back_populates="email_otp_codes")

    @staticmethod
    def generate_code() -> str:
        """Generate a random 6-digit numeric code, zero-padded."""
        return f"{secrets.randbelow(1_000_000):06d}"

    def is_expired(self) -> bool:
        """Check if code is expired"""
        return datetime.utcnow() > self.expires_at

    def is_revoked(self) -> bool:
        """Check if code has been superseded by a newer one"""
        return self.revoked_at is not None

    def is_locked_out(self) -> bool:
        """Check if code has been locked out due to too many wrong attempts"""
        return self.attempt_count >= OTP_MAX_ATTEMPTS

    def is_valid(self) -> bool:
        """Check if code is valid (not used, not revoked, not expired, not locked out)"""
        return (
            not self.is_used
            and not self.is_revoked()
            and not self.is_expired()
            and not self.is_locked_out()
        )

    def __repr__(self):
        return f"<EmailOtpCode {self.id} for user {self.user_id}>"
