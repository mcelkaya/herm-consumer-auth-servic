from dataclasses import dataclass
from typing import Optional
from uuid import UUID, uuid4
from sqlalchemy import select, and_
from sqlalchemy.ext.asyncio import AsyncSession
from datetime import datetime, timedelta
from fastapi import HTTPException, status
from app.models.user import User
from app.models.email_verification_token import EmailVerificationToken
from app.models.user_email_alias import UserEmailAlias
from app.services.sqs_producer import notification_producer
from app.core.config import settings
import logging

logger = logging.getLogger(__name__)


@dataclass
class VerifyEmailResult:
    """Outcome of a verify_email call.

    `kind` is "primary" when the token verified the user's signup email and
    "alias" when it verified a secondary email. For alias verifications the
    caller should NOT issue a fresh login session — the token represents
    proof of email ownership only, not a login intent.
    """
    user: "User"
    kind: str  # "primary" | "alias"
    alias_email: Optional[str] = None


class EmailVerificationService:
    """Service for handling email verification functionality"""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def create_verification_token(
        self,
        user_id: UUID,
        ip_address: Optional[str],
        expiry_hours: int = 24,
        alias_email_id: Optional[UUID] = None,
    ) -> EmailVerificationToken:
        """
        Create a new email verification token.

        If alias_email_id is None, this is a primary email verification token
        for the user; existing primary tokens for this user are revoked.

        If alias_email_id is set, this is an alias verification token; only
        existing tokens for THAT specific alias are revoked. Primary tokens
        and tokens for other aliases are left untouched, since they each
        carry independent state.

        Any existing active tokens in scope are REVOKED (superseded), not
        marked as used. This preserves the distinction:

          - is_used=True       → token was successfully consumed by verification
          - revoked_at IS NOT NULL → token was superseded by a newer one (resend)
        """
        scope = and_(
            EmailVerificationToken.user_id == user_id,
            EmailVerificationToken.is_used == False,  # noqa: E712
            EmailVerificationToken.revoked_at.is_(None),
        )
        if alias_email_id is None:
            scope = and_(scope, EmailVerificationToken.alias_email_id.is_(None))
        else:
            scope = and_(scope, EmailVerificationToken.alias_email_id == alias_email_id)

        result = await self.db.execute(select(EmailVerificationToken).where(scope))
        old_tokens = result.scalars().all()

        now = datetime.utcnow()
        for old_token in old_tokens:
            old_token.revoked_at = now

        token = EmailVerificationToken(
            token=EmailVerificationToken.generate_token(),
            user_id=user_id,
            alias_email_id=alias_email_id,
            expires_at=now + timedelta(hours=expiry_hours),
            ip_address=ip_address,
        )

        self.db.add(token)
        await self.db.commit()
        await self.db.refresh(token)

        return token

    async def send_verification_email(
        self,
        user: User,
        language: str = "en",
        ip_address: Optional[str] = None,
        expiry_hours: int = 24,
    ) -> bool:
        """
        Send email verification to user.

        Args:
            user: User object
            language: Language code from frontend (e.g., 'en', 'tr')
            ip_address: IP address of requester for audit
            expiry_hours: Token expiry time in hours

        Returns:
            True if email queued successfully, False otherwise
        """
        # Create verification token (revokes any existing active ones)
        verification_token = await self.create_verification_token(
            user.id, ip_address, expiry_hours
        )

        # Build verification link
        verification_link = (
            f"{settings.FRONTEND_URL}/verify-email?token={verification_token.token}"
        )

        # Prepare user name (simple fallback since User model doesn't have name fields)
        user_name = user.email.split("@")[0]

        # Send email verification notification via SQS
        message_id = notification_producer.send_email_verification(
            email=user.email,
            user_name=user_name,
            verification_link=verification_link,
            user_id=user.id,
            language=language,
            correlation_id=str(uuid4()),
        )

        logger.info(
            f"Queued email verification notification: {message_id} "
            f"for user: {user.email} (language: {language}, expires in {expiry_hours} hours)"
        )

        return True

    async def send_alias_verification_email(
        self,
        user: User,
        alias: UserEmailAlias,
        language: str = "en",
        ip_address: Optional[str] = None,
        expiry_hours: int = 24,
    ) -> bool:
        """
        Send a verification email to an alias address.

        Uses the same /verify-email?token=... frontend route as primary
        verification; the backend distinguishes alias tokens by
        EmailVerificationToken.alias_email_id.
        """
        verification_token = await self.create_verification_token(
            user.id, ip_address, expiry_hours, alias_email_id=alias.id
        )

        verification_link = (
            f"{settings.FRONTEND_URL}/verify-email?token={verification_token.token}"
        )

        user_name = user.email.split("@")[0]

        message_id = notification_producer.send_alias_email_verification(
            email=alias.email,
            user_name=user_name,
            verification_link=verification_link,
            user_id=user.id,
            alias_email=alias.email,
            language=language,
            correlation_id=str(uuid4()),
        )

        logger.info(
            f"Queued alias email verification notification: {message_id} "
            f"for alias: {alias.email} (user_id={user.id}, language={language}, "
            f"expires in {expiry_hours} hours)"
        )

        return True

    async def verify_token(self, token: str) -> Optional[EmailVerificationToken]:
        """
        Look up a verification token by its string value.

        Returns None for tokens that don't exist or are expired.
        Returns the token object even if it is used or revoked — the caller
        (verify_email) decides how to handle each state.
        """
        result = await self.db.execute(
            select(EmailVerificationToken).where(EmailVerificationToken.token == token)
        )
        verification_token = result.scalar_one_or_none()

        if not verification_token:
            logger.warning("Email verification attempted with non-existent token")
            return None

        if verification_token.is_expired():
            logger.warning(
                f"Email verification attempted with expired token "
                f"for user {verification_token.user_id}"
            )
            return None

        if verification_token.is_used:
            logger.info(
                f"Email verification attempted with already-used token "
                f"for user {verification_token.user_id} (allowing for idempotency check)"
            )

        if verification_token.is_revoked():
            logger.info(
                f"Email verification attempted with revoked (superseded) token "
                f"for user {verification_token.user_id}"
            )

        return verification_token

    async def verify_email(
        self,
        token: str,
        ip_address: Optional[str] = None,
    ) -> VerifyEmailResult:
        """
        Verify a primary or alias email using a token.

        If the token has alias_email_id set, the alias is marked verified
        and the owning User is returned (user.is_verified is NOT modified).
        Otherwise the User's primary email is marked verified.

        Idempotent: returns success even if already verified.

        Token states handled (primary):
          - not found / expired                     → 400 invalid/expired
          - revoked (superseded by resend)          → 400 with "use the latest email"
          - already used + already verified         → success (idempotency)
          - already used + NOT verified             → 400 (genuine replay/race)
          - active + first-time use                 → mark used, mark verified

        Raises:
            HTTPException: with appropriate status and message
        """
        verification_token = await self.verify_token(token)

        if not verification_token:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired verification token",
            )

        # Get user
        result = await self.db.execute(
            select(User).where(User.id == verification_token.user_id)
        )
        user = result.scalar_one_or_none()

        if not user:
            logger.error(f"User not found for valid token: {verification_token.user_id}")
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found",
            )

        # Alias verification path — same state machine, but operates on the
        # UserEmailAlias row instead of User.
        if verification_token.alias_email_id is not None:
            return await self._verify_alias_with_token(
                user=user,
                verification_token=verification_token,
                ip_address=ip_address,
            )

        # IDEMPOTENT: If already verified, return success regardless of token state.
        # Handles duplicate calls (e.g. React StrictMode) and the case where the user
        # clicks the same link twice.
        if user.is_verified:
            logger.info(
                f"Email verification: User already verified: {user.email} "
                f"(token used: {verification_token.is_used}, "
                f"revoked: {verification_token.is_revoked()}) "
                f"- returning success for idempotency"
            )
            if not verification_token.is_used:
                verification_token.is_used = True
                verification_token.used_at = datetime.utcnow()
                await self.db.commit()
            return VerifyEmailResult(user=user, kind="primary")

        # User is NOT verified yet. Reject if the token is unusable:

        # REVOKED: user clicked an older email after requesting a resend.
        # This is normal user behavior, not malicious. Tell them to use the latest email.
        if verification_token.is_revoked():
            logger.info(
                f"Email verification: Superseded token for unverified user {user.email} "
                f"- user likely clicked an older email after requesting a resend"
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="This verification link has been replaced. Please use the most recent email.",
            )

        # USED but not revoked, on an unverified user → genuine replay/race.
        # The token was successfully consumed once but verification didn't complete.
        # Reject for safety.
        if verification_token.is_used:
            logger.warning(
                f"Email verification: Token already used but user NOT verified: {user.email} "
                f"(suspicious activity detected) - rejecting"
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired verification token",
            )

        # FIRST-TIME VERIFICATION: Update user status
        user.is_verified = True
        self.db.add(user)

        # Mark token as used
        verification_token.is_used = True
        verification_token.used_at = datetime.utcnow()
        self.db.add(verification_token)

        # Commit changes
        await self.db.commit()

        # Refresh user to get updated data
        await self.db.refresh(user)

        logger.info(
            f"Email successfully verified for user: {user.email} "
            f"(from IP: {ip_address or 'unknown'})"
        )

        return VerifyEmailResult(user=user, kind="primary")

    async def _verify_alias_with_token(
        self,
        user: User,
        verification_token: EmailVerificationToken,
        ip_address: Optional[str],
    ) -> VerifyEmailResult:
        """Mark a UserEmailAlias as verified."""
        result = await self.db.execute(
            select(UserEmailAlias).where(
                UserEmailAlias.id == verification_token.alias_email_id
            )
        )
        alias = result.scalar_one_or_none()

        if not alias:
            logger.error(
                f"Alias not found for valid token: "
                f"alias_email_id={verification_token.alias_email_id} "
                f"user_id={verification_token.user_id}"
            )
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Email alias not found",
            )

        # IDEMPOTENT: alias already verified — succeed regardless of token state.
        if alias.is_verified:
            logger.info(
                f"Alias email verification: alias already verified: {alias.email} "
                f"(user_id={user.id}) — returning success for idempotency"
            )
            if not verification_token.is_used:
                verification_token.is_used = True
                verification_token.used_at = datetime.utcnow()
                await self.db.commit()
            return VerifyEmailResult(user=user, kind="alias", alias_email=alias.email)

        # REVOKED → user clicked an older email after a resend.
        if verification_token.is_revoked():
            logger.info(
                f"Alias email verification: superseded token for unverified alias "
                f"{alias.email} (user_id={user.id})"
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="This verification link has been replaced. Please use the most recent email.",
            )

        # USED but not revoked, alias unverified → genuine replay.
        if verification_token.is_used:
            logger.warning(
                f"Alias email verification: token already used but alias NOT verified: "
                f"{alias.email} (user_id={user.id}) — rejecting"
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired verification token",
            )

        # First-time alias verification. Re-check the global uniqueness
        # invariant — between alias creation and click, another user could
        # have verified the same address. (DB partial-unique index will also
        # block it, but we want a clean error message.)
        from sqlalchemy import func as sa_func

        dup = await self.db.execute(
            select(UserEmailAlias).where(
                and_(
                    sa_func.lower(UserEmailAlias.email) == alias.email.lower(),
                    UserEmailAlias.is_verified == True,  # noqa: E712
                    UserEmailAlias.id != alias.id,
                )
            )
        )
        if dup.scalar_one_or_none() is not None:
            logger.warning(
                f"Alias email verification: address already verified by another user: "
                f"{alias.email} (user_id={user.id})"
            )
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="This email is already verified on another account.",
            )

        # Also ensure no OTHER user owns this address as their PRIMARY email.
        # The partial unique index only covers verified alias rows, so without
        # this a race — alias claimed before another user signs up with the
        # same address as primary — could leave two users owning one address.
        primary_owner = await self.db.execute(
            select(User).where(
                and_(
                    sa_func.lower(User.email) == alias.email.lower(),
                    User.id != user.id,
                )
            )
        )
        if primary_owner.scalar_one_or_none() is not None:
            logger.warning(
                f"Alias email verification: address is another user's primary "
                f"email: {alias.email} (user_id={user.id})"
            )
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="This email is already in use on another account.",
            )

        now = datetime.utcnow()
        alias.is_verified = True
        alias.verified_at = now
        self.db.add(alias)

        verification_token.is_used = True
        verification_token.used_at = now
        self.db.add(verification_token)

        await self.db.commit()
        await self.db.refresh(alias)

        logger.info(
            f"Alias email verified: {alias.email} for user {user.id} "
            f"(from IP: {ip_address or 'unknown'})"
        )

        return VerifyEmailResult(user=user, kind="alias", alias_email=alias.email)

    async def cleanup_expired_tokens(self) -> int:
        """
        Delete expired email verification tokens.

        Returns:
            Number of tokens deleted
        """
        result = await self.db.execute(
            select(EmailVerificationToken).where(
                EmailVerificationToken.expires_at < datetime.utcnow()
            )
        )
        expired_tokens = result.scalars().all()

        for token in expired_tokens:
            await self.db.delete(token)

        await self.db.commit()

        logger.info(
            f"Cleaned up {len(expired_tokens)} expired email verification tokens"
        )
        return len(expired_tokens)