"""Secondary (alias) email management for users."""

from datetime import datetime
from typing import List, Optional
from uuid import UUID

from fastapi import HTTPException, status
from sqlalchemy import and_, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.email_verification_token import EmailVerificationToken
from app.models.user import User
from app.models.user_email_alias import UserEmailAlias
from app.services.email_verification_service import EmailVerificationService

import logging

logger = logging.getLogger(__name__)


def _normalize_email(email: str) -> str:
    return email.strip().lower()


class EmailAliasService:
    """Manage a user's secondary email addresses.

    Uniqueness rules (matches DB partial unique index):
      - An email may be verified by at most ONE user across the system —
        either as `users.email` or as a verified `user_email_aliases.email`.
      - Unverified alias rows are claim placeholders. They block other users
        from adding the same address until their verification token expires
        (24h). Once stale, the next add call evicts them lazily.
    """

    def __init__(self, db: AsyncSession):
        self.db = db
        self.verification_service = EmailVerificationService(db)

    # ----- queries ------------------------------------------------------

    async def list_for_user(self, user: User) -> List[UserEmailAlias]:
        result = await self.db.execute(
            select(UserEmailAlias)
            .where(UserEmailAlias.user_id == user.id)
            .order_by(UserEmailAlias.created_at.asc())
        )
        return list(result.scalars().all())

    async def get_for_user(self, user: User, alias_id: UUID) -> UserEmailAlias:
        result = await self.db.execute(
            select(UserEmailAlias).where(
                and_(
                    UserEmailAlias.id == alias_id,
                    UserEmailAlias.user_id == user.id,
                )
            )
        )
        alias = result.scalar_one_or_none()
        if alias is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Email alias not found",
            )
        return alias

    # ----- mutations ----------------------------------------------------

    async def add_alias(
        self,
        user: User,
        email: str,
        language: str = "en",
        ip_address: Optional[str] = None,
    ) -> UserEmailAlias:
        """Claim a new alias for the user and send a verification email.

        Rejects:
          - duplicate of the user's primary email
          - duplicate of an existing alias on the same user (verified or pending)
          - address verified on any user (current or another)
          - address claimed (unverified) by another user whose token has not yet expired
        """
        normalized = _normalize_email(email)

        if not normalized or "@" not in normalized:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid email address",
            )

        if user.email and normalized == user.email.lower():
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="This email is your primary email",
            )

        # Same address verified as primary email by another user.
        other_primary = await self.db.execute(
            select(User).where(
                and_(
                    func.lower(User.email) == normalized,
                    User.id != user.id,
                )
            )
        )
        if other_primary.scalar_one_or_none() is not None:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="This email is already in use",
            )

        # Same alias on this user (regardless of verification state).
        own_alias = await self.db.execute(
            select(UserEmailAlias).where(
                and_(
                    UserEmailAlias.user_id == user.id,
                    func.lower(UserEmailAlias.email) == normalized,
                )
            )
        )
        if own_alias.scalar_one_or_none() is not None:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="You have already added this email",
            )

        # Same address claimed by another user — verified blocks unconditionally;
        # unverified blocks only while their newest token is still active. If
        # every token for that row has expired or been revoked, the claim is
        # stale and we evict it.
        await self._evict_stale_alias_claims(normalized)

        other_aliases = await self.db.execute(
            select(UserEmailAlias).where(
                and_(
                    func.lower(UserEmailAlias.email) == normalized,
                    UserEmailAlias.user_id != user.id,
                )
            )
        )
        if other_aliases.scalar_one_or_none() is not None:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="This email is already in use",
            )

        # Create the alias row, then send the verification email. We commit
        # the row first so the verification token can reference it.
        alias = UserEmailAlias(
            user_id=user.id,
            email=normalized,
            is_verified=False,
        )
        self.db.add(alias)
        await self.db.commit()
        await self.db.refresh(alias)

        await self.verification_service.send_alias_verification_email(
            user=user,
            alias=alias,
            language=language,
            ip_address=ip_address,
        )

        return alias

    async def resend_verification(
        self,
        user: User,
        alias_id: UUID,
        language: str = "en",
        ip_address: Optional[str] = None,
    ) -> UserEmailAlias:
        alias = await self.get_for_user(user, alias_id)

        if alias.is_verified:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="This email is already verified",
            )

        await self.verification_service.send_alias_verification_email(
            user=user,
            alias=alias,
            language=language,
            ip_address=ip_address,
        )
        return alias

    async def remove_alias(self, user: User, alias_id: UUID) -> None:
        alias = await self.get_for_user(user, alias_id)
        # Cascade on alias_email_id deletes any associated tokens.
        await self.db.delete(alias)
        await self.db.commit()

    # ----- internals ----------------------------------------------------

    async def _evict_stale_alias_claims(self, normalized_email: str) -> None:
        """Delete unverified alias rows whose newest verification token has
        expired or been revoked. Verified rows are never touched here.

        Called before checking other-user collisions in add_alias so that
        a stale claim doesn't permanently block a legitimate new claim.
        """
        result = await self.db.execute(
            select(UserEmailAlias).where(
                and_(
                    func.lower(UserEmailAlias.email) == normalized_email,
                    UserEmailAlias.is_verified == False,  # noqa: E712
                )
            )
        )
        candidates = result.scalars().all()
        if not candidates:
            return

        now = datetime.utcnow()
        for alias in candidates:
            token_q = await self.db.execute(
                select(EmailVerificationToken)
                .where(EmailVerificationToken.alias_email_id == alias.id)
                .order_by(EmailVerificationToken.created_at.desc())
                .limit(1)
            )
            latest = token_q.scalar_one_or_none()
            # No token (shouldn't normally happen) → claim is stale.
            # Active token (not used, not revoked, not expired) → still binding.
            if latest is None or not latest.is_valid():
                # is_valid() returns False when used, revoked, or expired.
                # For an unverified alias all three mean: nothing is going
                # to verify this row, so it's safe to drop.
                if latest is not None and latest.is_used:
                    # used + alias.is_verified=False is the suspicious-replay
                    # case verify_email rejects. Don't evict — leave it for
                    # investigation. The DB partial unique index does NOT
                    # block other-user claims here because is_verified=False.
                    continue
                if latest is None or latest.is_revoked() or latest.expires_at < now:
                    await self.db.delete(alias)
        await self.db.commit()
