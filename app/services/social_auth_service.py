"""Social sign-in / sign-up / account-linking orchestration.

This sits on top of `social_providers.verify_social_token` and owns the
decision tree once an identity is trusted:

PUBLIC sign-in/up (`authenticate`):
  1. Recognise a returning social user by (provider, sub) → log in. Email is
     never used for recognition; sub is stable, email is not.
  2. First time we have seen this provider identity:
       a. Provider email is present AND provider-verified, AND it matches a
          LOCAL verified email (primary with is_verified, or a verified alias)
          → auto-link to that user and log in. (Verified on BOTH sides.)
       b. An account with that email exists but a side is unverified, or the
          provider email is unverified → refuse to auto-link; signal the
          frontend to have the user log in with their existing method and link
          from settings. (AccountNeedsLinkingError)
       c. No account with that email → create a new social user (is_verified
          mirrors the provider) and link.
       d. No usable email at all (e.g. Apple repeat login, no prior link) →
          AccountNeedsLinkingError.

AUTHENTICATED linking from /settings (`link_account`):
  identity is already proven by the session, so NO email match is required —
  this is the only path that works for Apple "Hide My Email" relay addresses.
"""

from typing import List, Optional
from dataclasses import dataclass

from fastapi import HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models.user import User
from app.models.user_email_alias import UserEmailAlias
from app.models.user_oauth_account import UserOAuthAccount
from app.repositories.user_repository import UserRepository
from app.repositories.user_oauth_account_repository import UserOAuthAccountRepository
from app.schemas.user import TokenResponse
from app.services.social_providers import (
    NormalizedIdentity,
    SocialConfigError,
    SocialTokenError,
    verify_social_token,
)
from app.services.token_service import TokenService, create_access_token

import logging

logger = logging.getLogger(__name__)


def _normalize_email(email: Optional[str]) -> Optional[str]:
    if not email:
        return None
    return email.strip().lower()


# --- signalling exceptions ---------------------------------------------------


class AccountNeedsLinkingError(Exception):
    """An account with this email exists but cannot be auto-linked safely.

    The frontend should ask the user to sign in with their existing method and
    link this provider from the settings page.
    """

    def __init__(self, provider: str, email: Optional[str]):
        self.provider = provider
        self.email = email
        super().__init__("account exists; linking required")


class ProviderIdentityConflictError(Exception):
    """This provider identity is already linked to a DIFFERENT user."""


class ProviderAlreadyLinkedError(Exception):
    """This user already has an identity linked for this provider."""


# --- result ------------------------------------------------------------------


@dataclass
class SocialAuthResult:
    user: User
    created: bool
    tokens: TokenResponse
    link: UserOAuthAccount


class SocialAuthService:
    def __init__(self, db: AsyncSession):
        self.db = db
        self.user_repo = UserRepository(db)
        self.oauth_repo = UserOAuthAccountRepository(db)
        self.token_service = TokenService(db)

    # ----- public sign-in / sign-up -------------------------------------

    async def authenticate(
        self,
        provider: str,
        credential: str,
        credential_type: Optional[str] = None,
        *,
        nonce: Optional[str] = None,
        referral_code: Optional[str] = None,
        marketing_consent: bool = False,
        utm: Optional[dict] = None,
        device_info: Optional[str] = None,
        ip_address: Optional[str] = None,
    ) -> SocialAuthResult:
        identity = await verify_social_token(provider, credential, credential_type, nonce=nonce)

        # 1. Returning user, recognised by stable subject id.
        link = await self.oauth_repo.get_by_provider_identity(
            identity.provider, identity.provider_user_id
        )
        if link:
            user = await self.user_repo.get_by_id(link.user_id)
            if not user or not user.is_active:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="User account is inactive",
                )
            tokens = await self._issue_tokens(user, device_info, ip_address)
            return SocialAuthResult(user=user, created=False, tokens=tokens, link=link)

        # 2. First time we've seen this identity.
        normalized = _normalize_email(identity.email)

        # 2a. Auto-link only when verified on BOTH sides.
        if normalized and identity.email_verified:
            verified_user = await self._find_user_by_verified_email(normalized)
            if verified_user:
                new_link = await self.oauth_repo.create(
                    user_id=verified_user.id,
                    provider=identity.provider,
                    provider_user_id=identity.provider_user_id,
                    email_at_link=identity.email,
                )
                tokens = await self._issue_tokens(verified_user, device_info, ip_address)
                return SocialAuthResult(
                    user=verified_user, created=False, tokens=tokens, link=new_link
                )

        # 2b. An account holds this email but we couldn't safely auto-link
        #     (local side unverified, or provider email unverified) → needs
        #     manual linking from settings.
        if normalized:
            any_owner = await self._find_user_by_any_email(normalized)
            if any_owner:
                raise AccountNeedsLinkingError(provider=identity.provider, email=identity.email)

        # 2d. No usable email at all → cannot create or match.
        if not normalized:
            raise AccountNeedsLinkingError(provider=identity.provider, email=None)

        # 2c. Brand-new social user.
        user = await self._create_social_user(normalized, identity, marketing_consent, utm)
        new_link = await self.oauth_repo.create(
            user_id=user.id,
            provider=identity.provider,
            provider_user_id=identity.provider_user_id,
            email_at_link=identity.email,
        )

        # Referral linkage mirrors password signup: only fires for NEW users.
        if referral_code:
            await self._link_referral(user, referral_code)

        tokens = await self._issue_tokens(user, device_info, ip_address)
        return SocialAuthResult(user=user, created=True, tokens=tokens, link=new_link)

    # ----- authenticated linking (settings page) ------------------------

    async def link_account(
        self,
        current_user: User,
        provider: str,
        credential: str,
        credential_type: Optional[str] = None,
        *,
        nonce: Optional[str] = None,
    ) -> UserOAuthAccount:
        identity = await verify_social_token(provider, credential, credential_type, nonce=nonce)

        existing = await self.oauth_repo.get_by_provider_identity(
            identity.provider, identity.provider_user_id
        )
        if existing:
            if existing.user_id == current_user.id:
                return existing  # idempotent: already linked to this user
            raise ProviderIdentityConflictError()

        already = await self.oauth_repo.get_for_user_and_provider(
            current_user.id, identity.provider
        )
        if already:
            raise ProviderAlreadyLinkedError()

        link = await self.oauth_repo.create(
            user_id=current_user.id,
            provider=identity.provider,
            provider_user_id=identity.provider_user_id,
            email_at_link=identity.email,
        )
        await self.db.commit()
        await self.db.refresh(link)
        return link

    async def list_links(self, user: User) -> List[UserOAuthAccount]:
        return await self.oauth_repo.list_for_user(user.id)

    async def unlink(self, user: User, provider: str) -> None:
        link = await self.oauth_repo.get_for_user_and_provider(user.id, provider.lower())
        if not link:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="No linked account for this provider",
            )
        # Don't let a user strand themselves: if they have no password and this
        # is their last remaining sign-in method, refuse to remove it.
        if not user.hashed_password:
            links = await self.oauth_repo.list_for_user(user.id)
            if len(links) <= 1:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Cannot remove your only sign-in method. Set a password first.",
                )
        await self.oauth_repo.delete(link)
        await self.db.commit()

    # ----- internals ----------------------------------------------------

    async def _find_user_by_verified_email(self, normalized: str) -> Optional[User]:
        """A user who has this email VERIFIED — as a verified primary, or as a
        verified alias. This is the only set we auto-link to."""
        # Verified primary.
        primary = await self.db.execute(
            select(User).where(
                func.lower(User.email) == normalized,
                User.is_verified == True,  # noqa: E712
            )
        )
        user = primary.scalar_one_or_none()
        if user:
            return user

        # Verified alias.
        alias = await self.db.execute(
            select(User)
            .join(UserEmailAlias, UserEmailAlias.user_id == User.id)
            .where(
                func.lower(UserEmailAlias.email) == normalized,
                UserEmailAlias.is_verified == True,  # noqa: E712
            )
        )
        return alias.scalar_one_or_none()

    async def _find_user_by_any_email(self, normalized: str) -> Optional[User]:
        """Any user who holds this email at all (primary or alias, verified or
        not). Used to detect a collision that blocks silent account creation."""
        primary = await self.db.execute(
            select(User).where(func.lower(User.email) == normalized)
        )
        user = primary.scalar_one_or_none()
        if user:
            return user

        alias = await self.db.execute(
            select(User)
            .join(UserEmailAlias, UserEmailAlias.user_id == User.id)
            .where(func.lower(UserEmailAlias.email) == normalized)
        )
        return alias.scalar_one_or_none()

    async def _create_social_user(
        self,
        normalized_email: str,
        identity: NormalizedIdentity,
        marketing_consent: bool,
        utm: Optional[dict],
    ) -> User:
        utm = utm or {}
        user = User(
            email=normalized_email,
            hashed_password=None,  # social-only account; no password
            is_verified=bool(identity.email_verified),
            marketing_consent=marketing_consent,
            utm_source=utm.get("utm_source"),
            utm_medium=utm.get("utm_medium"),
            utm_campaign=utm.get("utm_campaign"),
            utm_term=utm.get("utm_term"),
            utm_content=utm.get("utm_content"),
        )
        self.db.add(user)
        await self.db.flush()
        await self.db.refresh(user)
        return user

    async def _link_referral(self, user: User, referral_code: str) -> None:
        # Reuse the exact consumer-service call password signup uses.
        from app.services.user_service import UserService

        await UserService(self.db)._link_referral_signup(
            user_id=user.id, email=user.email, referral_code=referral_code
        )

    async def _issue_tokens(
        self, user: User, device_info: Optional[str], ip_address: Optional[str]
    ) -> TokenResponse:
        access_token = create_access_token(user)
        refresh_token = await self.token_service.create_refresh_token(
            user=user, device_info=device_info, ip_address=ip_address
        )
        return TokenResponse(
            access_token=access_token,
            refresh_token=refresh_token.token,
            expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        )