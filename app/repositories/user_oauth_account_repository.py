from typing import Optional, List
from uuid import UUID
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.user_oauth_account import UserOAuthAccount


class UserOAuthAccountRepository:
    """Repository for social-login identity links.

    Mirrors UserRepository's conventions: this layer uses flush (not commit),
    leaving transaction boundaries to the calling service/endpoint.
    """

    def __init__(self, db: AsyncSession):
        self.db = db

    async def get_by_provider_identity(
        self, provider: str, provider_user_id: str
    ) -> Optional[UserOAuthAccount]:
        """Return the link for a provider's stable subject id, if any.

        This is the primary lookup on repeat social logins: a returning user is
        recognised by (provider, sub), never by email.
        """
        result = await self.db.execute(
            select(UserOAuthAccount).where(
                UserOAuthAccount.provider == provider,
                UserOAuthAccount.provider_user_id == provider_user_id,
            )
        )
        return result.scalar_one_or_none()

    async def get_for_user_and_provider(
        self, user_id: UUID, provider: str
    ) -> Optional[UserOAuthAccount]:
        """Return this user's link for a given provider, if they have one."""
        result = await self.db.execute(
            select(UserOAuthAccount).where(
                UserOAuthAccount.user_id == user_id,
                UserOAuthAccount.provider == provider,
            )
        )
        return result.scalar_one_or_none()

    async def list_for_user(self, user_id: UUID) -> List[UserOAuthAccount]:
        """All provider links on a user's account (for the settings page)."""
        result = await self.db.execute(
            select(UserOAuthAccount)
            .where(UserOAuthAccount.user_id == user_id)
            .order_by(UserOAuthAccount.created_at.asc())
        )
        return list(result.scalars().all())

    async def create(
        self,
        user_id: UUID,
        provider: str,
        provider_user_id: str,
        email_at_link: Optional[str] = None,
    ) -> UserOAuthAccount:
        link = UserOAuthAccount(
            user_id=user_id,
            provider=provider,
            provider_user_id=provider_user_id,
            email_at_link=email_at_link,
        )
        self.db.add(link)
        await self.db.flush()
        await self.db.refresh(link)
        return link

    async def delete(self, link: UserOAuthAccount) -> None:
        await self.db.delete(link)
        await self.db.flush()