from typing import Optional, List
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql import func

from app.models.oauth_consent import OAuthConsent


class OAuthConsentRepository:
    """Data access for consumer standing consents (flush, not commit)."""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def get(self, user_id: UUID, client_id: str) -> Optional[OAuthConsent]:
        result = await self.db.execute(
            select(OAuthConsent).where(
                OAuthConsent.user_id == user_id,
                OAuthConsent.client_id == client_id,
            )
        )
        return result.scalar_one_or_none()

    async def upsert(self, user_id: UUID, client_id: str, scopes: List[str]) -> OAuthConsent:
        """Create or extend a consent, unioning scopes and clearing any revocation."""
        consent = await self.get(user_id, client_id)
        if consent is None:
            consent = OAuthConsent(user_id=user_id, client_id=client_id, granted_scopes=list(scopes))
            self.db.add(consent)
        else:
            merged = list(dict.fromkeys(list(consent.granted_scopes or []) + list(scopes)))
            consent.granted_scopes = merged
            consent.revoked_at = None
            consent.last_used_at = func.now()
        await self.db.flush()
        return consent

    async def list_for_user(self, user_id: UUID) -> List[OAuthConsent]:
        result = await self.db.execute(
            select(OAuthConsent).where(
                OAuthConsent.user_id == user_id,
                OAuthConsent.revoked_at.is_(None),
            ).order_by(OAuthConsent.granted_at.desc())
        )
        return list(result.scalars().all())
