from typing import Optional, List
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.oauth_client import OAuthClient


class OAuthClientRepository:
    """Data access for partner OAuth client registrations.

    Like the other repositories here, this layer uses flush (not commit),
    leaving transaction boundaries to the calling service/endpoint.
    """

    def __init__(self, db: AsyncSession):
        self.db = db

    async def create(self, client: OAuthClient) -> OAuthClient:
        self.db.add(client)
        await self.db.flush()
        await self.db.refresh(client)
        return client

    async def get_by_client_id(self, client_id: str) -> Optional[OAuthClient]:
        result = await self.db.execute(
            select(OAuthClient).where(OAuthClient.client_id == client_id)
        )
        return result.scalar_one_or_none()

    async def get_by_client_ids(self, client_ids: List[str]) -> List[OAuthClient]:
        if not client_ids:
            return []
        result = await self.db.execute(
            select(OAuthClient).where(OAuthClient.client_id.in_(client_ids))
        )
        return list(result.scalars().all())

    async def list_by_brand(self, brand_id: UUID) -> List[OAuthClient]:
        """All clients owned by a brand, newest first (management listing)."""
        result = await self.db.execute(
            select(OAuthClient)
            .where(OAuthClient.brand_id == brand_id)
            .order_by(OAuthClient.created_at.desc())
        )
        return list(result.scalars().all())

    async def list_by_company(self, company_id: UUID) -> List[OAuthClient]:
        result = await self.db.execute(
            select(OAuthClient)
            .where(OAuthClient.company_id == company_id)
            .order_by(OAuthClient.created_at.desc())
        )
        return list(result.scalars().all())
