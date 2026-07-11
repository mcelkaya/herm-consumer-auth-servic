"""Service layer for the partner OAuth client registry (Login with Herm).

Encapsulates client creation (id + one-time secret generation), secret
regeneration, updates, and revocation. Callers are the internal registry
endpoints; brand ownership is enforced upstream by wizard-service and recorded
on the client for audit / reconciliation.
"""
from datetime import datetime, timezone
from typing import Optional, Tuple
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from app.models.oauth_client import OAuthClient
from app.repositories.oauth_client_repository import OAuthClientRepository
from app.schemas.oauth_client import OAuthClientCreate, OAuthClientUpdate


class OAuthClientService:
    def __init__(self, db: AsyncSession):
        self.db = db
        self.repo = OAuthClientRepository(db)

    async def create(self, payload: OAuthClientCreate) -> Tuple[OAuthClient, Optional[str]]:
        """Create a client. Returns (client, plaintext_secret).

        plaintext_secret is set only for confidential clients and must be shown
        to the caller exactly once — it is never stored or recoverable.
        """
        secret_plain: Optional[str] = None
        secret_hash: Optional[str] = None
        if payload.client_type == "confidential":
            secret_plain, secret_hash = OAuthClient.generate_client_secret()

        client = OAuthClient(
            client_id=OAuthClient.generate_client_id(),
            client_secret_hash=secret_hash,
            client_type=payload.client_type,
            client_name=payload.client_name,
            logo_url=payload.logo_url,
            brand_id=payload.brand_id,
            company_id=payload.company_id,
            created_by_user_id=payload.created_by_user_id,
            redirect_uris=payload.redirect_uris,
            allowed_scopes=payload.allowed_scopes,
            is_sandbox=payload.is_sandbox,
            status="active",
        )
        await self.repo.create(client)
        return client, secret_plain

    async def regenerate_secret(self, client: OAuthClient) -> str:
        """Rotate a confidential client's secret. Returns the new plaintext once."""
        if client.client_type != "confidential":
            raise ValueError("public clients have no secret")
        secret_plain, secret_hash = OAuthClient.generate_client_secret()
        client.client_secret_hash = secret_hash
        await self.db.flush()
        return secret_plain

    async def update(self, client: OAuthClient, payload: OAuthClientUpdate) -> OAuthClient:
        data = payload.model_dump(exclude_unset=True, exclude={"is_sandbox"})
        for field in ("client_name", "logo_url", "redirect_uris", "allowed_scopes", "status"):
            if field in data and data[field] is not None:
                setattr(client, field, data[field])
        if data.get("status") == "revoked" and client.revoked_at is None:
            client.revoked_at = datetime.now(timezone.utc)
        await self.db.flush()
        return client

    async def revoke(self, client: OAuthClient) -> OAuthClient:
        client.status = "revoked"
        client.revoked_at = datetime.now(timezone.utc)
        await self.db.flush()
        return client

    async def get(self, client_id: str) -> Optional[OAuthClient]:
        return await self.repo.get_by_client_id(client_id)

    async def list_for_brand(self, brand_id: UUID):
        return await self.repo.list_by_brand(brand_id)
