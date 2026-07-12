"""Consumer-facing management of "Login with Herm" consents ("Connected Apps").

A consumer sees which partner apps they authorized and can revoke access —
which revokes the standing consent AND the client's refresh tokens for this
user (stateless access tokens expire on their own within ~15 min). Guarded by
the consumer JWT (get_current_user); gated behind OIDC_PROVIDER_ENABLED.
"""
import logging
from datetime import datetime, timezone
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import func, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.dependencies import get_current_user
from app.core.config import settings
from app.db.session import get_db
from app.models.oauth_refresh_token import OAuthRefreshToken
from app.models.user import User
from app.repositories.oauth_client_repository import OAuthClientRepository
from app.repositories.oauth_consent_repository import OAuthConsentRepository

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/pii/oauth", tags=["Connected Apps"])


def _require_enabled() -> None:
    if not settings.OIDC_PROVIDER_ENABLED:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not Found")


class ConnectedApp(BaseModel):
    client_id: str
    client_name: str
    logo_url: Optional[str] = None
    granted_scopes: List[str]
    granted_at: Optional[datetime] = None
    last_used_at: Optional[datetime] = None


@router.get("/consents", response_model=List[ConnectedApp])
async def list_consents(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> List[ConnectedApp]:
    _require_enabled()
    consents = await OAuthConsentRepository(db).list_for_user(user.id)
    if not consents:
        return []
    clients = await OAuthClientRepository(db).get_by_client_ids([c.client_id for c in consents])
    by_id = {c.client_id: c for c in clients}
    result: List[ConnectedApp] = []
    for c in consents:
        client = by_id.get(c.client_id)
        if client is None:
            continue  # client deleted — skip orphaned consent
        result.append(
            ConnectedApp(
                client_id=c.client_id,
                client_name=client.client_name,
                logo_url=client.logo_url,
                granted_scopes=c.granted_scopes or [],
                granted_at=c.granted_at,
                last_used_at=c.last_used_at,
            )
        )
    return result


@router.delete("/consents/{client_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_consent(
    client_id: str,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> None:
    _require_enabled()
    consent = await OAuthConsentRepository(db).get(user.id, client_id)
    if consent is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Consent not found")
    if consent.revoked_at is None:
        consent.revoked_at = datetime.now(timezone.utc)
        # Revoke the client's refresh tokens for THIS user (scoped by user_id).
        await db.execute(
            update(OAuthRefreshToken)
            .where(
                OAuthRefreshToken.client_id == client_id,
                OAuthRefreshToken.user_id == user.id,
                OAuthRefreshToken.revoked_at.is_(None),
            )
            .values(revoked_at=func.now())
        )
        await db.flush()
        logger.info("oauth consent revoked by user=%s client=%s", user.id, client_id)
    return None
