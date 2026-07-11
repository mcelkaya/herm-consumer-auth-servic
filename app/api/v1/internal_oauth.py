"""Internal OAuth client-registry endpoints (Login with Herm).

Called ONLY by wizard-service (brand developer dashboard backend). Guarded by a
DEDICATED shared secret `X-Internal-API-Key: <WIZARD_AUTH_KEY>` — separate from
the 9-service INTERNAL_API_KEY — and compared in constant time. These paths sit
under /internal/* which is blocked at the public ALB, so they are reachable
only via internal Service Connect.

Brand ownership is enforced by wizard BEFORE it calls here (ADMIN role +
UserBrandAssignment); the asserted brand_id/company_id/user are recorded on the
client for audit and orphan reconciliation.
"""
import hmac
import logging
from typing import List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, Header, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.db.session import get_db
from app.schemas.oauth_client import (
    OAuthClientCreate,
    OAuthClientCreated,
    OAuthClientPublic,
    OAuthClientUpdate,
)
from app.services.oauth_client_service import OAuthClientService

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/internal/oauth", tags=["Internal OAuth Registry"])


async def verify_wizard_auth_key(
    x_internal_api_key: Optional[str] = Header(None, alias="X-Internal-API-Key"),
) -> bool:
    expected = settings.WIZARD_AUTH_KEY
    if not expected:
        # Fail closed: registry unusable until the dedicated key is configured.
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Client registry not configured",
        )
    if not x_internal_api_key or not hmac.compare_digest(x_internal_api_key, expected):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid internal API key",
        )
    return True


def _created(client, secret: Optional[str]) -> OAuthClientCreated:
    resp = OAuthClientCreated.model_validate(client)
    resp.client_secret = secret
    return resp


@router.post(
    "/clients",
    response_model=OAuthClientCreated,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(verify_wizard_auth_key)],
)
async def create_client(payload: OAuthClientCreate, db: AsyncSession = Depends(get_db)):
    """Register a new partner client. Returns the secret exactly once."""
    client, secret = await OAuthClientService(db).create(payload)
    logger.info("oauth_client created client_id=%s brand=%s", client.client_id, client.brand_id)
    return _created(client, secret)


@router.get(
    "/clients",
    response_model=List[OAuthClientPublic],
    dependencies=[Depends(verify_wizard_auth_key)],
)
async def list_clients(brand_id: UUID = Query(...), db: AsyncSession = Depends(get_db)):
    """List a brand's clients (never returns secrets)."""
    return await OAuthClientService(db).list_for_brand(brand_id)


async def _get_or_404(db: AsyncSession, client_id: str):
    client = await OAuthClientService(db).get(client_id)
    if client is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Client not found")
    return client


@router.get(
    "/clients/{client_id}",
    response_model=OAuthClientPublic,
    dependencies=[Depends(verify_wizard_auth_key)],
)
async def get_client(client_id: str, db: AsyncSession = Depends(get_db)):
    return await _get_or_404(db, client_id)


@router.patch(
    "/clients/{client_id}",
    response_model=OAuthClientPublic,
    dependencies=[Depends(verify_wizard_auth_key)],
)
async def update_client(client_id: str, payload: OAuthClientUpdate, db: AsyncSession = Depends(get_db)):
    client = await _get_or_404(db, client_id)
    return await OAuthClientService(db).update(client, payload)


@router.post(
    "/clients/{client_id}/regenerate-secret",
    response_model=OAuthClientCreated,
    dependencies=[Depends(verify_wizard_auth_key)],
)
async def regenerate_secret(client_id: str, db: AsyncSession = Depends(get_db)):
    client = await _get_or_404(db, client_id)
    try:
        secret = await OAuthClientService(db).regenerate_secret(client)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    logger.info("oauth_client secret regenerated client_id=%s", client_id)
    return _created(client, secret)


@router.delete(
    "/clients/{client_id}",
    response_model=OAuthClientPublic,
    dependencies=[Depends(verify_wizard_auth_key)],
)
async def revoke_client(client_id: str, db: AsyncSession = Depends(get_db)):
    client = await _get_or_404(db, client_id)
    logger.info("oauth_client revoked client_id=%s", client_id)
    return await OAuthClientService(db).revoke(client)
