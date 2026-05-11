"""Internal service-to-service endpoints for herm-auth-service.

All endpoints under this router are guarded by `X-Internal-API-Key`
(`settings.INTERNAL_API_KEY`). They are not exposed publicly — the ALB /
ingress should restrict them to the internal VPC.

Currently exposed:

  POST /internal/users/lookup-by-email
    Resolve an email address (primary or verified alias) to a user_id UUID.
    Used by data-processing / ETL services to attribute scraped emails to
    a Herm user. Only the user's primary email and VERIFIED aliases match;
    unverified alias claims are ignored.

    Headers:  X-Internal-API-Key: <shared-secret>
    Body:     {"email": "user@example.com"}
    200:      {"user_id": "<uuid>"}
    404:      no user owns this email
    422:      malformed input

Future: incorporate user_email_connections.email_address from
herm-consumer-service into the lookup so OAuth-connected mailboxes are
treated as owned by the connecting user.
"""

import logging
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, Header, HTTPException, status
from pydantic import BaseModel, EmailStr, ConfigDict
from sqlalchemy import and_, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.db.session import get_db
from app.models.user import User
from app.models.user_email_alias import UserEmailAlias

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/internal", tags=["Internal API"])


async def verify_internal_api_key(
    x_internal_api_key: Optional[str] = Header(None, alias="X-Internal-API-Key"),
) -> bool:
    if not settings.INTERNAL_API_KEY:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Internal API not configured",
        )
    if not x_internal_api_key or x_internal_api_key != settings.INTERNAL_API_KEY:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid internal API key",
        )
    return True


class LookupByEmailRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: EmailStr


class LookupByEmailResponse(BaseModel):
    user_id: UUID


@router.post(
    "/users/lookup-by-email",
    response_model=LookupByEmailResponse,
    dependencies=[Depends(verify_internal_api_key)],
)
async def lookup_user_by_email(
    payload: LookupByEmailRequest,
    db: AsyncSession = Depends(get_db),
) -> LookupByEmailResponse:
    """Return the user_id that owns the given email address.

    Matches against `users.email` (primary) and verified
    `user_email_aliases.email`. Case-insensitive. 404 if no match.
    """
    normalized = payload.email.strip().lower()

    # Primary email match.
    primary = await db.execute(
        select(User.id).where(func.lower(User.email) == normalized)
    )
    user_id = primary.scalar_one_or_none()
    if user_id is not None:
        return LookupByEmailResponse(user_id=user_id)

    # Verified alias match. Unverified claims are excluded — they don't
    # prove ownership.
    alias = await db.execute(
        select(UserEmailAlias.user_id).where(
            and_(
                func.lower(UserEmailAlias.email) == normalized,
                UserEmailAlias.is_verified == True,  # noqa: E712
            )
        )
    )
    user_id = alias.scalar_one_or_none()
    if user_id is not None:
        return LookupByEmailResponse(user_id=user_id)

    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail="No user owns this email",
    )
