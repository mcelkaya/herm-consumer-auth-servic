"""Authenticated social account management (the /settings page).

All endpoints require a Bearer JWT (get_current_user) and act only on the
caller's own account.

    GET    /pii/auth/social
        List the caller's linked providers.

    POST   /pii/auth/social/{provider}/link
        Link a provider to the CURRENT user. No email match is required —
        identity is already proven by the session — so this is the path that
        works for Apple "Hide My Email" relay addresses and for the
        "accountExistsNeedsLink" case from public social sign-in.
        409 auth.social.identityLinkedToOtherUser — this provider identity is
            already attached to a different account.
        409 auth.social.providerAlreadyLinked     — you already linked this
            provider.

    DELETE /pii/auth/social/{provider}
        Unlink a provider. Refuses to remove your only sign-in method when you
        have no password set.
"""

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.dependencies import get_current_user
from app.core.audit_log import audit
from app.db.session import get_db
from app.models.user import User
from app.schemas.social import (
    LinkedAccountResponse,
    LinkedAccountsListResponse,
    SocialLinkRequest,
    SocialProvider,
)
from app.services.social_auth_service import (
    ProviderAlreadyLinkedError,
    ProviderIdentityConflictError,
    SocialAuthService,
)
from app.services.social_providers import SocialConfigError, SocialTokenError

router = APIRouter(prefix="/pii/auth/social", tags=["Social Authentication"])


@router.get("", response_model=LinkedAccountsListResponse)
async def list_linked_accounts(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> LinkedAccountsListResponse:
    service = SocialAuthService(db)
    links = await service.list_links(current_user)
    return LinkedAccountsListResponse(
        accounts=[LinkedAccountResponse.model_validate(link) for link in links]
    )


@router.post(
    "/{provider}/link",
    response_model=LinkedAccountResponse,
    status_code=status.HTTP_201_CREATED,
)
async def link_social_account(
    provider: SocialProvider,
    body: SocialLinkRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> LinkedAccountResponse:
    ip_address = request.client.host if request.client else None
    service = SocialAuthService(db)
    try:
        link = await service.link_account(
            current_user=current_user,
            provider=provider.value,
            credential=body.credential,
            credential_type=body.credential_type.value if body.credential_type else None,
            nonce=body.nonce,
        )
    except SocialTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error_key": "auth.social.invalidToken"},
        )
    except SocialConfigError:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error_key": "auth.social.providerMisconfigured"},
        )
    except ProviderIdentityConflictError:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"error_key": "auth.social.identityLinkedToOtherUser"},
        )
    except ProviderAlreadyLinkedError:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"error_key": "auth.social.providerAlreadyLinked"},
        )

    audit(
        "social_account_linked",
        ip=ip_address,
        provider=provider.value,
        user_id=str(current_user.id),
    )
    return LinkedAccountResponse.model_validate(link)


@router.delete("/{provider}", status_code=status.HTTP_204_NO_CONTENT)
async def unlink_social_account(
    provider: SocialProvider,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    service = SocialAuthService(db)
    await service.unlink(current_user, provider.value)
    ip_address = request.client.host if request.client else None
    audit(
        "social_account_unlinked",
        ip=ip_address,
        provider=provider.value,
        user_id=str(current_user.id),
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)