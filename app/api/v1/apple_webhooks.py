"""Sign in with Apple server-to-server notifications.

    POST /public/webhooks/apple
        Body: {"payload": "<JWT signed by Apple>"}

Registered in the Apple developer portal under the App ID's Sign in with
Apple capability ("Server-to-Server Notification Endpoint"). Apple notifies
us when one of OUR app's users:

    consent-revoked   — revoked Sign in with Apple for our app. We sign the
                        user out everywhere but KEEP the link: the stable
                        `sub` is unchanged, so re-consenting later lands on
                        the same account.
    account-delete    — permanently deleted their Apple account. The `sub`
                        is dead, so we drop the link and sign the user out.
                        The local account itself survives (it may have a
                        password or other providers).
    email-disabled /  — toggled Hide My Email forwarding. We never send mail
    email-enabled       to relay addresses from here, so audit-log only.

Unknown subs are acknowledged with 200 (e.g. the user deleted their Herm
account before revoking on Apple's side); anything that fails signature,
issuer, or audience verification gets 401 so Apple retries and a
misconfiguration shows up in their delivery logs.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.audit_log import audit
from app.db.session import get_db
from app.repositories.user_oauth_account_repository import UserOAuthAccountRepository
from app.services import apple_account_service
from app.services.social_providers import SocialTokenError
from app.services.token_service import TokenService

router = APIRouter(prefix="/public/webhooks", tags=["Webhooks"])


class AppleWebhookRequest(BaseModel):
    payload: str = Field(..., min_length=1, description="Signed JWT from Apple")


@router.post("/apple")
async def apple_webhook(
    body: AppleWebhookRequest,
    db: AsyncSession = Depends(get_db),
):
    try:
        event = await apple_account_service.verify_apple_webhook(body.payload)
    except SocialTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error_key": "auth.social.invalidToken"},
        )

    event_type = event.get("type")
    sub = event.get("sub")

    links = UserOAuthAccountRepository(db)
    link = await links.get_by_provider_identity("apple", sub) if sub else None
    if link is None:
        audit("apple_webhook_unmatched", event_type=event_type)
        return {"status": "ok"}

    user_id = link.user_id
    if event_type == "consent-revoked":
        await TokenService(db).revoke_all_user_tokens(user_id)
    elif event_type == "account-delete":
        await TokenService(db).revoke_all_user_tokens(user_id)
        await links.delete(link)
    # email-disabled / email-enabled need no action.

    audit("apple_webhook", event_type=event_type, user_id=str(user_id))
    return {"status": "ok"}
