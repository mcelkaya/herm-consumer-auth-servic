"""Public keys for verifying consumer/admin RS256 access tokens.

Served at ``/herm-auth/.well-known/access-token-jwks.json``. Deliberately a
separate document from the OIDC JWKS (``/.well-known/jwks.json``):

* the OIDC JWKS is gated by OIDC_PROVIDER_ENABLED and needs DB + KMS on every
  request; internal token verification must not depend on the partner OIDC
  feature flag, KMS or the DB;
* keeping the key sets apart means a partner-held OIDC token (same ``iss``)
  can never verify at an internal service, and our internal access-token keys
  are never trusted by partner relying parties;
* rotation wants a shorter cache lifetime than the OIDC document.

Returns 404 until ACCESS_TOKEN_SIGNING_KEYS holds a valid keyset, so
deploying this route is a no-op. Served from memory: no DB, no KMS.
"""
from fastapi import APIRouter, HTTPException, Response, status

from app.core.security import get_access_token_keyset

router = APIRouter(prefix="/.well-known", tags=["auth"])


@router.get("/access-token-jwks.json")
async def access_token_jwks(response: Response):
    keyset = get_access_token_keyset()
    if keyset is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not Found")
    response.headers["Cache-Control"] = "public, max-age=300"
    return keyset.public_jwks()
