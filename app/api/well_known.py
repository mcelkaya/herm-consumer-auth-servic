"""OIDC discovery + JWKS endpoints for Login with Herm.

Served at the issuer root (``/herm-auth/.well-known/*``), unauthenticated and
cacheable. The whole surface is gated behind ``OIDC_PROVIDER_ENABLED``; while
the flag is off every endpoint returns 404, so shipping this router is a no-op
until the provider is deliberately enabled.
"""
from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.db.session import get_db
from app.services.oidc_key_service import oidc_key_service

router = APIRouter(prefix="/.well-known", tags=["oidc"])


def _require_enabled() -> None:
    if not settings.OIDC_PROVIDER_ENABLED:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not Found")


@router.get("/openid-configuration")
async def openid_configuration(response: Response):
    _require_enabled()
    issuer = settings.OIDC_ISSUER
    response.headers["Cache-Control"] = "public, max-age=3600"
    return {
        "issuer": issuer,
        "authorization_endpoint": f"{issuer}/oidc/authorize",
        "token_endpoint": f"{issuer}/oidc/token",
        "userinfo_endpoint": f"{issuer}/oidc/userinfo",
        "jwks_uri": f"{issuer}/.well-known/jwks.json",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "subject_types_supported": ["pairwise"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "scopes_supported": ["openid", "email", "profile"],
        "token_endpoint_auth_methods_supported": [
            "client_secret_basic",
            "client_secret_post",
            "none",
        ],
        "code_challenge_methods_supported": ["S256"],
        "authorization_response_iss_parameter_supported": True,
    }


@router.get("/jwks.json")
async def jwks(response: Response, db: AsyncSession = Depends(get_db)):
    _require_enabled()
    if not settings.OIDC_SIGNING_KEY_ARN:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Signing key not configured",
        )
    await oidc_key_service.ensure_active_key(db)
    response.headers["Cache-Control"] = "public, max-age=3600"
    return await oidc_key_service.get_jwks(db)
