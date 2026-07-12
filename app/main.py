import asyncio
import logging
from contextlib import asynccontextmanager
import redis.asyncio as aioredis
from fastapi import FastAPI, status
from fastapi.middleware.cors import CORSMiddleware
from app.core.config import settings
from app.core.error_handlers import register_exception_handlers
from app.api.v1 import public_auth, pii_auth, admin_auth, internal, social_auth, social_link, internal_oauth, pii_oauth
from app.api import well_known, oidc
from app.middleware.security import SecurityHeadersMiddleware, NullByteSanitizerMiddleware
from app.db.session import AsyncSessionLocal
from app.services.token_service import TokenService
from app.services.admin_token_service import AdminTokenService


class HealthCheckFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        return "/herm-auth/v1/public/health" not in record.getMessage()


logging.getLogger("uvicorn.access").addFilter(HealthCheckFilter())


async def _cleanup_stale_tokens_loop() -> None:
    """Delete revoked/expired refresh tokens every 24 hours."""
    while True:
        await asyncio.sleep(24 * 60 * 60)
        try:
            async with AsyncSessionLocal() as db:
                deleted = await TokenService(db).cleanup_stale_tokens()
                admin_deleted = await AdminTokenService(db).cleanup_stale_tokens()
                logging.info("Token cleanup: %d consumer + %d admin tokens deleted", deleted, admin_deleted)
        except Exception:
            logging.exception("Token cleanup failed")


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.redis = aioredis.from_url(
        settings.REDIS_URL,
        encoding="utf-8",
        decode_responses=True,
    )
    cleanup_task = asyncio.create_task(_cleanup_stale_tokens_loop())
    yield
    cleanup_task.cancel()
    await app.state.redis.aclose()


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="Herm Auth Service",
    docs_url="/herm-auth/v1/public/docs" if settings.DEBUG else None,
    redoc_url="/herm-auth/v1/public/redoc" if settings.DEBUG else None,
    openapi_url="/herm-auth/v1/public/openapi.json" if settings.DEBUG else None,
    lifespan=lifespan,
)

# CORS middleware - specific origins required when using credentials
# Cannot use ["*"] with allow_credentials=True (browser security restriction)
cors_origins = settings.CORS_ORIGINS

app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(NullByteSanitizerMiddleware)

app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["Set-Cookie"],
)


# Health check endpoint
@app.get("/herm-auth/v1/public/health", status_code=status.HTTP_200_OK)
async def health_check():
    return {
        "status": "healthy",
        "service": settings.APP_NAME,
        "version": settings.APP_VERSION
    }


# Include routers
app.include_router(public_auth.router, prefix="/herm-auth/v1")
app.include_router(pii_auth.router, prefix="/herm-auth/v1")
app.include_router(admin_auth.router, prefix="/herm-auth/v1")
app.include_router(internal.router, prefix="/herm-auth/v1")

# Login with Herm — partner OAuth client registry (wizard-service is the only
# caller; guarded by the dedicated WIZARD_AUTH_KEY, blocked at the public ALB).
app.include_router(internal_oauth.router, prefix="/herm-auth/v1")

# Login with Herm — consumer "Connected Apps" (list/revoke own consents).
app.include_router(pii_oauth.router, prefix="/herm-auth/v1")

# Social login (Google / Apple / Facebook)
#   social_auth: POST /herm-auth/v1/public/auth/social/{provider}  (public)
#   social_link: GET/POST/DELETE /herm-auth/v1/pii/auth/social/... (authenticated)
app.include_router(social_auth.router, prefix="/herm-auth/v1")
app.include_router(social_link.router, prefix="/herm-auth/v1")

# Login with Herm — OIDC discovery/JWKS at the issuer root (/herm-auth/.well-known/*).
# Routes are always mounted but each returns 404 unless OIDC_PROVIDER_ENABLED.
app.include_router(well_known.router, prefix="/herm-auth")
app.include_router(oidc.router, prefix="/herm-auth")


register_exception_handlers(app)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=settings.DEBUG
    )