import asyncio
import logging
import uuid
from contextlib import asynccontextmanager
import redis.asyncio as aioredis
from fastapi import FastAPI, Request, status
from fastapi.exceptions import HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from app.core.config import settings
from app.api.v1 import public_auth, pii_auth, admin_auth, internal
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


# Exception handlers
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    error_id = str(uuid.uuid4())
    logging.error(
        "Unhandled exception [ID: %s]: %s",
        error_id,
        exc,
        exc_info=True,
        extra={
            "error_id": error_id,
            "path": request.url.path,
            "method": request.method,
            "client_ip": request.client.host if request.client else None,
        },
    )
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "An unexpected error occurred. Please try again later.", "error_id": error_id},
    )


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    if exc.status_code >= 500:
        logging.error(
            "HTTP %s: %s",
            exc.status_code,
            exc.detail,
            extra={"path": request.url.path, "method": request.method},
        )
    elif exc.status_code >= 400:
        logging.warning(
            "HTTP %s: %s",
            exc.status_code,
            exc.detail,
            extra={"path": request.url.path, "method": request.method},
        )
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=settings.DEBUG
    )
