import logging
from contextlib import asynccontextmanager
import redis.asyncio as aioredis
from fastapi import FastAPI, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from app.core.config import settings
from app.api.v1 import auth
from app.middleware.security import SecurityHeadersMiddleware


class HealthCheckFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        return "/herm-auth/health" not in record.getMessage()


logging.getLogger("uvicorn.access").addFilter(HealthCheckFilter())


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.redis = aioredis.from_url(
        settings.REDIS_URL,
        encoding="utf-8",
        decode_responses=True,
    )
    yield
    await app.state.redis.aclose()


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="Herm Auth Service",
    docs_url="/herm-auth/docs" if settings.DEBUG else None,
    redoc_url="/herm-auth/redoc" if settings.DEBUG else None,
    openapi_url="/herm-auth/openapi.json" if settings.DEBUG else None,
    lifespan=lifespan,
)

# CORS middleware - specific origins required when using credentials
# Cannot use ["*"] with allow_credentials=True (browser security restriction)
cors_origins = settings.CORS_ORIGINS

app.add_middleware(SecurityHeadersMiddleware)

app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["Set-Cookie"],
)


# Health check endpoint
@app.get("/herm-auth/health", status_code=status.HTTP_200_OK)
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "service": settings.APP_NAME,
        "version": settings.APP_VERSION
    }


# Include routers
app.include_router(auth.router, prefix="/herm-auth/api/v1")


# Exception handlers
@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    """Global exception handler"""
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "Internal server error"}
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=settings.PORT,
        reload=settings.DEBUG
    )
