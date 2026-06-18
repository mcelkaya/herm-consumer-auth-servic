import uuid
import logging
from fastapi import FastAPI, Request, status
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import HTTPException, RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

logger = logging.getLogger(__name__)


def register_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(request: Request, exc: RequestValidationError):
        logger.warning(
            f"Validation error: {exc.errors()}",
            extra={"path": request.url.path, "method": request.method},
        )
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            # jsonable_encoder is required: Pydantic v2's exc.errors() embeds the
            # raw exception object under ctx.error, which json.dumps cannot
            # serialize. Without this the handler raises TypeError, producing a
            # header-less 500 (no CORS headers) that the browser misreports as a
            # CORS error.
            content={"detail": jsonable_encoder(exc.errors())},
        )

    @app.exception_handler(StarletteHTTPException)
    async def starlette_http_exception_handler(request: Request, exc: StarletteHTTPException):
        if exc.status_code >= 500:
            logger.error(
                f"HTTP {exc.status_code}: {exc.detail}",
                extra={"path": request.url.path, "method": request.method, "status_code": exc.status_code},
            )
        elif exc.status_code >= 400:
            logger.warning(
                f"HTTP {exc.status_code}: {exc.detail}",
                extra={"path": request.url.path, "method": request.method, "status_code": exc.status_code},
            )
        return JSONResponse(
            status_code=exc.status_code,
            content={"detail": exc.detail},
        )

    @app.exception_handler(HTTPException)
    async def http_exception_handler(request: Request, exc: HTTPException):
        if exc.status_code >= 500:
            logger.error(
                f"HTTP {exc.status_code}: {exc.detail}",
                extra={"path": request.url.path, "method": request.method, "status_code": exc.status_code},
            )
        elif exc.status_code >= 400:
            logger.warning(
                f"HTTP {exc.status_code}: {exc.detail}",
                extra={"path": request.url.path, "method": request.method, "status_code": exc.status_code},
            )
        return JSONResponse(
            status_code=exc.status_code,
            content={"detail": exc.detail},
        )

    @app.exception_handler(Exception)
    async def global_exception_handler(request: Request, exc: Exception):
        error_id = str(uuid.uuid4())
        logger.error(
            f"Unhandled exception [ID: {error_id}]: {exc}",
            exc_info=True,
            extra={
                "error_id": error_id,
                "path": request.url.path,
                "method": request.method,
                "client_ip": request.client.host if request.client else None,
                "user_agent": request.headers.get("user-agent"),
            },
        )
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "detail": "An unexpected error occurred. Please try again later.",
                "error_id": error_id,
            },
        )
