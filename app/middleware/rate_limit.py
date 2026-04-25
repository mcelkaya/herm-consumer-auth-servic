"""
Rate limiting middleware for API endpoints — Redis-backed, multi-worker safe.
"""

import redis.asyncio as aioredis
from fastapi import Request, HTTPException, status


def _get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


async def _check_rate_limit(
    request: Request,
    label: str,
    max_requests: int,
    window_seconds: int,
) -> None:
    """
    Fixed-window Redis rate limiter keyed by endpoint label + client IP.
    Uses INCR + EXPIRE so the window resets atomically on first hit.
    """
    client_ip = _get_client_ip(request)
    key = f"rate:{label}:{client_ip}"
    redis: aioredis.Redis = request.app.state.redis

    count = await redis.incr(key)
    if count == 1:
        await redis.expire(key, window_seconds)

    if count > max_requests:
        ttl = max(await redis.ttl(key), 0)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Rate limit exceeded. Try again in {ttl} seconds.",
            headers={"Retry-After": str(ttl)},
        )


async def rate_limit_login(request: Request):
    await _check_rate_limit(request, "login", max_requests=5, window_seconds=300)


async def rate_limit_admin_login(request: Request):
    await _check_rate_limit(request, "admin_login", max_requests=5, window_seconds=900)


async def rate_limit_forgot_password(request: Request):
    await _check_rate_limit(request, "forgot_password", max_requests=3, window_seconds=900)


async def rate_limit_reset_password(request: Request):
    await _check_rate_limit(request, "reset_password", max_requests=5, window_seconds=900)


async def rate_limit_resend_verification(request: Request):
    await _check_rate_limit(request, "resend_verification", max_requests=3, window_seconds=900)


async def rate_limit_signup(request: Request):
    await _check_rate_limit(request, "signup", max_requests=10, window_seconds=3600)


async def rate_limit_verify_email(request: Request):
    await _check_rate_limit(request, "verify_email", max_requests=3, window_seconds=900)
