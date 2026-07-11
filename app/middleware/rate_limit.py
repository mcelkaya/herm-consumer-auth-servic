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


async def enforce_rate_limit(request: Request, key: str, max_requests: int, window_seconds: int) -> None:
    """Fixed-window limiter keyed by an EXPLICIT sub-key (e.g. client_id / jti),
    not the client IP — used by the OIDC flow endpoints."""
    redis: aioredis.Redis = request.app.state.redis
    rkey = f"rate:{key}"
    count = await redis.incr(rkey)
    if count == 1:
        await redis.expire(rkey, window_seconds)
    if count > max_requests:
        ttl = max(await redis.ttl(rkey), 0)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Rate limit exceeded. Try again in {ttl} seconds.",
            headers={"Retry-After": str(ttl)},
        )


async def rate_limit_oidc_authorize(request: Request):
    # Unauthenticated GET; per-IP + WAF at the edge.
    await _check_rate_limit(request, "oidc_authorize", max_requests=60, window_seconds=60)


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
    # verify_email is idempotent, so the limit only needs to stop abuse, not
    # honest duplicates: clients double/triple-fire (e.g. React StrictMode),
    # so 3 per window rate-limited legitimate single verifications. Matches
    # rate_limit_verify_otp's allowance.
    await _check_rate_limit(request, "verify_email", max_requests=10, window_seconds=900)


async def rate_limit_send_otp(request: Request):
    await _check_rate_limit(request, "send_otp", max_requests=3, window_seconds=900)


async def rate_limit_verify_otp(request: Request):
    # Distinct from rate_limit_send_otp: a 6-digit code needs room for a
    # handful of honest mistyped-code retries, so this allows more attempts
    # per IP than sending codes does. attempt_count on EmailOtpCode handles
    # per-code brute-force lockout (5 wrong guesses); this IP-based limiter
    # is a second, independent layer against spraying guesses across codes.
    await _check_rate_limit(request, "verify_otp", max_requests=10, window_seconds=900)


# ---------------------------------------------------------------------------
# Email alias limits
#
# These are keyed by IDs from the validated JWT / DB (user id, alias id), NOT
# by client IP. The IP limiters above read X-Forwarded-For, whose first hop is
# client-controlled and therefore spoofable; an authenticated, per-resource
# key cannot be bypassed that way.
# ---------------------------------------------------------------------------

# Max new aliases a single user may create per rolling 24h window.
ALIAS_ADD_DAILY_MAX = 3
ALIAS_ADD_WINDOW_SECONDS = 24 * 60 * 60

# Max verification resends per individual alias per window.
ALIAS_RESEND_MAX = 3
ALIAS_RESEND_WINDOW_SECONDS = 15 * 60


async def assert_alias_add_quota(request: Request, user_id: str) -> None:
    """Reject if the user already hit the daily new-alias limit.

    Read-only check. Only *successful* adds are counted (see record_alias_add),
    so duplicate/invalid attempts don't burn a slot, and because the counter
    never decrements, add -> delete -> add can't be used to send more than
    ALIAS_ADD_DAILY_MAX verification emails per day.
    """
    redis: aioredis.Redis = request.app.state.redis
    key = f"rate:add_alias:{user_id}"
    current = await redis.get(key)
    if current is not None and int(current) >= ALIAS_ADD_DAILY_MAX:
        ttl = max(await redis.ttl(key), 0)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=(
                f"You can add at most {ALIAS_ADD_DAILY_MAX} email addresses "
                f"per day. Try again in {ttl} seconds."
            ),
            headers={"Retry-After": str(ttl)},
        )


async def record_alias_add(request: Request, user_id: str) -> None:
    """Count one *successful* alias creation toward the per-user daily quota.

    Call this only after the alias was created and its email queued, so failed
    adds (409 duplicate, 400 invalid) never consume quota.
    """
    redis: aioredis.Redis = request.app.state.redis
    key = f"rate:add_alias:{user_id}"
    count = await redis.incr(key)
    if count == 1:
        await redis.expire(key, ALIAS_ADD_WINDOW_SECONDS)


async def assert_alias_resend_quota(request: Request, alias_id: str) -> None:
    """Per-alias resend limit, keyed by the server-generated alias UUID.

    Caps how many verification emails can be sent to one alias address in a
    window. Call this only after confirming the alias belongs to the caller,
    so a guessed alias id can't be used to drain another user's quota.
    """
    redis: aioredis.Redis = request.app.state.redis
    key = f"rate:alias_resend:{alias_id}"
    count = await redis.incr(key)
    if count == 1:
        await redis.expire(key, ALIAS_RESEND_WINDOW_SECONDS)
    if count > ALIAS_RESEND_MAX:
        ttl = max(await redis.ttl(key), 0)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=(
                "Too many verification emails for this address. "
                f"Try again in {ttl} seconds."
            ),
            headers={"Retry-After": str(ttl)},
        )