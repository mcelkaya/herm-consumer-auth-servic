"""
Rate limiting middleware for API endpoints

This provides simple in-memory rate limiting based on IP address.
For production use with multiple workers, consider using Redis-based rate limiting.
"""

from fastapi import Request, HTTPException, status
from typing import Dict, Tuple
from datetime import datetime, timedelta
from collections import defaultdict
import threading


class RateLimiter:
    """
    Simple in-memory rate limiter

    For production with multiple workers, use Redis-based solution like:
    - slowapi (https://github.com/laurents/slowapi)
    - fastapi-limiter (https://github.com/long2ice/fastapi-limiter)
    """

    def __init__(self):
        # Store: IP -> (request_count, window_start_time)
        self._storage: Dict[str, Tuple[int, datetime]] = defaultdict(lambda: (0, datetime.utcnow()))
        self._lock = threading.Lock()

    def _get_client_ip(self, request: Request) -> str:
        """Extract client IP from request"""
        # Try X-Forwarded-For header first (for proxies/load balancers)
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            # Get the first IP in the chain (original client)
            return forwarded.split(",")[0].strip()

        # Fallback to direct client host
        return request.client.host if request.client else "unknown"

    def _cleanup_expired_entries(self, window_seconds: int):
        """Remove expired entries from storage"""
        now = datetime.utcnow()
        expired_keys = [
            ip for ip, (_, window_start) in self._storage.items()
            if now - window_start > timedelta(seconds=window_seconds * 2)  # Clean up after 2x window
        ]

        for key in expired_keys:
            del self._storage[key]

    async def check_rate_limit(
        self,
        request: Request,
        max_requests: int,
        window_seconds: int
    ) -> None:
        """
        Check if request exceeds rate limit

        Args:
            request: FastAPI request object
            max_requests: Maximum number of requests allowed
            window_seconds: Time window in seconds

        Raises:
            HTTPException: 429 Too Many Requests if limit exceeded
        """
        client_ip = self._get_client_ip(request)
        now = datetime.utcnow()

        with self._lock:
            # Cleanup old entries periodically
            if len(self._storage) > 1000:  # Arbitrary threshold
                self._cleanup_expired_entries(window_seconds)

            # Get current count and window start
            count, window_start = self._storage[client_ip]

            # Check if we're still in the same window
            if now - window_start < timedelta(seconds=window_seconds):
                # Same window - check if limit exceeded
                if count >= max_requests:
                    retry_after = int((window_start + timedelta(seconds=window_seconds) - now).total_seconds())
                    raise HTTPException(
                        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                        detail=f"Rate limit exceeded. Try again in {retry_after} seconds.",
                        headers={"Retry-After": str(retry_after)}
                    )

                # Increment counter
                self._storage[client_ip] = (count + 1, window_start)
            else:
                # New window - reset counter
                self._storage[client_ip] = (1, now)


# Global rate limiter instance
rate_limiter = RateLimiter()


# Dependency factories for common rate limits
async def rate_limit_forgot_password(request: Request):
    """
    Rate limit for forgot password endpoint

    Limit: 3 requests per 15 minutes (900 seconds)
    """
    import asyncio
    return asyncio.create_task(
        rate_limiter.check_rate_limit(request, max_requests=3, window_seconds=900)
    )


async def rate_limit_reset_password(request: Request):
    """
    Rate limit for reset password endpoint

    Limit: 5 requests per 15 minutes (900 seconds)
    """
    import asyncio
    return asyncio.create_task(
        rate_limiter.check_rate_limit(request, max_requests=5, window_seconds=900)
    )


async def rate_limit_login(request: Request):
    """
    Rate limit for login endpoint

    Limit: 5 requests per 5 minutes (300 seconds)
    """
    import asyncio
    return asyncio.create_task(
        rate_limiter.check_rate_limit(request, max_requests=5, window_seconds=300)
    )


async def rate_limit_resend_verification(request: Request):
    """
    Rate limit for resend verification endpoint

    Limit: 3 requests per 15 minutes (900 seconds)
    """
    import asyncio
    return asyncio.create_task(
        rate_limiter.check_rate_limit(request, max_requests=3, window_seconds=900)
    )