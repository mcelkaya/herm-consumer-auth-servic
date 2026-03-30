import redis.asyncio as aioredis


class TokenBlocklistService:
    """Redis-backed access token revocation list keyed by jti."""

    REDIS_KEY_PREFIX = "blocklist:jti:"

    def __init__(self, redis: aioredis.Redis):
        self._redis = redis

    async def add(self, jti: str, ttl_seconds: int) -> None:
        """Mark a jti as revoked. Key expires automatically after ttl_seconds."""
        key = f"{self.REDIS_KEY_PREFIX}{jti}"
        await self._redis.setex(key, ttl_seconds, "1")

    async def is_blocked(self, jti: str) -> bool:
        """Return True if the jti has been revoked."""
        key = f"{self.REDIS_KEY_PREFIX}{jti}"
        result = await self._redis.exists(key)
        return result > 0
