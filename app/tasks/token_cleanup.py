"""
Token cleanup task for removing expired refresh tokens

This task should be run periodically (e.g., daily) to clean up expired refresh tokens
from the database. This prevents the refresh_tokens table from growing indefinitely.

Example usage with cron:
    # Run daily at 2 AM
    0 2 * * * cd /path/to/project && python -c "from app.tasks.token_cleanup import run_cleanup; import asyncio; asyncio.run(run_cleanup())"

Or with APScheduler in your FastAPI app:
    from apscheduler.schedulers.asyncio import AsyncIOScheduler
    from app.tasks.token_cleanup import cleanup_expired_tokens_task

    scheduler = AsyncIOScheduler()
    scheduler.add_job(cleanup_expired_tokens_task, 'cron', hour=2, minute=0)
    scheduler.start()
"""

from datetime import datetime
from sqlalchemy.ext.asyncio import AsyncSession
from app.db.session import AsyncSessionLocal
from app.services.token_service import TokenService


async def cleanup_expired_tokens_task():
    """
    Cleanup expired refresh tokens from the database

    This function should be called by a scheduler (e.g., cron, APScheduler)
    to periodically remove expired tokens.

    Returns:
        int: Number of tokens deleted
    """
    async with AsyncSessionLocal() as session:
        try:
            token_service = TokenService(session)
            count = await token_service.cleanup_expired_tokens()
            print(f"[{datetime.utcnow()}] Cleaned up {count} expired refresh tokens")
            return count
        except Exception as e:
            print(f"[{datetime.utcnow()}] Error cleaning up expired tokens: {e}")
            raise


async def run_cleanup():
    """
    Convenience function to run the cleanup task directly

    Usage:
        python -m app.tasks.token_cleanup
    """
    count = await cleanup_expired_tokens_task()
    print(f"Cleanup completed. Removed {count} expired tokens.")


if __name__ == "__main__":
    import asyncio
    asyncio.run(run_cleanup())
