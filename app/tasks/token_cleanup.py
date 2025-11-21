"""
Token cleanup task for removing expired refresh tokens and password reset tokens

This task should be run periodically (e.g., daily) to clean up expired tokens
from the database. This prevents the tokens tables from growing indefinitely.

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
from app.services.reset_password_service import ResetPasswordService


async def cleanup_expired_tokens_task():
    """
    Cleanup expired refresh tokens and password reset tokens from the database

    This function should be called by a scheduler (e.g., cron, APScheduler)
    to periodically remove expired tokens.

    Returns:
        dict: Number of tokens deleted by type
    """
    async with AsyncSessionLocal() as session:
        try:
            # Cleanup refresh tokens
            token_service = TokenService(session)
            refresh_count = await token_service.cleanup_expired_tokens()
            print(f"[{datetime.utcnow()}] Cleaned up {refresh_count} expired refresh tokens")

            # Cleanup password reset tokens
            reset_service = ResetPasswordService(session)
            reset_count = await reset_service.cleanup_expired_tokens()
            print(f"[{datetime.utcnow()}] Cleaned up {reset_count} expired password reset tokens")

            return {
                "refresh_tokens": refresh_count,
                "password_reset_tokens": reset_count,
                "total": refresh_count + reset_count
            }
        except Exception as e:
            print(f"[{datetime.utcnow()}] Error cleaning up expired tokens: {e}")
            raise


async def run_cleanup():
    """
    Convenience function to run the cleanup task directly

    Usage:
        python -m app.tasks.token_cleanup
    """
    result = await cleanup_expired_tokens_task()
    print(f"Cleanup completed. Removed {result['total']} expired tokens "
          f"({result['refresh_tokens']} refresh, {result['password_reset_tokens']} password reset).")


if __name__ == "__main__":
    import asyncio
    asyncio.run(run_cleanup())
