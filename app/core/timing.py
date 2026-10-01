import asyncio
import logging
import time
from contextlib import asynccontextmanager

logger = logging.getLogger(__name__)


@asynccontextmanager
async def min_duration(seconds: float, label: str):
    """Make the wrapped block take at least `seconds`, so response time does
    not reveal which branch ran (e.g. whether an account exists). Pick a
    budget well above the slow branch; overruns are logged so it can be tuned.
    """
    start = time.monotonic()
    try:
        yield
    finally:
        elapsed = time.monotonic() - start
        if elapsed > seconds:
            logger.warning(f"{label}: took {elapsed:.3f}s, over the {seconds}s timing budget")
        else:
            await asyncio.sleep(seconds - elapsed)
