import pytest
import pytest_asyncio
import asyncio
from typing import AsyncGenerator
from httpx import AsyncClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from app.main import app
from app.db.session import Base, get_db
from app.core.config import settings
from app.core.security import security_service
from app.models.user import User
import redis.asyncio as aioredis

# Test database URL
TEST_DATABASE_URL = settings.TEST_DATABASE_URL

# Create test engine
test_engine = create_async_engine(
    TEST_DATABASE_URL,
    echo=False,
    pool_pre_ping=True,
)

TestSessionLocal = async_sessionmaker(
    test_engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


@pytest.fixture(scope="session")
def event_loop():
    """Create event loop for async tests"""
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest_asyncio.fixture(scope="function")
async def db_session() -> AsyncGenerator[AsyncSession, None]:
    """Create test database session"""
    # Create all tables (dedicated test-db container starts with no schema)
    async with test_engine.begin() as conn:
        await conn.execute(text(f"CREATE SCHEMA IF NOT EXISTS {settings.DATABASE_SCHEMA}"))
        await conn.run_sync(Base.metadata.create_all)
    
    # Create session
    async with TestSessionLocal() as session:
        yield session
        # Rollback any uncommitted changes
        await session.rollback()

    # Drop all tables
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


@pytest_asyncio.fixture(scope="function")
async def client(db_session: AsyncSession) -> AsyncGenerator[AsyncClient, None]:
    """Create test client"""
    async def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db
    # httpx's AsyncClient(app=...) shortcut does not run the app's lifespan,
    # so app.state.redis (normally set in app.main.lifespan) is never
    # populated. Every rate-limited endpoint reads request.app.state.redis,
    # so without this every such endpoint 500s in tests.
    app.state.redis = aioredis.from_url(
        settings.REDIS_URL, encoding="utf-8", decode_responses=True
    )

    async with AsyncClient(app=app, base_url="http://test") as ac:
        yield ac

    await app.state.redis.aclose()
    app.dependency_overrides.clear()


@pytest_asyncio.fixture(scope="function")
async def test_user(db_session: AsyncSession) -> User:
    """A persisted, active, unverified user for integration tests."""
    user = User(
        email="testuser@example.com",
        hashed_password=security_service.get_password_hash("TestPassword123!"),
        is_active=True,
        is_verified=False,
    )
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)
    return user


@pytest_asyncio.fixture(autouse=True)
async def flush_rate_limit_keys():
    """Delete all rate:* keys from Redis between tests to prevent bleed-over."""
    yield
    redis = aioredis.from_url(settings.REDIS_URL, encoding="utf-8", decode_responses=True)
    keys = await redis.keys("rate:*")
    if keys:
        await redis.delete(*keys)
    await redis.aclose()
