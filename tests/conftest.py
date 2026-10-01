import json
import os

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

# Access tokens are RS256-only: give the whole test session a throwaway keyset
# BEFORE app.core.config builds `settings` (generated per run, never committed).
# Forced, not setdefault, so a developer's local .env cannot change the mode.
TEST_ACCESS_TOKEN_KID = "at-test"
TEST_ACCESS_TOKEN_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
os.environ["ACCESS_TOKEN_ALGORITHM"] = "RS256"
os.environ["ACCESS_TOKEN_SIGNING_KEYS"] = json.dumps({
    "active": TEST_ACCESS_TOKEN_KID,
    "keys": {
        TEST_ACCESS_TOKEN_KID: TEST_ACCESS_TOKEN_KEY.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode(),
    },
})

import pytest
import pytest_asyncio
from typing import AsyncGenerator
from unittest.mock import MagicMock
from httpx import AsyncClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from app.main import app
from app.db.session import Base, get_db
from app.core.config import settings
from app.core.security import security_service
from app.models.user import User
from app.services.sqs_producer import notification_producer
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


@pytest.fixture(autouse=True)
def stub_notification_sqs(monkeypatch) -> MagicMock:
    """Keep notification publishes (OTP, password reset, verification) off real SQS.

    The global producer builds a real boto3 client at import time, so signup /
    send-otp / forgot-password would otherwise call AWS with whatever
    credentials the shell has (InvalidClientTokenId, or worse, a real queue).
    """
    client = MagicMock()
    client.send_message.return_value = {"MessageId": "test-message-id"}
    monkeypatch.setattr(notification_producer, "sqs_client", client)
    return client


@pytest_asyncio.fixture(autouse=True)
async def flush_rate_limit_keys():
    """Delete all rate:* keys from Redis between tests to prevent bleed-over."""
    yield
    redis = aioredis.from_url(settings.REDIS_URL, encoding="utf-8", decode_responses=True)
    keys = await redis.keys("rate:*")
    if keys:
        await redis.delete(*keys)
    await redis.aclose()
