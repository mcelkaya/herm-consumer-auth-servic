"""Tests for GET /internal/stats/daily-metrics (daily Slack digest source)."""

from datetime import datetime, timedelta, timezone

import pytest

from app.core.config import settings
from app.models.user import User

_URL = "/internal/stats/daily-metrics"


@pytest.fixture(autouse=True)
def _configure_internal_key():
    """Ensure the internal API key is set so the endpoint is reachable."""
    original = settings.INTERNAL_API_KEY
    settings.INTERNAL_API_KEY = "test-internal-key"
    yield
    settings.INTERNAL_API_KEY = original


def _headers():
    return {"X-Internal-API-Key": "test-internal-key"}


@pytest.mark.asyncio
async def test_counts_only_users_from_last_24h(client, db_session):
    now = datetime.now(timezone.utc)
    db_session.add_all(
        [
            User(email="fresh1@test.com", created_at=now - timedelta(hours=1)),
            User(email="fresh2@test.com", created_at=now - timedelta(hours=23)),
            User(email="stale@test.com", created_at=now - timedelta(days=3)),
        ]
    )
    await db_session.commit()

    resp = await client.get(_URL, headers=_headers())

    assert resp.status_code == 200
    assert resp.json() == {"users_24h": 2}


@pytest.mark.asyncio
async def test_rejects_missing_or_wrong_key(client):
    assert (await client.get(_URL)).status_code in (401, 403, 422)
    assert (
        await client.get(_URL, headers={"X-Internal-API-Key": "nope"})
    ).status_code == 403
