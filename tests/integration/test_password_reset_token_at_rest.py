"""Password-reset tokens must not be stored in plain text.

A DB read (backup, replica, SQL injection elsewhere) must not be enough to
take over an account: only a hash of the token may be persisted, and the
stored value itself must not work as a reset token.
"""

import json
from urllib.parse import parse_qs, urlparse

import pytest
from httpx import AsyncClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models.user import User

FORGOT = "/herm-auth/v1/public/auth/forgot-password"
RESET = "/herm-auth/v1/public/auth/reset-password"


def _raw_token_from_sqs(stub_notification_sqs) -> str:
    body = json.loads(stub_notification_sqs.send_message.call_args.kwargs["MessageBody"])
    link = body["variables"]["reset_link"]
    return parse_qs(urlparse(link).query)["token"][0]


@pytest.mark.asyncio
async def test_reset_token_is_hashed_at_rest(
    client: AsyncClient,
    db_session: AsyncSession,
    test_user: User,
    stub_notification_sqs,
):
    response = await client.post(FORGOT, json={"email": test_user.email})
    assert response.status_code == 200
    raw_token = _raw_token_from_sqs(stub_notification_sqs)

    rows = (
        await db_session.execute(
            text(
                f"SELECT * FROM {settings.DATABASE_SCHEMA}.password_reset_tokens "
                "WHERE user_id = :uid"
            ),
            {"uid": test_user.id},
        )
    ).mappings().all()
    assert len(rows) == 1
    stored_strings = [v for v in rows[0].values() if isinstance(v, str)]

    # The raw token appears nowhere in the row.
    assert all(raw_token not in v for v in stored_strings)

    # No stored value works as a reset token (e.g. the stored hash).
    for value in stored_strings:
        r = await client.post(RESET, json={"token": value, "new_password": "NewSecurePassword123!"})
        assert r.status_code == 400, f"stored column value accepted as a reset token: {r.json()}"

    # The raw token from the email still works.
    r = await client.post(RESET, json={"token": raw_token, "new_password": "NewSecurePassword123!"})
    assert r.status_code == 200
