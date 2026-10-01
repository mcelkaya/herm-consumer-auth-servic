"""Responses must not reveal whether an email has an account.

Covers forgot-password, send-otp and verify-otp: same status + body for an
existing and a non-existent email across the whole flow (including after the
OTP lockout), response time independent of existence, and an OTP failure
budget per email that requesting a new code does not reset.
"""

import json
import statistics
import time

import pytest
from httpx import AsyncClient

from app.models.email_otp_code import OTP_MAX_ATTEMPTS
from app.models.user import User

AUTH = "/herm-auth/v1/public/auth"
UNKNOWN = "nobody-here@example.com"

# Generous vs. the gaps this guards against (bcrypt ~200ms, SQS/DB work),
# small vs. jitter on a local run.
TIMING_TOLERANCE_S = 0.1


def _ip(n: int) -> dict:
    # The per-IP limiters key on X-Forwarded-For; give each flow its own IP so
    # they only test what they mean to.
    return {"X-Forwarded-For": f"203.0.113.{n}"}


def _last_otp(stub_notification_sqs) -> str:
    body = json.loads(stub_notification_sqs.send_message.call_args.kwargs["MessageBody"])
    return body["variables"]["code"]


def _wrong(code: str) -> str:
    return "000000" if code != "000000" else "111111"


async def _flow(client: AsyncClient, email: str, wrong_code: str, headers: dict) -> list:
    """forgot-password, send-otp, then OTP_MAX_ATTEMPTS + 2 wrong guesses."""
    seen = []
    r = await client.post(f"{AUTH}/forgot-password", json={"email": email}, headers=headers)
    seen.append(("forgot", r.status_code, r.json()))
    r = await client.post(f"{AUTH}/send-otp", json={"email": email}, headers=headers)
    seen.append(("send-otp", r.status_code, r.json()))
    for i in range(OTP_MAX_ATTEMPTS + 2):
        r = await client.post(
            f"{AUTH}/verify-otp", json={"email": email, "code": wrong_code}, headers=headers
        )
        seen.append((f"verify#{i + 1}", r.status_code, r.json()))
    return seen


@pytest.mark.asyncio
async def test_existing_and_unknown_email_get_identical_responses(
    client: AsyncClient, test_user: User, stub_notification_sqs
):
    # Existing user first, so we can pick a guaranteed-wrong code for it.
    r = await client.post(f"{AUTH}/send-otp", json={"email": test_user.email}, headers=_ip(1))
    assert r.status_code == 200
    wrong = _wrong(_last_otp(stub_notification_sqs))

    existing = await _flow(client, test_user.email, wrong, _ip(2))
    unknown = await _flow(client, UNKNOWN, wrong, _ip(3))

    assert existing == unknown


@pytest.mark.asyncio
async def test_new_code_after_lockout_does_not_reset_the_email_budget(
    client: AsyncClient, test_user: User, stub_notification_sqs
):
    r = await client.post(f"{AUTH}/send-otp", json={"email": test_user.email}, headers=_ip(10))
    assert r.status_code == 200
    wrong = _wrong(_last_otp(stub_notification_sqs))
    for _ in range(OTP_MAX_ATTEMPTS):
        r = await client.post(
            f"{AUTH}/verify-otp", json={"email": test_user.email, "code": wrong}, headers=_ip(10)
        )
        assert r.status_code == 400

    # Fresh code, and guesses from another IP: still out of budget for this email.
    r = await client.post(f"{AUTH}/send-otp", json={"email": test_user.email}, headers=_ip(11))
    assert r.status_code == 200
    new_code = _last_otp(stub_notification_sqs)

    r = await client.post(
        f"{AUTH}/verify-otp", json={"email": test_user.email, "code": new_code}, headers=_ip(11)
    )
    assert r.status_code == 400, f"new code reset the per-email budget: {r.status_code} {r.json()}"


@pytest.mark.asyncio
async def test_email_budget_window_is_fifteen_minutes(
    client: AsyncClient, test_user: User, stub_notification_sqs
):
    """The per-email lockout lasts 15 minutes (product decision, 2026-10-01)."""
    from app.main import app
    from app.middleware.rate_limit import OTP_EMAIL_WINDOW_SECONDS, _otp_email_key

    assert OTP_EMAIL_WINDOW_SECONDS == 15 * 60

    r = await client.post(f"{AUTH}/send-otp", json={"email": test_user.email}, headers=_ip(20))
    assert r.status_code == 200
    wrong = _wrong(_last_otp(stub_notification_sqs))
    r = await client.post(
        f"{AUTH}/verify-otp", json={"email": test_user.email, "code": wrong}, headers=_ip(20)
    )
    assert r.status_code == 400

    ttl = await app.state.redis.ttl(_otp_email_key(test_user.email))
    assert 0 < ttl <= 15 * 60


async def _median_time(client: AsyncClient, path: str, payload: dict, headers: dict, n: int) -> float:
    samples = []
    for _ in range(n):
        start = time.perf_counter()
        await client.post(f"{AUTH}/{path}", json=payload, headers=headers)
        samples.append(time.perf_counter() - start)
    return statistics.median(samples)


@pytest.fixture
def slow_sqs(stub_notification_sqs):
    """Give the notification publish a realistic network cost."""

    def send_message(**kwargs):
        time.sleep(0.2)
        return {"MessageId": "test-message-id"}

    stub_notification_sqs.send_message.side_effect = send_message
    return stub_notification_sqs


@pytest.mark.asyncio
@pytest.mark.parametrize("path", ["forgot-password", "send-otp"])
async def test_email_sending_endpoints_take_the_same_time_for_unknown_email(
    client: AsyncClient, test_user: User, slow_sqs, path
):
    existing = await _median_time(client, path, {"email": test_user.email}, _ip(20), n=1)
    unknown = await _median_time(client, path, {"email": UNKNOWN}, _ip(21), n=1)

    assert abs(existing - unknown) < TIMING_TOLERANCE_S, (
        f"{path}: existing {existing:.3f}s vs unknown {unknown:.3f}s"
    )


@pytest.mark.asyncio
async def test_verify_otp_wrong_code_takes_the_same_time_for_unknown_email(
    client: AsyncClient, test_user: User, stub_notification_sqs
):
    r = await client.post(f"{AUTH}/send-otp", json={"email": test_user.email}, headers=_ip(30))
    assert r.status_code == 200
    wrong = _wrong(_last_otp(stub_notification_sqs))

    existing = await _median_time(
        client, "verify-otp", {"email": test_user.email, "code": wrong}, _ip(31), n=3
    )
    unknown = await _median_time(
        client, "verify-otp", {"email": UNKNOWN, "code": wrong}, _ip(32), n=3
    )

    assert abs(existing - unknown) < TIMING_TOLERANCE_S, (
        f"verify-otp: existing {existing:.3f}s vs unknown {unknown:.3f}s"
    )
