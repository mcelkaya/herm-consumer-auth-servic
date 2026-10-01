"""Single-use / attempt-budget guarantees must hold under concurrent requests.

Each request runs in its own session (= its own DB connection), as separate
API workers would, against the real Postgres test DB.
"""

import asyncio
from datetime import datetime, timedelta

import pytest
from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import security_service
from app.models.email_otp_code import EmailOtpCode, OTP_MAX_ATTEMPTS
from app.models.password_reset_token import PasswordResetToken
from app.models.user import User
from app.services.email_otp_service import EmailOtpService
from app.services.forgot_password_service import ForgotPasswordService
from app.services.reset_password_service import ResetPasswordService
from tests.conftest import TestSessionLocal

N = 8


async def _gather_outcomes(make_call):
    """Run N calls concurrently, each in a fresh session; return results/exceptions."""

    async def one(i):
        async with TestSessionLocal() as session:
            try:
                return await make_call(session, i)
            except HTTPException as exc:
                return exc

    return await asyncio.gather(*(one(i) for i in range(N)))


@pytest.mark.asyncio
async def test_concurrent_resets_with_same_token_succeed_exactly_once(
    db_session: AsyncSession, test_user: User
):
    _, raw_token = await ForgotPasswordService(db_session).create_reset_token(
        test_user.id, ip_address=None
    )

    outcomes = await _gather_outcomes(
        lambda s, i: ResetPasswordService(s).reset_password(raw_token, f"NewPassword{i}123!")
    )

    successes = [o for o in outcomes if o is True]
    assert len(successes) == 1, f"reset token used {len(successes)} times"
    assert all(o.status_code == 400 for o in outcomes if o is not True)


async def _otp_for(db_session: AsyncSession, user: User, plaintext: str) -> EmailOtpCode:
    code = EmailOtpCode(
        code_hash=security_service.get_password_hash(plaintext),
        user_id=user.id,
        expires_at=datetime.utcnow() + timedelta(minutes=10),
    )
    db_session.add(code)
    await db_session.commit()
    return code


@pytest.mark.asyncio
async def test_concurrent_wrong_otp_guesses_never_exceed_max_attempts(
    db_session: AsyncSession, test_user: User, monkeypatch
):
    otp = await _otp_for(db_session, test_user, "123456")

    evaluated = 0
    real_verify = security_service.verify_password

    def counting_verify(plain, hashed):
        nonlocal evaluated
        if hashed == otp.code_hash:
            evaluated += 1
        return real_verify(plain, hashed)

    monkeypatch.setattr(security_service, "verify_password", counting_verify)

    outcomes = await _gather_outcomes(
        lambda s, i: EmailOtpService(s).verify_otp_code(test_user.email, f"{i:06d}")
    )

    assert all(isinstance(o, HTTPException) for o in outcomes)
    assert evaluated <= OTP_MAX_ATTEMPTS, f"{evaluated} guesses evaluated (max {OTP_MAX_ATTEMPTS})"

    async with TestSessionLocal() as s:
        row = (await s.execute(select(EmailOtpCode).where(EmailOtpCode.id == otp.id))).scalar_one()
    assert row.attempt_count == OTP_MAX_ATTEMPTS


@pytest.mark.asyncio
async def test_concurrent_correct_otp_is_consumed_exactly_once(
    db_session: AsyncSession, test_user: User
):
    await _otp_for(db_session, test_user, "123456")

    outcomes = await _gather_outcomes(
        lambda s, i: EmailOtpService(s).verify_otp_code(test_user.email, "123456")
    )

    successes = [o for o in outcomes if not isinstance(o, HTTPException)]
    assert len(successes) == 1, f"OTP code consumed {len(successes)} times"
