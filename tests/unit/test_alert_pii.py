"""Reproduces: send_alert forwarded title/message/details verbatim, so the
unhandled-exception handler's ``str(exc)`` shipped emails and tokens to Slack
(and into the ALERT log record) unredacted.
"""

import logging
from unittest.mock import AsyncMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.core.error_handlers import register_exception_handlers
from app.core.pii import redact

EMAIL = "victim@example.com"
JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.c2lnbmF0dXJlc2lnbmF0dXJl"
BEARER = "Bearer opaque-token-value-123"
RAW = (EMAIL, JWT, "opaque-token-value-123")


def _app() -> FastAPI:
    app = FastAPI()
    register_exception_handlers(app)

    @app.get("/boom")
    async def boom():
        raise RuntimeError(f"lookup failed for {EMAIL} with {JWT} and {BEARER}")

    return app


def test_unhandled_exception_alert_is_redacted_for_slack_and_log(caplog):
    post = AsyncMock(return_value=True)
    with patch("app.utils.alerting.settings.ALERT_SLACK_WEBHOOK", "https://hooks.example/x"), \
         patch("app.utils.alerting.slack_notifier.post", post), \
         caplog.at_level(logging.ERROR, logger="app.utils.alerting"):
        resp = TestClient(_app(), raise_server_exceptions=False).get("/boom")

    assert resp.status_code == 500
    post.assert_awaited_once()
    slack_payload = repr(post.await_args)
    alert_records = [r for r in caplog.records if r.name == "app.utils.alerting"]
    assert alert_records, "ALERT log record not emitted"
    alert_log = " ".join(r.getMessage() + repr(r.__dict__) for r in alert_records)

    for raw in RAW:
        assert raw not in slack_payload
        assert raw not in alert_log
    assert "v***@example.com" in slack_payload


@pytest.mark.asyncio
async def test_send_alert_redacts_every_string_in_details():
    from app.utils.alerting import send_alert

    post = AsyncMock(return_value=True)
    with patch("app.utils.alerting.settings.ALERT_SLACK_WEBHOOK", "https://hooks.example/x"), \
         patch("app.utils.alerting.slack_notifier.post", post):
        await send_alert(
            "warning",
            f"title {EMAIL}",
            f"msg {BEARER}",
            {"client_id": "herm-client", "note": f"seen {JWT}", "refresh_token": "rt-plain"},
        )

    payload = repr(post.await_args)
    for raw in (*RAW, "rt-plain"):
        assert raw not in payload
    assert "herm-client" in payload


def test_redact_masks_ipv6_but_not_times():
    out = redact("from 2001:db8:85a3::8a2e:370:7334 and 2001:0db8:85a3:0000:0000:8a2e:0370:7334 at 12:34:56")
    assert "2001:db8" not in out and "2001:0db8" not in out
    assert "12:34:56" in out
