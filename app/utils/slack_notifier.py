"""Slack Incoming-Webhook notifier.

A thin async client that POSTs a message to a Slack Incoming Webhook URL.
Used for system alerts (see ``app/core/config.py``):

* ``ALERT_SLACK_WEBHOOK`` — system alerts, fed from ``send_alert``.

The webhook URL is passed per call, so one notifier can serve multiple channels.

Mirrors the alerting "never raise" contract: a Slack outage must never crash the
service. A blank webhook URL is a no-op — the intended behaviour in dev/test
where notifications shouldn't go anywhere.
"""

from __future__ import annotations

import logging

import httpx

logger = logging.getLogger(__name__)


class SlackNotifier:
    """Posts messages to Slack Incoming Webhooks. Never raises."""

    async def post(
        self,
        webhook_url: str,
        text: str,
        blocks: list | None = None,
    ) -> bool:
        """POST a message to ``webhook_url``.

        Args:
            webhook_url: Slack Incoming Webhook URL. Blank → no-op.
            text: Fallback/plain text (also used for notifications/previews).
            blocks: Optional Slack Block Kit blocks for rich formatting.

        Returns:
            True if Slack accepted the message, False on no-op or any failure.
        """
        if not webhook_url:
            logger.debug("Slack webhook URL unset — skipping post")
            return False

        payload: dict = {"text": text}
        if blocks:
            payload["blocks"] = blocks

        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    webhook_url, json=payload, timeout=10.0
                )
                response.raise_for_status()
            return True
        except Exception:
            # A Slack outage must never crash the caller — log and move on.
            logger.warning("Failed to post message to Slack", exc_info=True)
            return False


slack_notifier = SlackNotifier()
