"""Alerting utility.

Single entry point — ``send_alert(level, title, message, details)`` — that
fans out by severity:

* ``critical`` — logs at ERROR and posts to the ops Slack channel.
* ``warning``  — logs at WARNING and posts to the ops Slack channel.
* ``info``     — logs at INFO only (keeps the Slack channel signal-rich).

Mirrors the ``herm-data-processing-service`` alerting pattern, trimmed to the
Slack + logging path (this service has no notification SQS queue).

Alerts must NEVER raise: a failure to reach Slack is logged and swallowed —
``slack_notifier`` already guarantees this, so ``send_alert`` is safe to call
from anywhere, including exception handlers.
"""

from __future__ import annotations

import logging
from typing import Any, Literal

from app.core.config import settings
from app.utils.slack_notifier import slack_notifier

logger = logging.getLogger(__name__)


AlertLevel = Literal["critical", "warning", "info"]


async def send_alert(
    level: AlertLevel,
    title: str,
    message: str,
    details: dict[str, Any] | None = None,
) -> None:
    """Send a service alert. Never raises.

    Args:
        level: Severity tier. ``critical`` and ``warning`` post to Slack;
            ``info`` logs only.
        title: Short headline.
        message: Full body text.
        details: Optional structured context (error_id, path, method, etc.) —
            surfaced in logs and in the Slack context line.
    """
    details = details or {}
    log_extra = {"alert_level": level, "alert_title": title, **details}

    if level == "critical":
        logger.error("ALERT[critical] %s — %s", title, message, extra=log_extra)
    elif level == "warning":
        logger.warning("ALERT[warning] %s — %s", title, message, extra=log_extra)
    else:
        logger.info("ALERT[info] %s — %s", title, message, extra=log_extra)

    # Slack delivery for actionable tiers. ``info`` is log-only to keep the
    # ops channel signal-rich. No-ops when ALERT_SLACK_WEBHOOK is unset.
    if level in ("critical", "warning"):
        await _deliver_slack(
            level=level, title=title, message=message, details=details
        )


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------


_SLACK_EMOJI = {"critical": "🔴", "warning": "🟠"}


async def _deliver_slack(
    *,
    level: AlertLevel,
    title: str,
    message: str,
    details: dict[str, Any],
) -> None:
    """Post the alert to the ops Slack channel via Incoming Webhook.

    No-ops when ``ALERT_SLACK_WEBHOOK`` is unset (dev/test). ``slack_notifier``
    never raises, so this is safe to call unconditionally.
    """
    emoji = _SLACK_EMOJI.get(level, "")
    header = f"{emoji} [{level.upper()}] {title}".strip()
    blocks: list[dict[str, Any]] = [
        {"type": "section", "text": {"type": "mrkdwn", "text": f"*{header}*\n{message}"}},
    ]

    # Compact context line: service/env plus any structured details.
    context_bits = [
        f"service: {settings.APP_NAME}",
        f"env: {settings.ENVIRONMENT}",
    ]
    for key, value in details.items():
        context_bits.append(f"{key}: {value}")
    blocks.append(
        {
            "type": "context",
            "elements": [{"type": "mrkdwn", "text": " | ".join(context_bits)}],
        }
    )

    await slack_notifier.post(settings.ALERT_SLACK_WEBHOOK, text=header, blocks=blocks)
