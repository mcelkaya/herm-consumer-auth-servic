import json
from datetime import datetime
from typing import Optional
from uuid import UUID

import boto3

from app.core.config import settings


class NotificationProducer:
    """SQS Producer for herm-notification-service."""

    def __init__(self):
        sqs_config = {"region_name": settings.AWS_REGION}
        if settings.AWS_ENDPOINT_URL:
            sqs_config["endpoint_url"] = settings.AWS_ENDPOINT_URL
        self.sqs = boto3.client("sqs", **sqs_config)

    def send_notification(
        self,
        template_slug: str,
        recipient_email: str,
        variables: dict,
        user_id: Optional[str] = None,
        language: str = "en",
        priority: str = "standard",
        channel: str = "email",
        correlation_id: Optional[str] = None,
        source_service: str = "main",
    ) -> str:
        """
        Send a notification message to the notification service queue.

        Args:
            template_slug: Template identifier (e.g., 'password_reset', 'welcome')
            recipient_email: Recipient's email address
            variables: Template variables for rendering
            user_id: Optional user identifier
            language: Language code ('en', 'tr'), defaults to 'en'
            priority: 'high', 'standard', or 'low'
            channel: Notification channel ('email' for now)
            correlation_id: Optional request correlation ID for tracing
            source_service: Name of the calling service

        Returns:
            SQS Message ID
        """
        message = {
            "channel": channel,
            "template_slug": template_slug,
            "recipient": {
                "email": recipient_email,
                "user_id": str(user_id),
            },
            "language": language,
            "variables": variables,
            "priority": priority,
            "metadata": {
                "source_service": source_service,
                "correlation_id": correlation_id or str(UUID(int=0).hex),
                "triggered_at": datetime.utcnow().isoformat(),
            },
        }

        response = self.sqs.send_message(
            QueueUrl=settings.NOTIFICATION_QUEUE_URL,
            MessageBody=json.dumps(message),
            MessageAttributes={
                "priority": {"DataType": "String", "StringValue": priority},
                "channel": {"DataType": "String", "StringValue": channel},
                "template": {"DataType": "String", "StringValue": template_slug},
            },
        )

        return response["MessageId"]

    # Convenience methods for common notifications

    def send_password_reset(
        self,
        email: str,
        user_name: str,
        reset_link: str,
        expiry_hours: int = 24,
        user_id: Optional[str] = None,
        language: str = "en",
        correlation_id: Optional[str] = None,
    ) -> str:
        """Send password reset email (HIGH priority)."""
        return self.send_notification(
            template_slug="password_reset",
            recipient_email=email,
            variables={
                "user_name": user_name,
                "reset_link": reset_link,
                "expiry_hours": expiry_hours,
            },
            user_id=user_id,
            language=language,
            priority="high",
            source_service="auth",
            correlation_id=correlation_id,
        )

    def send_email_verification(
        self,
        email: str,
        user_name: str,
        verification_link: str,
        user_id: Optional[str] = None,
        language: str = "en",
        correlation_id: Optional[str] = None,
    ) -> str:
        """Send email verification (HIGH priority)."""
        return self.send_notification(
            template_slug="email_verification",
            recipient_email=email,
            variables={
                "user_name": user_name,
                "verification_link": verification_link,
            },
            user_id=user_id,
            language=language,
            priority="high",
            source_service="auth",
            correlation_id=correlation_id,
        )

    def send_two_factor_code(
        self,
        email: str,
        code: str,
        expiry_minutes: int = 10,
        user_id: Optional[str] = None,
        language: str = "en",
        correlation_id: Optional[str] = None,
    ) -> str:
        """Send 2FA code (HIGH priority)."""
        return self.send_notification(
            template_slug="two_factor_code",
            recipient_email=email,
            variables={
                "code": code,
                "expiry_minutes": expiry_minutes,
            },
            user_id=user_id,
            language=language,
            priority="high",
            source_service="auth",
            correlation_id=correlation_id,
        )

    def send_welcome(
        self,
        email: str,
        user_name: str,
        login_url: str,
        app_name: str = "HERM",
        user_id: Optional[str] = None,
        language: str = "en",
        correlation_id: Optional[str] = None,
    ) -> str:
        """Send welcome email (STANDARD priority)."""
        return self.send_notification(
            template_slug="welcome",
            recipient_email=email,
            variables={
                "user_name": user_name,
                "app_name": app_name,
                "login_url": login_url,
            },
            user_id=user_id,
            language=language,
            priority="standard",
            source_service="main",
            correlation_id=correlation_id,
        )


notification_producer = NotificationProducer()