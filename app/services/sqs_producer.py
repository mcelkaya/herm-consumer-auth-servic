"""SQS Producer for sending notifications to the notification service"""

from uuid import UUID, uuid4
import json
import logging
from typing import Optional
import boto3
from app.core.config import settings
from app.schemas.user import (
    NotificationMessage,
    RecipientSchema,
    Channel,
    Priority
)

logger = logging.getLogger(__name__)


class NotificationProducer:
    """SQS producer for sending notifications"""

    def __init__(self):
        self.sqs_client = boto3.client(
            'sqs',
            region_name=settings.AWS_REGION,
            aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
            aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY
        )
        self.queue_url = settings.NOTIFICATION_QUEUE_URL

    def _send_message(self, message: NotificationMessage) -> str:
        """
        Internal method to send message to SQS

        Args:
            message: NotificationMessage object

        Returns:
            Message ID from SQS
        """
        try:
            response = self.sqs_client.send_message(
                QueueUrl=self.queue_url,
                MessageBody=message.model_dump_json(),
                MessageAttributes={
                    'template_slug': {
                        'StringValue': message.template_slug,
                        'DataType': 'String'
                    },
                    'priority': {
                        'StringValue': message.priority.value,
                        'DataType': 'String'
                    },
                    'language': {
                        'StringValue': message.language,
                        'DataType': 'String'
                    }
                }
            )
            
            message_id = response.get('MessageId')
            logger.info(
                f"Sent notification to SQS - "
                f"Template: {message.template_slug}, "
                f"Language: {message.language}, "
                f"MessageId: {message_id}"
            )
            return message_id
            
        except Exception as e:
            logger.error(f"Failed to send message to SQS: {str(e)}")
            raise

    def send_welcome(
        self,
        email: str,
        user_name: str,
        login_url: str,
        user_id: UUID,
        language: str = "en",
        correlation_id: str = None
    ) -> str:
        """Send welcome email notification"""
        message = NotificationMessage(
            channel=Channel.EMAIL,
            template_slug="welcome",
            recipient=RecipientSchema(
                email=email,
                user_id=str(user_id),
                name=user_name
            ),
            language=language,
            variables={
                "user_name": user_name,
                "login_url": login_url
            },
            priority=Priority.HIGH,
            metadata={
                "source_service": "auth-service",
                "correlation_id": correlation_id or str(uuid4()),
                "user_id": str(user_id)
            }
        )
        return self._send_message(message)

    def send_password_reset(
        self,
        email: str,
        user_name: str,
        reset_link: str,
        expiry_hours: int,
        user_id: UUID,
        language: str = "en",
        correlation_id: str = None
    ) -> str:
        """Send password reset email notification"""
        message = NotificationMessage(
            channel=Channel.EMAIL,
            template_slug="password_reset",
            recipient=RecipientSchema(
                email=email,
                user_id=str(user_id),
                name=user_name
            ),
            language=language,
            variables={
                "reset_link": reset_link,
                "user_name": user_name,
                "expiry_hours": str(expiry_hours)
            },
            priority=Priority.HIGH,
            metadata={
                "source_service": "auth-service",
                "correlation_id": correlation_id or str(uuid4()),
                "user_id": str(user_id)
            }
        )
        return self._send_message(message)

    def send_email_verification(
        self,
        email: str,
        user_name: str,
        verification_link: str,
        user_id: UUID,
        language: str = "en",
        correlation_id: str = None
    ) -> str:
        """Send email verification notification"""
        message = NotificationMessage(
            channel=Channel.EMAIL,
            template_slug="email_verification",
            recipient=RecipientSchema(
                email=email,
                user_id=str(user_id),
                name=user_name
            ),
            language=language,
            variables={
                "verification_link": verification_link,
                "user_name": user_name
            },
            priority=Priority.HIGH,
            metadata={
                "source_service": "auth-service",
                "correlation_id": correlation_id or str(uuid4()),
                "user_id": str(user_id)
            }
        )
        return self._send_message(message)


# Global instance
notification_producer = NotificationProducer()