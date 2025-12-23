import json
import uuid
from typing import Dict, Optional
import boto3
from botocore.exceptions import ClientError
from app.core.config import settings
import logging

logger = logging.getLogger(__name__)


class NotificationService:
    """Service for sending notifications to SQS queue"""

    def __init__(self):
        self.sqs_client = boto3.client(
            'sqs',
            region_name=settings.AWS_REGION,
            aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
            aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY
        )
        self.queue_url = settings.NOTIFICATION_QUEUE_URL

    async def send_email_notification(
        self,
        template_slug: str,
        recipient_email: str,
        user_id: str,
        language: str,
        variables: Dict[str, str],
        priority: str = "high",
        source_service: str = "auth-service"
    ) -> bool:
        """
        Send email notification to SQS queue

        Args:
            template_slug: Email template identifier (e.g., 'password_reset', 'email_verification')
            recipient_email: Recipient's email address
            user_id: User's UUID as string
            language: Language code (e.g., 'en', 'tr')
            variables: Template variables dictionary
            priority: Priority level ('high', 'medium', 'low')
            source_service: Source service name

        Returns:
            bool: True if message sent successfully, False otherwise
        """
        correlation_id = str(uuid.uuid4())

        message = {
            "channel": "email",
            "template_slug": template_slug,
            "recipient": {
                "email": recipient_email,
                "user_id": user_id
            },
            "language": language,
            "variables": variables,
            "priority": priority,
            "metadata": {
                "source_service": source_service,
                "correlation_id": correlation_id
            }
        }

        try:
            response = self.sqs_client.send_message(
                QueueUrl=self.queue_url,
                MessageBody=json.dumps(message),
                MessageAttributes={
                    'priority': {
                        'StringValue': priority,
                        'DataType': 'String'
                    },
                    'template_slug': {
                        'StringValue': template_slug,
                        'DataType': 'String'
                    }
                }
            )

            logger.info(
                f"Email notification sent to SQS queue - "
                f"Template: {template_slug}, Recipient: {recipient_email}, "
                f"Correlation ID: {correlation_id}, Message ID: {response.get('MessageId')}"
            )
            return True

        except ClientError as e:
            logger.error(
                f"Failed to send email notification to SQS - "
                f"Template: {template_slug}, Recipient: {recipient_email}, "
                f"Correlation ID: {correlation_id}, Error: {str(e)}"
            )
            return False
        except Exception as e:
            logger.error(
                f"Unexpected error sending email notification - "
                f"Template: {template_slug}, Recipient: {recipient_email}, "
                f"Correlation ID: {correlation_id}, Error: {str(e)}"
            )
            return False


# Global instance
notification_service = NotificationService()