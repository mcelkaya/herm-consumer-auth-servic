"""add revoked_at to email_verification_tokens

Distinguishes "superseded by a newer token" (revoked_at IS NOT NULL) from
"successfully consumed" (is_used=True). Without this distinction, clicking
an older verification email after requesting a resend was being flagged as
suspicious activity and rejected with 400.

Revision ID: 009_add_revoked_at_to_email_verification_tokens
Revises: 008_add_marketing_consent
Create Date: 2026-04-28

"""
from alembic import op
import sqlalchemy as sa

from app.core.config import settings


# revision identifiers, used by Alembic.
revision = "009_add_revoked_at_to_email_verification_tokens"
down_revision = "008_add_marketing_consent"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "email_verification_tokens",
        sa.Column("revoked_at", sa.DateTime(timezone=False), nullable=True),
        schema=settings.DATABASE_SCHEMA,
    )


def downgrade() -> None:
    op.drop_column(
        "email_verification_tokens",
        "revoked_at",
        schema=settings.DATABASE_SCHEMA,
    )