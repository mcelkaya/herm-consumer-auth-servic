"""add marketing_consent to users

Revision ID: 008_add_marketing_consent
Revises: 007
Create Date: 2026-04-28
"""
from alembic import op
import sqlalchemy as sa
from app.core.config import settings

revision = "008_add_marketing_consent"
down_revision = "007_add_utm_fields"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column(
            "marketing_consent",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
        schema=settings.DATABASE_SCHEMA,
    )


def downgrade() -> None:
    op.drop_column(
        "users",
        "marketing_consent",
        schema=settings.DATABASE_SCHEMA,
    )