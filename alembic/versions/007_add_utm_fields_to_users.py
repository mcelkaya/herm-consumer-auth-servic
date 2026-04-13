"""Add UTM tracking fields to users table

Revision ID: 007_add_utm_fields
Revises: 006_add_admin_users
Create Date: 2025-01-01 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = "007_add_utm_fields"
down_revision = "006_add_admin_users"
branch_labels = None
depends_on = None

SCHEMA = "herm_auth"


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column("utm_source", sa.String(255), nullable=True),
        schema=SCHEMA,
    )
    op.add_column(
        "users",
        sa.Column("utm_medium", sa.String(255), nullable=True),
        schema=SCHEMA,
    )
    op.add_column(
        "users",
        sa.Column("utm_campaign", sa.String(255), nullable=True),
        schema=SCHEMA,
    )
    op.add_column(
        "users",
        sa.Column("utm_term", sa.String(255), nullable=True),
        schema=SCHEMA,
    )
    op.add_column(
        "users",
        sa.Column("utm_content", sa.String(255), nullable=True),
        schema=SCHEMA,
    )


def downgrade() -> None:
    op.drop_column("users", "utm_content", schema=SCHEMA)
    op.drop_column("users", "utm_term", schema=SCHEMA)
    op.drop_column("users", "utm_campaign", schema=SCHEMA)
    op.drop_column("users", "utm_medium", schema=SCHEMA)
    op.drop_column("users", "utm_source", schema=SCHEMA)
