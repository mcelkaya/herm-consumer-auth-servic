"""add user_oauth_accounts for social login (google / apple / facebook)

Links a provider identity (the provider's stable `sub`) to a local user so the
same person can sign in with multiple providers and resolve to one profile.
See app/models/user_oauth_account.py for the linking rules.

Revision ID: 011_add_user_oauth_accounts
Revises: 010_add_user_email_aliases
Create Date: 2026-06-12
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from app.core.config import settings


revision = "011_add_user_oauth_accounts"
down_revision = "010_add_user_email_aliases"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "user_oauth_accounts",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            nullable=False,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("provider", sa.String(length=32), nullable=False),
        sa.Column("provider_user_id", sa.String(length=255), nullable=False),
        sa.Column("email_at_link", sa.String(length=255), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=False),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=False),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(
            ["user_id"],
            [f"{settings.DATABASE_SCHEMA}.users.id"],
            ondelete="CASCADE",
        ),
        # One provider identity (e.g. a specific Google account) maps to
        # exactly one local user. This is the constraint that makes
        # "sign in with Google" deterministic on repeat logins.
        sa.UniqueConstraint(
            "provider",
            "provider_user_id",
            name="uq_user_oauth_provider_identity",
        ),
        # A user holds at most one identity per provider. Relax this (drop the
        # constraint in a later migration) if you ever want to allow linking
        # two Google accounts to one profile.
        sa.UniqueConstraint(
            "user_id",
            "provider",
            name="uq_user_oauth_user_provider",
        ),
        schema=settings.DATABASE_SCHEMA,
    )

    op.create_index(
        "ix_user_oauth_accounts_user_id",
        "user_oauth_accounts",
        ["user_id"],
        schema=settings.DATABASE_SCHEMA,
    )
    op.create_index(
        "ix_user_oauth_accounts_provider_user_id",
        "user_oauth_accounts",
        ["provider_user_id"],
        schema=settings.DATABASE_SCHEMA,
    )


def downgrade() -> None:
    op.drop_index(
        "ix_user_oauth_accounts_provider_user_id",
        table_name="user_oauth_accounts",
        schema=settings.DATABASE_SCHEMA,
    )
    op.drop_index(
        "ix_user_oauth_accounts_user_id",
        table_name="user_oauth_accounts",
        schema=settings.DATABASE_SCHEMA,
    )
    op.drop_table("user_oauth_accounts", schema=settings.DATABASE_SCHEMA)