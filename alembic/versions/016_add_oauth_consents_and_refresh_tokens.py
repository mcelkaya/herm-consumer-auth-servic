"""add oauth_consents + oauth_refresh_tokens (Login with Herm authorization server)

Consumer standing consent per partner client, and partner refresh tokens
(offline_access, flagged off in v1) hashed at rest. Purely additive.

Revision ID: 016_add_oauth_consents_and_refresh_tokens
Revises: 015_add_oauth_clients_table
Create Date: 2026-07-11
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from app.core.config import settings

revision = "016_add_oauth_consents_and_refresh_tokens"
down_revision = "015_add_oauth_clients_table"
branch_labels = None
depends_on = None

SCHEMA = settings.DATABASE_SCHEMA


def upgrade() -> None:
    op.create_table(
        "oauth_consents",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("client_id", sa.String(length=64), nullable=False),
        sa.Column("granted_scopes", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default="[]"),
        sa.Column("granted_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(["user_id"], [f"{SCHEMA}.users.id"], ondelete="CASCADE"),
        sa.UniqueConstraint("user_id", "client_id", name="uq_oauth_consents_user_client"),
        schema=SCHEMA,
    )
    op.create_index("ix_oauth_consents_user_id", "oauth_consents", ["user_id"], schema=SCHEMA)
    op.create_index("ix_oauth_consents_client_id", "oauth_consents", ["client_id"], schema=SCHEMA)

    op.create_table(
        "oauth_refresh_tokens",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("client_id", sa.String(length=64), nullable=False),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("scopes", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default="[]"),
        sa.Column("code_hash", sa.String(length=64), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(["user_id"], [f"{SCHEMA}.users.id"], ondelete="CASCADE"),
        sa.UniqueConstraint("token_hash", name="uq_oauth_refresh_tokens_hash"),
        schema=SCHEMA,
    )
    op.create_index("ix_oauth_refresh_tokens_token_hash", "oauth_refresh_tokens", ["token_hash"], schema=SCHEMA)
    op.create_index("ix_oauth_refresh_tokens_client_id", "oauth_refresh_tokens", ["client_id"], schema=SCHEMA)
    op.create_index("ix_oauth_refresh_tokens_user_id", "oauth_refresh_tokens", ["user_id"], schema=SCHEMA)
    op.create_index("ix_oauth_refresh_tokens_code_hash", "oauth_refresh_tokens", ["code_hash"], schema=SCHEMA)


def downgrade() -> None:
    op.drop_table("oauth_refresh_tokens", schema=SCHEMA)
    op.drop_table("oauth_consents", schema=SCHEMA)
