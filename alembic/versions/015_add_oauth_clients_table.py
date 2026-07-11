"""add oauth_clients table (Login with Herm partner client registry)

Registers partner "Login with Herm" OAuth clients owned by a brand. brand_id/
company_id reference the wizard-service tenant (different DB — no FK; ownership
enforced by wizard, recorded here for audit/reconciliation). Client secrets are
stored only as SHA-256 hashes. Purely additive; no existing table is touched.

Revision ID: 015_add_oauth_clients_table
Revises: 014_add_oauth_signing_keys_table
Create Date: 2026-07-11
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from app.core.config import settings


revision = "015_add_oauth_clients_table"
down_revision = "014_add_oauth_signing_keys_table"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "oauth_clients",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("client_id", sa.String(length=64), nullable=False),
        sa.Column("client_secret_hash", sa.String(length=64), nullable=True),
        sa.Column("client_type", sa.String(length=16), nullable=False, server_default="confidential"),
        sa.Column("client_name", sa.String(length=255), nullable=False),
        sa.Column("logo_url", sa.String(length=1024), nullable=True),
        sa.Column("brand_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("company_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("created_by_user_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("redirect_uris", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default="[]"),
        sa.Column("allowed_scopes", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default="[]"),
        sa.Column("is_sandbox", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("status", sa.String(length=16), nullable=False, server_default="active"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("client_id", name="uq_oauth_clients_client_id"),
        schema=settings.DATABASE_SCHEMA,
    )
    op.create_index("ix_oauth_clients_client_id", "oauth_clients", ["client_id"], schema=settings.DATABASE_SCHEMA)
    op.create_index("ix_oauth_clients_brand_id", "oauth_clients", ["brand_id"], schema=settings.DATABASE_SCHEMA)
    op.create_index("ix_oauth_clients_company_id", "oauth_clients", ["company_id"], schema=settings.DATABASE_SCHEMA)


def downgrade() -> None:
    op.drop_index("ix_oauth_clients_company_id", table_name="oauth_clients", schema=settings.DATABASE_SCHEMA)
    op.drop_index("ix_oauth_clients_brand_id", table_name="oauth_clients", schema=settings.DATABASE_SCHEMA)
    op.drop_index("ix_oauth_clients_client_id", table_name="oauth_clients", schema=settings.DATABASE_SCHEMA)
    op.drop_table("oauth_clients", schema=settings.DATABASE_SCHEMA)
