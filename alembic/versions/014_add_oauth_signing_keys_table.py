"""add oauth_signing_keys table (Login with Herm OIDC RS256 key registry)

Stores the public JWK, KMS key ARN, and rotation status (active/next/retired)
for the partner-facing OIDC signing keys. Private key material never lands
here — it stays in AWS KMS (non-exportable); this table only records what is
needed to publish JWKS and to pick the signing key. Purely additive; no
existing table is touched.

Revision ID: 014_add_oauth_signing_keys_table
Revises: 013_add_email_otp_codes_table
Create Date: 2026-07-11
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from app.core.config import settings


revision = "014_add_oauth_signing_keys_table"
down_revision = "013_add_email_otp_codes_table"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "oauth_signing_keys",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("kid", sa.String(length=255), nullable=False),
        sa.Column("kms_key_arn", sa.String(length=512), nullable=False),
        sa.Column("algorithm", sa.String(length=16), nullable=False, server_default="RS256"),
        sa.Column("public_jwk", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False, server_default="active"),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("kid", name="uq_oauth_signing_keys_kid"),
        schema=settings.DATABASE_SCHEMA,
    )

    op.create_index(
        "ix_oauth_signing_keys_status",
        "oauth_signing_keys",
        ["status"],
        schema=settings.DATABASE_SCHEMA,
    )


def downgrade() -> None:
    op.drop_index(
        "ix_oauth_signing_keys_status",
        table_name="oauth_signing_keys",
        schema=settings.DATABASE_SCHEMA,
    )
    op.drop_table("oauth_signing_keys", schema=settings.DATABASE_SCHEMA)
