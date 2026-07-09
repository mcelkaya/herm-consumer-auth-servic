"""add email_otp_codes table for 6-digit OTP email verification

Unlike email_verification_tokens' 64-char token (secrets.token_urlsafe(48),
high entropy, safe to store plaintext), a 6-digit OTP only has 1,000,000
possibilities, so the code is hashed at rest (code_hash) and attempt_count
caps brute-force guessing (locked out at 5 wrong attempts, enforced in
app/models/email_otp_code.py::is_locked_out).

Revision ID: 013_add_email_otp_codes_table
Revises: 012_make_hashed_password_nullable
Create Date: 2026-07-08
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from app.core.config import settings


revision = "013_add_email_otp_codes_table"
down_revision = "012_make_hashed_password_nullable"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "email_otp_codes",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("code_hash", sa.String(length=255), nullable=False),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=False), nullable=False),
        sa.Column("is_used", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("used_at", sa.DateTime(timezone=False), nullable=True),
        sa.Column("attempt_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("revoked_at", sa.DateTime(timezone=False), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=False),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column("ip_address", sa.String(length=45), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(
            ["user_id"],
            [f"{settings.DATABASE_SCHEMA}.users.id"],
            ondelete="CASCADE",
        ),
        schema=settings.DATABASE_SCHEMA,
    )

    op.create_index(
        "ix_email_otp_codes_user_id",
        "email_otp_codes",
        ["user_id"],
        schema=settings.DATABASE_SCHEMA,
    )


def downgrade() -> None:
    op.drop_index(
        "ix_email_otp_codes_user_id",
        table_name="email_otp_codes",
        schema=settings.DATABASE_SCHEMA,
    )
    op.drop_table("email_otp_codes", schema=settings.DATABASE_SCHEMA)
