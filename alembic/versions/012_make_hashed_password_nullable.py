"""make users.hashed_password nullable for social-only accounts

A user created via social login (Google / Apple / Facebook) never sets a
password, so there is nothing to store in hashed_password. Password login
against such an account is rejected in UserService.login with the same generic
401 as a wrong password (see the guard added there), so allowing NULL here does
not weaken authentication — it only stops social-only signup from violating a
NOT NULL constraint.

Revision ID: 012_make_hashed_password_nullable
Revises: 011_add_user_oauth_accounts
Create Date: 2026-06-12
"""
from alembic import op
import sqlalchemy as sa

from app.core.config import settings


revision = "012_make_hashed_password_nullable"
down_revision = "011_add_user_oauth_accounts"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.alter_column(
        "users",
        "hashed_password",
        existing_type=sa.String(length=255),
        nullable=True,
        schema=settings.DATABASE_SCHEMA,
    )


def downgrade() -> None:
    # WARNING: this will fail if any social-only users exist
    # (rows where hashed_password IS NULL). Backfill or delete those first.
    op.alter_column(
        "users",
        "hashed_password",
        existing_type=sa.String(length=255),
        nullable=False,
        schema=settings.DATABASE_SCHEMA,
    )