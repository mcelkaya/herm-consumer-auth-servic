"""Add admin_users and admin_refresh_tokens tables

Revision ID: 006_add_admin_users
Revises: 005_email_verification
Create Date: 2025-01-01 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = "006_add_admin_users"
down_revision = "005_email_verification"
branch_labels = None
depends_on = None

SCHEMA = "herm_auth"


def upgrade() -> None:
    # ------------------------------------------------------------------
    # admin_users
    # ------------------------------------------------------------------
    op.create_table(
        "admin_users",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            nullable=False,
        ),
        sa.Column("email", sa.String(255), nullable=False),
        sa.Column("hashed_password", sa.String(255), nullable=False),
        sa.Column("role", sa.String(50), nullable=False, server_default="admin"),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        schema=SCHEMA,
    )

    op.create_index(
        "ix_admin_users_email",
        "admin_users",
        ["email"],
        unique=True,
        schema=SCHEMA,
    )

    # ------------------------------------------------------------------
    # admin_refresh_tokens
    # ------------------------------------------------------------------
    op.create_table(
        "admin_refresh_tokens",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            nullable=False,
        ),
        sa.Column("token", sa.String(255), nullable=False),
        sa.Column(
            "admin_user_id",
            postgresql.UUID(as_uuid=True),
            nullable=False,
        ),
        sa.Column("expires_at", sa.DateTime(timezone=False), nullable=False),
        sa.Column(
            "is_revoked",
            sa.Boolean(),
            nullable=False,
            server_default="false",
        ),
        sa.Column("device_info", sa.Text(), nullable=True),
        sa.Column("ip_address", sa.String(45), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=False),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.ForeignKeyConstraint(
            ["admin_user_id"],
            [f"{SCHEMA}.admin_users.id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
        schema=SCHEMA,
    )

    op.create_index(
        "ix_admin_refresh_tokens_token",
        "admin_refresh_tokens",
        ["token"],
        unique=True,
        schema=SCHEMA,
    )

    op.create_index(
        "ix_admin_refresh_tokens_admin_user_id",
        "admin_refresh_tokens",
        ["admin_user_id"],
        schema=SCHEMA,
    )


def downgrade() -> None:
    op.drop_index(
        "ix_admin_refresh_tokens_admin_user_id",
        table_name="admin_refresh_tokens",
        schema=SCHEMA,
    )
    op.drop_index(
        "ix_admin_refresh_tokens_token",
        table_name="admin_refresh_tokens",
        schema=SCHEMA,
    )
    op.drop_table("admin_refresh_tokens", schema=SCHEMA)

    op.drop_index("ix_admin_users_email", table_name="admin_users", schema=SCHEMA)
    op.drop_table("admin_users", schema=SCHEMA)