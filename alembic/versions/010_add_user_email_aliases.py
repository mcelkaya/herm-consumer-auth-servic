"""add user_email_aliases and alias_email_id on email_verification_tokens

Users can register secondary email addresses on their account. Each alias goes
through the same verification flow as the primary email but marks the alias
row verified (not the user). The same email_verification_tokens table is used
with a nullable alias_email_id discriminator.

Revision ID: 010_add_user_email_aliases
Revises: 009_add_revoked_at_to_evt
Create Date: 2026-05-11
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from app.core.config import settings


revision = "010_add_user_email_aliases"
down_revision = "009_add_revoked_at_to_evt"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "user_email_aliases",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False, server_default=sa.text("gen_random_uuid()")),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("email", sa.String(length=255), nullable=False),
        sa.Column("is_verified", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("verified_at", sa.DateTime(timezone=False), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=False), nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=False), nullable=False, server_default=sa.text("now()")),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(["user_id"], [f"{settings.DATABASE_SCHEMA}.users.id"], ondelete="CASCADE"),
        schema=settings.DATABASE_SCHEMA,
    )

    op.create_index(
        "ix_user_email_aliases_user_id",
        "user_email_aliases",
        ["user_id"],
        schema=settings.DATABASE_SCHEMA,
    )
    op.create_index(
        "ix_user_email_aliases_email",
        "user_email_aliases",
        ["email"],
        schema=settings.DATABASE_SCHEMA,
    )
    # Partial unique: only verified aliases reserve the address globally.
    # Unverified rows are claim placeholders and may be reclaimed once their
    # token expires (see EmailAliasService.add_alias).
    op.execute(
        f"""
        CREATE UNIQUE INDEX uq_user_email_aliases_verified_email
        ON {settings.DATABASE_SCHEMA}.user_email_aliases (email)
        WHERE is_verified = TRUE
        """
    )

    op.add_column(
        "email_verification_tokens",
        sa.Column("alias_email_id", postgresql.UUID(as_uuid=True), nullable=True),
        schema=settings.DATABASE_SCHEMA,
    )
    op.create_foreign_key(
        "fk_email_verification_tokens_alias_email_id",
        "email_verification_tokens",
        "user_email_aliases",
        ["alias_email_id"],
        ["id"],
        source_schema=settings.DATABASE_SCHEMA,
        referent_schema=settings.DATABASE_SCHEMA,
        ondelete="CASCADE",
    )
    op.create_index(
        "ix_email_verification_tokens_alias_email_id",
        "email_verification_tokens",
        ["alias_email_id"],
        schema=settings.DATABASE_SCHEMA,
    )


def downgrade() -> None:
    op.drop_index(
        "ix_email_verification_tokens_alias_email_id",
        table_name="email_verification_tokens",
        schema=settings.DATABASE_SCHEMA,
    )
    op.drop_constraint(
        "fk_email_verification_tokens_alias_email_id",
        "email_verification_tokens",
        type_="foreignkey",
        schema=settings.DATABASE_SCHEMA,
    )
    op.drop_column(
        "email_verification_tokens",
        "alias_email_id",
        schema=settings.DATABASE_SCHEMA,
    )

    op.execute(
        f"DROP INDEX IF EXISTS {settings.DATABASE_SCHEMA}.uq_user_email_aliases_verified_email"
    )
    op.drop_index(
        "ix_user_email_aliases_email",
        table_name="user_email_aliases",
        schema=settings.DATABASE_SCHEMA,
    )
    op.drop_index(
        "ix_user_email_aliases_user_id",
        table_name="user_email_aliases",
        schema=settings.DATABASE_SCHEMA,
    )
    op.drop_table("user_email_aliases", schema=settings.DATABASE_SCHEMA)
