"""Add password reset tokens table

Revision ID: 003
Revises: 002
Create Date: 2025-11-21

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql
import os
import sys

# Add the project root to the path to import settings
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
from app.core.config import settings

# revision identifiers, used by Alembic.
revision: str = '003'
down_revision: Union[str, None] = '002'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Create password_reset_tokens table
    op.create_table(
        'password_reset_tokens',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('token', sa.String(length=64), nullable=False),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('expires_at', sa.DateTime(timezone=False), nullable=False),
        sa.Column('is_used', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('created_at', sa.DateTime(timezone=False), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=True),
        sa.Column('used_at', sa.DateTime(timezone=False), nullable=True),
        sa.Column('ip_address', sa.String(length=45), nullable=True),
        sa.ForeignKeyConstraint(['user_id'], [f'{settings.DATABASE_SCHEMA}.users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        schema=settings.DATABASE_SCHEMA
    )

    # Create indexes
    op.create_index(
        op.f('ix_password_reset_tokens_token'),
        'password_reset_tokens',
        ['token'],
        unique=True,
        schema=settings.DATABASE_SCHEMA
    )
    op.create_index(
        op.f('ix_password_reset_tokens_user_id'),
        'password_reset_tokens',
        ['user_id'],
        unique=False,
        schema=settings.DATABASE_SCHEMA
    )
    op.create_index(
        op.f('ix_password_reset_tokens_expires_at'),
        'password_reset_tokens',
        ['expires_at'],
        unique=False,
        schema=settings.DATABASE_SCHEMA
    )


def downgrade() -> None:
    op.drop_index(op.f('ix_password_reset_tokens_expires_at'), table_name='password_reset_tokens', schema=settings.DATABASE_SCHEMA)
    op.drop_index(op.f('ix_password_reset_tokens_user_id'), table_name='password_reset_tokens', schema=settings.DATABASE_SCHEMA)
    op.drop_index(op.f('ix_password_reset_tokens_token'), table_name='password_reset_tokens', schema=settings.DATABASE_SCHEMA)
    op.drop_table('password_reset_tokens', schema=settings.DATABASE_SCHEMA)
