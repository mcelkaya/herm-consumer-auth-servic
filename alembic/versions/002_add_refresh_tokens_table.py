"""Add refresh tokens table

Revision ID: 002
Revises: 001
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
revision: str = '002'
down_revision: Union[str, None] = '001'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Create refresh_tokens table
    op.create_table(
        'refresh_tokens',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('token', sa.String(length=255), nullable=False),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('is_revoked', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
        sa.Column('device_info', sa.String(length=500), nullable=True),
        sa.Column('ip_address', sa.String(length=45), nullable=True),
        sa.ForeignKeyConstraint(['user_id'], [f'{settings.DATABASE_SCHEMA}.users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        schema=settings.DATABASE_SCHEMA
    )

    # Create indexes
    op.create_index(
        op.f('ix_refresh_tokens_token'),
        'refresh_tokens',
        ['token'],
        unique=True,
        schema=settings.DATABASE_SCHEMA
    )


def downgrade() -> None:
    op.drop_index(op.f('ix_refresh_tokens_token'), table_name='refresh_tokens', schema=settings.DATABASE_SCHEMA)
    op.drop_table('refresh_tokens', schema=settings.DATABASE_SCHEMA)
