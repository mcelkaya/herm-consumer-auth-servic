"""Initial migration

Revision ID: 001
Revises: 
Create Date: 2025-11-11

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
revision: str = '001'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Create users table
    op.create_table(
        'users',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('email', sa.String(length=255), nullable=False),
        sa.Column('hashed_password', sa.String(length=255), nullable=False),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('is_verified', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        schema=settings.DATABASE_SCHEMA
    )
    op.create_index(op.f('ix_users_email'), 'users', ['email'], unique=True, schema=settings.DATABASE_SCHEMA)

    # Create connected_apps table
    op.create_table(
        'connected_apps',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('provider', sa.String(length=50), nullable=False),
        sa.Column('provider_email', sa.String(length=255), nullable=False),
        sa.Column('access_token', sa.Text(), nullable=False),
        sa.Column('refresh_token', sa.Text(), nullable=True),
        sa.Column('token_expires_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(['user_id'], [f'{settings.DATABASE_SCHEMA}.users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        schema=settings.DATABASE_SCHEMA
    )


def downgrade() -> None:
    op.drop_table('connected_apps', schema=settings.DATABASE_SCHEMA)
    op.drop_index(op.f('ix_users_email'), table_name='users', schema=settings.DATABASE_SCHEMA)
    op.drop_table('users', schema=settings.DATABASE_SCHEMA)

    # Drop schema if it was created (only if not using 'public')
    if settings.DATABASE_SCHEMA != 'public':
        op.execute(f'DROP SCHEMA IF EXISTS {settings.DATABASE_SCHEMA} CASCADE')
