"""Add user roles and remove connected apps

Revision ID: 004
Revises: 003
Create Date: 2025-12-08

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
revision: str = '004'
down_revision: Union[str, None] = '003'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Add role column to users table with default value 'user'
    op.add_column(
        'users',
        sa.Column('role', sa.String(length=50), nullable=False, server_default='user'),
        schema=settings.DATABASE_SCHEMA
    )

    # Drop connected_apps table
    op.drop_table('connected_apps', schema=settings.DATABASE_SCHEMA)


def downgrade() -> None:
    # Recreate connected_apps table
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

    # Remove role column from users table
    op.drop_column('users', 'role', schema=settings.DATABASE_SCHEMA)

