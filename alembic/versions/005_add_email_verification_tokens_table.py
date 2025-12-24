"""Add email verification tokens table

Revision ID: 005_email_verification
Revises: 004
Create Date: 2024-12-24 11:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '005_email_verification'
down_revision = '004'
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Create email_verification_tokens table"""
    op.create_table(
        'email_verification_tokens',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('token', sa.String(length=64), nullable=False),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('expires_at', sa.DateTime(timezone=False), nullable=False),
        sa.Column('is_used', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('created_at', sa.DateTime(timezone=False), nullable=False, server_default=sa.text('now()')),
        sa.Column('used_at', sa.DateTime(timezone=False), nullable=True),
        sa.Column('ip_address', sa.String(length=45), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['user_id'], ['herm_auth.users.id'], ondelete='CASCADE'),
        schema='herm_auth'
    )
    
    # Create indexes
    op.create_index(
        'ix_email_verification_tokens_token',
        'email_verification_tokens',
        ['token'],
        unique=True,
        schema='herm_auth'
    )
    op.create_index(
        'ix_email_verification_tokens_user_id',
        'email_verification_tokens',
        ['user_id'],
        schema='herm_auth'
    )


def downgrade() -> None:
    """Drop email_verification_tokens table"""
    op.drop_index('ix_email_verification_tokens_user_id', table_name='email_verification_tokens', schema='herm_auth')
    op.drop_index('ix_email_verification_tokens_token', table_name='email_verification_tokens', schema='herm_auth')
    op.drop_table('email_verification_tokens', schema='herm_auth')