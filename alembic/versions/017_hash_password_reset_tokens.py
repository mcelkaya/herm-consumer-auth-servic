"""store password reset tokens as SHA-256 hashes

password_reset_tokens.token held the raw reset token, so a DB read was enough
to reset any user's password. Rename it to token_hash and hash existing rows
IN PLACE (sha256 hex of the raw value, the same digest the app computes), so
reset links already in users' inboxes keep working. The unique index carries
over unchanged (distinct inputs -> distinct digests; both are 64 chars).

Downgrade cannot recover raw tokens, so it invalidates every unused token
(is_used = true) before renaming the column back.

Revision ID: 017_hash_password_reset_tokens
Revises: 016_add_oauth_consents_and_refresh_tokens
Create Date: 2026-10-01
"""
from alembic import op

from app.core.config import settings

revision = "017_hash_password_reset_tokens"
down_revision = "016_add_oauth_consents_and_refresh_tokens"
branch_labels = None
depends_on = None

SCHEMA = settings.DATABASE_SCHEMA
TABLE = f"{SCHEMA}.password_reset_tokens"


def upgrade() -> None:
    op.alter_column("password_reset_tokens", "token", new_column_name="token_hash", schema=SCHEMA)
    op.execute(f"ALTER INDEX {SCHEMA}.ix_password_reset_tokens_token RENAME TO ix_password_reset_tokens_token_hash")
    op.execute(
        f"UPDATE {TABLE} SET token_hash = encode(sha256(convert_to(token_hash, 'UTF8')), 'hex')"
    )


def downgrade() -> None:
    op.execute(f"UPDATE {TABLE} SET is_used = true WHERE is_used = false")
    op.execute(f"ALTER INDEX {SCHEMA}.ix_password_reset_tokens_token_hash RENAME TO ix_password_reset_tokens_token")
    op.alter_column("password_reset_tokens", "token_hash", new_column_name="token", schema=SCHEMA)
