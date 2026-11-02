"""add_family_id_and_revoked_at_to_refresh_sessions

Revision ID: f2001b0d2995
Revises: 1481b1cdf6a4
Create Date: 2026-10-16 18:39:29.181367

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'f2001b0d2995'
down_revision: Union[str, Sequence[str], None] = '1481b1cdf6a4'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _has_column(table_name: str, column_name: str) -> bool:
    inspector = sa.inspect(op.get_bind())
    if table_name not in inspector.get_table_names():
        return False
    return any(col["name"] == column_name for col in inspector.get_columns(table_name))


def _has_index(table_name: str, index_name: str) -> bool:
    inspector = sa.inspect(op.get_bind())
    if table_name not in inspector.get_table_names():
        return False
    return any(idx["name"] == index_name for idx in inspector.get_indexes(table_name))


def upgrade() -> None:
    """Upgrade schema."""
    with op.batch_alter_table('refresh_sessions', schema=None) as batch_op:
        if not _has_column('refresh_sessions', 'family_id'):
            batch_op.add_column(sa.Column('family_id', sa.String(length=64), nullable=False, server_default='legacy'))
        if not _has_column('refresh_sessions', 'parent_jti'):
            batch_op.add_column(sa.Column('parent_jti', sa.String(length=64), nullable=True))
        if not _has_column('refresh_sessions', 'revoked_at'):
            batch_op.add_column(sa.Column('revoked_at', sa.DateTime(timezone=True), nullable=True))
        if not _has_index('refresh_sessions', op.f('ix_refresh_sessions_family_id')):
            batch_op.create_index(batch_op.f('ix_refresh_sessions_family_id'), ['family_id'], unique=False)


def downgrade() -> None:
    """Downgrade schema."""
    with op.batch_alter_table('refresh_sessions', schema=None) as batch_op:
        if _has_index('refresh_sessions', op.f('ix_refresh_sessions_family_id')):
            batch_op.drop_index(batch_op.f('ix_refresh_sessions_family_id'))
        if _has_column('refresh_sessions', 'revoked_at'):
            batch_op.drop_column('revoked_at')
        if _has_column('refresh_sessions', 'parent_jti'):
            batch_op.drop_column('parent_jti')
        if _has_column('refresh_sessions', 'family_id'):
            batch_op.drop_column('family_id')
