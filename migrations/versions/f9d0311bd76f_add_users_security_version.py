"""add_users_security_version

Revision ID: f9d0311bd76f
Revises: 023d924aba69
Create Date: 2026-10-16 01:22:45.341517

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'f9d0311bd76f'
down_revision: Union[str, Sequence[str], None] = '023d924aba69'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _has_column(table_name: str, column_name: str) -> bool:
    inspector = sa.inspect(op.get_bind())
    if table_name not in inspector.get_table_names():
        return False
    return any(col["name"] == column_name for col in inspector.get_columns(table_name))


def upgrade() -> None:
    """Upgrade schema."""
    if not _has_column('users', 'security_version'):
        with op.batch_alter_table('users', schema=None) as batch_op:
            batch_op.add_column(sa.Column('security_version', sa.Integer(), nullable=False, server_default="1"))


def downgrade() -> None:
    """Downgrade schema."""
    if _has_column('users', 'security_version'):
        with op.batch_alter_table('users', schema=None) as batch_op:
            batch_op.drop_column('security_version')
