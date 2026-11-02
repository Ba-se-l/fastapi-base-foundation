"""add_casbin_rule

Revision ID: 1481b1cdf6a4
Revises: bce235971d47
Create Date: 2026-10-15 05:43:08.683416

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '1481b1cdf6a4'
down_revision: Union[str, Sequence[str], None] = 'bce235971d47'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _has_table(table_name: str) -> bool:
    inspector = sa.inspect(op.get_bind())
    return table_name in inspector.get_table_names()


def upgrade() -> None:
    """Upgrade schema."""
    if not _has_table('casbin_rule'):
        casbin_rule = op.create_table('casbin_rule',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('ptype', sa.String(length=255), nullable=False),
        sa.Column('v0', sa.String(length=255), nullable=False),
        sa.Column('v1', sa.String(length=255), nullable=False),
        sa.Column('v2', sa.String(length=255), nullable=True),
        sa.Column('v3', sa.String(length=255), nullable=True),
        sa.Column('v4', sa.String(length=255), nullable=True),
        sa.Column('v5', sa.String(length=255), nullable=True),
        sa.PrimaryKeyConstraint('id', name=op.f('pk_casbin_rule'))
        )
        op.bulk_insert(casbin_rule, [{'ptype': 'p', 'v0': 'admin', 'v1': '*', 'v2': '*'}])


def downgrade() -> None:
    """Downgrade schema."""
    if _has_table('casbin_rule'):
        op.drop_table('casbin_rule')
