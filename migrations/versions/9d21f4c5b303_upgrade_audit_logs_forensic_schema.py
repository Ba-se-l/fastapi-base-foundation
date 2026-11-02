"""upgrade audit logs forensic schema

Revision ID: 9d21f4c5b303
Revises: 8c10e3b4a202
Create Date: 2026-11-02 03:00:00.000000

"""
from collections.abc import Sequence
from alembic import op
import sqlalchemy as sa


revision: str = '9d21f4c5b303'
down_revision: str | Sequence[str] | None = '8c10e3b4a202'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


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
    with op.batch_alter_table('audit_logs', schema=None) as batch_op:
        if not _has_column('audit_logs', 'actor_id'):
            batch_op.add_column(sa.Column('actor_id', sa.String(length=64), nullable=True))
        if not _has_column('audit_logs', 'actor_snapshot'):
            batch_op.add_column(sa.Column('actor_snapshot', sa.String(length=255), nullable=True))
        if not _has_column('audit_logs', 'entity_type'):
            batch_op.add_column(sa.Column('entity_type', sa.String(length=64), nullable=True))
        if not _has_column('audit_logs', 'entity_id'):
            batch_op.add_column(sa.Column('entity_id', sa.String(length=64), nullable=True))
        if not _has_column('audit_logs', 'domain_id'):
            batch_op.add_column(sa.Column('domain_id', sa.String(length=64), nullable=True, server_default='global'))
        if not _has_column('audit_logs', 'outcome'):
            batch_op.add_column(sa.Column('outcome', sa.String(length=32), nullable=False, server_default='SUCCESS'))
        if not _has_column('audit_logs', 'changes_payload'):
            batch_op.add_column(sa.Column('changes_payload', sa.JSON(), nullable=True))
        if not _has_column('audit_logs', 'occurred_at'):
            batch_op.add_column(
                sa.Column('occurred_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now())
            )

        if not _has_index('audit_logs', op.f('ix_audit_logs_actor_id')):
            batch_op.create_index(op.f('ix_audit_logs_actor_id'), ['actor_id'], unique=False)
        if not _has_index('audit_logs', op.f('ix_audit_logs_entity_type')):
            batch_op.create_index(op.f('ix_audit_logs_entity_type'), ['entity_type'], unique=False)
        if not _has_index('audit_logs', op.f('ix_audit_logs_entity_id')):
            batch_op.create_index(op.f('ix_audit_logs_entity_id'), ['entity_id'], unique=False)
        if not _has_index('audit_logs', op.f('ix_audit_logs_domain_id')):
            batch_op.create_index(op.f('ix_audit_logs_domain_id'), ['domain_id'], unique=False)
        if not _has_index('audit_logs', op.f('ix_audit_logs_outcome')):
            batch_op.create_index(op.f('ix_audit_logs_outcome'), ['outcome'], unique=False)


def downgrade() -> None:
    with op.batch_alter_table('audit_logs', schema=None) as batch_op:
        if _has_index('audit_logs', op.f('ix_audit_logs_outcome')):
            batch_op.drop_index(op.f('ix_audit_logs_outcome'))
        if _has_index('audit_logs', op.f('ix_audit_logs_domain_id')):
            batch_op.drop_index(op.f('ix_audit_logs_domain_id'))
        if _has_index('audit_logs', op.f('ix_audit_logs_entity_id')):
            batch_op.drop_index(op.f('ix_audit_logs_entity_id'))
        if _has_index('audit_logs', op.f('ix_audit_logs_entity_type')):
            batch_op.drop_index(op.f('ix_audit_logs_entity_type'))
        if _has_index('audit_logs', op.f('ix_audit_logs_actor_id')):
            batch_op.drop_index(op.f('ix_audit_logs_actor_id'))

        if _has_column('audit_logs', 'occurred_at'):
            batch_op.drop_column('occurred_at')
        if _has_column('audit_logs', 'changes_payload'):
            batch_op.drop_column('changes_payload')
        if _has_column('audit_logs', 'outcome'):
            batch_op.drop_column('outcome')
        if _has_column('audit_logs', 'domain_id'):
            batch_op.drop_column('domain_id')
        if _has_column('audit_logs', 'entity_id'):
            batch_op.drop_column('entity_id')
        if _has_column('audit_logs', 'entity_type'):
            batch_op.drop_column('entity_type')
        if _has_column('audit_logs', 'actor_snapshot'):
            batch_op.drop_column('actor_snapshot')
        if _has_column('audit_logs', 'actor_id'):
            batch_op.drop_column('actor_id')

