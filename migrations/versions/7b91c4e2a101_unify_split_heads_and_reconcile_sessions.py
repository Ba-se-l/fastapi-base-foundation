"""unify split heads and reconcile legacy refresh sessions

Revision ID: 7b91c4e2a101
Revises: 6aa8f9bfed61, 669e5696de0c
Create Date: 2026-11-02 02:35:00.000000
"""
from collections.abc import Sequence
import sqlalchemy as sa
from alembic import op

revision: str = "7b91c4e2a101"
down_revision: str | Sequence[str] | None = ("6aa8f9bfed61", "669e5696de0c")
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    bind = op.get_bind()
    refresh_sessions = sa.table(
        "refresh_sessions",
        sa.column("id", sa.Integer),
        sa.column("user_id", sa.Integer),
        sa.column("refresh_token_jti", sa.String),
        sa.column("family_id", sa.String),
        sa.column("is_revoked", sa.Boolean),
    )
    users = sa.table(
        "users",
        sa.column("id", sa.Integer),
        sa.column("security_version", sa.Integer),
    )

    legacy_rows = bind.execute(
        sa.select(
            refresh_sessions.c.id,
            refresh_sessions.c.user_id,
            refresh_sessions.c.refresh_token_jti,
        ).where(
            sa.or_(
                refresh_sessions.c.family_id.is_(None),
                refresh_sessions.c.family_id == "",
                refresh_sessions.c.family_id == "legacy",
            )
        )
    ).fetchall()

    if legacy_rows:
        affected_user_ids = {row.user_id for row in legacy_rows}
        for row in legacy_rows:
            bind.execute(
                refresh_sessions.update()
                .where(refresh_sessions.c.id == row.id)
                .values(
                    family_id=row.refresh_token_jti,
                    is_revoked=True,
                )
            )
        bind.execute(
            users.update()
            .where(users.c.id.in_(affected_user_ids))
            .values(security_version=users.c.security_version + 1)
        )

    with op.batch_alter_table("refresh_sessions", schema=None) as batch_op:
        batch_op.alter_column(
            "family_id",
            existing_type=sa.String(length=64),
            server_default=None,
            existing_nullable=False,
        )


def downgrade() -> None:
    pass

