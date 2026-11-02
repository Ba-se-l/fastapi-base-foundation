"""upgrade casbin_rule to 4tuple domain support

Revision ID: 8c10e3b4a202
Revises: 7b91c4e2a101
Create Date: 2026-11-02 03:00:00.000000
"""
from collections.abc import Sequence
import sqlalchemy as sa
from alembic import op

revision: str = "8c10e3b4a202"
down_revision: str | Sequence[str] | None = "7b91c4e2a101"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    bind = op.get_bind()
    casbin_rule = sa.table(
        "casbin_rule",
        sa.column("id", sa.Integer),
        sa.column("ptype", sa.String),
        sa.column("v0", sa.String),
        sa.column("v1", sa.String),
        sa.column("v2", sa.String),
        sa.column("v3", sa.String),
        sa.column("v4", sa.String),
        sa.column("v5", sa.String),
    )

    # 1. For permission rules (ptype='p'): if v3 is NULL and v2 is NOT NULL, shift v2->v3, v1->v2, v1='global'
    rows_p = bind.execute(
        sa.select(
            casbin_rule.c.id,
            casbin_rule.c.v0,
            casbin_rule.c.v1,
            casbin_rule.c.v2,
            casbin_rule.c.v3,
        ).where(
            casbin_rule.c.ptype == "p",
            casbin_rule.c.v3.is_(None),
            casbin_rule.c.v2.isnot(None),
        )
    ).fetchall()

    for row in rows_p:
        bind.execute(
            casbin_rule.update()
            .where(casbin_rule.c.id == row.id)
            .values(
                v1="global",
                v2=row.v1,
                v3=row.v2,
            )
        )

    # 2. For grouping rules (ptype='g'): if v2 is NULL and v1 is NOT NULL, set v2='global'
    rows_g = bind.execute(
        sa.select(
            casbin_rule.c.id,
            casbin_rule.c.v0,
            casbin_rule.c.v1,
            casbin_rule.c.v2,
        ).where(
            casbin_rule.c.ptype == "g",
            casbin_rule.c.v2.is_(None),
            casbin_rule.c.v1.isnot(None),
        )
    ).fetchall()

    for row in rows_g:
        bind.execute(
            casbin_rule.update()
            .where(casbin_rule.c.id == row.id)
            .values(
                v2="global",
            )
        )


def downgrade() -> None:
    bind = op.get_bind()
    casbin_rule = sa.table(
        "casbin_rule",
        sa.column("id", sa.Integer),
        sa.column("ptype", sa.String),
        sa.column("v0", sa.String),
        sa.column("v1", sa.String),
        sa.column("v2", sa.String),
        sa.column("v3", sa.String),
    )

    # Reverse 'p'
    rows_p = bind.execute(
        sa.select(
            casbin_rule.c.id,
            casbin_rule.c.v1,
            casbin_rule.c.v2,
            casbin_rule.c.v3,
        ).where(
            casbin_rule.c.ptype == "p",
            casbin_rule.c.v1 == "global",
            casbin_rule.c.v3.isnot(None),
        )
    ).fetchall()

    for row in rows_p:
        bind.execute(
            casbin_rule.update()
            .where(casbin_rule.c.id == row.id)
            .values(
                v1=row.v2,
                v2=row.v3,
                v3=None,
            )
        )

    # Reverse 'g'
    rows_g = bind.execute(
        sa.select(
            casbin_rule.c.id,
            casbin_rule.c.v2,
        ).where(
            casbin_rule.c.ptype == "g",
            casbin_rule.c.v2 == "global",
        )
    ).fetchall()

    for row in rows_g:
        bind.execute(
            casbin_rule.update()
            .where(casbin_rule.c.id == row.id)
            .values(
                v2=None,
            )
        )

