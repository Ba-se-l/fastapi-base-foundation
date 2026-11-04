from sqlalchemy import Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from src.database import BaseModel as Base


class CasbinRule(Base):
    """SQLAlchemy ORM entity mapping the 4-tuple PyCasbin policy table (casbin_rule).

    Column Mapping for 4-Tuple Domain RBAC:
        - ptype: Policy type ('p' for permission policy, 'g' for role grouping policy).
        - v0: Subject (Role name or user identifier, e.g., 'admin', 'user').
        - v1: Domain / Tenant identifier (e.g., 'global' or specific tenant ID).
        - v2: Resource identifier (for 'p' rules, e.g., 'users', 'audit', '*') or Assigned Role (for 'g' rules).
        - v3: Action identifier (for 'p' rules, e.g., 'read', 'create', '*').
        - v4, v5: Reserved optional extension columns for future ABAC predicates.

    Attributes:
        id: Primary key unique identifier.
        ptype: Policy type token ('p' for permission, 'g' for role inheritance).
        v0: First rule parameter.
        v1: Second rule parameter.
        v2: Third rule parameter.
        v3: Fourth rule parameter.
        v4: Fifth rule parameter.
        v5: Sixth rule parameter.
    """

    __tablename__ = 'casbin_rule'

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ptype: Mapped[str] = mapped_column(String(255), nullable=False)
    v0: Mapped[str] = mapped_column(String(255), nullable=False)
    v1: Mapped[str] = mapped_column(String(255), nullable=False)
    v2: Mapped[str | None] = mapped_column(String(255), nullable=True)
    v3: Mapped[str | None] = mapped_column(String(255), nullable=True)
    v4: Mapped[str | None] = mapped_column(String(255), nullable=True)
    v5: Mapped[str | None] = mapped_column(String(255), nullable=True)

    def __str__(self) -> str:
        """Serializes the rule line for Casbin's load_policy parser.

        The adapter calls str(row) for every row during load_policy(); without this
        method, Casbin fails to parse stored policy lines correctly.

        Returns:
            Comma-separated representation of the policy rule.
        """
        values: list[str] = [self.ptype]
        for val in (self.v0, self.v1, self.v2, self.v3, self.v4, self.v5):
            if val is None:
                break
            values.append(val)
        return ', '.join(values)

    def __repr__(self) -> str:
        return f'<CasbinRule {self.id}: "{self}">'
