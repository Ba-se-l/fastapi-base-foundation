from datetime import datetime
from typing import Self

from pydantic import BaseModel as Base, ConfigDict, Field, model_validator

from src.share import Roles


class UserResponse(Base):
    """User response representation for API boundaries."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    """Unique identifier of the user."""

    name: str
    """Full display name."""

    email: str
    """User email address."""

    role: Roles
    """Assigned user role for authorization."""

    is_active: bool
    """Active status flag."""

    created_at: datetime
    """Account creation timestamp."""

    updated_at: datetime
    """Account last updated timestamp."""


class UserUpdate(Base):
    """Schema for partial user updates (PATCH semantics: omitted is allowed, explicit null is not)."""

    model_config = ConfigDict(extra="forbid")

    name: str | None = Field(default=None, min_length=1, max_length=100)
    """Updated display name."""

    is_active: bool | None = None
    """Updated active status."""

    role: Roles | None = None
    """Updated access role."""

    @model_validator(mode='after')
    def reject_explicit_nulls(self) -> Self:
        """Rejects explicit null for fields mapped to NOT NULL columns."""
        for field_name in ('name', 'is_active', 'role'):
            if field_name in self.model_fields_set and getattr(self, field_name) is None:
                raise ValueError(f"'{field_name}' cannot be null.")
        return self
