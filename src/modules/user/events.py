from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from src.share import DomainEvent, UserAction

__all__ = (
    'UserAccessDenied',
    'UserDeactivated',
    'UserInactiveTargeted',
    'UserNotFound',
    'UserUpdated',
    'UserUpdateSkipped',
)


@dataclass(frozen=True, slots=True, kw_only=True)
class UserNotFound(DomainEvent):
    """A lookup referenced a user identifier that does not exist."""

    user_id: int
    """Identifier that was requested."""


@dataclass(frozen=True, slots=True, kw_only=True)
class UserAccessDenied(DomainEvent):
    """An actor attempted an operation on a user without permission."""

    actor_id: int
    """Identifier of the user who attempted the operation."""

    actor_name: str
    """Display name of the actor at the time of the attempt."""

    target_user_id: int
    """Identifier of the user the operation targeted."""

    action: UserAction
    """Operation that was denied."""


@dataclass(frozen=True, slots=True, kw_only=True)
class UserInactiveTargeted(DomainEvent):
    """An operation targeted an account that was already inactive."""

    actor_id: int
    """Identifier of the user who attempted the operation."""

    actor_name: str
    """Display name of the actor at the time of the attempt."""

    target_user_id: int
    """Identifier of the user the operation targeted."""

    action: UserAction
    """Operation that failed due to inactivity."""


@dataclass(frozen=True, slots=True, kw_only=True)
class UserUpdated(DomainEvent):
    """A user profile was modified."""

    user_id: int
    """Identifier of the modified user."""

    actor_id: str | int | None = None
    """Identifier of the actor executing the update."""

    changes: Mapping[str, Any] = field(default_factory=dict)
    """Field-level diff in the form ``{field: {"old": ..., "new": ...}}``."""


@dataclass(frozen=True, slots=True, kw_only=True)
class UserUpdateSkipped(DomainEvent):
    """An update request carried no modifiable fields."""

    user_id: int
    """Identifier of the targeted user."""

    actor_id: str | int | None = None
    """Identifier of the actor initiating the skipped request."""


@dataclass(frozen=True, slots=True, kw_only=True)
class UserDeactivated(DomainEvent):
    """A user account was soft-deactivated."""

    user_id: int
    """Identifier of the deactivated user."""

    actor_id: str | int | None = None
    """Identifier of the actor performing deactivation."""
