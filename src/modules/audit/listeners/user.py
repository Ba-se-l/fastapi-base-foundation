from sqlalchemy.ext.asyncio import AsyncSession

from src.modules.audit.enum import LogAction
from src.modules.audit.schemas import LogSeverity
from src.modules.audit.service import sanitize_audit_payload, save_failed_event, save_success_event
from src.modules.user.events import (
    UserAccessDenied,
    UserDeactivated,
    UserInactiveTargeted,
    UserNotFound,
    UserUpdated,
    UserUpdateSkipped,
)
from src.share import UserAction
from src.share.event_bus import AsyncEventBus

__all__ = (
    'on_user_access_denied',
    'on_user_deactivated',
    'on_user_inactive_targeted',
    'on_user_not_found',
    'on_user_update_skipped',
    'on_user_updated',
    'register_user_listeners',
)

_ACCESS_DENIED_VERBS: dict[UserAction, str] = {
    UserAction.VIEW: 'view the profile of',
    UserAction.MODIFY: 'modify',
    UserAction.CHANGE_ROLE: 'change the role of',
}

_ACCESS_DENIED_SEVERITY: dict[UserAction, LogSeverity] = {
    UserAction.VIEW: LogSeverity.WARNING,
    UserAction.MODIFY: LogSeverity.CRITICAL,
    UserAction.CHANGE_ROLE: LogSeverity.CRITICAL,
}


async def on_user_not_found(event: UserNotFound, session: AsyncSession | None) -> None:
    """Records a lookup attempt for a non-existent user identifier.

    Args:
        event: The UserNotFound fact.
        session: Ignored by design; failure evidence uses an autonomous session.
    """
    await save_failed_event(
        message=f'User with identifier ID [{event.user_id}] was not found.',
        event_type='USER_NOT_FOUND',
        severity=LogSeverity.ERROR,
        user_id=str(event.user_id),
        actor_id=None,
        entity_type="user",
        entity_id=str(event.user_id),
        domain_id="global",
        outcome="FAILURE",
        ctx=event.audit_ctx,
    )


async def on_user_access_denied(event: UserAccessDenied, session: AsyncSession | None) -> None:
    """Records an unauthorized operation attempt on a user resource.

    Args:
        event: The UserAccessDenied fact.
        session: Ignored by design; failure evidence uses an autonomous session.
    """
    verb = _ACCESS_DENIED_VERBS.get(event.action, event.action.value)
    severity = _ACCESS_DENIED_SEVERITY.get(event.action, LogSeverity.CRITICAL)

    await save_failed_event(
        message=(
            f'User [ID: {event.actor_id} | Name: {event.actor_name}] is not authorized '
            f'to {verb} User [ID: {event.target_user_id}].'
        ),
        event_type=LogAction.SECURITY_ACCESS_DENIED,
        severity=severity,
        user_id=str(event.actor_id),
        actor_id=str(event.actor_id),
        actor_snapshot=event.actor_name,
        entity_type="user",
        entity_id=str(event.target_user_id),
        domain_id="global",
        outcome="DENIED",
        ctx=event.audit_ctx,
        extra_data={'action': event.action.value, 'target_user_id': event.target_user_id},
    )


async def on_user_inactive_targeted(event: UserInactiveTargeted, session: AsyncSession | None) -> None:
    """Records an operation targeting a deactivated user account.

    Args:
        event: The UserInactiveTargeted fact.
        session: Ignored by design; failure evidence uses an autonomous session.
    """
    verb = _ACCESS_DENIED_VERBS.get(event.action, event.action.value)

    await save_failed_event(
        message=(
            f'User [ID: {event.actor_id} | Name: {event.actor_name}] '
            f'trying to {verb} inactive User [ID: {event.target_user_id}].'
        ),
        event_type=LogAction.USER_DEACTIVATED,
        severity=LogSeverity.CRITICAL,
        user_id=str(event.target_user_id),
        actor_id=str(event.actor_id),
        actor_snapshot=event.actor_name,
        entity_type="user",
        entity_id=str(event.target_user_id),
        domain_id="global",
        outcome="FAILURE",
        ctx=event.audit_ctx,
    )


async def on_user_update_skipped(event: UserUpdateSkipped, session: AsyncSession | None) -> None:
    """Records an empty profile update request.

    Args:
        event: The UserUpdateSkipped fact.
        session: Ignored by design; non-success paths use an autonomous session.
    """
    actor_id_str = str(event.actor_id) if event.actor_id is not None else str(event.user_id)
    await save_failed_event(
        message=f'Update skipped for user ID [{event.user_id}]; update dict was empty.',
        event_type=LogAction.USER_UPDATED,
        severity=LogSeverity.WARNING,
        user_id=str(event.user_id),
        actor_id=actor_id_str,
        entity_type="user",
        entity_id=str(event.user_id),
        domain_id="global",
        outcome="SKIPPED",
        ctx=event.audit_ctx,
        extra_data={'update_dict': {}},
    )


async def on_user_updated(event: UserUpdated, session: AsyncSession | None) -> None:
    """Records a successful profile modification inside the caller's transaction.

    Args:
        event: The UserUpdated fact.
        session: Caller's active transaction for atomic persistence.
    """
    actor_id_str = str(event.actor_id) if event.actor_id is not None else str(event.user_id)
    sanitized_diff = sanitize_audit_payload(dict(event.changes))
    await save_success_event(
        message=f'User profile for ID [{event.user_id}] updated successfully.',
        session=session,
        event_type=LogAction.USER_UPDATED,
        user_id=str(event.user_id),
        actor_id=actor_id_str,
        entity_type="user",
        entity_id=str(event.user_id),
        domain_id="global",
        outcome="SUCCESS",
        changes_payload=sanitized_diff,
        ctx=event.audit_ctx,
        extra_data=sanitized_diff,
    )


async def on_user_deactivated(event: UserDeactivated, session: AsyncSession | None) -> None:
    """Records a successful account deactivation inside the caller's transaction.

    Args:
        event: The UserDeactivated fact.
        session: Caller's active transaction for atomic persistence.
    """
    actor_id_str = str(event.actor_id) if event.actor_id is not None else str(event.user_id)
    changes = {'is_active': {'old': True, 'new': False}}
    await save_success_event(
        message=f'User account deactivated successfully [ID: {event.user_id}].',
        session=session,
        event_type=LogAction.USER_DEACTIVATED,
        user_id=str(event.user_id),
        actor_id=actor_id_str,
        entity_type="user",
        entity_id=str(event.user_id),
        domain_id="global",
        outcome="SUCCESS",
        changes_payload=changes,
        ctx=event.audit_ctx,
        extra_data=changes,
    )


def register_user_listeners(bus: AsyncEventBus) -> None:
    """Subscribes all user-related audit listeners to the event bus.

    Args:
        bus: The application asynchronous event bus instance.
    """
    bus.subscribe(UserNotFound, on_user_not_found)
    bus.subscribe(UserAccessDenied, on_user_access_denied)
    bus.subscribe(UserInactiveTargeted, on_user_inactive_targeted)
    bus.subscribe(UserUpdateSkipped, on_user_update_skipped)
    bus.subscribe(UserUpdated, on_user_updated)
    bus.subscribe(UserDeactivated, on_user_deactivated)
