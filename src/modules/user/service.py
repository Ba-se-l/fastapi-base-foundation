from sqlalchemy.ext.asyncio import AsyncSession

from src.exc import AccessDeniedException
from src.modules.auth.repo import RefreshSessionRepository
from src.security import AuthorizationService
from src.share import (
    Action,
    AuditContext,
    Resource,
    Roles,
    UserAction,
    event_bus,
    get_extra_dict_for_updates,
)

from .events import (
    UserAccessDenied,
    UserDeactivated,
    UserInactiveTargeted,
    UserNotFound,
    UserUpdated,
    UserUpdateSkipped,
)
from .exc import UserInactiveException, UserNotFoundException
from .model import User
from .repo import UserRepository
from .schemas import UserUpdate


def _has_permission(actor: User, resource: Resource, action: Action) -> bool:
    """Evaluates a Casbin permission for an actor using primitive identity fields.

    Args:
        actor: Authenticated User ORM instance.
        resource: Target Resource enum.
        action: Requested Action enum.

    Returns:
        True if the permission is granted; False otherwise.
    """
    return AuthorizationService.is_allowed(
        user_id=actor.id,
        role=actor.role.value,
        resource=resource.value,
        action=action.value,
    )


async def _get_user_by_id(
    user_id: int,
    session: AsyncSession,
    ctx: AuditContext | None = None,
) -> User:
    """Internal helper to fetch a user entity by ID without permission checks.

    Args:
        user_id: Integer primary key of the target user.
        session: Active async database session.
        ctx: Optional audit context.

    Returns:
        The matched User ORM entity.

    Raises:
        UserNotFoundException: If no user exists with the given ID.
    """
    user_repo = UserRepository(session=session)
    user = await user_repo.get_by_id(user_id)
    if user is None:
        await event_bus.publish(event=UserNotFound(audit_ctx=ctx, user_id=user_id))
        raise UserNotFoundException(identifier=str(user_id))

    return user


async def get_user_by_id(
    getter: User,
    user_id: int,
    session: AsyncSession,
    audit_ctx: AuditContext | None = None,
) -> User:
    """Retrieves a single user with authorization enforcement (Self or Admin only).

    Args:
        getter: The authenticated user requesting the profile.
        user_id: Target user ID to retrieve.
        session: Active async database session.
        audit_ctx: Optional audit context.

    Returns:
        The target User ORM entity.

    Raises:
        AccessDeniedException: If getter lacks permission.
        UserNotFoundException: If user does not exist.
    """
    # Security Rule: Authorize BEFORE querying to prevent User Enumeration attacks
    if getter.id != user_id and not _has_permission(getter, Resource.USERS, Action.READ):
        await event_bus.publish(
            event=UserAccessDenied(
                audit_ctx=audit_ctx,
                actor_id=getter.id,
                actor_name=getter.name,
                target_user_id=user_id,
                action=UserAction.VIEW,
            )
        )
        raise AccessDeniedException('You are not authorized to view this profile.')

    return await _get_user_by_id(user_id=user_id, session=session, ctx=audit_ctx)


async def list_users(
    session: AsyncSession,
    *,
    offset: int = 0,
    limit: int = 20,
) -> tuple[list[User], int]:
    """Retrieves a paginated list of users and the total count.

    Args:
        session: Active async database session.
        offset: Number of records to skip.
        limit: Maximum number of records to retrieve.

    Returns:
        A tuple of (users_list, total_count).
    """
    user_repo = UserRepository(session=session)
    return await user_repo.get_multi(offset=offset, limit=limit)


async def update_user(
    updater: User,
    user_id: int,
    schema: UserUpdate,
    session: AsyncSession,
    audit_ctx: AuditContext | None = None,
) -> User:
    """Updates user profile attributes with strict RBAC checks and state audit trail.

    Args:
        updater: The user performing the modification.
        user_id: Integer primary key of the target user.
        schema: Validated fields to update.
        session: Active async database session.
        audit_ctx: Optional audit context.

    Returns:
        The updated User ORM entity.

    Raises:
        AccessDeniedException: If updater is not Admin and not modifying self, or attempting role escalation.
        UserNotFoundException: If no user exists with the given ID.
        UserInactiveException: If target user account is deactivated.
    """
    # 1. Authorize: Only Admin or Self can modify
    if updater.id != user_id and not _has_permission(updater, Resource.USERS, Action.UPDATE):
        await event_bus.publish(
            event=UserAccessDenied(
                audit_ctx=audit_ctx,
                actor_id=updater.id,
                actor_name=updater.name,
                target_user_id=user_id,
                action=UserAction.MODIFY,
            )
        )
        raise AccessDeniedException('You are not authorized to modify this user.')

    # 2. Authorize: Role escalation restriction
    if schema.role is not None and not _has_permission(updater, Resource.USERS, Action.ASSIGN_ROLE):
        await event_bus.publish(
            event=UserAccessDenied(
                audit_ctx=audit_ctx,
                actor_id=updater.id,
                actor_name=updater.name,
                target_user_id=user_id,
                action=UserAction.CHANGE_ROLE,
            )
        )
        raise AccessDeniedException('Only Administrators can modify user roles.')

    # 3. Retrieve target user
    user = await _get_user_by_id(user_id=user_id, session=session, ctx=audit_ctx)
    user_repo = UserRepository(session=session)

    # 3.5 Verify user is active
    if not user.is_active:
        await event_bus.publish(
            event=UserInactiveTargeted(
                audit_ctx=audit_ctx,
                actor_id=updater.id,
                actor_name=updater.name,
                target_user_id=user_id,
                action=UserAction.MODIFY,
            )
        )
        raise UserInactiveException(identifier=str(user_id))

    # 4. Apply updates with pre-update snapshot
    update_dict = schema.model_dump(exclude_unset=True)
    if update_dict:
        # P11 Governance check: If target is active admin and change deactivates or demotes them
        is_demoting = schema.role is not None and schema.role != Roles.ADMIN and user.role == Roles.ADMIN
        is_deactivating = update_dict.get('is_active') is False and user.is_active is True
        if user.role == Roles.ADMIN and user.is_active and (is_demoting or is_deactivating):
            active_admins = await user_repo.acquire_admin_governance_lock_and_count()
            if active_admins <= 1:
                raise AccessDeniedException('Cannot deactivate or demote the last remaining active administrator.')

        if is_deactivating:
            update_dict['security_version'] = user.security_version + 1
            await RefreshSessionRepository(session=session).revoke_all_for_user(user.id)

        old_state = {k: getattr(user, k, None) for k in update_dict}
        user = await user_repo.update(instance=user, update_dict=update_dict)
        await session.flush()

        await event_bus.publish(
            event=UserUpdated(
                audit_ctx=audit_ctx,
                user_id=user_id,
                actor_id=updater.id,
                changes=get_extra_dict_for_updates(update_dict=update_dict, old_state=old_state),
            ),
            session=session,
        )
        return user

    await event_bus.publish(
        event=UserUpdateSkipped(
            audit_ctx=audit_ctx,
            user_id=user_id,
            actor_id=updater.id,
        )
    )
    return user


async def deactivate_user(
    user_id: int,
    session: AsyncSession,
    audit_ctx: AuditContext | None = None,
    actor_id: str | int | None = None,
) -> User:
    """Deactivates a user account (soft deactivation).

    Args:
        user_id: Integer primary key of the user to deactivate.
        session: Active async database session.
        audit_ctx: Optional audit context.
        actor_id: Optional actor identifier performing the deactivation.

    Returns:
        The deactivated User entity.

    Raises:
        AccessDeniedException: If target is the last active administrator.
        UserNotFoundException: If the user does not exist.
    """
    user = await _get_user_by_id(user_id=user_id, session=session, ctx=audit_ctx)
    user_repo = UserRepository(session=session)

    # P11 Governance check: block deactivating last admin
    if user.role == Roles.ADMIN and user.is_active:
        active_admins = await user_repo.acquire_admin_governance_lock_and_count()
        if active_admins <= 1:
            raise AccessDeniedException('Cannot deactivate the last remaining active administrator.')

    user = await user_repo.update(
        instance=user,
        update_dict={'is_active': False, 'security_version': user.security_version + 1},
    )
    await RefreshSessionRepository(session=session).revoke_all_for_user(user.id)
    await session.flush()

    await event_bus.publish(
        event=UserDeactivated(
            audit_ctx=audit_ctx,
            user_id=user_id,
            actor_id=actor_id,
        ),
        session=session,
    )

    return user
