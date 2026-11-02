from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING

from fastapi import Depends
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.ext.asyncio import AsyncSession

from src.database import SessionDep, get_session
from src.exc import (
    AccessDeniedException,
    PermissionDeniedException,
    InactiveEntityException,
    InvalidCredentialsException,
    TokenStaleException,
)
from src.security import decode_access_token, AuthorizationService
from src.security.authorization import GLOBAL_DOMAIN
from src.settings import settings
from src.share import Roles, Resource, Action
from .repo import RefreshSessionRepository

if TYPE_CHECKING:
    from src.modules.user import User

logger = logging.getLogger(__name__)

_oauth2_scheme = OAuth2PasswordBearer(tokenUrl=f'{settings.api_prefix}/auth/login')


async def get_current_user(
    token: str = Depends(_oauth2_scheme),
    session: SessionDep = None,
) -> User:
    """Extracts and validates the current authenticated user from the JWT token.

    Args:
        token: The JWT bearer token extracted from the Authorization header.
        session: The async database session injected by FastAPI.

    Returns:
        The authenticated User ORM instance.

    Raises:
        InvalidCredentialsException: If the token is invalid or the user does not exist.
        InactiveEntityException: If the user account has been deactivated.
        TokenStaleException: If the token security version does not match the user's current version
            or if the associated session family has been revoked.
    """
    payload = decode_access_token(token=token)
    user_id = payload.user_id

    # Lazy import to break module-level circular dependency
    from src.modules.user import UserRepository

    user_repo = UserRepository(session=session)
    user = await user_repo.get_by_id(user_id)

    if user is None:
        raise InvalidCredentialsException()

    if not user.is_active:
        raise InactiveEntityException(entity='User', identifier=str(user.id))

    if payload.sec_ver != user.security_version:
        raise TokenStaleException()

    if not payload.fid:
        raise InvalidCredentialsException("Token is missing session family binding")

    refresh_repo = RefreshSessionRepository(session=session)
    is_active = await refresh_repo.is_family_active(family_id=payload.fid, user_id=user.id)
    if not is_active:
        raise TokenStaleException()

    return user


async def require_active_user(
    current_user: User = Depends(get_current_user),
) -> User:
    """Ensures that the authenticated user is currently active.

    Args:
        current_user: Authenticated user injected by FastAPI.

    Returns:
        The active User instance.

    Raises:
        InactiveEntityException: If user is inactive.
    """
    if not current_user.is_active:
        raise InactiveEntityException(entity='User', identifier=str(current_user.id))
    return current_user


def require_role(*allowed_roles: Roles) -> Callable[[User], Awaitable[User]]:
    """Dependency factory that enforces Role-Based Access Control (RBAC).

    Args:
        *allowed_roles: One or more authorized Roles required to access the endpoint.

    Returns:
        An async FastAPI dependency callable validating user role.
    """

    async def _role_checker(
        current_user: User = Depends(get_current_user),
    ) -> User:
        if current_user.role not in allowed_roles:
            allowed_names = [role.value for role in allowed_roles]
            raise AccessDeniedException(
                f"Operation requires one of the following roles: {allowed_names}."
            )
        return current_user

    return _role_checker


def require_permission(
    *,
    resource: Resource | str,
    action: Action | str,
    domain: str = GLOBAL_DOMAIN,
) -> Callable[[User], Awaitable[User]]:
    """Dependency factory enforcing a Casbin permission check on the current user.

    Args:
        resource: The protected resource namespace.
        action: The operation requested on the resource.
        domain: The authorization domain (defaults to 'global').

    Returns:
        An async FastAPI dependency returning the authorized User instance.

    Raises:
        AccessDeniedException: If neither the user's role nor specific subject grants permit the action.
    """
    res_val = resource.value if hasattr(resource, 'value') else str(resource)
    act_val = action.value if hasattr(action, 'value') else str(action)

    async def _permission_checker(
        current_user: User = Depends(get_current_user),
    ) -> User:
        allowed = AuthorizationService.is_allowed(
            user_id=current_user.id,
            role=current_user.role.value,
            resource=res_val,
            action=act_val,
            domain=domain,
        )
        if not allowed:
            logger.warning(
                'Permission denied: user_id=%s role=%s resource=%s action=%s domain=%s',
                current_user.id,
                current_user.role.value,
                res_val,
                act_val,
                domain,
            )
            raise AccessDeniedException(
                f"You do not have permission to perform '{act_val}' on '{res_val}'."
            )
        return current_user

    return _permission_checker
