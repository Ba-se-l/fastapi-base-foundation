from fastapi import APIRouter, Depends, status

from src.database import SessionDep
from src.modules.auth.dependencies import get_current_user, require_permission, require_role
from src.settings import settings
from src.share import (
    Action,
    AuditContext,
    PaginatedResponse,
    PaginationMeta,
    PaginationParams,
    Resource,
    Roles,
    get_audit_context,
)
from . import service
from .model import User
from .schemas import UserResponse, UserUpdate

router = APIRouter(prefix=f"{settings.api_prefix}/users", tags=["Users"])


@router.get(
    "/me",
    response_model=UserResponse,
    status_code=status.HTTP_200_OK,
    summary="Get current user profile",
    description="Returns the profile information of the currently authenticated user.",
)
async def get_my_profile(
    current_user: User = Depends(get_current_user),
) -> UserResponse:
    """Returns the authenticated user profile."""
    return UserResponse.model_validate(current_user)


@router.get(
    "",
    response_model=PaginatedResponse[UserResponse],
    status_code=status.HTTP_200_OK,
    summary="List all users",
    description="Returns a paginated list of all registered users with metadata.",
)
async def list_users_endpoint(
    pagination: PaginationParams = Depends(),
    session: SessionDep = None,
    _: User = Depends(require_permission(resource=Resource.USERS, action=Action.READ)),
) -> PaginatedResponse[UserResponse]:
    """Retrieves a paginated list of users."""
    users, total = await service.list_users(
        session=session,
        offset=pagination.offset,
        limit=pagination.page_size,
    )
    return PaginatedResponse(
        data=[UserResponse.model_validate(u) for u in users],
        pagination=PaginationMeta.from_params(
            page=pagination.page,
            page_size=pagination.page_size,
            total=total,
        ),
    )


@router.get(
    "/{user_id}",
    response_model=UserResponse,
    status_code=status.HTTP_200_OK,
    summary="Get user by ID",
    description="Retrieves a user by primary key. Restricted to Admin or the user themselves.",
)
async def get_user_endpoint(
    user_id: int,
    current_user: User = Depends(get_current_user),
    session: SessionDep = None,
    audit_ctx: AuditContext = Depends(get_audit_context)
) -> UserResponse:
    """Retrieves user by ID with authorization check."""
    user = await service.get_user_by_id(
        getter=current_user,
        user_id=user_id,
        session=session,
        audit_ctx=audit_ctx
    )
    return UserResponse.model_validate(user)


@router.patch(
    "/{user_id}",
    response_model=UserResponse,
    status_code=status.HTTP_200_OK,
    summary="Update user profile",
    description="Updates user fields. Role updates are restricted to Admins.",
)
async def update_user_endpoint(
    user_id: int,
    request: UserUpdate,
    current_user: User = Depends(get_current_user),
    session: SessionDep = None,
    audit_ctx: AuditContext = Depends(get_audit_context)
) -> UserResponse:
    """Updates user information with privilege checks."""
    updated_user = await service.update_user(
        updater=current_user,
        user_id=user_id,
        schema=request,
        session=session,
        audit_ctx=audit_ctx
    )
    return UserResponse.model_validate(updated_user)
