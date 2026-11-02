from fastapi import APIRouter, Cookie, Depends, Request, Response, status
from sqlalchemy.ext.asyncio import AsyncSession

from src.database import SessionDep
from src.exc import AccessDeniedException, InvalidCredentialsException
from src.modules.user import User, UserResponse
from src.settings import Environment, settings
from src.share import AuditContext, MessageResponse, RateLimiter, get_audit_context
from . import service
from .dependencies import get_current_user
from .schemas import ChangePasswordRequest, LoginRequest, RefreshRequest, RegisterRequest, TokenResponse

router = APIRouter(prefix=f"{settings.api_prefix}/auth", tags=["Authentication"])

auth_rate_limiter = RateLimiter()


def set_refresh_cookie(response: Response, token: str) -> None:
    """Sets the refresh token into an HttpOnly, SameSite-protected cookie."""
    secure = settings.refresh_cookie_secure
    if secure is None:
        secure = settings.environment in (Environment.PRO, Environment.PROD, Environment.STAGING)
    response.set_cookie(
        key=settings.refresh_cookie_name,
        value=token,
        httponly=True,
        secure=secure,
        samesite=settings.refresh_cookie_samesite,
        path=settings.refresh_cookie_path,
        max_age=settings.refresh_token_expires_days * 86400,
    )


def clear_refresh_cookie(response: Response) -> None:
    """Clears the refresh token cookie."""
    secure = settings.refresh_cookie_secure
    if secure is None:
        secure = settings.environment in (Environment.PRO, Environment.PROD, Environment.STAGING)
    response.delete_cookie(
        key=settings.refresh_cookie_name,
        path=settings.refresh_cookie_path,
        httponly=True,
        secure=secure,
        samesite=settings.refresh_cookie_samesite,
    )


def verify_cookie_csrf_origin(request: Request) -> None:
    """Guards cookie-authenticated requests against cross-site request forgery."""
    if "*" in settings.allowed_origins:
        return
    origin = request.headers.get("origin") or request.headers.get("referer")
    if origin:
        origin_clean = origin.rstrip("/")
        allowed = [o.rstrip("/") for o in settings.allowed_origins]
        if not any(origin_clean.startswith(a) for a in allowed):
            raise AccessDeniedException("CSRF check failed: Origin or Referer header untrusted.")


def resolve_refresh_token(
    body: RefreshRequest | None,
    cookie_token: str | None,
    request: Request,
) -> str:
    """Resolves refresh token honoring priority, transport modes, and CSRF protection."""
    body_token = body.refresh_token if body and body.refresh_token else None

    # Priority 1: Explicit JSON body token (favored in dual mode for automated API callers & test suites)
    if body_token:
        if settings.auth_transport_mode == "cookie":
            raise InvalidCredentialsException("JSON refresh token disabled in cookie-only mode.")
        return body_token

    # Priority 2: Cookie token fallback
    if cookie_token:
        if settings.auth_transport_mode == "json":
            raise InvalidCredentialsException("Cookie refresh token disabled in json-only mode.")
        verify_cookie_csrf_origin(request)
        return cookie_token

    # Neither provided
    raise InvalidCredentialsException("Refresh token is required via JSON payload or cookie.")


@router.post(
    "/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new user",
    description="Creates a new user account with a hashed password.",
    dependencies=[Depends(auth_rate_limiter)],
)
async def register(
    request: RegisterRequest,
    session: SessionDep,
    audit_ctx: AuditContext = Depends(get_audit_context),
) -> UserResponse:
    """Registers a new user and returns the user profile."""
    if not settings.allow_public_registration:
        raise AccessDeniedException("Public user registration is disabled.")
    user = await service.register_user(schema=request, session=session, audit_ctx=audit_ctx)
    return UserResponse.model_validate(user)


@router.post(
    "/login",
    response_model=TokenResponse,
    status_code=status.HTTP_200_OK,
    summary="Login and get token pair",
    description="Authenticates user credentials and returns JWT access + refresh tokens.",
    dependencies=[Depends(auth_rate_limiter)],
)
async def login(
    request: LoginRequest,
    response: Response,
    session: SessionDep,
    audit_ctx: AuditContext = Depends(get_audit_context),
) -> TokenResponse:
    """Authenticates a user and issues a dual-token pair."""
    tokens = await service.login_user(schema=request, session=session, audit_ctx=audit_ctx)
    if settings.auth_transport_mode in ("dual", "cookie"):
        set_refresh_cookie(response, tokens.refresh_token)
    return tokens


@router.post(
    "/refresh",
    response_model=TokenResponse,
    status_code=status.HTTP_200_OK,
    summary="Refresh token pair",
    description=(
        "Exchanges a valid refresh token for a new access + refresh token pair. "
        "The old refresh token is revoked (rotation)."
    ),
    dependencies=[Depends(auth_rate_limiter)],
)
async def refresh(
    http_request: Request,
    response: Response,
    session: SessionDep,
    request: RefreshRequest | None = None,
    cookie_token: str | None = Cookie(default=None, alias=settings.refresh_cookie_name),
    audit_ctx: AuditContext = Depends(get_audit_context),
) -> TokenResponse:
    """Rotates refresh token and issues a fresh token pair."""
    raw_token = resolve_refresh_token(body=request, cookie_token=cookie_token, request=http_request)
    tokens = await service.refresh_token(
        schema=RefreshRequest(refresh_token=raw_token),
        session=session,
        audit_ctx=audit_ctx,
    )
    if settings.auth_transport_mode in ("dual", "cookie"):
        set_refresh_cookie(response, tokens.refresh_token)
    return tokens


@router.post(
    "/logout",
    response_model=MessageResponse,
    status_code=status.HTTP_200_OK,
    summary="Logout current device",
    dependencies=[Depends(auth_rate_limiter)],
)
async def logout_endpoint(
    http_request: Request,
    response: Response,
    session: SessionDep,
    request: RefreshRequest | None = None,
    cookie_token: str | None = Cookie(default=None, alias=settings.refresh_cookie_name),
    audit_ctx: AuditContext = Depends(get_audit_context),
) -> MessageResponse:
    """Revokes the provided refresh token (single device logout)."""
    raw_token = resolve_refresh_token(body=request, cookie_token=cookie_token, request=http_request)
    await service.logout(refresh_token_str=raw_token, session=session, audit_ctx=audit_ctx)
    clear_refresh_cookie(response)
    return MessageResponse(message="Logged out successfully.")


@router.post(
    "/logout-all",
    response_model=MessageResponse,
    status_code=status.HTTP_200_OK,
    summary="Logout all devices",
    dependencies=[Depends(auth_rate_limiter)],
)
async def logout_all_endpoint(
    response: Response,
    current_user: User = Depends(get_current_user),
    session: SessionDep = None,
    audit_ctx: AuditContext = Depends(get_audit_context),
) -> MessageResponse:
    """Revokes all refresh sessions for the current user."""
    await service.logout_all(user=current_user, session=session, audit_ctx=audit_ctx)
    clear_refresh_cookie(response)
    return MessageResponse(message="All sessions revoked successfully.")


@router.post(
    "/change-password",
    response_model=MessageResponse,
    status_code=status.HTTP_200_OK,
    summary="Change account password",
    description="Updates user password, increments security version, and revokes all active sessions.",
    dependencies=[Depends(auth_rate_limiter)],
)
async def change_password_endpoint(
    request: ChangePasswordRequest,
    response: Response,
    current_user: User = Depends(get_current_user),
    session: SessionDep = None,
    audit_ctx: AuditContext = Depends(get_audit_context),
) -> MessageResponse:
    """Updates user credentials and invalidates all existing sessions."""
    await service.change_password(
        user=current_user,
        schema=request,
        session=session,
        audit_ctx=audit_ctx,
    )
    clear_refresh_cookie(response)
    return MessageResponse(message="Password changed successfully. All active sessions have been terminated.")
