import asyncio
import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from src.exc import (
    InvalidCredentialsException,
    TokenRevokedException,
)
from src.modules.user import (
    User,
    UserAlreadyExistsException,
    UserInactiveException,
    UserNotFoundException,
    UserRepository,
)
from src.modules.user.events import UserNotFound
from src.security import (
    SECURITY_PASSWORD_HASH,
    create_access_token,
    create_refresh_token,
    decode_refresh_token,
    hash_password,
    hash_password_async,
    verify_dummy_password_async,
    verify_password,
    verify_password_async,
    verify_and_update,
    verify_and_update_password_async,
)
from src.settings import settings
from src.share import AuditContext, event_bus

from .events import (
    AuthAction,
    AuthAllSessionsRevoked,
    AuthEmailAlreadyRegistered,
    AuthEmailNotFound,
    AuthInactiveUserRejected,
    AuthInvalidPassword,
    AuthLoggedIn,
    AuthLoggedOut,
    AuthRefreshSessionExpired,
    AuthRefreshSessionNotFound,
    AuthRegistrationFailed,
    AuthTokenPairIssued,
    AuthTokenReplayDetected,
    AuthTokenRotated,
    AuthUserRegistered,
    AuthPasswordChanged
)
from .model import RefreshSession
from .repo import RefreshSessionRepository
from .schemas import ChangePasswordRequest, LoginRequest, RefreshRequest, RegisterRequest, TokenResponse


def _is_duplicate_email_integrity_error(exc: IntegrityError) -> bool:
    """Determines whether an IntegrityError was caused by a duplicate user email constraint.

    Args:
        exc: The caught SQLAlchemy IntegrityError instance.

    Returns:
        True if the error message/constraint indicates a unique email violation.
    """
    raw_msg = str(getattr(exc, "orig", exc)).lower()
    return any(marker in raw_msg for marker in ("email", "uq_users_email", "ix_users_email", "unique"))


async def _issue_token_pair(
    user: User,
    session: AsyncSession,
    device_info: str | None = None,
    ctx: AuditContext | None = None,
    family_id: str | None = None,
    parent_jti: str | None = None,
) -> TokenResponse:
    """Creates an access + refresh token pair and persists the refresh session.

    Args:
        user: The authenticated user.
        session: The active database session.
        device_info: Optional client device identifier.
        ctx: Optional audit context.
        family_id: Session lineage family identifier. Generated fresh if None.
        parent_jti: JTI of the predecessor token in the family tree.

    Returns:
        A TokenResponse containing both tokens.
    """
    if family_id is None:
        family_id = uuid.uuid4().hex

    # Step 1: Generate access token with family claim fid
    access_token = create_access_token(
        user_id=user.id,
        security_version=user.security_version,
        family_id=family_id,
    )

    # Step 2: Generate refresh token + JTI with family claim fid
    refresh_token, jti = create_refresh_token(
        user_id=user.id,
        security_version=user.security_version,
        family_id=family_id,
    )

    # Step 3: Persist refresh session to database
    refresh_repo = RefreshSessionRepository(session=session)
    refresh_session = RefreshSession(
        user_id=user.id,
        refresh_token_jti=jti,
        device_info=device_info,
        is_revoked=False,
        expires_at=datetime.now(timezone.utc) + timedelta(days=settings.refresh_token_expires_days),
        family_id=family_id,
        parent_jti=parent_jti,
    )
    await refresh_repo.create(instance=refresh_session)
    await session.flush()

    await event_bus.publish(
        event=AuthTokenPairIssued(
            audit_ctx=ctx,
            user_id=user.id,
        ),
        session=session,
    )

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
    )


async def register_user(
    schema: RegisterRequest,
    session: AsyncSession,
    audit_ctx: AuditContext | None = None,
) -> User:
    """Registers a new user account.

    Orchestration steps:
        1. Check if the email is already taken.
        2. Hash the plain-text password asynchronously.
        3. Create the ``User`` ORM instance.
        4. Persist via ``UserRepository.create``.

    Args:
        schema: The validated registration request.
        session: The active database session.
        audit_ctx: Optional audit context.

    Returns:
        The newly created ``User`` ORM instance.

    Raises:
        UserAlreadyExistsException: If the email is already registered.
    """
    user_repo = UserRepository(session=session)

    # Step 1: Check email uniqueness
    is_user_exist, user = await user_repo.is_exist_by_email(email=schema.email, return_orm=True)
    if is_user_exist and user is not None:
        await event_bus.publish(
            event=AuthEmailAlreadyRegistered(
                audit_ctx=audit_ctx,
                user_id=user.id,
                email=user.email,
                name=schema.name,
            )
        )
        raise UserAlreadyExistsException(field='email', value=schema.email)

    # Step 2: Hash the password asynchronously
    hashed_password = await hash_password_async(password=schema.password)

    # Step 3: Build the ORM model
    instance = User(
        name=schema.name,
        email=schema.email,
        hashed_password=hashed_password,
    )

    # Step 4: Persist with IntegrityError safety net
    try:
        user = await user_repo.create(instance=instance)
        await session.flush()
    except IntegrityError as ie:
        await event_bus.publish(
            event=AuthRegistrationFailed(
                audit_ctx=audit_ctx,
                email=schema.email,
                error="integrity_constraint_violation",
            ),
            session=session,
        )
        if _is_duplicate_email_integrity_error(ie):
            raise UserAlreadyExistsException(field='email', value=schema.email) from ie
        raise

    await event_bus.publish(
        event=AuthUserRegistered(
            audit_ctx=audit_ctx,
            user_id=user.id,
            email=user.email,
            name=user.name,
        ),
        session=session,
    )

    return user


async def login_user(
    schema: LoginRequest,
    session: AsyncSession,
    audit_ctx: AuditContext | None = None,
) -> TokenResponse:
    """Authenticates a user and issues a JWT access token.

    Orchestration steps:
        1. Fetch the user by email.
        2. Verify the password hash.
        3. Check that the user account is active.
        4. Generate and return the JWT access token.

    Args:
        schema: The validated login request containing email and password.
        session: The active database session.
        audit_ctx: Optional audit context.

    Returns:
        A ``TokenResponse`` containing the JWT ``access_token``.

    Raises:
        InvalidCredentialsException: If the email or password is wrong.
        UserInactiveException: If the user account is deactivated.
    """
    user_repo = UserRepository(session=session)

    # Step 1: Fetch user by email
    user = await user_repo.get_by_email(schema.email)
    if user is None:
        await verify_dummy_password_async(schema.password)

        await event_bus.publish(
            event=AuthEmailNotFound(
                audit_ctx=audit_ctx,
                email=schema.email,
            )
        )
        raise InvalidCredentialsException()

    # Step 2: Verify the password
    is_hashed_match, new_hash = await verify_and_update_password_async(
        plain_password=schema.password,
        hashed_password=user.hashed_password,
    )
    if not is_hashed_match:
        await event_bus.publish(
            event=AuthInvalidPassword(
                audit_ctx=audit_ctx,
                user_id=user.id,
                email=user.email,
            )
        )
        raise InvalidCredentialsException()

    if new_hash:
        user.hashed_password = new_hash
        await session.flush()

    # Step 3: Check active status
    if not user.is_active:
        await event_bus.publish(
            event=AuthInactiveUserRejected(
                audit_ctx=audit_ctx,
                user_id=user.id,
                email=user.email,
                action=AuthAction.LOGIN,
            )
        )
        raise UserInactiveException(identifier=str(user.id))

    await event_bus.publish(
        event=AuthLoggedIn(
            audit_ctx=audit_ctx,
            user_id=user.id,
        ),
        session=session,
    )

    # Step 4: Issue dual token pair
    return await _issue_token_pair(
        user=user,
        session=session,
        device_info=audit_ctx.user_agent if audit_ctx else None,
        ctx=audit_ctx,
    )


async def logout(
    refresh_token_str: str,
    session: AsyncSession,
    audit_ctx: AuditContext | None = None,
) -> None:
    """Revokes a single refresh session and its family (logout current device).

    Args:
        refresh_token_str: The refresh token to revoke.
        session: The active database session.
        audit_ctx: Optional audit context.

    Raises:
        InvalidCredentialsException: If the token is malformed.
    """
    payload = decode_refresh_token(token=refresh_token_str)
    jti = payload.jti
    token_user_id = payload.user_id

    refresh_repo = RefreshSessionRepository(session=session)
    existing_session = await refresh_repo.get_by_jti(jti=jti)
    if existing_session is None:
        raise TokenRevokedException()
    if existing_session.user_id != token_user_id:
        raise InvalidCredentialsException()

    # Always revoke the whole family, even if existing_session was already revoked/rotated (P02)
    await refresh_repo.revoke_family(
        family_id=existing_session.family_id,
        user_id=existing_session.user_id,
    )

    await event_bus.publish(
        event=AuthLoggedOut(
            audit_ctx=audit_ctx,
            user_id=token_user_id,
        ),
        session=session,
    )


async def logout_all(
    user: User | int,
    session: AsyncSession,
    audit_ctx: AuditContext | None = None,
) -> int:
    """Revokes all refresh sessions and increments security version (logout all devices).

    Args:
        user: The authenticated User instance or user integer ID.
        session: The active database session.
        audit_ctx: Optional audit context.

    Returns:
        The number of revoked session records.
    """
    if isinstance(user, int):
        user_repo = UserRepository(session=session)
        user_obj = await user_repo.get_by_id(user)
        if user_obj is None:
            raise UserNotFoundException(identifier=str(user))
    else:
        user_obj = user

    refresh_repo = RefreshSessionRepository(session=session)
    revoked_count = await refresh_repo.revoke_all_for_user(user_id=user_obj.id)

    user_obj.security_version += 1
    session.add(user_obj)
    await session.flush()

    await event_bus.publish(
        event=AuthAllSessionsRevoked(
            audit_ctx=audit_ctx,
            user_id=user_obj.id,
        ),
        session=session,
    )
    return revoked_count


async def refresh_token(
    schema: RefreshRequest,
    session: AsyncSession,
    audit_ctx: AuditContext | None = None,
) -> TokenResponse:
    """Exchanges a valid refresh token for a new token pair (rotation).

    Rotation Protocol:
        1. Decode the refresh token to extract the JTI.
        2. Look up the refresh session in the database.
        3. Verify the session exists, is not revoked, and not expired.
        4. Revoke the old refresh session.
        5. Issue a fresh token pair.

    Args:
        schema: The request containing the current refresh token.
        session: The active database session.
        audit_ctx: Optional audit context.

    Returns:
        A new TokenResponse with fresh access + refresh tokens.

    Raises:
        InvalidCredentialsException: If the token is malformed or expired.
        TokenRevokedException: If the session is revoked or not found.
        UserNotFoundException: If the subject user does not exist.
        UserInactiveException: If the subject user is deactivated.
    """
    # Step 1: Decode the refresh token
    payload = decode_refresh_token(token=schema.refresh_token)
    user_id = payload.user_id
    jti = payload.jti

    # Step 2: Look up the session and user
    user_repo = UserRepository(session=session)
    refresh_repo = RefreshSessionRepository(session=session)
    existing_session = await refresh_repo.get_by_jti(jti=jti)

    # Step 2.5: Validate user is active
    user = await user_repo.get_by_id(id=user_id)
    if not user:
        await event_bus.publish(
            event=UserNotFound(
                audit_ctx=audit_ctx,
                user_id=user_id,
            )
        )
        raise UserNotFoundException(identifier=str(user_id))

    if not user.is_active:
        await event_bus.publish(
            event=AuthInactiveUserRejected(
                audit_ctx=audit_ctx,
                user_id=user_id,
                email=user.email,
                action=AuthAction.REFRESH,
            )
        )
        raise UserInactiveException(identifier=str(user_id))

    # Step 3: Validate the session
    if existing_session is None:
        await event_bus.publish(
            event=AuthRefreshSessionNotFound(
                audit_ctx=audit_ctx,
                user_id=user_id,
            )
        )
        raise TokenRevokedException()

    if existing_session.user_id != user_id:
        raise TokenRevokedException()

    if existing_session.family_id != payload.fid:
        raise TokenRevokedException()

    if payload.sec_ver != user.security_version:
        raise TokenRevokedException()

    expires_at = existing_session.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)

    if expires_at < datetime.now(timezone.utc):
        await event_bus.publish(
            event=AuthRefreshSessionExpired(
                audit_ctx=audit_ctx,
                user_id=user_id,
                session_id=existing_session.id,
            )
        )
        raise TokenRevokedException()

    # Step 4: Atomic CAS revocation (prevents concurrent double-successor race condition)
    revoked = await refresh_repo.revoke_if_active(jti=jti)
    if not revoked:
        # Session was already revoked concurrently or reused — potential token theft!
        # Targeted Family Revocation (Smart Device Isolation) strictly scoped to user
        await refresh_repo.revoke_family(
            family_id=existing_session.family_id,
            user_id=existing_session.user_id,
        )
        await event_bus.publish(
            event=AuthTokenReplayDetected(
                audit_ctx=audit_ctx,
                user_id=user_id,
                session_id=existing_session.id,
            ),
            session=session,
        )
        # G1 GUARDRAIL: Commit immediately before raising exception
        # to persist family revocation before get_session() triggers rollback!
        await session.commit()
        raise TokenRevokedException()

    await event_bus.publish(
        event=AuthTokenRotated(
            audit_ctx=audit_ctx,
            user_id=user_id,
        ),
        session=session,
    )

    # Step 5: Issue a fresh pair inheriting the SAME family_id
    return await _issue_token_pair(
        user=user,
        session=session,
        device_info=audit_ctx.user_agent if audit_ctx else None,
        ctx=audit_ctx,
        family_id=existing_session.family_id,
        parent_jti=existing_session.refresh_token_jti,
    )


async def change_password(
    user: User,
    schema: ChangePasswordRequest,
    session: AsyncSession,
    audit_ctx: AuditContext | None = None,
) -> bool:
    """Updates user password, increments security version, and revokes all refresh sessions.

    Args:
        user: The authenticated user requesting the password change.
        schema: Validated change-password request schema.
        session: Active async database session.
        audit_ctx: Optional request audit telemetry.

    Returns:
        True upon successful credential rotation.

    Raises:
        InvalidCredentialsException: If the current password verification fails.
    """
    session_repo = RefreshSessionRepository(session=session)

    # Step 1: Verify old password
    is_password_valid = await verify_password_async(
        plain_password=schema.old_password,
        hashed_password=user.hashed_password,
    )
    if not is_password_valid:
        raise InvalidCredentialsException()

    # Step 2: Hash and set new password, increment security version
    user.hashed_password = await hash_password_async(schema.new_password)
    user.security_version += 1
    await session.flush()

    # Step 3: Revoke all refresh sessions
    await session_repo.revoke_all_for_user(user_id=user.id)

    # Step 4: Broadcast domain event for audit logging
    await event_bus.publish(
        event=AuthPasswordChanged(
            audit_ctx=audit_ctx,
            user_id=user.id,
            email=user.email,
        ),
        session=session,
    )

    return True
