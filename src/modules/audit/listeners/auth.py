from sqlalchemy.ext.asyncio import AsyncSession

from src.modules.audit.enum import LogAction
from src.modules.audit.schemas import LogSeverity
from src.modules.audit.service import save_failed_event, save_success_event, scrub_error_reason
from src.modules.auth.events import ( 
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
    AuthPasswordChanged,
)

from src.share.event_bus import AsyncEventBus

__all__ = (
    'on_auth_all_sessions_revoked',
    'on_auth_email_already_registered',
    'on_auth_email_not_found',
    'on_auth_inactive_user_rejected',
    'on_auth_invalid_password',
    'on_auth_logged_in',
    'on_auth_logged_out',
    'on_auth_refresh_session_expired',
    'on_auth_refresh_session_not_found',
    'on_auth_registration_failed',
    'on_auth_token_pair_issued',
    'on_auth_token_replay_detected',
    'on_auth_token_rotated',
    'on_auth_user_registered',
    'on_auth_password_changed',
    'register_auth_listeners',
)

# ——— Failure listeners: autonomous session (evidence survives business rollback) ———


async def on_auth_email_already_registered(
    event: AuthEmailAlreadyRegistered,
    session: AsyncSession | None,
) -> None:
    """Records a collision during registration attempt.

    Args:
        event: The AuthEmailAlreadyRegistered fact.
        session: Ignored; failure audit records use an autonomous session.
    """
    await save_failed_event(
        message=f'User creation failed: email [{event.email}] already exists.',
        event_type=LogAction.USER_REGISTERED,
        severity=LogSeverity.ERROR,
        user_id=str(event.user_id),
        actor_id=str(event.user_id),
        entity_type="user",
        entity_id=str(event.user_id),
        domain_id="global",
        outcome="FAILURE",
        ctx=event.audit_ctx,
        extra_data={'email': event.email, 'name': event.name},
    )


async def on_auth_registration_failed(
    event: AuthRegistrationFailed,
    session: AsyncSession | None,
) -> None:
    """Records an unhandled integrity or persistence failure during registration.

    Args:
        event: The AuthRegistrationFailed fact.
        session: Ignored; failure audit records use an autonomous session.
    """
    await save_failed_event(
        message='User creation failed due to duplicate entry or constraint error.',
        event_type=LogAction.USER_REGISTERED,
        severity=LogSeverity.CRITICAL,
        entity_type="user",
        domain_id="global",
        outcome="FAILURE",
        ctx=event.audit_ctx,
        extra_data={'email': event.email, 'error': scrub_error_reason(event.error)},
    )


async def on_auth_email_not_found(
    event: AuthEmailNotFound,
    session: AsyncSession | None,
) -> None:
    """Records a login attempt with an unrecognized email address.

    Args:
        event: The AuthEmailNotFound fact.
        session: Ignored; failure audit records use an autonomous session.
    """
    await save_failed_event(
        message=f'User login failed: email [{event.email}] not found.',
        event_type=LogAction.AUTH_LOGIN_FAILED,
        severity=LogSeverity.ERROR,
        user_id=None,
        actor_id=None,
        entity_type="user",
        domain_id="global",
        outcome="FAILURE",
        ctx=event.audit_ctx,
        extra_data={'reason': 'EMAIL_NOT_FOUND', 'email': event.email},
    )


async def on_auth_invalid_password(
    event: AuthInvalidPassword,
    session: AsyncSession | None,
) -> None:
    """Records a failed credential check on an existing user account.

    Args:
        event: The AuthInvalidPassword fact.
        session: Ignored; failure audit records use an autonomous session.
    """
    await save_failed_event(
        message=f'User login failed: invalid password for [{event.email}].',
        event_type=LogAction.AUTH_LOGIN_FAILED,
        severity=LogSeverity.ERROR,
        user_id=str(event.user_id),
        actor_id=str(event.user_id),
        entity_type="user",
        entity_id=str(event.user_id),
        domain_id="global",
        outcome="FAILURE",
        ctx=event.audit_ctx,
        extra_data={'reason': 'INVALID_PASSWORD', 'email': event.email},
    )


async def on_auth_inactive_user_rejected(
    event: AuthInactiveUserRejected,
    session: AsyncSession | None,
) -> None:
    """Records an authentication or token refresh attempt on a deactivated user.

    Args:
        event: The AuthInactiveUserRejected fact.
        session: Ignored; failure audit records use an autonomous session.
    """
    await save_failed_event(
        message=f'User {event.action.value} failed: account for [ID: {event.user_id} | Email: {event.email}] is deactivated.',
        event_type=LogAction.AUTH_LOGIN_FAILED,
        severity=LogSeverity.CRITICAL,
        user_id=str(event.user_id),
        actor_id=str(event.user_id),
        entity_type="user",
        entity_id=str(event.user_id),
        domain_id="global",
        outcome="FAILURE",
        ctx=event.audit_ctx,
        extra_data={
            'reason': 'ACCOUNT_DEACTIVATED',
            'user_id': event.user_id,
            'email': event.email,
        },
    )


async def on_auth_refresh_session_not_found(
    event: AuthRefreshSessionNotFound,
    session: AsyncSession | None,
) -> None:
    """Records a token renewal attempt using an unknown session identifier.

    Args:
        event: The AuthRefreshSessionNotFound fact.
        session: Ignored; failure audit records use an autonomous session.
    """
    await save_failed_event(
        message='Refresh token session not found.',
        event_type=LogAction.AUTH_TOKEN_REVOKED,
        severity=LogSeverity.ERROR,
        user_id=str(event.user_id),
        actor_id=str(event.user_id),
        entity_type="refresh_session",
        domain_id="global",
        outcome="FAILURE",
        ctx=event.audit_ctx,
        extra_data={'reason': 'SESSION_NOT_FOUND'},
    )


async def on_auth_refresh_session_expired(
    event: AuthRefreshSessionExpired,
    session: AsyncSession | None,
) -> None:
    """Records an attempt to use an expired refresh token.

    Args:
        event: The AuthRefreshSessionExpired fact.
        session: Ignored; failure audit records use an autonomous session.
    """
    await save_failed_event(
        message=f'Refresh token session [{event.session_id}] expired.',
        event_type=LogAction.AUTH_TOKEN_REVOKED,
        severity=LogSeverity.ERROR,
        user_id=str(event.user_id),
        actor_id=str(event.user_id),
        entity_type="refresh_session",
        entity_id=str(event.session_id),
        domain_id="global",
        outcome="FAILURE",
        ctx=event.audit_ctx,
        extra_data={'session_id': event.session_id, 'reason': 'SESSION_EXPIRED'},
    )


async def on_auth_token_replay_detected(
    event: AuthTokenReplayDetected,
    session: AsyncSession | None,
) -> None:
    """Records a replay of an already-revoked refresh token (potential theft).

    Args:
        event: The AuthTokenReplayDetected fact.
        session: Ignored; failure audit records use an autonomous session.
    """
    await save_failed_event(
        message=f'Revoked refresh token re-use detected for user [{event.user_id}] (possible token theft).',
        event_type=LogAction.AUTH_TOKEN_REVOKED,
        severity=LogSeverity.CRITICAL,
        user_id=str(event.user_id),
        actor_id=str(event.user_id),
        entity_type="refresh_session",
        entity_id=str(event.session_id),
        domain_id="global",
        outcome="CRITICAL",
        ctx=event.audit_ctx,
        extra_data={
            'session_id': event.session_id,
            'reason': 'TOKEN_REPLAY_ATTACK',
        },
    )


# ——— Success listeners: SAME transaction (atomic with business state change) ———


async def on_auth_user_registered(
    event: AuthUserRegistered,
    session: AsyncSession | None,
) -> None:
    """Records a successful registration inside the caller's transaction.

    Args:
        event: The AuthUserRegistered fact.
        session: Caller's active transaction for atomic persistence.
    """
    await save_success_event(
        message=f'User with ID [{event.user_id}] registered successfully.',
        session=session,
        event_type=LogAction.USER_REGISTERED,
        user_id=str(event.user_id),
        actor_id=str(event.user_id),
        entity_type="user",
        entity_id=str(event.user_id),
        domain_id="global",
        outcome="SUCCESS",
        ctx=event.audit_ctx,
        extra_data={'email': event.email, 'name': event.name},
    )


async def on_auth_logged_in(
    event: AuthLoggedIn,
    session: AsyncSession | None,
) -> None:
    """Records a successful user login inside the caller's transaction.

    Args:
        event: The AuthLoggedIn fact.
        session: Caller's active transaction for atomic persistence.
    """
    await save_success_event(
        message=f'User with ID [{event.user_id}] authenticated successfully.',
        session=session,
        event_type=LogAction.AUTH_LOGIN_SUCCESS,
        user_id=str(event.user_id),
        actor_id=str(event.user_id),
        entity_type="user",
        entity_id=str(event.user_id),
        domain_id="global",
        outcome="SUCCESS",
        ctx=event.audit_ctx,
    )


async def on_auth_token_pair_issued(
    event: AuthTokenPairIssued,
    session: AsyncSession | None,
) -> None:
    """Records token pair issuance inside the caller's transaction.

    Args:
        event: The AuthTokenPairIssued fact.
        session: Caller's active transaction for atomic persistence.
    """
    await save_success_event(
        message='Access & refresh token pair generated successfully.',
        session=session,
        event_type=LogAction.CUSTOM,
        user_id=str(event.user_id),
        actor_id=str(event.user_id),
        entity_type="refresh_session",
        domain_id="global",
        outcome="SUCCESS",
        ctx=event.audit_ctx,
    )


async def on_auth_token_rotated(
    event: AuthTokenRotated,
    session: AsyncSession | None,
) -> None:
    """Records token rotation inside the caller's transaction.

    Args:
        event: The AuthTokenRotated fact.
        session: Caller's active transaction for atomic persistence.
    """
    await save_success_event(
        message='Token pair refreshed and rotated successfully.',
        session=session,
        event_type=LogAction.AUTH_TOKEN_ROTATED,
        user_id=str(event.user_id),
        actor_id=str(event.user_id),
        entity_type="refresh_session",
        domain_id="global",
        outcome="SUCCESS",
        ctx=event.audit_ctx,
    )


async def on_auth_logged_out(
    event: AuthLoggedOut,
    session: AsyncSession | None,
) -> None:
    """Records a single session revocation inside the caller's transaction.

    Args:
        event: The AuthLoggedOut fact.
        session: Caller's active transaction for atomic persistence.
    """
    await save_success_event(
        message=f'User with ID [{event.user_id}] logged out successfully.',
        session=session,
        event_type=LogAction.AUTH_LOGOUT,
        user_id=str(event.user_id),
        actor_id=str(event.user_id),
        entity_type="refresh_session",
        domain_id="global",
        outcome="SUCCESS",
        ctx=event.audit_ctx,
    )


async def on_auth_all_sessions_revoked(
    event: AuthAllSessionsRevoked,
    session: AsyncSession | None,
) -> None:
    """Records a full session revocation across all devices inside the caller's transaction.

    Args:
        event: The AuthAllSessionsRevoked fact.
        session: Caller's active transaction for atomic persistence.
    """
    await save_success_event(
        message=f'Revoked all sessions for user ID [{event.user_id}] successfully.',
        session=session,
        event_type=LogAction.AUTH_TOKEN_REVOKED,
        user_id=str(event.user_id),
        actor_id=str(event.user_id),
        entity_type="refresh_session",
        domain_id="global",
        outcome="SUCCESS",
        ctx=event.audit_ctx,
    )


async def on_auth_password_changed(
    event: AuthPasswordChanged,
    session: AsyncSession | None,
) -> None:
    """Records a successful password change inside the caller's transaction.

    Args:
        event: The AuthPasswordChanged fact.
        session: Caller's active transaction for atomic persistence.
    """
    await save_success_event(
        message=f"User [ID: {event.user_id} | Email: {event.email}] changed password successfully.",
        session=session,
        event_type=LogAction.AUTH_PASSWORD_CHANGED,
        user_id=str(event.user_id),
        actor_id=str(event.user_id),
        entity_type="user",
        entity_id=str(event.user_id),
        domain_id="global",
        outcome="SUCCESS",
        ctx=event.audit_ctx,
    )


def register_auth_listeners(bus: AsyncEventBus) -> None:
    """Subscribes all authentication-related audit listeners to the event bus.

    Args:
        bus: The application asynchronous event bus instance.
    """
    bus.subscribe(AuthEmailAlreadyRegistered, on_auth_email_already_registered)
    bus.subscribe(AuthRegistrationFailed, on_auth_registration_failed)
    bus.subscribe(AuthEmailNotFound, on_auth_email_not_found)
    bus.subscribe(AuthInvalidPassword, on_auth_invalid_password)
    bus.subscribe(AuthInactiveUserRejected, on_auth_inactive_user_rejected)
    bus.subscribe(AuthRefreshSessionNotFound, on_auth_refresh_session_not_found)
    bus.subscribe(AuthRefreshSessionExpired, on_auth_refresh_session_expired)
    bus.subscribe(AuthTokenReplayDetected, on_auth_token_replay_detected)
    bus.subscribe(AuthUserRegistered, on_auth_user_registered)
    bus.subscribe(AuthLoggedIn, on_auth_logged_in)
    bus.subscribe(AuthTokenPairIssued, on_auth_token_pair_issued)
    bus.subscribe(AuthTokenRotated, on_auth_token_rotated)
    bus.subscribe(AuthLoggedOut, on_auth_logged_out)
    bus.subscribe(AuthAllSessionsRevoked, on_auth_all_sessions_revoked)
    bus.subscribe(AuthPasswordChanged, on_auth_password_changed)
