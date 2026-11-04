from sqlalchemy.ext.asyncio import AsyncSession

from src.modules.audit.repo import AuditLogRepository
from src.modules.auth.events import (
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
)
from src.share import AuditContext
from src.share.event_bus import event_bus


async def test_auth_domain_events_dispatch(db_session: AsyncSession) -> None:
    """Verifies that all 14 Auth domain events are handled and logged."""
    audit_repo = AuditLogRepository(session=db_session)
    ctx = AuditContext(ip_address="127.0.0.1", user_agent="PyTestClient", request_id="req-auth-1")

    # Failure events (autonomous session)
    await event_bus.publish(
        AuthEmailAlreadyRegistered(audit_ctx=ctx, user_id=10, email="dupe@test.com", name="Dupe")
    )
    await event_bus.publish(
        AuthRegistrationFailed(audit_ctx=ctx, email="fail@test.com", error="DB Constraint")
    )
    await event_bus.publish(AuthEmailNotFound(audit_ctx=ctx, email="ghost@test.com"))
    await event_bus.publish(AuthInvalidPassword(audit_ctx=ctx, user_id=11, email="user@test.com"))
    await event_bus.publish(
        AuthInactiveUserRejected(
            audit_ctx=ctx,
            user_id=12,
            email="deact@test.com",
            action=AuthAction.LOGIN,
        )
    )
    await event_bus.publish(AuthRefreshSessionNotFound(audit_ctx=ctx, user_id=13))
    await event_bus.publish(AuthRefreshSessionExpired(audit_ctx=ctx, user_id=14, session_id=101))
    await event_bus.publish(AuthTokenReplayDetected(audit_ctx=ctx, user_id=15, session_id=102))

    # Success events (in-session)
    await event_bus.publish(
        AuthUserRegistered(audit_ctx=ctx, user_id=16, email="reg@test.com", name="Reg"),
        session=db_session,
    )
    await event_bus.publish(AuthLoggedIn(audit_ctx=ctx, user_id=16), session=db_session)
    await event_bus.publish(AuthTokenPairIssued(audit_ctx=ctx, user_id=16), session=db_session)
    await event_bus.publish(AuthTokenRotated(audit_ctx=ctx, user_id=16), session=db_session)
    await event_bus.publish(AuthLoggedOut(audit_ctx=ctx, user_id=16), session=db_session)
    await event_bus.publish(AuthAllSessionsRevoked(audit_ctx=ctx, user_id=16), session=db_session)

    await db_session.commit()

    logs, total = await audit_repo.get_multi(limit=50)
    assert total >= 14
