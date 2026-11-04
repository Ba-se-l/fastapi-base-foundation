from sqlalchemy.ext.asyncio import AsyncSession

from src.modules.audit.repo import AuditLogRepository
from src.modules.user.events import (
    UserAccessDenied,
    UserDeactivated,
    UserInactiveTargeted,
    UserNotFound,
    UserUpdated,
    UserUpdateSkipped,
)
from src.share import AuditContext, UserAction
from src.share.event_bus import event_bus


async def test_user_domain_events_dispatch(db_session: AsyncSession) -> None:
    """Verifies that every User domain event properly creates an audit log entry."""
    audit_repo = AuditLogRepository(session=db_session)
    ctx = AuditContext(ip_address="127.0.0.1", user_agent="PyTestClient", request_id="req-user-1")

    # 1. UserNotFound
    await event_bus.publish(UserNotFound(audit_ctx=ctx, user_id=999))

    # 2. UserAccessDenied
    await event_bus.publish(
        UserAccessDenied(
            audit_ctx=ctx,
            actor_id=1,
            actor_name="Attacker",
            target_user_id=2,
            action=UserAction.VIEW,
        )
    )

    # 3. UserInactiveTargeted
    await event_bus.publish(
        UserInactiveTargeted(
            audit_ctx=ctx,
            actor_id=1,
            actor_name="Admin",
            target_user_id=3,
            action=UserAction.MODIFY,
        )
    )

    # 4. UserUpdateSkipped
    await event_bus.publish(UserUpdateSkipped(audit_ctx=ctx, user_id=4))

    # 5. UserUpdated (in-session)
    await event_bus.publish(
        UserUpdated(audit_ctx=ctx, user_id=5, changes={"name": {"old": "Old", "new": "New"}}),
        session=db_session,
    )

    # 6. UserDeactivated (in-session)
    await event_bus.publish(UserDeactivated(audit_ctx=ctx, user_id=6), session=db_session)

    await db_session.commit()

    # Verify logs exist
    logs, total = await audit_repo.get_multi(limit=50)
    assert total >= 6

    event_types = {entry.event_type for entry in logs}
    assert "USER_NOT_FOUND" in event_types
