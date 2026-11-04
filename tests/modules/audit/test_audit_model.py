import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from src.modules.audit.model import AuditLog
from src.modules.audit.repo import AuditLogRepository
from src.share.limits import (
    AUDIT_IP_MAX,
    AUDIT_REQUEST_ID_MAX,
    AUDIT_USER_AGENT_MAX,
    AUDIT_USER_ID_MAX,
)


def test_audit_log_model_column_lengths_match_constants():
    """Verifies that AuditLog column definitions exactly match the exported limits constants."""
    table = AuditLog.__table__
    assert table.c.user_id.type.length == AUDIT_USER_ID_MAX
    assert table.c.request_id.type.length == AUDIT_REQUEST_ID_MAX
    assert table.c.ip_address.type.length == AUDIT_IP_MAX
    assert table.c.user_agent.type.length == AUDIT_USER_AGENT_MAX


async def test_oversized_user_agent_truncated_in_audit_log(
    client: AsyncClient,
    db_session: AsyncSession,
):
    """Verifies that an oversized User-Agent (5000 chars) is truncated to 255 chars in audit persistence."""
    huge_ua = "EnterpriseBot/" + "x" * 5000
    user_payload = {
        "name": "Huge UA User",
        "email": "huge.ua@enterprise.io",
        "password": "StrongPassword123!",
    }
    resp = await client.post(
        "/api/v1/auth/register",
        json=user_payload,
        headers={"User-Agent": huge_ua},
    )
    assert resp.status_code == 201
    user_id = resp.json()["id"]

    await db_session.commit()
    audit_repo = AuditLogRepository(session=db_session)
    user_logs, _ = await audit_repo.get_by_user(str(user_id))
    assert len(user_logs) > 0
    persisted_log = user_logs[0]
    assert len(persisted_log.user_agent) == AUDIT_USER_AGENT_MAX
    assert persisted_log.user_agent == huge_ua[:AUDIT_USER_AGENT_MAX]


async def test_audit_log_immutability(db_session: AsyncSession):
    """Verifies that AuditLogRepository strictly blocks updates and deletions."""
    repo = AuditLogRepository(session=db_session)
    log_entry = AuditLog(
        event_type="TEST_IMMUTABLE",
        severity="INFO",
        message="Original immutable audit record",
    )
    saved = await repo.create(log_entry)
    await db_session.flush()

    # Verify update is strictly prohibited
    with pytest.raises(NotImplementedError, match="immutable"):
        await repo.update(saved, {"message": "Tampered message"})

    # Verify delete is strictly prohibited
    with pytest.raises(NotImplementedError, match="immutable"):
        await repo.delete(saved)
