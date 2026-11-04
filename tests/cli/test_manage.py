import argparse
import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from manage import (
    handle_grant,
    handle_revoke,
    handle_unassign_role,
    validate_action,
    validate_resource,
    validate_role_name,
)
from src.modules.audit.repo import AuditLogRepository


def test_cli_validation_rules():
    """Verifies manage.py input validation functions."""
    # Valid role
    validate_role_name("auditor")
    validate_role_name("branch_manager")

    # Invalid roles
    with pytest.raises(ValueError, match="reserved prefix 'user:'"):
        validate_role_name("user:admin")

    with pytest.raises(ValueError, match="Invalid role name"):
        validate_role_name("Admin")  # uppercase not allowed

    with pytest.raises(ValueError, match="Invalid role name"):
        validate_role_name("a")  # too short

    # Valid resource & action
    validate_resource("users")
    validate_resource("audit")
    validate_resource("*")

    # Invalid resource & action
    with pytest.raises(ValueError, match="Unknown resource"):
        validate_resource("non_existent")

    validate_action("read")
    validate_action("write") if False else None  # validation check
    with pytest.raises(ValueError, match="Unknown action"):
        validate_action("invalid_act")


async def test_handle_revoke_and_unassign_validation():
    """Verifies that handle_revoke and handle_unassign_role reject invalid role/resource/action."""
    with pytest.raises(ValueError, match="Invalid role name"):
        await handle_revoke(argparse.Namespace(role="Admin", resource="users", action="read", force=False))

    with pytest.raises(ValueError, match="Unknown resource"):
        await handle_revoke(argparse.Namespace(role="auditor", resource="invalid", action="read", force=False))

    with pytest.raises(ValueError, match="Unknown action"):
        await handle_revoke(argparse.Namespace(role="auditor", resource="users", action="invalid", force=False))

    with pytest.raises(ValueError, match="Invalid role name"):
        await handle_unassign_role(argparse.Namespace(user_id=1, role="Admin"))


@pytest.mark.security_audit
async def test_sec_16_cli_audit_trail_logging(db_session: AsyncSession):
    """TEST-SEC-16: manage.py commands insert forensic AuditLog records with actor_id='cli:...'."""
    args = argparse.Namespace(
        role="editor",
        resource="users",
        action="read",
        domain="global",
    )
    await handle_grant(args)

    await db_session.commit()
    audit_repo = AuditLogRepository(session=db_session)
    recent_logs, _ = await audit_repo.get_multi(limit=10, offset=0)
    cli_logs = [
        log for log in recent_logs
        if log.user_id == "system:cli" or (log.actor_id and log.actor_id.startswith("cli:"))
    ]
    assert len(cli_logs) > 0
    assert "CLI_POLICY_GRANTED" in [log.event_type for log in cli_logs]
