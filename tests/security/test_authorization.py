import asyncio

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from src.modules.user import User, UserRepository
from src.security import (
    AuthorizationNotInitializedError,
    AuthorizationService,
    CasbinRule,
    hash_password,
)
from src.settings import settings
from src.share import Roles


async def test_get_enforcer_before_initialize_raises():
    """Verifies that accessing the enforcer before initialization raises an explicit error."""
    AuthorizationService.reset()
    with pytest.raises(AuthorizationNotInitializedError):
        AuthorizationService.get_enforcer()


def test_casbin_rule_str_serialization():
    """Verifies that CasbinRule converts properly to CSV string lines for the Casbin loader."""
    policy_rule = CasbinRule(
        ptype="p",
        v0="admin",
        v1="*",
        v2="*",
        v3=None,
        v4=None,
        v5=None,
    )
    assert str(policy_rule) == "p, admin, *, *"

    grouping_rule = CasbinRule(
        ptype="g",
        v0="user:42",
        v1="auditor",
        v2=None,
        v3=None,
        v4=None,
        v5=None,
    )
    assert str(grouping_rule) == "g, user:42, auditor"


async def test_policies_persist_across_reinitialization(db_session: AsyncSession):
    """Verifies that policies written to the database persist and reload on subsequent initializations."""
    enforcer = AuthorizationService.get_enforcer()
    await enforcer.add_policy("manager", "users", "read")

    # Simulate process restart by resetting cache and reinitializing from test_engine
    engine = db_session.bind
    AuthorizationService.reset()
    await AuthorizationService.initialize(engine)

    new_enforcer = AuthorizationService.get_enforcer()
    assert new_enforcer.has_policy("manager", "users", "read") is True


async def test_route_permissions_admin_allowed_user_denied(
    client: AsyncClient,
    db_session: AsyncSession,
    make_access_token,
):
    """Verifies that routes protected by require_permission allow admin and reject standard users."""
    user_repo = UserRepository(session=db_session)

    admin = User(
        name="Admin User",
        email="admin_p2@enterprise.io",
        hashed_password=hash_password("AdminSecr3t!"),
        role=Roles.ADMIN,
        is_active=True,
    )
    user = User(
        name="Normal User",
        email="user_p2@enterprise.io",
        hashed_password=hash_password("UserSecr3t!"),
        role=Roles.USER,
        is_active=True,
    )
    await user_repo.create(admin)
    await user_repo.create(user)
    await db_session.commit()

    admin_token = await make_access_token(user_id=admin.id)
    user_token = await make_access_token(user_id=user.id)

    # 1. /users endpoint (Resource.USERS, Action.READ)
    resp_user = await client.get("/api/v1/users", headers={"Authorization": f"Bearer {user_token}"})
    assert resp_user.status_code == 403
    assert resp_user.json()["error"]["code"] == "ACCESS_DENIED"

    resp_admin = await client.get("/api/v1/users", headers={"Authorization": f"Bearer {admin_token}"})
    assert resp_admin.status_code == 200

    # 2. /audit/logs endpoint (Resource.AUDIT, Action.READ)
    resp_audit_user = await client.get("/api/v1/audit/logs", headers={"Authorization": f"Bearer {user_token}"})
    assert resp_audit_user.status_code == 403

    resp_audit_admin = await client.get("/api/v1/audit/logs", headers={"Authorization": f"Bearer {admin_token}"})
    assert resp_audit_admin.status_code == 200

    # 3. /audit/export endpoint (Resource.AUDIT, Action.EXPORT)
    resp_export_user = await client.get("/api/v1/audit/export", headers={"Authorization": f"Bearer {user_token}"})
    assert resp_export_user.status_code == 403

    resp_export_admin = await client.get("/api/v1/audit/export", headers={"Authorization": f"Bearer {admin_token}"})
    assert resp_export_admin.status_code == 200


async def test_runtime_per_user_grant_applies_immediately(
    client: AsyncClient,
    db_session: AsyncSession,
    make_access_token,
):
    """Verifies that granting a role to user:id immediately unlocks permitted actions with granular control."""
    user_repo = UserRepository(session=db_session)
    user = User(
        name="Auditor Candidate",
        email="auditor@enterprise.io",
        hashed_password=hash_password("AuditorSecr3t!"),
        role=Roles.USER,
        is_active=True,
    )
    await user_repo.create(user)
    await db_session.commit()

    user_token = await make_access_token(user_id=user.id)

    # Step 1: Initially denied
    init_resp = await client.get("/api/v1/audit/logs", headers={"Authorization": f"Bearer {user_token}"})
    assert init_resp.status_code == 403

    # Step 2: Grant 'auditor' role permission to read audit, and assign user to 'auditor'
    enforcer = AuthorizationService.get_enforcer()
    await enforcer.add_policy("auditor", "audit", "read")
    await enforcer.add_grouping_policy(AuthorizationService.user_subject(user.id), "auditor")

    # Step 3: Now user can read audit logs immediately
    read_resp = await client.get("/api/v1/audit/logs", headers={"Authorization": f"Bearer {user_token}"})
    assert read_resp.status_code == 200

    # Step 4: Granular check: user CANNOT export audit logs because only 'read' was granted
    export_resp = await client.get("/api/v1/audit/export", headers={"Authorization": f"Bearer {user_token}"})
    assert export_resp.status_code == 403

    # Step 5: Revoke grouping policy -> user is immediately denied again
    await enforcer.remove_grouping_policy(AuthorizationService.user_subject(user.id), "auditor")
    revoked_resp = await client.get("/api/v1/audit/logs", headers={"Authorization": f"Bearer {user_token}"})
    assert revoked_resp.status_code == 403


async def test_role_wide_grant_unlocks_service_level_read(
    client: AsyncClient,
    db_session: AsyncSession,
    make_access_token,
):
    """Verifies that policy grants unlock service-level checks dynamically without code changes."""
    user_repo = UserRepository(session=db_session)
    user_a = User(
        name="User A",
        email="usera@enterprise.io",
        hashed_password=hash_password("Pass1234!"),
        role=Roles.USER,
        is_active=True,
    )
    user_b = User(
        name="User B",
        email="userb@enterprise.io",
        hashed_password=hash_password("Pass1234!"),
        role=Roles.USER,
        is_active=True,
    )
    await user_repo.create(user_a)
    await user_repo.create(user_b)
    await db_session.commit()

    token_a = await make_access_token(user_id=user_a.id)

    # User A tries to view User B's profile -> 403 Forbidden
    resp_init = await client.get(f"/api/v1/users/{user_b.id}", headers={"Authorization": f"Bearer {token_a}"})
    assert resp_init.status_code == 403

    # Grant 'user' role permission to read 'users'
    enforcer = AuthorizationService.get_enforcer()
    await enforcer.add_policy("user", "users", "read")

    # Now User A can view User B's profile
    resp_allowed = await client.get(f"/api/v1/users/{user_b.id}", headers={"Authorization": f"Bearer {token_a}"})
    assert resp_allowed.status_code == 200
    assert resp_allowed.json()["id"] == user_b.id


async def test_assign_role_is_independent_from_update(
    client: AsyncClient,
    db_session: AsyncSession,
    make_access_token,
):
    """Verifies that permission to update users does NOT automatically allow modifying user roles."""
    user_repo = UserRepository(session=db_session)
    manager = User(
        name="Manager",
        email="manager@enterprise.io",
        hashed_password=hash_password("Manager123!"),
        role=Roles.USER,
        is_active=True,
    )
    target = User(
        name="Target User",
        email="target@enterprise.io",
        hashed_password=hash_password("Target123!"),
        role=Roles.USER,
        is_active=True,
    )
    await user_repo.create(manager)
    await user_repo.create(target)
    await db_session.commit()

    manager_token = await make_access_token(user_id=manager.id)

    # Grant 'manager' role USERS:UPDATE (but NOT USERS:ASSIGN_ROLE)
    enforcer = AuthorizationService.get_enforcer()
    await enforcer.add_policy("manager", "users", "update")
    await enforcer.add_grouping_policy(AuthorizationService.user_subject(manager.id), "manager")

    # Manager can update name
    resp_update_name = await client.patch(
        f"/api/v1/users/{target.id}",
        json={"name": "Updated Name"},
        headers={"Authorization": f"Bearer {manager_token}"},
    )
    assert resp_update_name.status_code == 200
    assert resp_update_name.json()["name"] == "Updated Name"

    # Manager attempts to escalate target's role to 'admin' -> 403 Forbidden
    resp_update_role = await client.patch(
        f"/api/v1/users/{target.id}",
        json={"role": "admin"},
        headers={"Authorization": f"Bearer {manager_token}"},
    )
    assert resp_update_role.status_code == 403
    assert resp_update_role.json()["error"]["code"] == "ACCESS_DENIED"


async def test_empty_policy_store_fails_closed(
    client: AsyncClient,
    db_session: AsyncSession,
    make_access_token,
):
    """Verifies that an empty policy store results in fail-closed behavior, denying even admins."""
    user_repo = UserRepository(session=db_session)
    admin = User(
        name="Admin",
        email="admin_empty@enterprise.io",
        hashed_password=hash_password("AdminSecr3t!"),
        role=Roles.ADMIN,
        is_active=True,
    )
    await user_repo.create(admin)
    await db_session.commit()

    admin_token = await make_access_token(user_id=admin.id)

    # Clear all policies from enforcer
    enforcer = AuthorizationService.get_enforcer()
    enforcer.clear_policy()

    # Admin request must be denied (fail closed)
    resp = await client.get("/api/v1/users", headers={"Authorization": f"Bearer {admin_token}"})
    assert resp.status_code == 403
    assert resp.json()["error"]["code"] == "ACCESS_DENIED"


@pytest.mark.security_audit
async def test_sec_10_casbin_ttl_cache_refresh(
    client: AsyncClient,
    db_session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
):
    """TEST-SEC-10: check_and_refresh_cache reloads policies when TTL expires."""
    monkeypatch.setattr(settings, "authz_cache_ttl_seconds", 0.01)
    before_loaded = AuthorizationService._last_loaded

    await asyncio.sleep(0.02)
    await AuthorizationService.check_and_refresh_cache()
    assert AuthorizationService._last_loaded > before_loaded
