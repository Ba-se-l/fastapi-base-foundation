import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from src.modules.audit.enum import LogAction
from src.modules.audit.repo import AuditLogRepository
from src.modules.user import User, UserRepository
from src.security import create_access_token, hash_password


@pytest.mark.asyncio
async def test_change_password_and_token_invalidation(
    client: AsyncClient,
    db_session: AsyncSession,
) -> None:
    """Verifies that changing a password increments security_version and invalidates tokens."""
    # 1. Register a test user
    reg_payload = {
        "name": "Phase1 Security User",
        "email": "security.user@enterprise.io",
        "password": "InitialPassword123!",
    }
    reg_resp = await client.post("/api/v1/auth/register", json=reg_payload)
    assert reg_resp.status_code == 201

    # 2. Login to get initial token pair
    login_payload = {
        "email": "security.user@enterprise.io",
        "password": "InitialPassword123!",
    }
    login_resp = await client.post("/api/v1/auth/login", json=login_payload)
    assert login_resp.status_code == 200
    token_data = login_resp.json()
    old_access_token = token_data["access_token"]
    old_refresh_token = token_data["refresh_token"]

    # 3. Verify old access token works on a protected route
    profile_resp = await client.get(
        "/api/v1/users/me",
        headers={"Authorization": f"Bearer {old_access_token}"},
    )
    assert profile_resp.status_code == 200

    # 4. Change password using the old access token
    change_payload = {
        "old_password": "InitialPassword123!",
        "new_password": "UpdatedPassword456@",
    }
    change_resp = await client.post(
        "/api/v1/auth/change-password",
        json=change_payload,
        headers={"Authorization": f"Bearer {old_access_token}"},
    )
    assert change_resp.status_code == 200
    assert "Password changed successfully" in change_resp.json()["message"]

    # 5. Immediate Invalidation: Old access token MUST now be rejected with 401 TOKEN_STALE
    stale_resp = await client.get(
        "/api/v1/users/me",
        headers={"Authorization": f"Bearer {old_access_token}"},
    )
    assert stale_resp.status_code == 401
    assert stale_resp.json()["error"]["code"] == "TOKEN_STALE"

    # 6. Session Revocation: Old refresh token MUST be rejected with 401 TOKEN_REVOKED
    refresh_resp = await client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": old_refresh_token},
    )
    assert refresh_resp.status_code == 401
    assert refresh_resp.json()["error"]["code"] == "TOKEN_REVOKED"

    # 7. Old password cannot be used to login
    bad_login = await client.post(
        "/api/v1/auth/login",
        json={"email": "security.user@enterprise.io", "password": "InitialPassword123!"},
    )
    assert bad_login.status_code == 401

    # 8. New password logs in successfully
    new_login = await client.post(
        "/api/v1/auth/login",
        json={"email": "security.user@enterprise.io", "password": "UpdatedPassword456@"},
    )
    assert new_login.status_code == 200
    new_token = new_login.json()["access_token"]

    # 9. New token accesses protected route seamlessly
    new_profile = await client.get(
        "/api/v1/users/me",
        headers={"Authorization": f"Bearer {new_token}"},
    )
    assert new_profile.status_code == 200


@pytest.mark.asyncio
async def test_change_password_validation_rules(
    client: AsyncClient,
    db_session: AsyncSession,
) -> None:
    """Verifies validation rules for the change-password endpoint."""
    # 1. Register & login
    reg_payload = {
        "name": "Validation Rule User",
        "email": "validation.user@enterprise.io",
        "password": "ValidPassword123!",
    }
    await client.post("/api/v1/auth/register", json=reg_payload)
    login_resp = await client.post(
        "/api/v1/auth/login",
        json={"email": "validation.user@enterprise.io", "password": "ValidPassword123!"},
    )
    token = login_resp.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # 2. Case: Wrong old password -> 401
    wrong_old = await client.post(
        "/api/v1/auth/change-password",
        json={"old_password": "WrongPassword999!", "new_password": "NewValidPassword456@"},
        headers=headers,
    )
    assert wrong_old.status_code == 401
    assert wrong_old.json()["error"]["code"] == "INVALID_CREDENTIALS"

    # 3. Case: New password identical to old password -> 422
    same_pwd = await client.post(
        "/api/v1/auth/change-password",
        json={"old_password": "ValidPassword123!", "new_password": "ValidPassword123!"},
        headers=headers,
    )
    assert same_pwd.status_code == 422

    # 4. Case: Weak new password -> 422
    weak_pwd = await client.post(
        "/api/v1/auth/change-password",
        json={"old_password": "ValidPassword123!", "new_password": "weak"},
        headers=headers,
    )
    assert weak_pwd.status_code == 422


@pytest.mark.asyncio
async def test_audit_logs_password_changed_event(
    client: AsyncClient,
    db_session: AsyncSession,
) -> None:
    """Verifies that changing password creates an AUTH_PASSWORD_CHANGED audit record."""
    audit_repo = AuditLogRepository(session=db_session)

    reg_payload = {
        "name": "Audit Track User",
        "email": "audit.track@enterprise.io",
        "password": "InitialPass123!",
    }
    reg_resp = await client.post("/api/v1/auth/register", json=reg_payload)
    user_id = str(reg_resp.json()["id"])

    login_resp = await client.post(
        "/api/v1/auth/login",
        json={"email": "audit.track@enterprise.io", "password": "InitialPass123!"},
    )
    token = login_resp.json()["access_token"]

    await client.post(
        "/api/v1/auth/change-password",
        json={"old_password": "InitialPass123!", "new_password": "ChangedPass456@"},
        headers={"Authorization": f"Bearer {token}"},
    )

    await db_session.commit()

    logs, _ = await audit_repo.get_by_user(user_id=user_id)
    pwd_event = next((l for l in logs if l.event_type == LogAction.AUTH_PASSWORD_CHANGED), None)
    assert pwd_event is not None
    assert pwd_event.severity == "INFO"
    assert "changed password successfully" in pwd_event.message
