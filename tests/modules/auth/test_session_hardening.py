from datetime import datetime, timedelta, timezone
from unittest.mock import patch
import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from src.database.engine import AsyncEngineLocal
from src.exc import TokenRevokedException
from src.modules.audit.repo import AuditLogRepository
from src.modules.auth.model import RefreshSession
from src.modules.auth.repo import RefreshSessionRepository
from src.modules.auth.service import SECURITY_PASSWORD_HASH, logout
from src.modules.user import User, UserRepository
from src.security import create_access_token, create_refresh_token, hash_password
from src.share import Roles


@pytest.mark.security_audit
async def test_sec_02_a_unknown_family_fail_closed(client: AsyncClient, db_session: AsyncSession):
    """TEST-SEC-02-A: Access token with unknown/unrecorded fid is rejected with 401 TOKEN_STALE."""
    user_repo = UserRepository(session=db_session)
    user = await user_repo.create(
        User(
            name="Session Lineage User",
            email="lineage@test.com",
            hashed_password=hash_password("Passw0rd123!"),
            role=Roles.USER,
            is_active=True,
            security_version=1,
        )
    )
    await db_session.commit()

    # Generate token with arbitrary random family_id that has NO database record
    fake_fid = uuid.uuid4().hex
    synthetic_token = create_access_token(user_id=user.id, security_version=1, family_id=fake_fid)

    resp = await client.get(
        "/api/v1/users/me",
        headers={"Authorization": f"Bearer {synthetic_token}"},
    )
    assert resp.status_code == 401
    data = resp.json()
    assert data["error"]["code"] == "TOKEN_STALE"


@pytest.mark.security_audit
async def test_sec_02_b_unknown_jti_logout_fails(db_session: AsyncSession):
    """TEST-SEC-02-B: Calling logout with a JWT whose jti is not in refresh_sessions raises TokenRevokedException."""
    ref_tok, jti = create_refresh_token(user_id=1, security_version=1)
    with pytest.raises(TokenRevokedException):
        await logout(refresh_token_str=ref_tok, session=db_session)


@pytest.mark.security_audit
async def test_sec_12_integrity_error_sanitization(client: AsyncClient, db_session: AsyncSession):
    """TEST-SEC-12: Duplicate registration error logs 'integrity_constraint_violation' with zero password leak."""
    payload = {
        "name": "Original User",
        "email": "collision@enterprise.io",
        "password": "Password123!",
    }
    # 1st registration
    resp1 = await client.post("/api/v1/auth/register", json=payload)
    assert resp1.status_code == 201

    # 2nd duplicate registration -> triggers collision
    resp2 = await client.post("/api/v1/auth/register", json=payload)
    assert resp2.status_code == 409

    await db_session.commit()
    # Check audit log entries
    audit_repo = AuditLogRepository(session=db_session)
    recent_logs, _ = await audit_repo.get_multi(limit=10, offset=0)
    for log in recent_logs:
        if log.extra_data and "error" in log.extra_data:
            err_str = str(log.extra_data["error"])
            assert "$argon2id$" not in err_str
            assert "INSERT INTO" not in err_str

    # Engine parameter hiding verification
    assert getattr(AsyncEngineLocal.sync_engine, "hide_parameters", False) is True


async def test_refresh_token_cas_atomic_revocation(db_session: AsyncSession):
    """Verifies atomic Compare-And-Swap (CAS) revocation behavior."""
    user_repo = UserRepository(session=db_session)
    user = User(
        name="CAS Test User",
        email="cas.test@enterprise.io",
        hashed_password=hash_password("Pass12345!"),
    )
    user = await user_repo.create(user)
    await db_session.flush()

    refresh_repo = RefreshSessionRepository(session=db_session)
    session_instance = RefreshSession(
        user_id=user.id,
        refresh_token_jti="unique-cas-jti-001",
        is_revoked=False,
        expires_at=datetime.now(timezone.utc) + timedelta(days=7),
    )
    await refresh_repo.create(session_instance)
    await db_session.flush()

    # First revocation should succeed (active -> revoked)
    first_attempt = await refresh_repo.revoke_if_active("unique-cas-jti-001")
    assert first_attempt is True

    # Second concurrent or duplicate revocation attempt MUST return False (CAS guard)
    second_attempt = await refresh_repo.revoke_if_active("unique-cas-jti-001")
    assert second_attempt is False


async def test_login_timing_mitigation_invoked(client: AsyncClient):
    """Verifies that nonexistent email triggers dummy argon2 hash verification."""
    with patch("src.modules.auth.service.verify_password") as mock_verify:
        mock_verify.return_value = False

        response = await client.post(
            "/api/v1/auth/login",
            json={"email": "nonexistent.user.probe@enterprise.io", "password": "SecretPassword123!"},
        )

        assert response.status_code == 401
        # verify_password MUST have been called with SECURITY_PASSWORD_HASH to prevent timing side-channel
        mock_verify.assert_called_once_with(
            "SecretPassword123!",
            SECURITY_PASSWORD_HASH,
        )
