import asyncio
from datetime import datetime, timedelta, timezone
from pathlib import Path
import uuid
import pytest
from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory
from httpx import ASGITransport, AsyncClient
import jwt
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from main import app
from src.database.base import BaseModel
from src.database.session import get_session
from src.exc.base import AccessDeniedException
from src.modules.audit.enum import LogAction, LogSeverity
from src.modules.audit.model import AuditLog
from src.modules.audit.repo import AuditLogRepository
from src.modules.audit.schemas import LogQueryFilter
from src.modules.audit.service import drain_background_tasks, save_success_event
import src.modules.auth.service as auth_srv
from src.modules.auth.model import RefreshSession
from src.modules.auth.repo import RefreshSessionRepository
from src.modules.user.model import User
from src.modules.user.repo import UserRepository
from src.modules.user.service import deactivate_user
from src.security import (
    AuthorizationService,
    create_access_token,
    create_refresh_token,
    decode_access_token,
    decode_refresh_token,
    hash_password,
)
from src.settings import settings
from src.share import Roles
from tests.support.database import TestSessionLocal
from tests.support.paths import ALEMBIC_INI

pytestmark = [pytest.mark.release_gate]


@pytest.mark.asyncio
async def test_rg01_single_alembic_head_and_no_schema_drift(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """RG-01: Verifies single alembic head and clean schema upgrade with zero drift (N01)."""
    ini_path = ALEMBIC_INI
    cfg = Config(str(ini_path))
    script = ScriptDirectory.from_config(cfg)
    heads = script.get_heads()
    assert len(heads) == 1, f"Expected 1 head revision, got {heads}"
    assert heads[0] == "9d21f4c5b303"

    db_file = tmp_path / "rg01_drift_check.db"
    db_url = f"sqlite+aiosqlite:///{db_file.as_posix()}"
    monkeypatch.setattr(settings, "database_url", db_url)
    cfg.set_main_option("sqlalchemy.url", db_url)

    await asyncio.to_thread(command.upgrade, cfg, "head")
    await asyncio.to_thread(command.check, cfg)


@pytest.mark.asyncio
async def test_rg02_login_commit_failure_does_not_issue_200_or_tokens(
    client: AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """RG-02: Failure of session.commit() prevents 200 OK and issuance of tokens/cookies (F01)."""
    user_payload = {
        "name": "Commit Fail User",
        "email": "rg02_commit_fail@enterprise.io",
        "password": "StrongP@ssw0rd!1",
    }
    reg_res = await client.post("/api/v1/auth/register", json=user_payload)
    assert reg_res.status_code == 201
    user_id = reg_res.json()["id"]

    original_commit = AsyncSession.commit

    async def simulated_failing_commit(self: AsyncSession) -> None:
        raise RuntimeError("Simulated Database Commit Crash")

    monkeypatch.setattr(AsyncSession, "commit", simulated_failing_commit)

    try:
        login_res = await client.post(
            "/api/v1/auth/login",
            json={"email": user_payload["email"], "password": user_payload["password"]},
        )
        assert login_res.status_code != 200
        assert "access_token" not in login_res.json()
    except RuntimeError:
        pass
    finally:
        monkeypatch.setattr(AsyncSession, "commit", original_commit)

    async with TestSessionLocal() as session:
        stmt = select(RefreshSession).where(RefreshSession.user_id == user_id)
        res = await session.execute(stmt)
        sessions = res.scalars().all()
        assert len(sessions) == 0


@pytest.mark.asyncio
async def test_rg03_non_numeric_or_malformed_jwt_subject_returns_401_not_500(client: AsyncClient) -> None:
    """RG-03: Non-numeric, missing fid, or malformed JWT subjects return 401 instead of 500 (F02)."""
    # 1. Non-integer string subject
    bad_sub_payload = {
        "sub": "not-an-integer",
        "exp": datetime.now(timezone.utc) + timedelta(minutes=15),
        "iat": datetime.now(timezone.utc),
        "type": "access",
        "sec_ver": 1,
        "fid": str(uuid.uuid4()),
    }
    tok_bad_sub = jwt.encode(bad_sub_payload, settings.access_secret_key, algorithm=settings.algorithm)
    res1 = await client.get("/api/v1/users/me", headers={"Authorization": f"Bearer {tok_bad_sub}"})
    assert res1.status_code == 401
    assert res1.status_code != 500

    # 2. Missing fid claim
    no_fid_payload = {
        "sub": "1",
        "exp": datetime.now(timezone.utc) + timedelta(minutes=15),
        "iat": datetime.now(timezone.utc),
        "type": "access",
        "sec_ver": 1,
    }
    tok_no_fid = jwt.encode(no_fid_payload, settings.access_secret_key, algorithm=settings.algorithm)
    res2 = await client.get("/api/v1/users/me", headers={"Authorization": f"Bearer {tok_no_fid}"})
    assert res2.status_code == 401
    assert res2.status_code != 500

    # 3. Non-positive subject
    neg_sub_payload = {
        "sub": "-10",
        "exp": datetime.now(timezone.utc) + timedelta(minutes=15),
        "iat": datetime.now(timezone.utc),
        "type": "access",
        "sec_ver": 1,
        "fid": str(uuid.uuid4()),
    }
    tok_neg_sub = jwt.encode(neg_sub_payload, settings.access_secret_key, algorithm=settings.algorithm)
    res3 = await client.get("/api/v1/users/me", headers={"Authorization": f"Bearer {tok_neg_sub}"})
    assert res3.status_code == 401
    assert res3.status_code != 500


@pytest.mark.asyncio
async def test_rg04_rolled_back_transaction_does_not_write_success_audit_file(
    db_session: AsyncSession, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """RG-04: Rolled back transaction discards staged success audit files (F03)."""
    monkeypatch.setattr(settings, "log_dir", str(tmp_path))
    monkeypatch.setattr(settings, "log_to_file", True)
    monkeypatch.setattr(settings, "log_to_db", True)

    await save_success_event(
        "Rolled back transaction audit test",
        session=db_session,
        event_type=LogAction.USER_UPDATED,
        user_id="rg04-user-999",
    )

    await db_session.rollback()
    await drain_background_tasks()

    # DB records rolled back
    res = await db_session.execute(select(AuditLog).where(AuditLog.user_id == "rg04-user-999"))
    assert res.scalars().all() == []

    # File log must not contain rolled back event
    date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    json_file = tmp_path / f"{date_str}.json"
    if json_file.exists():
        content = json_file.read_text(encoding="utf-8")
        assert "rg04-user-999" not in content
        assert "Rolled back transaction audit test" not in content


@pytest.mark.asyncio
async def test_rg05_refresh_token_carries_and_enforces_actual_security_version(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """RG-05: Refresh tokens carry and enforce actual user security_version (F04, P07)."""
    user = User(
        name="Security Version User",
        email="rg05_secver@enterprise.io",
        hashed_password=hash_password("StrongP@ssw0rd!1"),
        role=Roles.USER,
        is_active=True,
        security_version=7,
    )
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)

    acc = create_access_token(user_id=user.id, security_version=user.security_version, family_id="fam-rg05")
    ref, _ = create_refresh_token(user_id=user.id, security_version=user.security_version, family_id="fam-rg05")

    acc_payload = decode_access_token(acc)
    ref_payload = decode_refresh_token(ref)
    assert acc_payload.sec_ver == 7
    assert ref_payload.sec_ver == 7

    repo = RefreshSessionRepository(db_session)
    await repo.create(
        RefreshSession(
            user_id=user.id,
            refresh_token_jti=ref_payload.jti,
            family_id="fam-rg05",
            expires_at=datetime.now(timezone.utc) + timedelta(days=7),
        )
    )
    await db_session.commit()

    # Tampered token with sec_ver=1 must fail
    tampered_data = dict(ref_payload.model_dump())
    tampered_data["sec_ver"] = 1
    tampered_ref = jwt.encode(tampered_data, settings.refresh_secret_key, algorithm=settings.algorithm)

    res = await client.post("/api/v1/auth/refresh", json={"refresh_token": tampered_ref})
    assert res.status_code == 401


@pytest.mark.asyncio
async def test_rg06_current_device_logout_immediately_revokes_access_and_refresh_tokens(
    client: AsyncClient,
) -> None:
    """RG-06: Device logout revokes access and refresh token of that device while other devices remain valid (P01)."""
    user_payload = {
        "name": "Multi Device User",
        "email": "rg06_devices@enterprise.io",
        "password": "StrongP@ssw0rd!1",
    }
    reg_res = await client.post("/api/v1/auth/register", json=user_payload)
    assert reg_res.status_code == 201

    # Device A
    res_a = await client.post(
        "/api/v1/auth/login",
        json={"email": user_payload["email"], "password": user_payload["password"]},
    )
    tokens_a = res_a.json()
    acc_a = tokens_a["access_token"]
    ref_a = tokens_a["refresh_token"]

    # Device B
    res_b = await client.post(
        "/api/v1/auth/login",
        json={"email": user_payload["email"], "password": user_payload["password"]},
    )
    tokens_b = res_b.json()
    acc_b = tokens_b["access_token"]
    ref_b = tokens_b["refresh_token"]

    # Both devices work
    me_a = await client.get("/api/v1/users/me", headers={"Authorization": f"Bearer {acc_a}"})
    assert me_a.status_code == 200
    me_b = await client.get("/api/v1/users/me", headers={"Authorization": f"Bearer {acc_b}"})
    assert me_b.status_code == 200

    # Logout Device A explicitly
    logout_a = await client.post("/api/v1/auth/logout", json={"refresh_token": ref_a})
    assert logout_a.status_code == 200

    # Device A access token is immediately revoked
    me_a_after = await client.get("/api/v1/users/me", headers={"Authorization": f"Bearer {acc_a}"})
    assert me_a_after.status_code == 401

    # Device A refresh token is revoked
    ref_a_after = await client.post("/api/v1/auth/refresh", json={"refresh_token": ref_a})
    assert ref_a_after.status_code == 401

    # Device B remains active and functional
    me_b_after = await client.get("/api/v1/users/me", headers={"Authorization": f"Bearer {acc_b}"})
    assert me_b_after.status_code == 200
    ref_b_after = await client.post("/api/v1/auth/refresh", json={"refresh_token": ref_b})
    assert ref_b_after.status_code == 200


@pytest.mark.asyncio
async def test_rg07_logout_with_rotated_ancestor_revokes_entire_family(client: AsyncClient) -> None:
    """RG-07: Logout with an already-rotated ancestor token revokes the entire session family (P02)."""
    user_payload = {
        "name": "Ancestor Logout User",
        "email": "rg07_ancestor@enterprise.io",
        "password": "StrongP@ssw0rd!1",
    }
    await client.post("/api/v1/auth/register", json=user_payload)
    login_res = await client.post(
        "/api/v1/auth/login",
        json={"email": user_payload["email"], "password": user_payload["password"]},
    )
    r1 = login_res.json()["refresh_token"]

    # Rotate R1 -> R2
    rot_res = await client.post("/api/v1/auth/refresh", json={"refresh_token": r1})
    assert rot_res.status_code == 200
    a2 = rot_res.json()["access_token"]
    r2 = rot_res.json()["refresh_token"]

    # Logout with ancestor R1
    logout_res = await client.post("/api/v1/auth/logout", json={"refresh_token": r1})
    assert logout_res.status_code == 200

    # R2 must now be rejected
    res_r2 = await client.post("/api/v1/auth/refresh", json={"refresh_token": r2})
    assert res_r2.status_code == 401

    # A2 must now be rejected
    res_a2 = await client.get("/api/v1/users/me", headers={"Authorization": f"Bearer {a2}"})
    assert res_a2.status_code == 401


@pytest.mark.asyncio
async def test_rg08_refresh_replay_revokes_family_and_invalidates_latest_access_token(
    client: AsyncClient,
) -> None:
    """RG-08: Refresh token replay revokes entire family, invalidates latest access token, and logs CRITICAL audit (P03)."""
    user_payload = {
        "name": "Replay Attack User",
        "email": "rg08_replay@enterprise.io",
        "password": "StrongP@ssw0rd!1",
    }
    await client.post("/api/v1/auth/register", json=user_payload)
    login_res = await client.post(
        "/api/v1/auth/login",
        json={"email": user_payload["email"], "password": user_payload["password"]},
    )
    r1 = login_res.json()["refresh_token"]

    # Rotate R1 -> (A2, R2)
    rot_res = await client.post("/api/v1/auth/refresh", json={"refresh_token": r1})
    assert rot_res.status_code == 200
    a2 = rot_res.json()["access_token"]
    r2 = rot_res.json()["refresh_token"]

    # Replay old R1
    replay_res = await client.post("/api/v1/auth/refresh", json={"refresh_token": r1})
    assert replay_res.status_code == 401

    # Latest access token A2 is now invalid
    res_a2 = await client.get("/api/v1/users/me", headers={"Authorization": f"Bearer {a2}"})
    assert res_a2.status_code == 401

    # Latest refresh token R2 is now invalid
    res_r2 = await client.post("/api/v1/auth/refresh", json={"refresh_token": r2})
    assert res_r2.status_code == 401

    # CRITICAL audit logged in TestSessionLocal
    async with TestSessionLocal() as session:
        stmt = select(AuditLog).where(
            AuditLog.severity == "CRITICAL",
            AuditLog.event_type == "AUTH_TOKEN_REVOKED",
        )
        res = await session.execute(stmt)
        logs = res.scalars().all()
        assert len(logs) >= 1


@pytest.mark.asyncio
async def test_rg09_purge_preserves_unexpired_revoked_tombstones_for_replay_detection(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """RG-09: Purge preserves unexpired revoked session tombstones to retain replay detection (P04)."""
    user_payload = {
        "name": "Tombstone User",
        "email": "rg09_tombstone@enterprise.io",
        "password": "StrongP@ssw0rd!1",
    }
    await client.post("/api/v1/auth/register", json=user_payload)
    login_res = await client.post(
        "/api/v1/auth/login",
        json={"email": user_payload["email"], "password": user_payload["password"]},
    )
    r1 = login_res.json()["refresh_token"]

    # Rotate R1 -> R2
    rot_res = await client.post("/api/v1/auth/refresh", json={"refresh_token": r1})
    r2 = rot_res.json()["refresh_token"]

    # Purge with grace period
    repo = RefreshSessionRepository(db_session)
    deleted = await repo.purge_expired_tombstones(grace_seconds=300)
    await db_session.commit()
    assert deleted == 0

    # R1 still exists as revoked tombstone
    p1 = decode_refresh_token(r1)
    s1 = await repo.get_by_jti(p1.jti)
    assert s1 is not None
    assert s1.is_revoked is True

    # Replaying R1 still detects replay and revokes R2
    replay_res = await client.post("/api/v1/auth/refresh", json={"refresh_token": r1})
    assert replay_res.status_code == 401

    res_r2 = await client.post("/api/v1/auth/refresh", json={"refresh_token": r2})
    assert res_r2.status_code == 401


@pytest.mark.asyncio
async def test_rg10_full_auth_lifecycle_audit_coverage_with_context(
    client: AsyncClient,
) -> None:
    """RG-10: Full auth lifecycle generates complete audit trails with correlation context (P05)."""
    headers = {"X-Request-ID": "req-rg10-trace-77", "X-Forwarded-For": "198.51.100.42"}
    user_payload = {
        "name": "Audit Trace User",
        "email": "rg10_audit@enterprise.io",
        "password": "StrongP@ssw0rd!1",
    }
    await client.post("/api/v1/auth/register", json=user_payload)

    # 1. Failed login
    await client.post(
        "/api/v1/auth/login",
        json={"email": user_payload["email"], "password": "WrongPassword!99"},
        headers=headers,
    )

    # 2. Successful login
    login_res = await client.post(
        "/api/v1/auth/login",
        json={"email": user_payload["email"], "password": user_payload["password"]},
        headers=headers,
    )
    r1 = login_res.json()["refresh_token"]

    # 3. Rotate
    rot_res = await client.post("/api/v1/auth/refresh", json={"refresh_token": r1}, headers=headers)
    r2 = rot_res.json()["refresh_token"]

    # 4. Logout
    await client.post("/api/v1/auth/logout", json={"refresh_token": r2}, headers=headers)

    async with TestSessionLocal() as session:
        repo = AuditLogRepository(session)
        logs, _ = await repo.query_logs(LogQueryFilter(search=""))
        event_types = {l.event_type for l in logs}

        assert "AUTH_LOGIN_FAILED" in event_types
        assert "AUTH_LOGIN_SUCCESS" in event_types
        assert "AUTH_TOKEN_ROTATED" in event_types
        assert "AUTH_LOGOUT" in event_types


@pytest.mark.asyncio
async def test_rg11_audit_repository_enforces_append_only_immutability(db_session: AsyncSession) -> None:
    """RG-11: Audit log repository enforces append-only immutability by prohibiting update/delete (P06)."""
    repo = AuditLogRepository(db_session)
    instance = AuditLog(
        event_type="TEST_IMMUTABLE",
        severity="INFO",
        message="Immutable audit trial entry",
    )

    with pytest.raises(NotImplementedError, match="immutable and cannot be updated"):
        await repo.update(instance, {"message": "Tampered message"})

    with pytest.raises(NotImplementedError, match="immutable and cannot be deleted"):
        await repo.delete(instance)


@pytest.mark.asyncio
async def test_rg12_family_revocation_is_strictly_user_scoped(db_session: AsyncSession) -> None:
    """RG-12: Session family revocation is strictly user-scoped (P08)."""
    u1 = User(name="User A", email="rg12_u1@enterprise.io", hashed_password="h1", role=Roles.USER, is_active=True)
    u2 = User(name="User B", email="rg12_u2@enterprise.io", hashed_password="h2", role=Roles.USER, is_active=True)
    db_session.add_all([u1, u2])
    await db_session.commit()
    await db_session.refresh(u1)
    await db_session.refresh(u2)

    shared_fid = "shared-family-id-1234"
    repo = RefreshSessionRepository(db_session)
    await repo.create(
        RefreshSession(
            user_id=u1.id,
            refresh_token_jti="jti-u1-1",
            family_id=shared_fid,
            expires_at=datetime.now(timezone.utc) + timedelta(days=1),
        )
    )
    await repo.create(
        RefreshSession(
            user_id=u2.id,
            refresh_token_jti="jti-u2-1",
            family_id=shared_fid,
            expires_at=datetime.now(timezone.utc) + timedelta(days=1),
        )
    )
    await db_session.commit()

    # Revoke for u1 only
    revoked = await repo.revoke_family(family_id=shared_fid, user_id=u1.id)
    await db_session.commit()
    assert revoked == 1

    s1 = await repo.get_by_jti("jti-u1-1")
    s2 = await repo.get_by_jti("jti-u2-1")
    assert s1.is_revoked is True
    assert s2.is_revoked is False
    assert await repo.is_family_active(family_id=shared_fid, user_id=u2.id) is True


@pytest.mark.asyncio
async def test_rg13_unknown_email_login_executes_async_dummy_verification(
    client: AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """RG-13: Login with non-existent email executes async dummy verification to prevent timing attacks (P09)."""
    calls: list[str] = []
    original_dummy = auth_srv.verify_dummy_password_async

    async def spy_dummy(password: str) -> None:
        calls.append(password)
        await original_dummy(password)

    monkeypatch.setattr(auth_srv, "verify_dummy_password_async", spy_dummy)

    res = await client.post(
        "/api/v1/auth/login",
        json={"email": "nonexistent_target_user@enterprise.io", "password": "DummyPassword123!"},
    )
    assert res.status_code == 401
    assert len(calls) == 1
    assert calls[0] == "DummyPassword123!"


@pytest.mark.asyncio
async def test_rg14_admin_updating_user_records_distinct_actor_and_target_with_redaction(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """RG-14: Admin modifying target user records distinct actor/target and redacts sensitive diffs (P10, F44, F22)."""
    # 1. Create target user
    target_user = User(
        name="Target Employee",
        email="rg14_target@enterprise.io",
        hashed_password=hash_password("StrongP@ssw0rd!1"),
        role=Roles.USER,
        is_active=True,
    )
    # 2. Create admin user
    admin_user = User(
        name="Security Admin",
        email="rg14_admin@enterprise.io",
        hashed_password=hash_password("StrongP@ssw0rd!1"),
        role=Roles.ADMIN,
        is_active=True,
    )
    db_session.add_all([target_user, admin_user])
    await db_session.commit()
    await db_session.refresh(target_user)
    await db_session.refresh(admin_user)

    # Login as admin
    login_res = await client.post(
        "/api/v1/auth/login",
        json={"email": "rg14_admin@enterprise.io", "password": "StrongP@ssw0rd!1"},
    )
    admin_acc = login_res.json()["access_token"]

    # Admin updates target profile
    update_res = await client.patch(
        f"/api/v1/users/{target_user.id}",
        json={"name": "Promoted Target Employee"},
        headers={"Authorization": f"Bearer {admin_acc}"},
    )
    assert update_res.status_code == 200

    # Query audit logs
    repo = AuditLogRepository(db_session)
    logs, _ = await repo.query_logs(
        LogQueryFilter(actor_id=str(admin_user.id), entity_id=str(target_user.id))
    )
    assert len(logs) >= 1
    audit = logs[0]
    assert audit.actor_id == str(admin_user.id)
    assert audit.entity_type == "user"
    assert audit.entity_id == str(target_user.id)
    assert audit.outcome == "SUCCESS"
    assert audit.changes_payload is not None
    payload_str = str(audit.changes_payload)
    assert "password" not in payload_str or "[REDACTED]" in payload_str


@pytest.mark.asyncio
async def test_rg15_concurrent_deactivation_of_last_two_admins_is_serialized_and_blocked(tmp_path: Path) -> None:
    """RG-15: Concurrent deactivation of last two admins is serialized and blocked by governance lock (P11)."""
    db_file = tmp_path / "rg15_governance.db"
    db_url = f"sqlite+aiosqlite:///{db_file.as_posix()}"
    engine = create_async_engine(db_url, echo=False)
    session_factory = async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)

    async with engine.begin() as conn:
        await conn.run_sync(BaseModel.metadata.create_all)

    # Seed exactly two active admins
    async with session_factory() as session:
        a1 = User(name="Admin 1", email="a1_gov@enterprise.io", hashed_password="h1", role=Roles.ADMIN, is_active=True)
        a2 = User(name="Admin 2", email="a2_gov@enterprise.io", hashed_password="h2", role=Roles.ADMIN, is_active=True)
        session.add_all([a1, a2])
        await session.commit()
        await session.refresh(a1)
        await session.refresh(a2)
        a1_id, a2_id = a1.id, a2.id

    async def attempt_deactivate(target_id: int) -> tuple[bool, str | None]:
        try:
            async with session_factory() as sess:
                await deactivate_user(user_id=target_id, session=sess)
                await sess.commit()
                return True, None
        except AccessDeniedException as ex:
            return False, str(ex)
        except Exception as ex:
            return False, str(ex)

    # Run both concurrently
    results = await asyncio.gather(
        attempt_deactivate(a1_id),
        attempt_deactivate(a2_id),
    )

    success_count = sum(1 for success, _ in results if success)
    failure_count = sum(1 for success, _ in results if not success)

    # Exactly one must succeed and one must be blocked
    assert success_count == 1, f"Expected 1 success, got {results}"
    assert failure_count == 1, f"Expected 1 failure, got {results}"

    # Verify at least one active admin remains in the DB
    async with session_factory() as session:
        active_admins = await session.execute(
            select(func.count()).select_from(User).where(User.role == Roles.ADMIN, User.is_active.is_(True))
        )
        assert active_admins.scalar_one() == 1

    await engine.dispose()
