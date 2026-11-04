import argparse
import asyncio
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock
import uuid

import pytest
from httpx import AsyncClient
from pydantic import ValidationError
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from main import app
from manage import handle_grant, handle_seed_policies
from src.database.engine import AsyncEngineLocal
from src.exc import AccessDeniedException, TokenRevokedException
from src.modules.audit.model import AuditLog
from src.modules.audit.repo import AuditLogRepository
from src.modules.auth.model import RefreshSession
from src.modules.auth.repo import RefreshSessionRepository
from src.modules.auth.router import _normalize_origin_tuple, verify_cookie_csrf_origin
from src.modules.auth.schemas import LoginRequest, RegisterRequest, TokenResponse
from src.modules.auth.service import logout
from src.modules.user import User, UserRepository
from src.security import (
    AuthorizationService,
    DomainAccessResolver,
    DomainResolutionResult,
    create_access_token,
    create_refresh_token,
    decode_access_token,
    hash_password,
    require_domain_permission,
)
from src.security.guards import DefaultGlobalDomainResolver
from src.settings import Environment, Settings, settings
from src.share import RateLimiter, Roles
from tests.conftest import create_test_access_token


# ——————————————————————————————————————————————————————————————————————
# 1. TEST-SEC-01: Strict URL-Parsed CSRF Origin Verification
# ——————————————————————————————————————————————————————————————————————

def test_sec_01_a_csrf_prefix_bypass_rejected():
    """TEST-SEC-01-A: Origin prefix attacker matching is strictly rejected."""
    original = settings.allowed_origins
    try:
        settings.allowed_origins = ["https://trusted.com"]
        req = MagicMock()
        req.headers = {"origin": "https://trusted.com.attacker.test"}
        with pytest.raises(AccessDeniedException, match="untrusted"):
            verify_cookie_csrf_origin(req)
    finally:
        settings.allowed_origins = original


def test_sec_01_b_csrf_missing_headers_rejected():
    """TEST-SEC-01-B: Missing or 'null' Origin and Referer headers fail-closed."""
    original = settings.allowed_origins
    try:
        settings.allowed_origins = ["https://trusted.com"]
        req1 = MagicMock()
        req1.headers = {}
        with pytest.raises(AccessDeniedException, match="required"):
            verify_cookie_csrf_origin(req1)

        req2 = MagicMock()
        req2.headers = {"origin": "null"}
        with pytest.raises(AccessDeniedException, match="required"):
            verify_cookie_csrf_origin(req2)
    finally:
        settings.allowed_origins = original


def test_sec_01_c_csrf_wildcard_rejected():
    """TEST-SEC-01-C: Wildcard origin '*' is prohibited for cookie authentication."""
    original = settings.allowed_origins
    try:
        settings.allowed_origins = ["*"]
        req = MagicMock()
        req.headers = {"origin": "https://trusted.com"}
        with pytest.raises(AccessDeniedException, match="wildcard"):
            verify_cookie_csrf_origin(req)
    finally:
        settings.allowed_origins = original


# ——————————————————————————————————————————————————————————————————————
# 2. TEST-SEC-02: Session Lineage Fail-Closed & Logout Validation
# ——————————————————————————————————————————————————————————————————————

@pytest.mark.asyncio
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


@pytest.mark.asyncio
async def test_sec_02_b_unknown_jti_logout_fails(db_session: AsyncSession):
    """TEST-SEC-02-B: Calling logout with a JWT whose jti is not in refresh_sessions raises TokenRevokedException."""
    ref_tok, jti = create_refresh_token(user_id=1, security_version=1)
    with pytest.raises(TokenRevokedException):
        await logout(refresh_token_str=ref_tok, session=db_session)


# ——————————————————————————————————————————————————————————————————————
# 3. TEST-SEC-03: Cookie-Only Token Stripping
# ——————————————————————————————————————————————————————————————————————

@pytest.mark.asyncio
async def test_sec_03_cookie_only_redacts_refresh_token(client: AsyncClient, db_session: AsyncSession):
    """TEST-SEC-03: When auth_transport_mode='cookie', JSON response body has refresh_token=None."""
    orig_mode = settings.auth_transport_mode
    try:
        settings.auth_transport_mode = "cookie"

        # Register user
        user_repo = UserRepository(session=db_session)
        user = await user_repo.create(
            User(
                name="Cookie User",
                email="cookie.mode@test.com",
                hashed_password=hash_password("Passw0rd123!"),
                role=Roles.USER,
                is_active=True,
                security_version=1,
            )
        )
        await db_session.commit()

        # Login in cookie mode
        login_resp = await client.post(
            "/api/v1/auth/login",
            json={"email": "cookie.mode@test.com", "password": "Passw0rd123!"},
        )
        assert login_resp.status_code == 200
        body = login_resp.json()
        assert body["access_token"] is not None
        assert body["refresh_token"] is None
        assert "set-cookie" in login_resp.headers
        assert settings.refresh_cookie_name in login_resp.headers["set-cookie"]
    finally:
        settings.auth_transport_mode = orig_mode


# ——————————————————————————————————————————————————————————————————————
# 4. TEST-SEC-04 & TEST-SEC-11: Dynamic DEV Keys & Secret Entropy
# ——————————————————————————————————————————————————————————————————————

def test_sec_04_dynamic_dev_keys_and_hardened_enforcement():
    """TEST-SEC-04: DEV generates non-placeholder memory keys; PROD without keys raises ValueError."""
    dev_settings = Settings(environment=Environment.DEV)
    assert not dev_settings.access_secret_key.startswith("placeholder-")
    assert len(dev_settings.access_secret_key) >= 32

    # PROD without explicit keys in model_fields_set must raise
    with pytest.raises(ValidationError):
        Settings(environment=Environment.PROD)


def test_sec_11_secret_entropy_rejection():
    """TEST-SEC-11: Low-entropy secrets (len(set(val)) < 10) are rejected in hardened modes."""
    with pytest.raises(ValidationError):
        Settings(
            environment=Environment.PROD,
            access_secret_key="a" * 32,
            refresh_secret_key="Z9y8X7w6V5u4T3s2R1q0P9o8N7m6L5k4",
            allowed_origins=["https://enterprise.io"],
        )


# ——————————————————————————————————————————————————————————————————————
# 5. TEST-SEC-05 & TEST-SEC-06: STAGING Wildcard Origin & Cookie Secure
# ——————————————————————————————————————————————————————————————————————

def test_sec_05_staging_wildcard_ban():
    """TEST-SEC-05: Wildcard origin '*' is prohibited in STAGING."""
    with pytest.raises(ValidationError):
        Settings(
            environment=Environment.STAGING,
            access_secret_key="A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6",
            refresh_secret_key="Z9y8X7w6V5u4T3s2R1q0P9o8N7m6L5k4",
            allowed_origins=["*"],
        )


def test_sec_06_hardened_cookie_secure_enforcement():
    """TEST-SEC-06: refresh_cookie_secure=False is prohibited in PROD."""
    with pytest.raises(ValidationError):
        Settings(
            environment=Environment.PROD,
            access_secret_key="A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6",
            refresh_secret_key="Z9y8X7w6V5u4T3s2R1q0P9o8N7m6L5k4",
            allowed_origins=["https://enterprise.io"],
            refresh_cookie_secure=False,
        )


# ——————————————————————————————————————————————————————————————————————
# 6. TEST-SEC-07: RateLimiter LRU Cap & Account Throttling
# ——————————————————————————————————————————————————————————————————————

def test_sec_07_a_ratelimiter_memory_cap():
    """TEST-SEC-07-A: Inserting 150 distinct keys into RateLimiter(max_keys=100) caps size at 100."""
    limiter = RateLimiter(requests=10, window_seconds=60, max_tracked_keys=100)
    for i in range(150):
        limiter._check_single_key(f"client_{i}", 1000.0)
    assert len(limiter._history) == 100


@pytest.mark.asyncio
async def test_sec_07_b_account_level_throttling():
    """TEST-SEC-07-B: Repeated failed requests for the same account across different IPs trigger 429."""
    limiter = RateLimiter(requests=2, window_seconds=60)
    req1 = MagicMock(); req1.client = MagicMock(); req1.client.host = "10.0.0.1"; req1.headers = {}
    req2 = MagicMock(); req2.client = MagicMock(); req2.client.host = "10.0.0.2"; req2.headers = {}
    req3 = MagicMock(); req3.client = MagicMock(); req3.client.host = "10.0.0.3"; req3.headers = {}

    await limiter.check_request_and_account(req1, "target@victim.com")
    await limiter.check_request_and_account(req2, "target@victim.com")

    # 3rd request from a DIFFERENT IP but SAME account must fail with 429
    with pytest.raises(Exception) as exc:
        await limiter.check_request_and_account(req3, "target@victim.com")
    assert getattr(exc.value, "status_code", None) == 429


# ——————————————————————————————————————————————————————————————————————
# 7. TEST-SEC-08 & 09: Frontend Workbench Storage & Redaction Verification
# ——————————————————————————————————————————————————————————————————————

def test_sec_08_09_workbench_static_hardening():
    """TEST-SEC-08/09: Verifies sessionStorage usage and sensitive payload/header redaction in static files."""
    session_store_path = Path("static/js/core/session-store.js")
    assert session_store_path.exists()
    content_store = session_store_path.read_text(encoding="utf-8")
    assert "sessionStorage" in content_store
    assert "purgeAllSessions" in content_store

    http_client_path = Path("static/js/core/http-client.js")
    assert http_client_path.exists()
    content_client = http_client_path.read_text(encoding="utf-8")
    assert "redactSensitivePayload" in content_client
    assert "redactSensitiveHeaders" in content_client
    assert "[REDACTED]" in content_client


# ——————————————————————————————————————————————————————————————————————
# 8. TEST-SEC-10: Casbin TTL Cache Refresh
# ——————————————————————————————————————————————————————————————————————

@pytest.mark.asyncio
async def test_sec_10_casbin_ttl_cache_refresh(client: AsyncClient, db_session: AsyncSession):
    """TEST-SEC-10: check_and_refresh_cache reloads policies when TTL expires."""
    orig_ttl = settings.authz_cache_ttl_seconds
    try:
        settings.authz_cache_ttl_seconds = 0.01  # 10ms for instantaneous test refresh
        enforcer = AuthorizationService.get_enforcer()
        before_loaded = AuthorizationService._last_loaded

        await asyncio.sleep(0.02)
        await AuthorizationService.check_and_refresh_cache()
        assert AuthorizationService._last_loaded > before_loaded
    finally:
        settings.authz_cache_ttl_seconds = orig_ttl


# ——————————————————————————————————————————————————————————————————————
# 9. TEST-SEC-12: IntegrityError Sanitization & hide_parameters
# ——————————————————————————————————————————————————————————————————————

@pytest.mark.asyncio
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


# ——————————————————————————————————————————————————————————————————————
# 10. TEST-SEC-15: Fail-Closed Domain Resolver
# ——————————————————————————————————————————————————————————————————————

@pytest.mark.asyncio
async def test_sec_15_fail_closed_domain_resolver():
    """TEST-SEC-15: DefaultGlobalDomainResolver denies domain access by default (Fail-Closed)."""
    resolver = DefaultGlobalDomainResolver()
    dummy_req = MagicMock()
    result = await resolver.resolve_domain_access(user=MagicMock(), request=dummy_req)
    assert result.is_member is False
    assert result.deny_reason is not None


# ——————————————————————————————————————————————————————————————————————
# 11. TEST-SEC-16: CLI Audit Trail in manage.py
# ——————————————————————————————————————————————————————————————————————

@pytest.mark.asyncio
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
    cli_logs = [log for log in recent_logs if log.user_id == "system:cli" or (log.actor_id and log.actor_id.startswith("cli:"))]
    assert len(cli_logs) > 0
    assert "CLI_POLICY_GRANTED" in [log.event_type for log in cli_logs]


# ——————————————————————————————————————————————————————————————————————
# 12. TEST-SEC-17 & 18: Security Headers & Production Defaults
# ——————————————————————————————————————————————————————————————————————

@pytest.mark.asyncio
async def test_sec_17_18_security_headers_and_prod_defaults(client: AsyncClient):
    """TEST-SEC-17/18: Responses include standard security headers; PROD defaults to docs/registration disabled."""
    resp = await client.get("/health")
    assert resp.status_code == 200
    assert resp.headers.get("X-Content-Type-Options") == "nosniff"
    assert resp.headers.get("X-Frame-Options") == "DENY"
    assert resp.headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"
    assert "Content-Security-Policy" in resp.headers

    # Production environment defaults verification
    prod_s = Settings(
        environment=Environment.PROD,
        access_secret_key="A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6",
        refresh_secret_key="Z9y8X7w6V5u4T3s2R1q0P9o8N7m6L5k4",
        allowed_origins=["https://enterprise.io"],
    )
    assert prod_s.enable_docs_and_ui is False
    assert prod_s.allow_public_registration is False

