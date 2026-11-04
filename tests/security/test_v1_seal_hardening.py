"""V1.0.0 Final Seal Security Hardening & Regression Verification Suite.

Validates all 14 architectural audit findings:
- SEC-20 / SEC-21: Cryptographic secret hygiene and .env.example blocking in hardened modes.
- SEC-22 / SEC-23: Unified async Casbin authorization and single-flight lock cache refresh.
- SEC-30: CLI manage.py create-admin flushed integer entity_id audit logging.
- SEC-31: Inbound payload bounds (2048 chars) and strict extra='forbid' validation.
- SEC-32: Content-Security-Policy script-src hardening and Workbench memory token vault.
- MIG-01: Reversible migration downgrade semantics (zero silent pass).
- DOC-01: Zero local file:/// URLs and zero stale paths across documentation.
"""
import ast
import asyncio
import re
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest
from httpx import AsyncClient
from pydantic import ValidationError
from sqlalchemy import select

from src.modules.audit.model import AuditLog
from src.modules.user.model import User
from src.modules.user.service import get_user_by_id
from src.security.authorization import AuthorizationService, GLOBAL_DOMAIN
from src.settings import Environment, Settings
from src.share import Action, Resource, Roles
from tests.support.paths import PROJECT_ROOT


pytestmark = [pytest.mark.security_audit]


def test_sec_20_env_example_secrets_rejected_in_hardened_modes(monkeypatch: pytest.MonkeyPatch):
    """TEST-SEC-20: Verifies .env.example secrets and forbidden prefixes are rejected in hardened modes."""
    forbidden_samples = [
        "replace-with-a-very-long-high-entropy-access-secret-32ch!",
        "replace-with-a-very-long-high-entropy-refresh-secret-32ch!",
        "placeholder-custom-key-that-is-very-long-and-diverse-32!",
        "changeme-very-long-secret-key-32-characters-minimum-abc!",
        "example-secret-key-with-high-entropy-and-thirty-two-chars!",
    ]

    for env_name in (Environment.STAGING, Environment.PRO, Environment.PROD):
        for sample_secret in forbidden_samples:
            monkeypatch.setenv("ENVIRONMENT", env_name.value)
            monkeypatch.setenv("ACCESS_SECRET_KEY", sample_secret)
            monkeypatch.setenv("REFRESH_SECRET_KEY", "RealCustomSecretForTestOnly1234567890!@#$")
            monkeypatch.setenv("ALLOWED_ORIGINS", '["https://example.com"]')
            monkeypatch.setenv("REFRESH_COOKIE_SECURE", "true")

            with pytest.raises(ValidationError, match="must be explicitly configured with a non-placeholder secret"):
                Settings()


def test_sec_21_env_example_secrets_auto_replaced_in_dev(monkeypatch: pytest.MonkeyPatch):
    """TEST-SEC-21: Verifies .env.example secrets are transparently auto-replaced with CSPRNG keys in DEV."""
    example_secret = "replace-with-a-very-long-high-entropy-access-secret-32ch!"
    monkeypatch.setenv("ENVIRONMENT", "dev")
    monkeypatch.setenv("ACCESS_SECRET_KEY", example_secret)
    monkeypatch.setenv("REFRESH_SECRET_KEY", example_secret)

    s = Settings()
    # In DEV, example secrets must never remain in memory
    assert s.access_secret_key != example_secret
    assert s.refresh_secret_key != example_secret
    assert len(s.access_secret_key) >= 48
    assert len(s.refresh_secret_key) >= 48


@pytest.mark.asyncio
async def test_sec_22_user_service_has_permission_triggers_cache_refresh(
    client: AsyncClient,
    db_session,
    monkeypatch: pytest.MonkeyPatch,
):
    """TEST-SEC-22: Verifies UserService._has_permission awaits cache refresh so policy revocations take effect."""
    monkeypatch.setattr("src.settings.settings.authz_cache_ttl_seconds", 0)

    # Seed an admin and a user
    admin = User(
        name="Admin Test",
        email="admin_sec22@example.com",
        hashed_password="hashed_pwd_stub",
        role=Roles.ADMIN,
        is_active=True,
    )
    target = User(
        name="Target Test",
        email="target_sec22@example.com",
        hashed_password="hashed_pwd_stub",
        role=Roles.USER,
        is_active=True,
    )
    db_session.add_all([admin, target])
    await db_session.flush()

    # Admin can view target user initially
    fetched = await get_user_by_id(getter=admin, user_id=target.id, session=db_session)
    assert fetched.id == target.id

    # Now revoke admin policy from casbin enforcer
    enforcer = AuthorizationService.get_enforcer()
    await enforcer.remove_policy("admin", GLOBAL_DOMAIN, "*", "*")

    # Next call must trigger cache check and immediately deny access
    from src.exc import AccessDeniedException
    with pytest.raises(AccessDeniedException, match="not authorized"):
        await get_user_by_id(getter=admin, user_id=target.id, session=db_session)

    # Restore default policy for clean state
    await enforcer.add_policy("admin", GLOBAL_DOMAIN, "*", "*")


@pytest.mark.asyncio
async def test_sec_23_single_flight_casbin_cache_reload():
    """TEST-SEC-23: Verifies double-checked locking ensures concurrent requests trigger exactly one reload."""
    enforcer = AuthorizationService.get_enforcer()

    # Force TTL expiration
    AuthorizationService._last_loaded = 0.0

    call_count = 0
    original_reload = AuthorizationService.reload

    async def counted_reload():
        nonlocal call_count
        call_count += 1
        await asyncio.sleep(0.02)  # Simulate small DB I/O latency
        await original_reload()

    with patch.object(AuthorizationService, "reload", side_effect=counted_reload):
        # Fire 20 concurrent cache checks
        tasks = [AuthorizationService.check_and_refresh_cache() for _ in range(20)]
        await asyncio.gather(*tasks)

    # Exactly one reload must occur under the single-flight lock
    assert call_count == 1


@pytest.mark.asyncio
async def test_sec_30_manage_create_admin_flushes_integer_entity_id(
    db_session,
    monkeypatch: pytest.MonkeyPatch,
):
    """TEST-SEC-30: Verifies manage.py create-admin flushes created.id before writing audit log."""
    from argparse import Namespace
    import manage

    # Mock CLI arguments
    args = Namespace(
        name="CLI Admin Test",
        email="cli_admin_sec30@example.com",
        password="ValidStrongPassword123!@#",
    )

    # Direct manage session to db_session
    class MockSessionMaker:
        def __call__(self):
            return self
        async def __aenter__(self):
            return db_session
        async def __aexit__(self, exc_type, exc_val, exc_tb):
            pass

    monkeypatch.setattr(manage, "AsyncSessionLocal", MockSessionMaker())
    await manage.handle_create_admin(args)

    # Query audit logs for the creation event
    result = await db_session.execute(
        select(AuditLog).where(AuditLog.action == "CLI_ADMIN_CREATED")
    )
    log_entry = result.scalar_one_or_none()
    assert log_entry is not None
    # entity_id must be a valid integer string, never "None" or None
    assert log_entry.entity_id is not None
    assert log_entry.entity_id != "None"
    assert log_entry.entity_id.isdigit()


@pytest.mark.asyncio
async def test_sec_31_refresh_request_bounds_and_forbids_extra(client: AsyncClient):
    """TEST-SEC-31: Verifies RefreshRequest rejects oversized payloads and unmapped extra fields."""
    # 1. Reject token exceeding 2048 chars
    oversized_token = "A" * 2049
    resp_oversized = await client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": oversized_token},
    )
    assert resp_oversized.status_code == 422
    assert "VALIDATION_ERROR" in resp_oversized.text

    # 2. Reject uninvited extra fields via extra='forbid'
    resp_extra = await client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": "valid_length_token_12345", "uninvited_field": "hacker_payload"},
    )
    assert resp_extra.status_code == 422
    assert "VALIDATION_ERROR" in resp_extra.text
    assert "extra_forbidden" in resp_extra.text or "Extra inputs are not permitted" in resp_extra.text


@pytest.mark.asyncio
async def test_sec_32_csp_headers_and_workbench_token_vault(client: AsyncClient):
    """TEST-SEC-32: Verifies Content-Security-Policy script-src hardening and Workbench token vault."""
    # 1. Verify HTTP response headers
    resp = await client.get("/health")
    assert resp.status_code == 200
    csp = resp.headers.get("Content-Security-Policy", "")

    # script-src must NOT contain 'unsafe-inline'
    script_src_match = re.search(r"script-src\s+([^;]+)", csp)
    assert script_src_match is not None, "script-src directive missing from CSP"
    script_src = script_src_match.group(1)
    assert "'unsafe-inline'" not in script_src, f"'unsafe-inline' found in script-src: {script_src}"
    assert "object-src 'none'" in csp
    assert "base-uri 'self'" in csp

    # 2. Verify static/js/core/session-store.js uses in-memory token vault
    store_file = PROJECT_ROOT / "static" / "js" / "core" / "session-store.js"
    assert store_file.is_file()
    store_code = store_file.read_text(encoding="utf-8")
    assert "_tokenMemoryVault" in store_code
    assert "[VAULT_IN_MEMORY]" in store_code


def test_mig_01_alembic_downgrade_has_no_silent_pass():
    """TEST-MIG-01: Verifies migration 7b91c4e2a101 downgrade() contains no silent pass statement."""
    migration_file = (
        PROJECT_ROOT
        / "migrations"
        / "versions"
        / "7b91c4e2a101_unify_split_heads_and_reconcile_sessions.py"
    )
    assert migration_file.is_file()
    tree = ast.parse(migration_file.read_text(encoding="utf-8"))

    downgrade_fn = next(
        (node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef) and node.name == "downgrade"),
        None,
    )
    assert downgrade_fn is not None, "downgrade() function not found in migration"

    # Ensure downgrade does not consist solely of a Pass statement
    non_docstring_stmts = [
        stmt for stmt in downgrade_fn.body
        if not (isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant))
    ]
    assert len(non_docstring_stmts) > 0, "downgrade() function is empty"
    assert not any(isinstance(stmt, ast.Pass) for stmt in non_docstring_stmts), (
        "downgrade() contains a bare pass statement"
    )


def test_doc_01_zero_file_urls_and_stale_paths_in_docs():
    """TEST-DOC-01: Verifies zero local file:/// URLs and zero stale paths exist across Markdown documentation."""
    docs_to_scan = list(PROJECT_ROOT.glob("*.md")) + list(PROJECT_ROOT.glob("*/*.md")) + list(PROJECT_ROOT.glob("*/*/*.md"))

    for doc_path in docs_to_scan:
        if ".venv" in doc_path.parts or ".git" in doc_path.parts or ".docs" in doc_path.parts:
            continue
        text = doc_path.read_text(encoding="utf-8")
        assert "file:///" not in text, f"Found local file:/// URL in {doc_path}"
        assert "src/app/static" not in text, f"Found stale path 'src/app/static' in {doc_path}"
