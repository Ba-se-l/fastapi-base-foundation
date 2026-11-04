from datetime import datetime, timezone
import json
from pathlib import Path
import re
import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from src.settings import settings
from src.modules.audit import (
    AuditLogRepository,
    ExportFormat,
    LogAction,
    LogSeverity,
    drain_background_tasks,
    export_audit_logs,
    get_user_audit_logs,
    log_event,
    save_failed_event,
    save_success_event,
)
from src.modules.audit.schemas import LogEvent, LogExportParams
from src.modules.user import User, UserRepository
from src.security import hash_password
from tests.conftest import create_test_access_token
from src.share import Roles


@pytest.mark.asyncio
async def test_audit_service_operations(db_session: AsyncSession):
    """Tests programmatic service logging, querying, and formatting."""
    # 1. Log success event for user 101
    log1 = await save_success_event(
        message='User logged in via biometric verification',
        event_type=LogAction.AUTH_LOGIN_SUCCESS,
        user_id='101',
        request_id='req-alpha-1',
        ip_address='192.168.1.50',
        extra_data={'method': 'fingerprint'},
        session=db_session,
    )
    assert log1.id is not None
    assert log1.severity == 'INFO'
    assert log1.user_id == '101'

    # 2. Log failed event for user 101
    log2 = await save_failed_event(
        message='Failed payment attempt for invoice #99',
        event_type=LogAction.SYSTEM_ERROR,
        severity=LogSeverity.WARNING,
        user_id='101',
        session=db_session,
    )
    assert log2.severity == 'WARNING'

    # 3. Log event for another user 202
    await save_success_event(
        message='User 202 profile updated',
        event_type=LogAction.USER_UPDATED,
        user_id='202',
        session=db_session,
    )
    await db_session.commit()

    # 4. Query logs specific to user 101
    user_101_logs, total_101 = await get_user_audit_logs('101', session=db_session)
    assert total_101 == 2
    assert len(user_101_logs) == 2
    assert all(entry.user_id == '101' for entry in user_101_logs)

    # 5. Test Export in all 3 formats for user 101
    # a. JSON export
    json_content, json_media, json_file = await export_audit_logs(
        LogExportParams(format=ExportFormat.JSON, user_id='101'),
        session=db_session,
    )
    assert json_media == 'application/json'
    assert json_file.endswith('.json')
    parsed_json = json.loads(json_content)
    assert len(parsed_json) == 2

    # b. TXT export
    txt_content, txt_media, txt_file = await export_audit_logs(
        LogExportParams(format=ExportFormat.TXT, user_id='101'),
        session=db_session,
    )
    assert 'text/plain' in txt_media
    assert txt_file.endswith('.txt')
    assert '[USER: 101]' in txt_content
    assert 'AUTH_LOGIN_SUCCESS' in txt_content

    # c. Markdown export
    md_content, md_media, md_file = await export_audit_logs(
        LogExportParams(format=ExportFormat.MARKDOWN, user_id='101'),
        session=db_session,
    )
    assert 'text/markdown' in md_media
    assert md_file.endswith('.md')
    assert '| ID | Timestamp (UTC) | Severity |' in md_content
    assert '`AUTH_LOGIN_SUCCESS`' in md_content


@pytest.mark.asyncio
async def test_audit_api_endpoints_and_rbac(client: AsyncClient, db_session: AsyncSession):
    """Tests administrative HTTP endpoints for audit log querying, filtering, and export."""
    user_repo = UserRepository(session=db_session)

    # 1. Seed Admin & Normal User
    admin = User(
        name='Security Officer',
        email='sec-admin@enterprise.io',
        hashed_password=hash_password('SecAdmin123!'),
        role=Roles.ADMIN,
        is_active=True,
    )
    await user_repo.create(admin)

    normal_user = User(
        name='Regular Employee',
        email='employee@enterprise.io',
        hashed_password=hash_password('Employee123!'),
        role=Roles.USER,
        is_active=True,
    )
    await user_repo.create(normal_user)
    await db_session.commit()

    admin_token = await create_test_access_token(db_session, user_id=admin.id)
    user_token = await create_test_access_token(db_session, user_id=normal_user.id)

    # 2. Seed audit log entries
    await save_success_event(
        message='Root login from corporate network',
        event_type=LogAction.AUTH_LOGIN_SUCCESS,
        user_id=str(admin.id),
        session=db_session,
    )
    await save_failed_event(
        message='Unauthorized sensitive file read attempt',
        event_type=LogAction.SECURITY_ACCESS_DENIED,
        severity=LogSeverity.CRITICAL,
        user_id=str(normal_user.id),
        session=db_session,
    )
    await db_session.commit()

    # 3. Normal user denied access -> 403 Forbidden
    denied_resp = await client.get(
        '/api/v1/audit/logs',
        headers={'Authorization': f'Bearer {user_token}'},
    )
    assert denied_resp.status_code == 403
    assert denied_resp.json()['error']['code'] == 'ACCESS_DENIED'

    # 4. Admin accesses logs list -> 200 OK
    admin_resp = await client.get(
        '/api/v1/audit/logs',
        headers={'Authorization': f'Bearer {admin_token}'},
    )
    assert admin_resp.status_code == 200
    list_data = admin_resp.json()
    assert list_data['success'] is True
    assert list_data['pagination']['total'] >= 2

    # 5. Admin accesses user-specific audit trail
    user_logs_resp = await client.get(
        f'/api/v1/audit/users/{normal_user.id}/logs',
        headers={'Authorization': f'Bearer {admin_token}'},
    )
    assert user_logs_resp.status_code == 200
    user_trail = user_logs_resp.json()
    assert user_trail['pagination']['total'] == 1
    assert user_trail['data'][0]['user_id'] == str(normal_user.id)
    assert user_trail['data'][0]['severity'] == 'CRITICAL'

    # 6. Admin downloads export file in Markdown
    export_resp = await client.get(
        f'/api/v1/audit/users/{normal_user.id}/export?format=md',
        headers={'Authorization': f'Bearer {admin_token}'},
    )
    assert export_resp.status_code == 200
    assert 'text/markdown' in export_resp.headers['content-type']
    assert 'attachment; filename="user_' in export_resp.headers['content-disposition']
    assert '| ID | Timestamp (UTC) | Severity |' in export_resp.text
    assert 'SECURITY_ACCESS_DENIED' in export_resp.text


@pytest.mark.asyncio
async def test_audit_context_and_sanitization(client: AsyncClient, db_session: AsyncSession):
    """Verifies AuditContext injection, password sanitization in logs, and diff tracking."""
    from src.share import AuditContext
    from src.modules.audit.repo import AuditLogRepository

    audit_repo = AuditLogRepository(session=db_session)

    # 1. Direct test of AuditContext with save_success_event
    ctx = AuditContext(
        ip_address="10.0.0.99",
        user_agent="AutomatedAuditor/1.0",
        request_id="req-ctx-test-123",
    )
    log = await save_success_event(
        message="Context injection test",
        event_type=LogAction.CUSTOM,
        session=db_session,
        ctx=ctx,
    )
    assert log.ip_address == "10.0.0.99"
    assert log.user_agent == "AutomatedAuditor/1.0"
    assert log.request_id == "req-ctx-test-123"

    # 2. Register user via API and verify password is NOT leaked in audit logs
    reg_payload = {
        "name": "Audit Sanitize User",
        "email": "audit.sanitize@example.com",
        "password": "StrongPassword123!",
    }
    reg_resp = await client.post(
        "/api/v1/auth/register",
        json=reg_payload,
        headers={"User-Agent": "TestClient/2.0"},
    )
    assert reg_resp.status_code == 201
    created_user_id = reg_resp.json()["id"]

    # Query audit logs for USER_REGISTERED
    await db_session.commit()
    user_logs, _ = await audit_repo.get_by_user(str(created_user_id))
    reg_log = next((l for l in user_logs if l.event_type == LogAction.USER_REGISTERED), None)
    assert reg_log is not None
    assert reg_log.extra_data is not None
    # Crucial security check: password must NEVER be in extra_data!
    assert "password" not in reg_log.extra_data
    assert reg_log.extra_data.get("email") == "audit.sanitize@example.com"
    assert reg_log.ip_address == "127.0.0.1"
    assert reg_log.user_agent == "TestClient/2.0"

    # 3. Update user and verify old vs new diff and NO duplicate skip log
    login_resp = await client.post(
        "/api/v1/auth/login",
        json={"email": "audit.sanitize@example.com", "password": "StrongPassword123!"},
    )
    assert login_resp.status_code == 200
    token = login_resp.json()["access_token"]

    update_resp = await client.patch(
        f"/api/v1/users/{created_user_id}",
        json={"name": "Audit Sanitize User Updated"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert update_resp.status_code == 200

    await db_session.commit()
    user_logs_after, _ = await audit_repo.get_by_user(str(created_user_id))
    update_logs = [l for l in user_logs_after if l.event_type == LogAction.USER_UPDATED]
    # Verify exactly 1 update log occurred (no duplicate skip log!)
    assert len(update_logs) == 1
    assert update_logs[0].severity == "INFO"
    assert "name" in update_logs[0].extra_data
    assert update_logs[0].extra_data["name"]["old"] == "Audit Sanitize User"
    assert update_logs[0].extra_data["name"]["new"] == "Audit Sanitize User Updated"


@pytest.mark.asyncio
async def test_audit_file_written_even_if_db_fails(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, db_session: AsyncSession):
    """Verifies that audit file appending succeeds reliably even when database persistence throws an exception."""
    monkeypatch.setattr(settings, "log_to_file", True)
    monkeypatch.setattr(settings, "log_to_db", True)
    monkeypatch.setattr(settings, "log_dir", str(tmp_path))

    async def mock_create(self, instance):
        raise RuntimeError("Simulated DB Connection Crash")

    monkeypatch.setattr(AuditLogRepository, "create", mock_create)

    event = LogEvent(
        event_type="DB_FAILURE_TEST",
        severity=LogSeverity.ERROR,
        message="This must be written to disk despite DB failure",
        user_id="user_db_fail_1",
    )

    with pytest.raises(RuntimeError, match="Simulated DB Connection Crash"):
        await log_event(event=event, session=db_session)

    # Await background task drain
    await drain_background_tasks()

    # Verify file was written
    date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    json_file = tmp_path / f"{date_str}.json"
    assert json_file.exists()
    content = json_file.read_text(encoding="utf-8")
    assert "This must be written to disk despite DB failure" in content


@pytest.mark.asyncio
async def test_drain_background_tasks_clears_pending_set(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Verifies that drain_background_tasks awaits all pending background writes."""
    monkeypatch.setattr(settings, "log_to_file", True)
    monkeypatch.setattr(settings, "log_to_db", False)
    monkeypatch.setattr(settings, "log_dir", str(tmp_path))

    event = LogEvent(event_type="DRAIN_TEST", message="Drain message")
    await log_event(event=event)
    await drain_background_tasks()
    from src.modules.audit.service import _background_tasks
    assert len(_background_tasks) == 0


@pytest.mark.asyncio
async def test_export_filename_sanitization(client: AsyncClient, db_session: AsyncSession):
    """Verifies that export filenames are sanitized against path traversal and CRLF headers."""
    admin_pass = "AdminP@ssw0rd!1"
    admin_payload = {"name": "Admin Export", "email": "admin.export@enterprise.io", "password": admin_pass}
    await client.post("/api/v1/auth/register", json=admin_payload)

    user_repo = UserRepository(session=db_session)
    admin_user = await user_repo.get_by_email("admin.export@enterprise.io")
    await user_repo.update(instance=admin_user, update_dict={"role": Roles.ADMIN})
    await db_session.commit()

    login_resp = await client.post("/api/v1/auth/login", json={"email": admin_payload["email"], "password": admin_pass})
    token = login_resp.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    malicious_uid = 'a"b; c\r\nد'
    resp = await client.get(
        "/api/v1/audit/export",
        params={"user_id": malicious_uid, "format": "json"},
        headers=headers,
    )
    assert resp.status_code == 200
    cd = resp.headers.get("Content-Disposition", "")
    assert cd is not None
    assert "\r" not in cd
    assert "\n" not in cd

    match = re.search(r'filename="([^"]+)"', cd)
    assert match is not None
    filename = match.group(1)
    assert re.match(r'^[A-Za-z0-9_.-]+$', filename) is not None

