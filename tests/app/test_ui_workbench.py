import pytest
from httpx import AsyncClient

from tests.support.paths import STATIC_DIR


async def test_ui_redirect(client: AsyncClient) -> None:
    """Verifies that GET /ui redirects to /ui/."""
    response = await client.get("/ui", follow_redirects=False)
    assert response.status_code == 307
    assert response.headers["location"] == "/ui/"


async def test_ui_mount_serves_html(client: AsyncClient) -> None:
    """Verifies that GET /ui/ serves static index.html with text/html content-type."""
    response = await client.get("/ui/")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    assert "Enterprise API Workbench" in response.text
    assert '<base href="/ui/">' in response.text


async def test_workbench_full_lifecycle_e2e(client: AsyncClient) -> None:
    """Verifies the complete end-to-end workflow automated by the UI Workbench."""
    demo_email = "workbench.demo@enterprise.io"
    demo_pass = "WorkbenchP@ss123!"
    demo_name = "Workbench Demo User"

    # Register
    reg_res = await client.post(
        "/api/v1/auth/register",
        json={"name": demo_name, "email": demo_email, "password": demo_pass},
    )
    assert reg_res.status_code == 201
    user_id = reg_res.json()["id"]
    assert reg_res.json()["name"] == demo_name

    # Login Device A
    login_a = await client.post(
        "/api/v1/auth/login",
        json={"email": demo_email, "password": demo_pass},
    )
    assert login_a.status_code == 200
    token_a_data = login_a.json()
    access_a = token_a_data["access_token"]
    refresh_a_1 = token_a_data["refresh_token"]

    # Login Device B
    login_b = await client.post(
        "/api/v1/auth/login",
        json={"email": demo_email, "password": demo_pass},
    )
    assert login_b.status_code == 200
    token_b_data = login_b.json()
    access_b = token_b_data["access_token"]
    refresh_b = token_b_data["refresh_token"]

    # Verify both devices have tokens
    assert access_a != access_b
    assert refresh_a_1 != refresh_b

    # Token Rotation on Device A
    rot_a = await client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": refresh_a_1},
    )
    assert rot_a.status_code == 200
    new_token_a_data = rot_a.json()
    access_a_2 = new_token_a_data["access_token"]
    refresh_a_2 = new_token_a_data["refresh_token"]
    assert refresh_a_2 != refresh_a_1

    # Simulate Replay Attack with Revoked refresh_a_1
    replay_res = await client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": refresh_a_1},
    )
    assert replay_res.status_code == 401
    assert replay_res.json()["error"]["code"] == "TOKEN_REVOKED"

    # Smart Device Isolation: Device B remains active
    me_b = await client.get(
        "/api/v1/users/me",
        headers={"Authorization": f"Bearer {access_b}"},
    )
    assert me_b.status_code == 200
    assert me_b.json()["email"] == demo_email

    # User Profile Update & Guardrails
    patch_ok = await client.patch(
        f"/api/v1/users/{user_id}",
        headers={"Authorization": f"Bearer {access_b}"},
        json={"name": "Architect Master"},
    )
    assert patch_ok.status_code == 200
    assert patch_ok.json()["name"] == "Architect Master"

    # Explicit null rejection
    patch_null = await client.patch(
        f"/api/v1/users/{user_id}",
        headers={"Authorization": f"Bearer {access_b}"},
        json={"name": None},
    )
    assert patch_null.status_code == 422

    # Audit Trail: As standard user, audit log access is restricted by RBAC (Casbin)
    audit_forbidden = await client.get(
        "/api/v1/audit/logs",
        headers={"Authorization": f"Bearer {access_b}"},
    )
    assert audit_forbidden.status_code == 403
    assert audit_forbidden.json()["error"]["code"] == "ACCESS_DENIED"


@pytest.mark.security_audit
def test_sec_08_09_workbench_static_hardening():
    """TEST-SEC-08/09: Verifies sessionStorage usage and sensitive payload/header redaction in static files."""
    session_store_path = STATIC_DIR / "js" / "core" / "session-store.js"
    assert session_store_path.exists()
    content_store = session_store_path.read_text(encoding="utf-8")
    assert "sessionStorage" in content_store
    assert "purgeAllSessions" in content_store

    http_client_path = STATIC_DIR / "js" / "core" / "http-client.js"
    assert http_client_path.exists()
    content_client = http_client_path.read_text(encoding="utf-8")
    assert "redactSensitivePayload" in content_client
    assert "redactSensitiveHeaders" in content_client
    assert "[REDACTED]" in content_client
