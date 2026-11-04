from unittest.mock import MagicMock

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from src.exc import AccessDeniedException
from src.modules.auth.router import verify_cookie_csrf_origin
from src.modules.user import User, UserRepository
from src.security import hash_password
from src.settings import settings
from src.share import Roles


@pytest.mark.security_audit
def test_sec_01_a_csrf_prefix_bypass_rejected(monkeypatch: pytest.MonkeyPatch):
    """TEST-SEC-01-A: Origin prefix attacker matching is strictly rejected."""
    monkeypatch.setattr(settings, "allowed_origins", ["https://trusted.com"])
    req = MagicMock()
    req.headers = {"origin": "https://trusted.com.attacker.test"}
    with pytest.raises(AccessDeniedException, match="untrusted"):
        verify_cookie_csrf_origin(req)


@pytest.mark.security_audit
def test_sec_01_b_csrf_missing_headers_rejected(monkeypatch: pytest.MonkeyPatch):
    """TEST-SEC-01-B: Missing or 'null' Origin and Referer headers fail-closed."""
    monkeypatch.setattr(settings, "allowed_origins", ["https://trusted.com"])
    req1 = MagicMock()
    req1.headers = {}
    with pytest.raises(AccessDeniedException, match="required"):
        verify_cookie_csrf_origin(req1)

    req2 = MagicMock()
    req2.headers = {"origin": "null"}
    with pytest.raises(AccessDeniedException, match="required"):
        verify_cookie_csrf_origin(req2)


@pytest.mark.security_audit
def test_sec_01_c_csrf_wildcard_rejected(monkeypatch: pytest.MonkeyPatch):
    """TEST-SEC-01-C: Wildcard origin '*' is prohibited for cookie authentication."""
    monkeypatch.setattr(settings, "allowed_origins", ["*"])
    req = MagicMock()
    req.headers = {"origin": "https://trusted.com"}
    with pytest.raises(AccessDeniedException, match="wildcard"):
        verify_cookie_csrf_origin(req)


@pytest.mark.security_audit
async def test_sec_03_cookie_only_redacts_refresh_token(
    client: AsyncClient,
    db_session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
):
    """TEST-SEC-03: When auth_transport_mode='cookie', JSON response body has refresh_token=None."""
    monkeypatch.setattr(settings, "auth_transport_mode", "cookie")

    # Register user
    user_repo = UserRepository(session=db_session)
    await user_repo.create(
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
