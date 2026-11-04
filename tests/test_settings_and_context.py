import pytest
from httpx import AsyncClient
from pydantic import ValidationError
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.requests import Request

from src.modules.audit.model import AuditLog
from src.modules.audit.repo import AuditLogRepository
from src.settings import Environment, Settings, settings
from src.share import (
    AUDIT_IP_MAX,
    AUDIT_REQUEST_ID_MAX,
    AUDIT_USER_AGENT_MAX,
    AUDIT_USER_ID_MAX,
    resolve_client_ip,
)


def test_audit_log_model_column_lengths_match_constants():
    """Verifies that AuditLog column definitions exactly match the exported limits constants."""
    table = AuditLog.__table__
    assert table.c.user_id.type.length == AUDIT_USER_ID_MAX
    assert table.c.request_id.type.length == AUDIT_REQUEST_ID_MAX
    assert table.c.ip_address.type.length == AUDIT_IP_MAX
    assert table.c.user_agent.type.length == AUDIT_USER_AGENT_MAX


def test_settings_algorithm_rejection():
    """Verifies that unsupported or weak JWT algorithms are rejected in all environments."""
    with pytest.raises(ValidationError):
        Settings(algorithm="none")
    with pytest.raises(ValidationError):
        Settings(algorithm="RS256")
    with pytest.raises(ValidationError):
        Settings(algorithm="HS128")


def test_settings_proxy_validation():
    """Verifies that enabling proxy headers requires a non-empty, valid trusted_proxies list."""
    # Empty trusted_proxies with trust_proxy_headers=True is rejected (fail-closed)
    with pytest.raises(ValidationError):
        Settings(trust_proxy_headers=True, trusted_proxies=[])

    # Malformed IP/CIDR is rejected
    with pytest.raises(ValidationError):
        Settings(trust_proxy_headers=True, trusted_proxies=["not-a-valid-ip"])

    # Valid IP and CIDR accepted
    s = Settings(trust_proxy_headers=True, trusted_proxies=["127.0.0.1", "10.0.0.0/8"])
    assert s.trust_proxy_headers is True
    assert "127.0.0.1" in s.trusted_proxies
    assert "10.0.0.0/8" in s.trusted_proxies


def test_settings_hardened_environments_rules():
    """Verifies secrets validation in STAGING and PRO environments."""
    for env in (Environment.STAGING, Environment.PRO):
        # Short secret key (< 32 chars)
        with pytest.raises(ValidationError):
            Settings(
                environment=env,
                access_secret_key="short",
                refresh_secret_key="b" * 32,
                allowed_origins=["https://enterprise.io"],
            )

        # Identical access and refresh secret keys
        with pytest.raises(ValidationError):
            Settings(
                environment=env,
                access_secret_key="a" * 32,
                refresh_secret_key="a" * 32,
                allowed_origins=["https://enterprise.io"],
            )

        # Placeholder secret key
        with pytest.raises(ValidationError):
            Settings(
                environment=env,
                access_secret_key="placeholder-change-it-in-production-mode",
                refresh_secret_key="b" * 32,
                allowed_origins=["https://enterprise.io"],
            )

    # Valid production settings pass
    pro_settings = Settings(
        environment=Environment.PRO,
        access_secret_key="A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6",
        refresh_secret_key="Z9y8X7w6V5u4T3s2R1q0P9o8N7m6L5k4",
        allowed_origins=["https://enterprise.io"],
        echo=False,
        reload=False,
    )
    assert pro_settings.environment == Environment.PRO


def test_settings_entropy_and_hardened_rejections():
    """Verifies low-entropy secrets, wildcard origins, and insecure cookies are rejected in hardened modes."""
    with pytest.raises(ValidationError):
        Settings(
            environment=Environment.PROD,
            access_secret_key="a" * 32,
            refresh_secret_key="Z9y8X7w6V5u4T3s2R1q0P9o8N7m6L5k4",
            allowed_origins=["https://enterprise.io"],
        )

    with pytest.raises(ValidationError):
        Settings(
            environment=Environment.STAGING,
            access_secret_key="A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6",
            refresh_secret_key="Z9y8X7w6V5u4T3s2R1q0P9o8N7m6L5k4",
            allowed_origins=["*"],
        )

    with pytest.raises(ValidationError):
        Settings(
            environment=Environment.PROD,
            access_secret_key="A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6",
            refresh_secret_key="Z9y8X7w6V5u4T3s2R1q0P9o8N7m6L5k4",
            allowed_origins=["https://enterprise.io"],
            refresh_cookie_secure=False,
        )

    with pytest.raises(ValidationError):
        Settings(
            environment=Environment.DEV,
            refresh_cookie_secure=False,
            refresh_cookie_samesite="none",
        )


def test_settings_environment_aware_defaults():
    """Verifies environment-aware defaults for docs/ui, public registration, and DEV keys."""
    dev_settings = Settings(environment=Environment.DEV)
    assert dev_settings.allow_public_registration is True
    assert dev_settings.enable_docs_and_ui is True
    assert len(dev_settings.access_secret_key) >= 32
    assert not dev_settings.access_secret_key.startswith("placeholder-")

    prod_settings = Settings(
        environment=Environment.PROD,
        access_secret_key="A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6",
        refresh_secret_key="Z9y8X7w6V5u4T3s2R1q0P9o8N7m6L5k4",
        allowed_origins=["https://enterprise.io"],
    )
    assert prod_settings.allow_public_registration is False
    assert prod_settings.enable_docs_and_ui is False


def test_resolve_client_ip_mechanics(monkeypatch: pytest.MonkeyPatch):
    """Verifies client IP resolution with untrusted and trusted reverse proxies."""
    def make_req(client_host: str, xff: str | None = None) -> Request:
        headers = []
        if xff is not None:
            headers.append((b"x-forwarded-for", xff.encode("utf-8")))
        scope = {
            "type": "http",
            "method": "GET",
            "path": "/",
            "headers": headers,
            "client": (client_host, 54321),
        }
        return Request(scope)

    # 1. Default (trust_proxy_headers=False): X-Forwarded-For is ignored
    monkeypatch.setattr(settings, "trust_proxy_headers", False)
    monkeypatch.setattr(settings, "trusted_proxies", [])
    req1 = make_req("127.0.0.1", "203.0.113.195")
    assert resolve_client_ip(req1) == "127.0.0.1"

    # 2. trust_proxy_headers=True but peer not in trusted_proxies -> distrusted
    monkeypatch.setattr(settings, "trust_proxy_headers", True)
    monkeypatch.setattr(settings, "trusted_proxies", ["10.0.0.1"])
    req2 = make_req("198.51.100.1", "203.0.113.195")
    assert resolve_client_ip(req2) == "198.51.100.1"

    # 3. Peer in trusted_proxies -> returns untrusted client from chain
    monkeypatch.setattr(settings, "trusted_proxies", ["127.0.0.1", "10.0.0.0/8"])
    req3 = make_req("127.0.0.1", "203.0.113.195, 10.0.0.2")
    assert resolve_client_ip(req3) == "203.0.113.195"

    # 4. Malformed XFF header from trusted peer -> falls back safely to peer
    req4 = make_req("127.0.0.1", "invalid_ip_format")
    assert resolve_client_ip(req4) == "127.0.0.1"


@pytest.mark.asyncio
async def test_request_id_middleware_sanitization(client: AsyncClient):
    """Verifies that incoming X-Request-ID headers exceeding limits or containing CRLF are replaced."""
    # Oversized Request ID (> 64 chars)
    long_id = "A" * 500
    resp1 = await client.get("/health", headers={"X-Request-ID": long_id})
    assert resp1.status_code == 200
    req_id1 = resp1.headers.get("X-Request-ID")
    assert req_id1 != long_id
    assert len(req_id1) <= AUDIT_REQUEST_ID_MAX

    # CRLF injection attempt
    injected_id = "clean_part\r\nInjected-Header: true"
    resp2 = await client.get("/health", headers={"X-Request-ID": injected_id})
    assert resp2.status_code == 200
    req_id2 = resp2.headers.get("X-Request-ID")
    assert req_id2 != injected_id
    assert len(req_id2) <= AUDIT_REQUEST_ID_MAX


@pytest.mark.asyncio
async def test_oversized_user_agent_truncated_in_audit_log(client: AsyncClient, db_session: AsyncSession):
    """Verifies that an oversized User-Agent (5000 chars) is truncated to 255 chars in audit persistence."""
    huge_ua = "EnterpriseBot/" + "x" * 5000
    user_payload = {
        "name": "Huge UA User",
        "email": "huge.ua@enterprise.io",
        "password": "StrongPassword123!",
    }
    resp = await client.post(
        "/api/v1/auth/register",
        json=user_payload,
        headers={"User-Agent": huge_ua},
    )
    assert resp.status_code == 201
    user_id = resp.json()["id"]

    await db_session.commit()
    audit_repo = AuditLogRepository(session=db_session)
    user_logs, _ = await audit_repo.get_by_user(str(user_id))
    assert len(user_logs) > 0
    persisted_log = user_logs[0]
    assert len(persisted_log.user_agent) == AUDIT_USER_AGENT_MAX
    assert persisted_log.user_agent == huge_ua[:AUDIT_USER_AGENT_MAX]
