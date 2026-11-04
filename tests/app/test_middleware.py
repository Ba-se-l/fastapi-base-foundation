import pytest
from httpx import AsyncClient

from src.settings import Environment, Settings
from src.share.limits import AUDIT_REQUEST_ID_MAX


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


@pytest.mark.security_audit
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
