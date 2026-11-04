from httpx import AsyncClient


async def test_health_endpoints(client: AsyncClient):
    """Verifies liveness and readiness probe responses."""
    # Liveness check
    liveness_resp = await client.get("/health")
    assert liveness_resp.status_code == 200
    live_data = liveness_resp.json()
    assert live_data["status"] == "ok"
    assert "version" in live_data
    assert "environment" in live_data

    # Readiness check
    ready_resp = await client.get("/health/ready")
    assert ready_resp.status_code == 200
    ready_data = ready_resp.json()
    assert ready_data["status"] == "ok"
    assert ready_data["checks"]["database"] == "ok"
