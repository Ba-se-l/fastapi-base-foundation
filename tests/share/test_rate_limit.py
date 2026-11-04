from unittest.mock import MagicMock

import pytest
from fastapi import HTTPException

from src.share.rate_limit import RateLimiter


@pytest.mark.security_audit
def test_sec_07_a_ratelimiter_memory_cap():
    """TEST-SEC-07-A: Inserting 150 distinct keys into RateLimiter(max_keys=100) caps size at 100."""
    limiter = RateLimiter(requests=10, window_seconds=60, max_tracked_keys=100)
    for i in range(150):
        limiter._check_single_key(f"client_{i}", 1000.0)
    assert len(limiter._history) == 100


@pytest.mark.security_audit
async def test_sec_07_b_account_level_throttling():
    """TEST-SEC-07-B: Repeated failed requests for the same account across different IPs trigger 429."""
    limiter = RateLimiter(requests=2, window_seconds=60)
    req1 = MagicMock(); req1.client = MagicMock(); req1.client.host = "10.0.0.1"; req1.headers = {}
    req2 = MagicMock(); req2.client = MagicMock(); req2.client.host = "10.0.0.2"; req2.headers = {}
    req3 = MagicMock(); req3.client = MagicMock(); req3.client.host = "10.0.0.3"; req3.headers = {}

    await limiter.check_request_and_account(req1, "target@victim.com")
    await limiter.check_request_and_account(req2, "target@victim.com")

    # 3rd request from a DIFFERENT IP but SAME account must fail with 429
    with pytest.raises(HTTPException, match="Too many requests") as exc:
        await limiter.check_request_and_account(req3, "target@victim.com")
    assert exc.value.status_code == 429
