from unittest.mock import MagicMock

import pytest

from src.security.guards import DefaultGlobalDomainResolver


@pytest.mark.security_audit
async def test_sec_15_fail_closed_domain_resolver():
    """TEST-SEC-15: DefaultGlobalDomainResolver denies domain access by default (Fail-Closed)."""
    resolver = DefaultGlobalDomainResolver()
    dummy_req = MagicMock()
    result = await resolver.resolve_domain_access(user=MagicMock(), request=dummy_req)
    assert result.is_member is False
    assert result.deny_reason is not None
