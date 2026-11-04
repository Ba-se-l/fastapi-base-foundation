import pytest
from starlette.requests import Request

from src.settings import settings
from src.share.helpers import resolve_client_ip


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
