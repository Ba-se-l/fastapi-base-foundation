import pytest
from pydantic import ValidationError

from src.settings import Environment, Settings


def test_settings_algorithm_rejection():
    """Verifies that unsupported or weak JWT algorithms are rejected in all environments."""
    with pytest.raises(ValidationError, match="Unsupported JWT algorithm 'none'"):
        Settings(algorithm="none")
    with pytest.raises(ValidationError, match="Unsupported JWT algorithm 'RS256'"):
        Settings(algorithm="RS256")
    with pytest.raises(ValidationError, match="Unsupported JWT algorithm 'HS128'"):
        Settings(algorithm="HS128")


def test_settings_proxy_validation():
    """Verifies that enabling proxy headers requires a non-empty, valid trusted_proxies list."""
    with pytest.raises(ValidationError, match="`trust_proxy_headers` is True but `trusted_proxies` is empty"):
        Settings(trust_proxy_headers=True, trusted_proxies=[])

    with pytest.raises(ValidationError, match="Invalid IP address or CIDR network in trusted_proxies"):
        Settings(trust_proxy_headers=True, trusted_proxies=["not-a-valid-ip"])

    s = Settings(trust_proxy_headers=True, trusted_proxies=["127.0.0.1", "10.0.0.0/8"])
    assert s.trust_proxy_headers is True
    assert "127.0.0.1" in s.trusted_proxies
    assert "10.0.0.0/8" in s.trusted_proxies


@pytest.mark.parametrize("env", [Environment.STAGING, Environment.PRO], ids=["staging", "pro"])
def test_settings_hardened_environments_rules(env: Environment):
    """Verifies secrets validation in STAGING and PRO environments."""
    # Short secret key (< 32 chars)
    with pytest.raises(ValidationError, match="must be at least 32 characters long"):
        Settings(
            environment=env,
            access_secret_key="short",
            refresh_secret_key="Z9y8X7w6V5u4T3s2R1q0P9o8N7m6L5k4",
            allowed_origins=["https://enterprise.io"],
        )

    # Identical access and refresh secret keys (using high-entropy keys to isolate distinct-secrets rule)
    high_entropy_key = "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6"
    with pytest.raises(ValidationError, match="must be distinct secrets"):
        Settings(
            environment=env,
            access_secret_key=high_entropy_key,
            refresh_secret_key=high_entropy_key,
            allowed_origins=["https://enterprise.io"],
        )

    # Placeholder secret key
    with pytest.raises(ValidationError, match="must be explicitly configured with a non-placeholder secret"):
        Settings(
            environment=env,
            access_secret_key="placeholder-change-it-in-production-mode",
            refresh_secret_key="Z9y8X7w6V5u4T3s2R1q0P9o8N7m6L5k4",
            allowed_origins=["https://enterprise.io"],
        )

    # Valid settings pass
    valid_settings = Settings(
        environment=env,
        access_secret_key="A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6",
        refresh_secret_key="Z9y8X7w6V5u4T3s2R1q0P9o8N7m6L5k4",
        allowed_origins=["https://enterprise.io"],
        echo=False,
        reload=False,
    )
    assert valid_settings.environment == env


def test_settings_entropy_and_hardened_rejections():
    """Verifies low-entropy secrets, wildcard origins, and insecure cookies are rejected in hardened modes."""
    with pytest.raises(ValidationError, match="lacks sufficient character diversity/entropy"):
        Settings(
            environment=Environment.PROD,
            access_secret_key="a" * 32,
            refresh_secret_key="Z9y8X7w6V5u4T3s2R1q0P9o8N7m6L5k4",
            allowed_origins=["https://enterprise.io"],
        )

    with pytest.raises(ValidationError, match="must not contain wildcard"):
        Settings(
            environment=Environment.STAGING,
            access_secret_key="A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6",
            refresh_secret_key="Z9y8X7w6V5u4T3s2R1q0P9o8N7m6L5k4",
            allowed_origins=["*"],
        )

    with pytest.raises(ValidationError, match="REFRESH_COOKIE_SECURE` cannot be False"):
        Settings(
            environment=Environment.PROD,
            access_secret_key="A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6",
            refresh_secret_key="Z9y8X7w6V5u4T3s2R1q0P9o8N7m6L5k4",
            allowed_origins=["https://enterprise.io"],
            refresh_cookie_secure=False,
        )

    with pytest.raises(ValidationError, match="SameSite='none' requires Secure=True"):
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


@pytest.mark.security_audit
def test_sec_04_dynamic_dev_keys_and_hardened_enforcement():
    """TEST-SEC-04: DEV generates non-placeholder memory keys; PROD without keys raises ValueError."""
    dev_settings = Settings(environment=Environment.DEV)
    assert not dev_settings.access_secret_key.startswith("placeholder-")
    assert len(dev_settings.access_secret_key) >= 32

    with pytest.raises(ValidationError):
        Settings(environment=Environment.PROD)


@pytest.mark.security_audit
def test_sec_11_secret_entropy_rejection():
    """TEST-SEC-11: Low-entropy secrets (len(set(val)) < 10) are rejected in hardened modes."""
    with pytest.raises(ValidationError, match="lacks sufficient character diversity/entropy"):
        Settings(
            environment=Environment.PROD,
            access_secret_key="a" * 32,
            refresh_secret_key="Z9y8X7w6V5u4T3s2R1q0P9o8N7m6L5k4",
            allowed_origins=["https://enterprise.io"],
        )


@pytest.mark.security_audit
def test_sec_05_staging_wildcard_ban():
    """TEST-SEC-05: Wildcard origin '*' is prohibited in STAGING."""
    with pytest.raises(ValidationError, match="must not contain wildcard"):
        Settings(
            environment=Environment.STAGING,
            access_secret_key="A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6",
            refresh_secret_key="Z9y8X7w6V5u4T3s2R1q0P9o8N7m6L5k4",
            allowed_origins=["*"],
        )


@pytest.mark.security_audit
def test_sec_06_hardened_cookie_secure_enforcement():
    """TEST-SEC-06: refresh_cookie_secure=False is prohibited in PROD."""
    with pytest.raises(ValidationError, match="REFRESH_COOKIE_SECURE` cannot be False"):
        Settings(
            environment=Environment.PROD,
            access_secret_key="A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6",
            refresh_secret_key="Z9y8X7w6V5u4T3s2R1q0P9o8N7m6L5k4",
            allowed_origins=["https://enterprise.io"],
            refresh_cookie_secure=False,
        )
