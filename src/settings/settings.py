from enum import StrEnum
import ipaddress
from typing import Literal, Self
from pydantic import field_validator, model_validator
from pydantic_settings import BaseSettings as Base, SettingsConfigDict


class Environment(StrEnum):
    """Runtime environment classification."""

    DEV = 'dev'
    TEST = 'test'
    STAGING = 'staging'
    PRO = 'pro'
    PROD = 'prod'


ALLOWED_JWT_ALGORITHMS: frozenset[str] = frozenset({'HS256', 'HS384', 'HS512'})
JWT_SECRET_MIN_LENGTH: int = 32
_HARDENED_ENVIRONMENTS: frozenset[Environment] = frozenset({Environment.STAGING, Environment.PRO, Environment.PROD})


class Settings(Base):

    model_config = SettingsConfigDict(
        env_file='.env',
        env_file_encoding='utf-8'
    )

    # ———————— APP Info ————————
    app_title: str = 'FastAPI Base Structure For Beginning'
    app_version: str = '1.0.0'
    app_description: str = 'placeholder'
    # ————————————————————————————


    # ———————— DB & SERVER ————————
    host: str = '127.0.0.1'
    port: int = 8000
    reload: bool = False
    allowed_origins: list[str] = ['*']
    allowed_headers: list[str] = ['*']
    allow_methods: list[str] = ['GET', 'POST', 'PATCH', 'DELETE']
    environment: Environment = Environment.DEV

    api_prefix: str = '/api/v1'

    database_url: str = 'sqlite+aiosqlite:///./database.db'
    echo: bool = False

    autoflush: bool = False
    expire_on_commit: bool = False

    trust_proxy_headers: bool = False
    trusted_proxies: list[str] = []
    # ————————————————————————————


    # ———————— JWT ————————
    access_secret_key: str = 'placeholder-change-it-in-production-mode'
    refresh_secret_key: str = 'placeholder-change-it-in-production-mode'
    algorithm: str = 'HS256'

    access_token_expires_minutes: int = 30
    refresh_token_expires_days: int = 30
    # ————————————————————————————

    # ———————— AUTH TRANSPORT & COOKIE ————————
    auth_transport_mode: Literal["dual", "cookie", "json"] = "dual"
    refresh_cookie_name: str = "refresh_token"
    refresh_cookie_secure: bool | None = None
    refresh_cookie_samesite: Literal["lax", "strict", "none"] = "lax"
    refresh_cookie_path: str = "/api/v1/auth"
    allow_public_registration: bool = True
    rate_limit_enabled: bool = True
    auth_rate_limit_requests: int = 10
    auth_rate_limit_window_seconds: int = 60
    authz_cache_ttl_seconds: int = 5
    # ————————————————————————————

    # ———————— AUDIT & LOGGING ————————
    log_dir: str = 'logs'
    log_to_file: bool = True
    log_to_db: bool = True

    audit_enabled: bool = True
    # ————————————————————————————

    @field_validator('trusted_proxies', mode='before')
    @classmethod
    def _validate_trusted_proxies(cls, v: object) -> list[str]:
        if v is None:
            return []
        items: list[str] = []
        if isinstance(v, str):
            items = [item.strip() for item in v.split(',') if item.strip()]
        elif isinstance(v, (list, tuple, set)):
            items = [str(item).strip() for item in v if str(item).strip()]
        else:
            raise ValueError(f"trusted_proxies must be a list or comma-separated string, got {type(v).__name__}")

        validated: list[str] = []
        for item in items:
            try:
                ipaddress.ip_network(item, strict=False)
                validated.append(item)
            except ValueError as err:
                raise ValueError(f"Invalid IP address or CIDR network in trusted_proxies: '{item}'") from err
        return validated

    @model_validator(mode='after')
    def _validate_settings_orchestrator(self) -> Self:
        self._check_algorithm()
        self._check_proxy_config()
        self._check_hardened_secrets()
        return self

    def _check_algorithm(self) -> None:
        if self.algorithm not in ALLOWED_JWT_ALGORITHMS:
            raise ValueError(
                f"Unsupported JWT algorithm '{self.algorithm}'. "
                f"Supported algorithms: {sorted(ALLOWED_JWT_ALGORITHMS)}"
            )

    def _check_proxy_config(self) -> None:
        if self.trust_proxy_headers and not self.trusted_proxies:
            raise ValueError(
                "`trust_proxy_headers` is True but `trusted_proxies` is empty. "
                "Specify at least one trusted CIDR network or IP address."
            )

    def _check_hardened_secrets(self) -> None:
        if self.environment in _HARDENED_ENVIRONMENTS:
            attrs = ('access_secret_key', 'refresh_secret_key')
            for attr in attrs:
                value: str = getattr(self, attr)
                if value.startswith('placeholder-change-it-in-production-mode'):
                    raise ValueError(
                        f"FATAL: {attr} contains a placeholder value. "
                        f"Set a real secret in `.env` before running in {self.environment} mode."
                    )
                if len(value) < JWT_SECRET_MIN_LENGTH:
                    raise ValueError(
                        f"FATAL: {attr} must be at least {JWT_SECRET_MIN_LENGTH} characters long in {self.environment} mode."
                    )

            if self.access_secret_key == self.refresh_secret_key:
                raise ValueError(
                    f"FATAL: access_secret_key and refresh_secret_key must be distinct secrets in {self.environment} mode."
                )

        if self.environment in (Environment.PRO, Environment.PROD):
            if self.echo:
                raise ValueError(
                    "FATAL: `ECHO` must be False in production to prevent SQL statement leaks."
                )

            if self.reload:
                raise ValueError(
                    "FATAL: `RELOAD` must be False in production mode."
                )

            if '*' in self.allowed_origins:
                raise ValueError(
                    "FATAL: `allowed_origins` must not contain wildcard '*' in production mode."
                )


settings = Settings()
