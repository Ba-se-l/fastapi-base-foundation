from datetime import datetime, timezone
from typing import Annotated, Literal
from dataclasses import dataclass, field
from pydantic import AfterValidator, BaseModel, Field
from typing_extensions import TypedDict

from .enum import TokenType


_HTTP_ERROR_CODE_MAP: dict[int, str] = {
    400: "BAD_REQUEST",
    401: "UNAUTHORIZED",
    403: "FORBIDDEN",
    404: "NOT_FOUND",
    405: "METHOD_NOT_ALLOWED",
    408: "REQUEST_TIMEOUT",
    409: "CONFLICT",
    413: "PAYLOAD_TOO_LARGE",
    415: "UNSUPPORTED_MEDIA_TYPE",
    422: "UNPROCESSABLE_ENTITY",
    429: "TOO_MANY_REQUESTS",
    500: "INTERNAL_SERVER_ERROR",
    502: "BAD_GATEWAY",
    503: "SERVICE_UNAVAILABLE",
    504: "GATEWAY_TIMEOUT",
}


def _validate_positive_int_subject(value: str) -> str:
    if not isinstance(value, str):
        raise ValueError("Token subject 'sub' must be a string")
    try:
        parsed = int(value)
    except ValueError as exc:
        raise ValueError("Token subject 'sub' must represent a valid integer") from exc
    if parsed <= 0:
        raise ValueError("Token subject 'sub' must be a positive integer")
    return value


SubjectIntStr = Annotated[str, AfterValidator(_validate_positive_int_subject)]
NonEmptyClaimStr = Annotated[str, Field(min_length=1, max_length=128)]


class TokenPayload(BaseModel):
    sub: SubjectIntStr
    exp: datetime
    iat: datetime
    type: TokenType | str
    jti: str | None = None
    fid: str | None = None
    sec_ver: Annotated[int, Field(ge=1)] = 1

    @property
    def user_id(self) -> int:
        return int(self.sub)


class AccessTokenPayload(TokenPayload):
    type: Literal["access"] | Literal[TokenType.ACCESS] = TokenType.ACCESS
    fid: NonEmptyClaimStr
    sec_ver: Annotated[int, Field(ge=1)]


class RefreshTokenPayload(TokenPayload):
    type: Literal["refresh"] | Literal[TokenType.REFRESH] = TokenType.REFRESH
    jti: NonEmptyClaimStr
    fid: NonEmptyClaimStr
    sec_ver: Annotated[int, Field(ge=1)]


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = 'Bearer'


@dataclass(frozen=True, slots=True)
class AuditContext:
    ip_address: str | None = None
    user_agent: str | None = None
    request_id: str | None = None


class AuditContextDict(TypedDict, total=True):
    ip: str | None
    """IP Address"""
    ua: str | None
    """User Agent"""
    req_id: str | None
    """Request ID"""


@dataclass(frozen=True, slots=True, kw_only=True)
class DomainEvent:
    """Immutable base for every domain fact published on the event bus.

    Subclasses MUST be declared with ``kw_only=True`` so they can define
    required fields without violating dataclass default-ordering rules.
    """

    occurred_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    """UTC timestamp at which the fact occurred."""

    audit_ctx: AuditContext | None = None
    """Request telemetry (IP, user agent, request ID) captured at publish time."""
