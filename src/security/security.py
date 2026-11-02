import asyncio
import uuid
from datetime import datetime, timedelta, timezone

import jwt
from pwdlib import PasswordHash
from pydantic import ValidationError

from ..exc import InvalidCredentialsException
from ..settings import settings
from ..share.enum import TokenType
from ..share.schemas import AccessTokenPayload, RefreshTokenPayload, TokenPayload

ph = PasswordHash.recommended()


SECURITY_PASSWORD_HASH: str = ph.hash("anti-timing-dummy-secret-fixed-entropy")
"""Pre-computed dummy argon2 hash constant used to equalize response latency during invalid login attempts."""


def hash_password(password: str) -> str:
    """Hashes a plaintext password using the recommended Argon2 password hasher.

    Args:
        password: The plaintext password string to hash.

    Returns:
        The encoded Argon2 password hash string.
    """
    return ph.hash(password=password)


def verify_password(password: str, hashed_password: str) -> bool:
    """Verifies a plaintext password against an Argon2 password hash.

    Args:
        password: The plaintext password string to verify.
        hashed_password: The existing Argon2 hash to compare against.

    Returns:
        True if the password matches the hash, False otherwise.
    """
    return ph.verify(password=password, hash=hashed_password)


def verify_and_update(password: str, hashed_password: str) -> tuple[bool, str | None]:
    """Verifies a plaintext password and checks if the hash needs upgrading.

    Args:
        password: The plaintext password string to verify.
        hashed_password: The existing hash to verify and potentially upgrade.

    Returns:
        A tuple of (is_valid, updated_hash_or_none).
    """
    return ph.verify_and_update(password=password, hash=hashed_password)


verify_and_update_password = verify_and_update


async def hash_password_async(password: str) -> str:
    """Asynchronously hashes a plaintext password off the main event loop."""
    return await asyncio.to_thread(hash_password, password)


async def verify_password_async(plain_password: str, hashed_password: str) -> bool:
    """Asynchronously verifies a password hash off the main event loop."""
    return await asyncio.to_thread(verify_password, plain_password, hashed_password)


async def verify_and_update_password_async(
    plain_password: str, hashed_password: str
) -> tuple[bool, str | None]:
    """Asynchronously verifies a password and upgrades its hash off the main event loop."""
    return await asyncio.to_thread(verify_and_update, plain_password, hashed_password)


async def verify_dummy_password_async(plain_password: str) -> None:
    """Asynchronously computes a dummy password verification to equalize timing."""
    await asyncio.to_thread(verify_password, plain_password, SECURITY_PASSWORD_HASH)


def create_access_token(
    user_id: int,
    security_version: int = 1,
    family_id: str | None = None,
    expires_delta: timedelta | None = None,
) -> str:
    """Generates a signed JWT access token for authentication.

    Args:
        user_id: The primary key of the authenticated user.
        security_version: Current credential/security version of the user.
        family_id: Optional session family lineage identifier.
        expires_delta: Optional custom duration before expiration. Defaults to settings value.

    Returns:
        A signed JWT access token string.
    """
    if expires_delta is None:
        expires_delta = timedelta(minutes=settings.access_token_expires_minutes)

    now = datetime.now(timezone.utc)
    fid = family_id or uuid.uuid4().hex

    payload = AccessTokenPayload(
        sub=str(user_id),
        type=TokenType.ACCESS,
        jti=uuid.uuid4().hex,
        iat=now,
        sec_ver=security_version,
        exp=now + expires_delta,
        fid=fid,
    )

    return jwt.encode(
        payload.model_dump(exclude_none=True),
        key=settings.access_secret_key,
        algorithm=settings.algorithm,
    )


def create_refresh_token(
    user_id: int,
    security_version: int = 1,
    family_id: str | None = None,
    jti: str | None = None,
) -> tuple[str, str]:
    """Generates a signed JWT refresh token with an assigned unique JTI identifier.

    Args:
        user_id: The primary key of the authenticated user.
        security_version: Current credential/security version of the user.
        family_id: Optional session family lineage identifier.
        jti: Optional pre-assigned JWT ID string. If None, a random UUID hex is generated.

    Returns:
        A tuple of (encoded_jwt_refresh_token, jti_identifier).
    """
    if isinstance(security_version, str) and family_id is None:
        family_id = security_version
        security_version = 1

    if jti is None:
        jti = uuid.uuid4().hex

    now = datetime.now(timezone.utc)
    expires_delta = timedelta(days=settings.refresh_token_expires_days)
    fid = family_id or uuid.uuid4().hex

    payload = RefreshTokenPayload(
        sub=str(user_id),
        type=TokenType.REFRESH,
        jti=jti,
        iat=now,
        sec_ver=security_version,
        exp=now + expires_delta,
        fid=fid,
    )

    return jwt.encode(
        payload.model_dump(exclude_none=True),
        key=settings.refresh_secret_key,
        algorithm=settings.algorithm,
    ), jti


def decode_access_token(token: str) -> AccessTokenPayload:
    """Decodes and validates a signed JWT access token.

    Args:
        token: The raw encoded JWT access token string.

    Returns:
        The validated AccessTokenPayload schema.

    Raises:
        InvalidCredentialsException: If the token signature is invalid, expired, missing claims, or not an ACCESS token.
    """
    try:
        raw_claims = jwt.decode(
            jwt=token,
            key=settings.access_secret_key,
            algorithms=[settings.algorithm],
            options={"require": ["sub", "exp", "iat", "type", "sec_ver", "fid"]},
        )
        payload = AccessTokenPayload.model_validate(raw_claims)
        if payload.type != TokenType.ACCESS:
            raise InvalidCredentialsException()
        return payload
    except (jwt.PyJWTError, ValidationError, ValueError, TypeError) as exc:
        raise InvalidCredentialsException() from exc


def decode_refresh_token(token: str) -> RefreshTokenPayload:
    """Decodes and validates a signed JWT refresh token.

    Args:
        token: The raw encoded JWT refresh token string.

    Returns:
        The validated RefreshTokenPayload schema containing the JTI.

    Raises:
        InvalidCredentialsException: If the token signature is invalid, expired, missing claims, lacks JTI, or not REFRESH.
    """
    try:
        raw_claims = jwt.decode(
            jwt=token,
            key=settings.refresh_secret_key,
            algorithms=[settings.algorithm],
            options={"require": ["sub", "exp", "iat", "type", "sec_ver", "fid", "jti"]},
        )
        payload = RefreshTokenPayload.model_validate(raw_claims)
        if payload.type != TokenType.REFRESH:
            raise InvalidCredentialsException()
        return payload
    except (jwt.PyJWTError, ValidationError, ValueError, TypeError) as exc:
        raise InvalidCredentialsException() from exc
