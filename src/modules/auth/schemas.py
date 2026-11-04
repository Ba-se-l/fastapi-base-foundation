from typing import Literal
from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator, model_validator


PASSWORD_MAX_LENGTH = 100
"""Single upper bound for every plaintext password field (bounds Argon2 CPU cost)."""


def normalize_seq(seq: object, to: Literal['none', 'lower', 'upper'] = 'none') -> object:
    """Strips and case-folds strings; returns non-strings unchanged for Pydantic to reject with 422."""
    if not isinstance(seq, str):
        return seq
    stripped = seq.strip()
    match to:
        case 'lower':
            return stripped.lower()
        case 'upper':
            return stripped.upper()
        case _:
            return stripped


def validate_pass(pwd: str) -> str:
    """Validates that password meets enterprise security standards.

    Args:
        pwd: Raw password string.

    Returns:
        Validated password string.

    Raises:
        ValueError: If password lacks required character classes.
    """
    if not any(c.isupper() for c in pwd):
        raise ValueError("Password must contain at least one uppercase letter.")
    if not any(c.islower() for c in pwd):
        raise ValueError("Password must contain at least one lowercase letter.")
    if not any(c.isdigit() for c in pwd):
        raise ValueError("Password must contain at least one digit.")
    special_chars = set("!@#$%^&*()_+-=[]{}|;':\",./<>?`~")
    if not any(c in special_chars for c in pwd):
        raise ValueError("Password must contain at least one special character.")
    return pwd


class RegisterRequest(BaseModel):
    """Schema for user registration request."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(..., min_length=1, max_length=100)
    """The user's full display name."""

    email: EmailStr
    """The user's email address. Must be unique across the system."""

    password: str = Field(..., min_length=8, max_length=PASSWORD_MAX_LENGTH)
    """The user's plain-text password. Will be hashed before storage."""

    @field_validator('email', mode='before')
    @classmethod
    def normalize_email(cls, v: object) -> object:
        """Normalizes email to lowercase and strips whitespace.

        Args:
            v: The raw email value from the request.

        Returns:
            Lowercase, stripped email string if string, or original object.
        """
        return normalize_seq(v, 'lower')

    @field_validator('password')
    @classmethod
    def validate_password_strength(cls, v: str) -> str:
        """Validates that password meets enterprise security standards."""
        return validate_pass(v)


class LoginRequest(BaseModel):
    """Schema for user login request."""

    model_config = ConfigDict(extra="forbid")

    email: EmailStr
    """The user's registered email address."""

    password: str = Field(..., max_length=PASSWORD_MAX_LENGTH)
    """The user's plain-text password for verification."""

    @field_validator('email', mode='before')
    @classmethod
    def normalize_email(cls, v: object) -> object:
        """Normalizes email to lowercase and strips whitespace.

        Args:
            v: The raw email value from the request.

        Returns:
            Lowercase, stripped email string if string, or original object.
        """
        return normalize_seq(v, 'lower')


class TokenResponse(BaseModel):
    """Schema for JWT dual-token API responses."""

    access_token: str
    """The short-lived JWT access token string."""

    refresh_token: str | None = None
    """The long-lived JWT refresh token string (omitted in cookie-only transport mode)."""

    token_type: str = 'bearer'
    """The token type. Always ``bearer``."""


class RefreshRequest(BaseModel):
    """Schema for token refresh request."""

    model_config = ConfigDict(extra="forbid")

    refresh_token: str | None = Field(
        default=None,
        min_length=1,
        max_length=2048,
        description="Encoded JWT refresh token (optional when provided via Cookie).",
    )
    """The current valid refresh token to exchange for new tokens (optional when provided via Cookie)."""


class ChangePasswordRequest(BaseModel):
    """Schema for authenticated user password change request."""

    model_config = ConfigDict(extra="forbid")

    old_password: str = Field(..., min_length=1, max_length=PASSWORD_MAX_LENGTH)
    """The user's current plain-text password for verification."""

    new_password: str = Field(..., min_length=8, max_length=PASSWORD_MAX_LENGTH)
    """The desired new plain-text password."""

    @field_validator('new_password')
    @classmethod
    def validate_password_strength(cls, v: str) -> str:
        """Validates that new password meets enterprise security standards."""
        return validate_pass(v)

    @model_validator(mode='after')
    def verify_different_passwords(self) -> 'ChangePasswordRequest':
        """Ensures that the new password is not identical to the current password."""
        if self.old_password == self.new_password:
            raise ValueError("New password must be different from the old password.")
        return self
