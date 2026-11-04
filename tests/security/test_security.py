import pytest

from src.exc import InvalidCredentialsException
from src.security import (
    create_access_token,
    create_refresh_token,
    decode_access_token,
    decode_refresh_token,
    hash_password,
    verify_password,
)
from src.share import TokenType


def test_password_hashing_and_verification():
    """Verifies password hashing is deterministic and salted."""
    password = "P@ssword123!"
    hashed = hash_password(password)

    assert hashed != password
    assert verify_password(password=password, hashed_password=hashed) is True
    assert verify_password(password="WrongPassword123!", hashed_password=hashed) is False


def test_access_token_creation_and_decoding():
    """Verifies access token contains expected claims and decodes cleanly."""
    user_id = 42
    token = create_access_token(user_id=user_id)

    payload = decode_access_token(token=token)
    assert payload.sub == str(user_id)
    assert payload.type == TokenType.ACCESS
    assert payload.exp is not None


def test_refresh_token_creation_and_decoding():
    """Verifies refresh token contains JTI claim and decodes properly."""
    user_id = 99
    token, jti = create_refresh_token(user_id=user_id)

    assert jti is not None
    assert len(jti) == 32

    payload = decode_refresh_token(token=token)
    assert payload.sub == str(user_id)
    assert payload.type == TokenType.REFRESH
    assert payload.jti == jti


def test_access_token_type_mismatch():
    """Ensures refresh token is rejected when decoding as access token."""
    user_id = 1
    token, _ = create_refresh_token(user_id=user_id)

    with pytest.raises(InvalidCredentialsException, match="Invalid token type"):
        decode_access_token(token=token)
