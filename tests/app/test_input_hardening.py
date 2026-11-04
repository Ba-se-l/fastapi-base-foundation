import logging
from typing import Any

import pytest
from httpx import AsyncClient


async def test_validation_errors_never_leak_secret_payloads(
    client: AsyncClient,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Verifies that submitted sensitive input values are not leaked into 422 response bodies or logs."""
    secret_marker = "zz-SECRET-weakpass"

    with caplog.at_level(logging.WARNING):
        # 1. Register with weak password containing marker
        resp = await client.post(
            "/api/v1/auth/register",
            json={
                "name": "Leak Test User",
                "email": "leak.test@enterprise.io",
                "password": secret_marker,
            },
        )
        assert resp.status_code == 422
        assert secret_marker not in resp.text
        assert secret_marker not in caplog.text

    # 2. Register valid user to obtain access token for change-password test
    valid_pass = "StrongP@ssw0rd!1"
    reg_resp = await client.post(
        "/api/v1/auth/register",
        json={
            "name": "Change Pass User",
            "email": "changepass.leak@enterprise.io",
            "password": valid_pass,
        },
    )
    assert reg_resp.status_code == 201

    login_resp = await client.post(
        "/api/v1/auth/login",
        json={"email": "changepass.leak@enterprise.io", "password": valid_pass},
    )
    assert login_resp.status_code == 200
    token = login_resp.json()["access_token"]

    caplog.clear()
    with caplog.at_level(logging.WARNING):
        # 3. Model-level validator error: old_password == new_password
        model_secret = "IdenticalPassw0rd!9"
        change_resp = await client.post(
            "/api/v1/auth/change-password",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "old_password": model_secret,
                "new_password": model_secret,
            },
        )
        assert change_resp.status_code == 422
        assert model_secret not in change_resp.text
        assert model_secret not in caplog.text


@pytest.mark.parametrize(
    "bad_email",
    [12345, True, [], {}],
    ids=["integer", "boolean", "list", "dict"],
)
async def test_non_string_email_rejected_with_422(
    client: AsyncClient,
    bad_email: Any,
) -> None:
    """Verifies that non-string email inputs result in 422 Unprocessable Entity instead of 500 error."""
    reg_resp = await client.post(
        "/api/v1/auth/register",
        json={"name": "Type Test", "email": bad_email, "password": "StrongP@ssw0rd!1"},
    )
    assert reg_resp.status_code == 422

    login_resp = await client.post(
        "/api/v1/auth/login",
        json={"email": bad_email, "password": "StrongP@ssw0rd!1"},
    )
    assert login_resp.status_code == 422


async def test_password_length_upper_bound(client: AsyncClient) -> None:
    """Verifies that passwords exceeding PASSWORD_MAX_LENGTH (100) are rejected with 422."""
    oversized_password = "A1!" + "x" * 98  # 101 characters

    login_resp = await client.post(
        "/api/v1/auth/login",
        json={"email": "any@enterprise.io", "password": oversized_password},
    )
    assert login_resp.status_code == 422

    valid_pass = "ValidP@ssw0rd!1"
    await client.post(
        "/api/v1/auth/register",
        json={"name": "Length User", "email": "length.user@enterprise.io", "password": valid_pass},
    )
    login_resp = await client.post(
        "/api/v1/auth/login",
        json={"email": "length.user@enterprise.io", "password": valid_pass},
    )
    token = login_resp.json()["access_token"]

    change_resp = await client.post(
        "/api/v1/auth/change-password",
        headers={"Authorization": f"Bearer {token}"},
        json={"old_password": valid_pass, "new_password": oversized_password},
    )
    assert change_resp.status_code == 422


async def test_patch_user_rejects_explicit_nulls(client: AsyncClient) -> None:
    """Verifies that PATCH /users/{id} rejects explicit null for NOT NULL columns with 422."""
    admin_pass = "AdminP@ssw0rd!1"
    reg_resp = await client.post(
        "/api/v1/auth/register",
        json={"name": "Patch Admin", "email": "patch.admin@enterprise.io", "password": admin_pass},
    )
    admin_id = reg_resp.json()["id"]

    login_resp = await client.post(
        "/api/v1/auth/login",
        json={"email": "patch.admin@enterprise.io", "password": admin_pass},
    )
    token = login_resp.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Explicit null for 'name'
    resp = await client.patch(f"/api/v1/users/{admin_id}", headers=headers, json={"name": None})
    assert resp.status_code == 422

    # Explicit null for 'is_active'
    resp = await client.patch(f"/api/v1/users/{admin_id}", headers=headers, json={"is_active": None})
    assert resp.status_code == 422

    # Explicit null for 'role'
    resp = await client.patch(f"/api/v1/users/{admin_id}", headers=headers, json={"role": None})
    assert resp.status_code == 422

    # Valid empty PATCH {} should succeed
    resp = await client.patch(f"/api/v1/users/{admin_id}", headers=headers, json={})
    assert resp.status_code == 200

    # Valid partial update should succeed
    resp = await client.patch(f"/api/v1/users/{admin_id}", headers=headers, json={"name": "New Name"})
    assert resp.status_code == 200
    assert resp.json()["name"] == "New Name"
