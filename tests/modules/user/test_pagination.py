from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from src.modules.user import User, UserRepository
from src.security import hash_password
from src.share import Roles


async def test_pagination_empty_database(
    client: AsyncClient,
    db_session: AsyncSession,
    make_access_token,
):
    """Verifies pagination metadata on an empty user table (except admin)."""
    user_repo = UserRepository(session=db_session)
    admin = User(
        name="Admin User",
        email="admin_page@enterprise.io",
        hashed_password=hash_password("AdminP@ss123!"),
        role=Roles.ADMIN,
        is_active=True,
    )
    await user_repo.create(admin)
    await db_session.commit()

    admin_token = await make_access_token(user_id=admin.id)

    # 1. Page 1 with standard size
    resp = await client.get(
        "/api/v1/users?page=1&page_size=20",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["success"] is True
    assert data["pagination"]["total"] == 1
    assert data["pagination"]["page"] == 1
    assert data["pagination"]["page_size"] == 20
    assert data["pagination"]["pages"] == 1
    assert len(data["data"]) == 1

    # 2. Page 999 (out of range page)
    resp_far = await client.get(
        "/api/v1/users?page=999&page_size=20",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp_far.status_code == 200
    data_far = resp_far.json()
    assert data_far["success"] is True
    assert data_far["pagination"]["total"] == 1
    assert len(data_far["data"]) == 0  # No records on page 999


async def test_pagination_invalid_query_params(
    client: AsyncClient,
    db_session: AsyncSession,
    make_access_token,
):
    """Verifies that out-of-bounds pagination parameters trigger 422 VALIDATION_ERROR."""
    user_repo = UserRepository(session=db_session)
    admin = User(
        name="Admin User",
        email="admin_page2@enterprise.io",
        hashed_password=hash_password("AdminP@ss123!"),
        role=Roles.ADMIN,
        is_active=True,
    )
    await user_repo.create(admin)
    await db_session.commit()

    admin_token = await make_access_token(user_id=admin.id)

    # page=0 is invalid (ge=1 constraint)
    resp_zero = await client.get(
        "/api/v1/users?page=0&page_size=20",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp_zero.status_code == 422
    assert resp_zero.json()["error"]["code"] == "VALIDATION_ERROR"

    # page_size=200 is invalid (le=100 constraint)
    resp_excess = await client.get(
        "/api/v1/users?page=1&page_size=200",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp_excess.status_code == 422
    assert resp_excess.json()["error"]["code"] == "VALIDATION_ERROR"
