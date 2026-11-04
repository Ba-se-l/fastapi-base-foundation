from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from src.modules.user import User, UserRepository
from src.security import hash_password
from src.share import Roles


async def test_rbac_and_user_endpoints(
    client: AsyncClient,
    db_session: AsyncSession,
    make_access_token,
):
    """Tests RBAC enforcement and user management endpoints."""
    user_repo = UserRepository(session=db_session)

    # Seed Admin User
    admin = User(
        name="Root Admin",
        email="admin@enterprise.io",
        hashed_password=hash_password("AdminSecr3t!"),
        role=Roles.ADMIN,
        is_active=True,
    )
    await user_repo.create(admin)

    # Seed Normal User
    normal_user = User(
        name="Normal User",
        email="user@enterprise.io",
        hashed_password=hash_password("UserSecr3t!"),
        role=Roles.USER,
        is_active=True,
    )
    await user_repo.create(normal_user)
    await db_session.commit()

    admin_token = await make_access_token(user_id=admin.id)
    user_token = await make_access_token(user_id=normal_user.id)

    # 1. Get current user profile (/users/me)
    me_resp = await client.get(
        "/api/v1/users/me",
        headers={"Authorization": f"Bearer {user_token}"},
    )
    assert me_resp.status_code == 200
    me_data = me_resp.json()
    assert me_data["email"] == "user@enterprise.io"
    assert me_data["role"] == "user"

    # 2. Normal user tries to access admin-only list (/users) -> 403 Forbidden
    forbidden_resp = await client.get(
        "/api/v1/users",
        headers={"Authorization": f"Bearer {user_token}"},
    )
    assert forbidden_resp.status_code == 403
    forbidden_data = forbidden_resp.json()
    assert forbidden_data["success"] is False
    assert forbidden_data["error"]["code"] == "ACCESS_DENIED"

    # 3. Admin user accesses list (/users) -> 200 OK + PaginatedResponse
    admin_list_resp = await client.get(
        "/api/v1/users?page=1&page_size=10",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert admin_list_resp.status_code == 200
    list_data = admin_list_resp.json()
    assert list_data["success"] is True
    assert len(list_data["data"]) == 2
    assert list_data["pagination"]["total"] == 2
    assert list_data["pagination"]["page"] == 1
    assert list_data["pagination"]["pages"] == 1
