import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from src.modules.user import User, UserRepository
from src.security import hash_password
from tests.conftest import create_test_access_token
from src.share import Roles


@pytest.mark.asyncio
async def test_user_crud_and_authorization(client: AsyncClient, db_session: AsyncSession):
    """Verifies user CRUD endpoints and authorization boundaries."""
    user_repo = UserRepository(session=db_session)

    # 1. Seed admin and normal users
    admin = User(
        name='System Admin',
        email='sysadmin@enterprise.io',
        hashed_password=hash_password('AdminP@ss123!'),
        role=Roles.ADMIN,
        is_active=True,
    )
    normal_user = User(
        name='Regular User',
        email='regular@enterprise.io',
        hashed_password=hash_password('UserP@ss123!'),
        role=Roles.USER,
        is_active=True,
    )
    other_user = User(
        name='Other User',
        email='other@enterprise.io',
        hashed_password=hash_password('OtherP@ss123!'),
        role=Roles.USER,
        is_active=True,
    )

    await user_repo.create(admin)
    await user_repo.create(normal_user)
    await user_repo.create(other_user)
    await db_session.commit()

    admin_token = await create_test_access_token(db_session, user_id=admin.id)
    user_token = await create_test_access_token(db_session, user_id=normal_user.id)

    # 2. Regular user fetches own profile by ID -> 200 OK
    resp = await client.get(
        f'/api/v1/users/{normal_user.id}',
        headers={'Authorization': f'Bearer {user_token}'},
    )
    assert resp.status_code == 200
    assert resp.json()['email'] == 'regular@enterprise.io'

    # 3. Regular user tries to view another user's profile -> 403 Forbidden
    forbidden_resp = await client.get(
        f'/api/v1/users/{other_user.id}',
        headers={'Authorization': f'Bearer {user_token}'},
    )
    assert forbidden_resp.status_code == 403
    assert forbidden_resp.json()['error']['code'] == 'ACCESS_DENIED'

    # 4. Regular user updates own name -> 200 OK
    update_resp = await client.patch(
        f'/api/v1/users/{normal_user.id}',
        headers={'Authorization': f'Bearer {user_token}'},
        json={'name': 'Regular User Updated'},
    )
    assert update_resp.status_code == 200
    assert update_resp.json()['name'] == 'Regular User Updated'

    # 5. Regular user tries to escalate role to admin -> 403 Forbidden
    escalate_resp = await client.patch(
        f'/api/v1/users/{normal_user.id}',
        headers={'Authorization': f'Bearer {user_token}'},
        json={'role': 'admin'},
    )
    assert escalate_resp.status_code == 403
    assert escalate_resp.json()['error']['code'] == 'ACCESS_DENIED'

    # 6. Admin updates another user's role and status -> 200 OK
    admin_patch_resp = await client.patch(
        f'/api/v1/users/{other_user.id}',
        headers={'Authorization': f'Bearer {admin_token}'},
        json={'role': 'admin', 'is_active': False},
    )
    assert admin_patch_resp.status_code == 200
    assert admin_patch_resp.json()['role'] == 'admin'
    assert admin_patch_resp.json()['is_active'] is False

    # 7. Non-existent user query by Admin -> 404 Not Found
    not_found_resp = await client.get(
        '/api/v1/users/99999',
        headers={'Authorization': f'Bearer {admin_token}'},
    )
    assert not_found_resp.status_code == 404
    assert not_found_resp.json()['error']['code'] == 'USER_NOT_FOUND'
