import uuid
from datetime import datetime, timedelta, timezone

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from src.modules.auth.model import RefreshSession
from src.modules.auth.repo import RefreshSessionRepository
from src.security import decode_access_token


@pytest.mark.asyncio
async def test_auth_full_lifecycle(client: AsyncClient):
    """Tests registration, login, token refresh, and logout flow."""
    user_payload = {
        'name': 'Test Engineer',
        'email': 'engineer@enterprise.io',
        'password': 'StrongP@ssw0rd!',
    }

    # 1. Register new user
    reg_response = await client.post('/api/v1/auth/register', json=user_payload)
    assert reg_response.status_code == 201
    data = reg_response.json()
    assert data['email'] == user_payload['email']
    assert data['name'] == user_payload['name']
    assert data['role'] == 'user'
    assert 'id' in data

    # 2. Reject duplicate email with 409 Conflict
    dup_response = await client.post('/api/v1/auth/register', json=user_payload)
    assert dup_response.status_code == 409
    dup_data = dup_response.json()
    assert dup_data['success'] is False
    assert dup_data['error']['code'] == 'USER_ALREADY_EXISTS'

    # 3. Reject weak password with 422 Unprocessable Entity
    weak_payload = dict(user_payload)
    weak_payload['email'] = 'other@enterprise.io'
    weak_payload['password'] = 'simple'
    weak_response = await client.post('/api/v1/auth/register', json=weak_payload)
    assert weak_response.status_code == 422

    # 4. Login with valid credentials
    login_response = await client.post(
        '/api/v1/auth/login',
        json={'email': user_payload['email'], 'password': user_payload['password']},
    )
    assert login_response.status_code == 200
    tokens = login_response.json()
    access_token = tokens['access_token']
    refresh_token = tokens['refresh_token']
    assert access_token is not None
    assert refresh_token is not None

    # 5. Refresh token rotation
    refresh_response = await client.post(
        '/api/v1/auth/refresh',
        json={'refresh_token': refresh_token},
    )
    assert refresh_response.status_code == 200
    new_tokens = refresh_response.json()
    new_access_token = new_tokens['access_token']
    new_refresh_token = new_tokens['refresh_token']
    assert new_access_token != access_token
    assert new_refresh_token != refresh_token

    # 6. Old refresh token should now be revoked (replay attack prevention)
    stale_response = await client.post(
        '/api/v1/auth/refresh',
        json={'refresh_token': refresh_token},
    )
    assert stale_response.status_code == 401
    stale_data = stale_response.json()
    assert stale_data['error']['code'] == 'TOKEN_REVOKED'

    # 7. Logout endpoint
    logout_response = await client.post(
        '/api/v1/auth/logout',
        json={'refresh_token': new_refresh_token},
    )
    assert logout_response.status_code == 200
    assert logout_response.json()['success'] is True


@pytest.mark.asyncio
async def test_replay_attack_persists_revocation_in_db(client: AsyncClient):
    """Verifies that replay detection commits session family revocation to DB before raising 401.

    Ensures the 'Rollback Trap' is eliminated: even though an exception is raised,
    the compromised family remains revoked in the database and legitimate tokens in the
    family are permanently invalidated.
    """
    user_payload = {
        'name': 'Replay Test User',
        'email': 'replay.test@enterprise.io',
        'password': 'StrongP@ssw0rd!1',
    }

    # 1. Register and login
    await client.post('/api/v1/auth/register', json=user_payload)
    login_resp = await client.post(
        '/api/v1/auth/login',
        json={'email': user_payload['email'], 'password': user_payload['password']},
    )
    tokens_v1 = login_resp.json()
    refresh_v1 = tokens_v1['refresh_token']

    # 2. Rotate to v2
    rot_resp = await client.post('/api/v1/auth/refresh', json={'refresh_token': refresh_v1})
    assert rot_resp.status_code == 200
    tokens_v2 = rot_resp.json()
    access_v2 = tokens_v2['access_token']
    refresh_v2 = tokens_v2['refresh_token']

    # 3. Attacker replays refresh_v1
    replay_resp = await client.post('/api/v1/auth/refresh', json={'refresh_token': refresh_v1})
    assert replay_resp.status_code == 401
    assert replay_resp.json()['error']['code'] == 'TOKEN_REVOKED'

    # 4. Verify DB persistence: the victim's refresh_v2 MUST also be revoked now
    victim_refresh_resp = await client.post('/api/v1/auth/refresh', json={'refresh_token': refresh_v2})
    assert victim_refresh_resp.status_code == 401
    assert victim_refresh_resp.json()['error']['code'] == 'TOKEN_REVOKED'

    # 5. Victim's access token v2 MUST be rejected because the family is inactive
    victim_access_resp = await client.get(
        '/api/v1/users/me',
        headers={'Authorization': f'Bearer {access_v2}'},
    )
    assert victim_access_resp.status_code == 401
    assert victim_access_resp.json()['error']['code'] == 'TOKEN_STALE'


@pytest.mark.asyncio
async def test_smart_device_isolation_on_replay(client: AsyncClient):
    """Verifies Smart Device Isolation: compromising one token family does NOT disrupt other devices."""
    user_payload = {
        'name': 'Multi Device User',
        'email': 'multidevice@enterprise.io',
        'password': 'StrongP@ssw0rd!2',
    }

    # 1. Register user
    await client.post('/api/v1/auth/register', json=user_payload)

    # 2. Device 1 logs in (Desktop - Family 1)
    dev1_login = await client.post(
        '/api/v1/auth/login',
        json={'email': user_payload['email'], 'password': user_payload['password']},
    )
    dev1_v1_tokens = dev1_login.json()
    dev1_v1_refresh = dev1_v1_tokens['refresh_token']

    # 3. Device 2 logs in (Mobile - Family 2)
    dev2_login = await client.post(
        '/api/v1/auth/login',
        json={'email': user_payload['email'], 'password': user_payload['password']},
    )
    dev2_v1_tokens = dev2_login.json()
    dev2_v1_access = dev2_v1_tokens['access_token']
    dev2_v1_refresh = dev2_v1_tokens['refresh_token']

    # 4. Device 1 rotates to v2
    dev1_rot = await client.post('/api/v1/auth/refresh', json={'refresh_token': dev1_v1_refresh})
    assert dev1_rot.status_code == 200
    dev1_v2_tokens = dev1_rot.json()
    dev1_v2_access = dev1_v2_tokens['access_token']
    dev1_v2_refresh = dev1_v2_tokens['refresh_token']

    # 5. Attacker replays Device 1's old token (dev1_v1_refresh)
    replay_resp = await client.post('/api/v1/auth/refresh', json={'refresh_token': dev1_v1_refresh})
    assert replay_resp.status_code == 401
    assert replay_resp.json()['error']['code'] == 'TOKEN_REVOKED'

    # 6. Device 1's Family 1 is revoked
    dev1_probe = await client.post('/api/v1/auth/refresh', json={'refresh_token': dev1_v2_refresh})
    assert dev1_probe.status_code == 401
    assert dev1_probe.json()['error']['code'] == 'TOKEN_REVOKED'

    dev1_me = await client.get('/api/v1/users/me', headers={'Authorization': f'Bearer {dev1_v2_access}'})
    assert dev1_me.status_code == 401
    assert dev1_me.json()['error']['code'] == 'TOKEN_STALE'

    # 7. SMART DEVICE ISOLATION: Device 2 (Mobile - Family 2) MUST NOT be affected!
    dev2_me = await client.get('/api/v1/users/me', headers={'Authorization': f'Bearer {dev2_v1_access}'})
    assert dev2_me.status_code == 200
    assert dev2_me.json()['email'] == user_payload['email']

    # Device 2 can still rotate cleanly
    dev2_rot = await client.post('/api/v1/auth/refresh', json={'refresh_token': dev2_v1_refresh})
    assert dev2_rot.status_code == 200
    assert 'access_token' in dev2_rot.json()


@pytest.mark.asyncio
async def test_single_device_logout_isolates_other_devices(client: AsyncClient):
    """Verifies that logging out on one device immediately invalidates its access token without affecting other devices."""
    user_payload = {
        'name': 'Single Logout User',
        'email': 'singlelogout@enterprise.io',
        'password': 'StrongP@ssw0rd!3',
    }

    await client.post('/api/v1/auth/register', json=user_payload)

    # Device 1 login
    d1_login = await client.post(
        '/api/v1/auth/login',
        json={'email': user_payload['email'], 'password': user_payload['password']},
    )
    d1_tokens = d1_login.json()
    d1_access = d1_tokens['access_token']
    d1_refresh = d1_tokens['refresh_token']

    # Device 2 login
    d2_login = await client.post(
        '/api/v1/auth/login',
        json={'email': user_payload['email'], 'password': user_payload['password']},
    )
    d2_tokens = d2_login.json()
    d2_access = d2_tokens['access_token']
    d2_refresh = d2_tokens['refresh_token']

    # Device 1 logs out
    logout_resp = await client.post('/api/v1/auth/logout', json={'refresh_token': d1_refresh})
    assert logout_resp.status_code == 200

    # Device 1 access token is immediately rejected (family marked inactive)
    d1_me = await client.get('/api/v1/users/me', headers={'Authorization': f'Bearer {d1_access}'})
    assert d1_me.status_code == 401
    assert d1_me.json()['error']['code'] == 'TOKEN_STALE'

    # Device 2 remains completely active
    d2_me = await client.get('/api/v1/users/me', headers={'Authorization': f'Bearer {d2_access}'})
    assert d2_me.status_code == 200

    d2_rot = await client.post('/api/v1/auth/refresh', json={'refresh_token': d2_refresh})
    assert d2_rot.status_code == 200


@pytest.mark.asyncio
async def test_logout_all_instantly_invalidates_all_devices(client: AsyncClient):
    """Verifies that logout-all increments security_version and kills all active tokens immediately."""
    user_payload = {
        'name': 'Logout All User',
        'email': 'logoutall@enterprise.io',
        'password': 'StrongP@ssw0rd!4',
    }

    await client.post('/api/v1/auth/register', json=user_payload)

    # Device 1 login
    d1_login = await client.post(
        '/api/v1/auth/login',
        json={'email': user_payload['email'], 'password': user_payload['password']},
    )
    d1_tokens = d1_login.json()
    d1_access = d1_tokens['access_token']

    # Device 2 login
    d2_login = await client.post(
        '/api/v1/auth/login',
        json={'email': user_payload['email'], 'password': user_payload['password']},
    )
    d2_tokens = d2_login.json()
    d2_access = d2_tokens['access_token']
    d2_refresh = d2_tokens['refresh_token']

    # Device 1 initiates logout-all
    logout_all_resp = await client.post(
        '/api/v1/auth/logout-all',
        headers={'Authorization': f'Bearer {d1_access}'},
    )
    assert logout_all_resp.status_code == 200

    # Device 1's access token is immediately stale
    d1_me = await client.get('/api/v1/users/me', headers={'Authorization': f'Bearer {d1_access}'})
    assert d1_me.status_code == 401
    assert d1_me.json()['error']['code'] == 'TOKEN_STALE'

    # Device 2's access token is immediately stale across all devices
    d2_me = await client.get('/api/v1/users/me', headers={'Authorization': f'Bearer {d2_access}'})
    assert d2_me.status_code == 401
    assert d2_me.json()['error']['code'] == 'TOKEN_STALE'

    # Device 2's refresh token is revoked
    d2_ref = await client.post('/api/v1/auth/refresh', json={'refresh_token': d2_refresh})
    assert d2_ref.status_code == 401
    assert d2_ref.json()['error']['code'] == 'TOKEN_REVOKED'


@pytest.mark.asyncio
async def test_revoke_family_is_user_scoped(db_session: AsyncSession):
    """Verifies that revoke_family only revokes sessions belonging to the specified user."""
    repo = RefreshSessionRepository(session=db_session)
    family_shared = 'fam-scope-test-123'
    now = datetime.now(timezone.utc)
    exp = now + timedelta(days=7)

    # Create session for User 101
    s1 = RefreshSession(
        user_id=101,
        refresh_token_jti=uuid.uuid4().hex,
        family_id=family_shared,
        is_revoked=False,
        expires_at=exp,
    )
    # Create session for User 102 with identical family_id (e.g. legacy state)
    s2 = RefreshSession(
        user_id=102,
        refresh_token_jti=uuid.uuid4().hex,
        family_id=family_shared,
        is_revoked=False,
        expires_at=exp,
    )
    db_session.add_all([s1, s2])
    await db_session.flush()

    # User 999 attempts to revoke family
    revoked_count = await repo.revoke_family(family_id=family_shared, user_id=999)
    assert revoked_count == 0

    await db_session.refresh(s1)
    await db_session.refresh(s2)
    assert s1.is_revoked is False
    assert s2.is_revoked is False

    # Revoking with user_id=101 should only revoke s1
    revoked_count = await repo.revoke_family(family_id=family_shared, user_id=101)
    assert revoked_count == 1

    await db_session.refresh(s1)
    await db_session.refresh(s2)
    assert s1.is_revoked is True
    assert s2.is_revoked is False


@pytest.mark.asyncio
async def test_logout_and_replay_do_not_touch_other_users(client: AsyncClient, db_session: AsyncSession):
    """Verifies that logout and replay detection for User A never revoke User B's sessions."""
    # Register User A and User B
    u_a = {'name': 'User A', 'email': 'usera@enterprise.io', 'password': 'StrongP@ssw0rd!A'}
    u_b = {'name': 'User B', 'email': 'userb@enterprise.io', 'password': 'StrongP@ssw0rd!B'}
    await client.post('/api/v1/auth/register', json=u_a)
    await client.post('/api/v1/auth/register', json=u_b)

    # Login both
    login_a = (await client.post('/api/v1/auth/login', json={'email': u_a['email'], 'password': u_a['password']})).json()
    login_b = (await client.post('/api/v1/auth/login', json={'email': u_b['email'], 'password': u_b['password']})).json()

    ref_a1 = login_a['refresh_token']
    ref_b = login_b['refresh_token']

    # User A rotates token once: ref_a1 is now stale
    rot_a = (await client.post('/api/v1/auth/refresh', json={'refresh_token': ref_a1})).json()
    ref_a2 = rot_a['refresh_token']

    # User A replays stale ref_a1 -> triggers replay attack detection and family revocation
    replay_resp = await client.post('/api/v1/auth/refresh', json={'refresh_token': ref_a1})
    assert replay_resp.status_code == 401

    # User A's new token ref_a2 is now revoked due to replay
    stale_a = await client.post('/api/v1/auth/refresh', json={'refresh_token': ref_a2})
    assert stale_a.status_code == 401

    # User B's token MUST still be active and valid
    rot_b = await client.post('/api/v1/auth/refresh', json={'refresh_token': ref_b})
    assert rot_b.status_code == 200

    # User B logs out
    new_ref_b = rot_b.json()['refresh_token']
    logout_b = await client.post('/api/v1/auth/logout', json={'refresh_token': new_ref_b})
    assert logout_b.status_code == 200


@pytest.mark.asyncio
async def test_issued_access_tokens_carry_fid(client: AsyncClient):
    """Verifies that all access tokens issued by login and refresh endpoints carry a non-empty fid claim."""
    user = {'name': 'Fid User', 'email': 'fid.user@enterprise.io', 'password': 'StrongP@ssw0rd!F'}
    await client.post('/api/v1/auth/register', json=user)

    login_resp = await client.post('/api/v1/auth/login', json={'email': user['email'], 'password': user['password']})
    assert login_resp.status_code == 200
    tokens = login_resp.json()

    # Verify access token has non-empty fid
    access_payload = decode_access_token(tokens['access_token'])
    assert access_payload.fid is not None
    assert len(access_payload.fid) > 0

    # Refresh and verify rotated access token also carries fid
    ref_resp = await client.post('/api/v1/auth/refresh', json={'refresh_token': tokens['refresh_token']})
    assert ref_resp.status_code == 200
    new_tokens = ref_resp.json()

    new_access_payload = decode_access_token(new_tokens['access_token'])
    assert new_access_payload.fid is not None
    assert len(new_access_payload.fid) > 0
    # Lineage: family_id must be inherited across rotations
    assert new_access_payload.fid == access_payload.fid

