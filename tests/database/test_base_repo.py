from sqlalchemy.ext.asyncio import AsyncSession

from src.modules.user.model import User
from src.modules.user.repo import UserRepository
from src.security import hash_password


async def test_deterministic_pagination_ordering(db_session: AsyncSession):
    """Verifies that BaseRepository.get_multi applies deterministic ordering by ID."""
    user_repo = UserRepository(session=db_session)

    created_ids: list[int] = []
    for idx in range(5):
        user = User(
            name=f"Order User {idx}",
            email=f"order_{idx}@enterprise.io",
            hashed_password=hash_password("Pass12345!"),
        )
        saved = await user_repo.create(user)
        await db_session.flush()
        created_ids.append(saved.id)

    items, total = await user_repo.get_multi(offset=0, limit=10)
    returned_ids = [item.id for item in items if item.id in created_ids]

    # Verify deterministic monotonic ascending order
    assert returned_ids == sorted(created_ids)
