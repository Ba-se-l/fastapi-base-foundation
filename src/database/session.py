from collections.abc import AsyncGenerator
from typing import Annotated

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from .engine import AsyncEngineLocal
from ..settings import settings


AsyncSessionLocal = async_sessionmaker(
    bind=AsyncEngineLocal,
    class_=AsyncSession,
    autoflush=settings.autoflush,
    expire_on_commit=settings.expire_on_commit,
)


async def get_session() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency that provides a transactional database session.

    Transaction boundary contract:
        - On success: commits the transaction automatically.
        - On exception: rolls back and re-raises.

    Repositories NEVER call ``commit()`` or ``rollback()``.
    The service layer may call ``flush()`` to obtain generated IDs
    within the same transaction, but the final commit/rollback is
    always handled here.

    Yields:
        An ``AsyncSession`` bound to a single transaction.
    """
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


SessionDep = Annotated[AsyncSession, Depends(get_session, scope="function")]
