from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine

from .base import BaseModel
from ..settings import settings

AsyncEngineLocal = create_async_engine(
    url=settings.database_url,
    echo=settings.echo,
    hide_parameters=True,
)


async def check_database_connection() -> bool:
    """Verifies that the database engine can successfully connect."""
    async with AsyncEngineLocal.connect() as conn:
        await conn.execute(text("SELECT 1"))
    return True


async def create_all_tables() -> None:
    """Creates all registered database tables (convenience for test harnesses)."""
    async with AsyncEngineLocal.begin() as conn:
        await conn.run_sync(BaseModel.metadata.create_all)
