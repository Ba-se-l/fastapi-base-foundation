from collections.abc import AsyncGenerator
import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from main import app
from src.database.base import BaseModel
from src.database.session import get_session

TEST_DATABASE_URL = 'sqlite+aiosqlite:///file:test_shared_mem?mode=memory&cache=shared&uri=true'

test_engine = create_async_engine(
    TEST_DATABASE_URL,
    echo=False,
    poolclass=StaticPool,
    connect_args={'check_same_thread': False},
)

TestSessionLocal = async_sessionmaker(
    bind=test_engine,
    class_=AsyncSession,
    autoflush=False,
    expire_on_commit=False,
)


import src.database.session
import src.modules.audit.model
import src.modules.audit.service
import src.modules.auth.model
import src.modules.user.model
from src.security import AuthorizationService
from src.share import reset_all_rate_limiters


@pytest_asyncio.fixture(autouse=True)
async def init_test_database(monkeypatch):
    """Initializes a fresh schema for each test session, binds AsyncSessionLocal, and initializes AuthorizationService."""
    reset_all_rate_limiters()
    monkeypatch.setattr(src.database.session, "AsyncSessionLocal", TestSessionLocal)
    monkeypatch.setattr(src.modules.audit.service, "AsyncSessionLocal", TestSessionLocal)
    async with test_engine.begin() as conn:
        await conn.run_sync(BaseModel.metadata.create_all)
    await AuthorizationService.initialize(test_engine)
    await AuthorizationService.seed_default_policies()
    yield
    reset_all_rate_limiters()
    AuthorizationService.reset()
    async with test_engine.begin() as conn:
        await conn.run_sync(BaseModel.metadata.drop_all)


@pytest_asyncio.fixture
async def db_session() -> AsyncGenerator[AsyncSession, None]:
    """Provides an isolated database session for testing."""
    async with TestSessionLocal() as session:
        yield session


@pytest_asyncio.fixture
async def client() -> AsyncGenerator[AsyncClient, None]:
    """Provides an HTTP test client connected to the FastAPI application."""

    async def _override_get_session() -> AsyncGenerator[AsyncSession, None]:
        async with TestSessionLocal() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise

    app.dependency_overrides[get_session] = _override_get_session
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url='http://test') as ac:
        yield ac
    app.dependency_overrides.clear()
