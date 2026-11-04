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


import uuid
from datetime import datetime, timedelta, timezone
from src.modules.auth.model import RefreshSession
from src.security import create_access_token as _base_create_access_token


async def create_test_access_token(
    db_session: AsyncSession,
    user_id: int,
    security_version: int = 1,
) -> str:
    """Creates a signed JWT access token and registers an active RefreshSession in the test DB."""
    family_id = uuid.uuid4().hex
    token = _base_create_access_token(
        user_id=user_id,
        security_version=security_version,
        family_id=family_id,
    )
    now = datetime.now(timezone.utc)
    sess = RefreshSession(
        user_id=user_id,
        family_id=family_id,
        refresh_token_jti=uuid.uuid4().hex,
        expires_at=now + timedelta(days=7),
        is_revoked=False,
    )
    db_session.add(sess)
    await db_session.commit()
    return token

