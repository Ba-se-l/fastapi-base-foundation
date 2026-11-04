import uuid
from collections.abc import AsyncGenerator, Callable, Awaitable
from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

import manage
import src.database.session
import src.modules.audit.model
import src.modules.audit.service
import src.modules.auth.model
import src.modules.user.model
from main import app
from src.database.base import BaseModel
from src.database.session import get_session
from src.modules.auth.model import RefreshSession
from src.security import AuthorizationService, create_access_token
from src.share import reset_all_rate_limiters
from tests.support.database import TEST_DATABASE_URL, TestSessionLocal, test_engine

# Re-export for any existing tests
__all__ = (
    "TEST_DATABASE_URL",
    "TestSessionLocal",
    "test_engine",
    "init_test_database",
    "db_session",
    "client",
    "make_access_token",
    "create_test_access_token",
)


@pytest_asyncio.fixture(autouse=True)
async def init_test_database(monkeypatch: pytest.MonkeyPatch) -> AsyncGenerator[None, None]:
    """Initializes an isolated in-memory database schema for each test function."""
    reset_all_rate_limiters()
    monkeypatch.setattr(src.database.session, "AsyncSessionLocal", TestSessionLocal)
    monkeypatch.setattr(src.modules.audit.service, "AsyncSessionLocal", TestSessionLocal)
    monkeypatch.setattr(manage, "AsyncSessionLocal", TestSessionLocal)

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
    """Provides an HTTP test client connected to the FastAPI application with session override."""

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
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac
    app.dependency_overrides.clear()


@pytest.fixture
def make_access_token(db_session: AsyncSession) -> Callable[..., Awaitable[str]]:
    """Factory fixture: generates a signed JWT and registers an active lineage RefreshSession."""

    async def _make(user_id: int, security_version: int = 1) -> str:
        family_id = uuid.uuid4().hex
        token = create_access_token(
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

    return _make


async def create_test_access_token(
    db_session: AsyncSession,
    user_id: int,
    security_version: int = 1,
) -> str:
    """Legacy helper for direct callers."""
    family_id = uuid.uuid4().hex
    token = create_access_token(
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
