from collections.abc import Sequence
from datetime import datetime, timedelta, timezone

from sqlalchemy import delete, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from src.database import BaseRepository
from .model import RefreshSession


class RefreshSessionRepository(BaseRepository[RefreshSession]):
    """Repository for RefreshSession CRUD and revocation operations.

    Attributes:
        model: The RefreshSession ORM class.
        session: The active async database session.
    """

    def __init__(self, session: AsyncSession):
        """Initializes with the RefreshSession model.

        Args:
            session: The active async database session.
        """
        super().__init__(class_=RefreshSession, session=session)

    async def get_by_jti(self, jti: str) -> RefreshSession | None:
        """Fetches a refresh session by its unique JTI claim.

        Args:
            jti: The JWT ID string.

        Returns:
            The RefreshSession instance or None if not found.
        """
        return await self.get_by_attr(refresh_token_jti=jti)

    async def revoke_if_active(self, jti: str) -> bool:
        """Atomically revokes a refresh session only if it is currently active.

        This guarantees atomic Compare-And-Swap (CAS) semantics to prevent
        race conditions where two concurrent requests rotate the same token.

        Args:
            jti: The JWT ID string to revoke.

        Returns:
            True if the session was successfully revoked (affected rows > 0),
            False if it was already revoked or not found.
        """
        now = datetime.now(timezone.utc)
        stmt = (
            update(RefreshSession)
            .where(
                RefreshSession.refresh_token_jti == jti,
                RefreshSession.is_revoked.is_(False),
            )
            .values(is_revoked=True, revoked_at=now)
        )

        result = await self.session.execute(stmt)
        return (result.rowcount or 0) > 0

    async def revoke_by_jti(self, jti: str) -> None:
        """Revokes a single refresh session by JTI.

        Args:
            jti: The JWT ID string to revoke.
        """
        now = datetime.now(timezone.utc)
        stmt = (
            update(RefreshSession)
            .where(
                RefreshSession.refresh_token_jti == jti,
                RefreshSession.is_revoked.is_(False),
            )
            .values(is_revoked=True, revoked_at=now)
        )
        await self.session.execute(stmt)

    async def revoke_family(self, family_id: str, user_id: int) -> int:
        """Revokes all active refresh sessions of one family, strictly scoped to one user.

        Args:
            family_id: The lineage family identifier string.
            user_id: Owner of the family. Rows of any other user are never touched.

        Returns:
            The number of revoked session records.
        """
        now = datetime.now(timezone.utc)
        stmt = (
            update(RefreshSession)
            .where(
                RefreshSession.family_id == family_id,
                RefreshSession.user_id == user_id,
                RefreshSession.is_revoked.is_(False),
            )
            .values(is_revoked=True, revoked_at=now)
        )
        result = await self.session.execute(stmt)
        return result.rowcount or 0

    async def revoke_all_for_user(self, user_id: int) -> int:
        """Revokes all active refresh sessions for a user.

        Used for logout-all-devices and post-password-change invalidation.

        Args:
            user_id: The user's primary key.

        Returns:
            The number of revoked session records.
        """
        now = datetime.now(timezone.utc)
        stmt = (
            update(RefreshSession)
            .where(
                RefreshSession.user_id == user_id,
                RefreshSession.is_revoked.is_(False),
            )
            .values(is_revoked=True, revoked_at=now)
        )
        result = await self.session.execute(stmt)
        return result.rowcount or 0

    async def is_family_active(self, family_id: str, user_id: int) -> bool:
        """Checks whether a session family currently possesses at least one valid, unrevoked, unexpired session.

        Enforces strict fail-closed validation: returns True only if an active unexpired record exists.

        Args:
            family_id: The session family identifier.
            user_id: The expected user subject ID.

        Returns:
            True if the family has an active, unexpired session; False otherwise.
        """
        now = datetime.now(timezone.utc)
        stmt_active = (
            select(RefreshSession.id)
            .where(
                RefreshSession.family_id == family_id,
                RefreshSession.user_id == user_id,
                RefreshSession.is_revoked.is_(False),
                RefreshSession.expires_at > now,
            )
            .limit(1)
        )
        active_id = (await self.session.execute(stmt_active)).scalar_one_or_none()
        return active_id is not None

    async def list_active_for_user(self, user_id: int) -> Sequence[RefreshSession]:
        """Fetches all active, unrevoked sessions for a specific user.

        Args:
            user_id: The user's primary key.

        Returns:
            A sequence of active RefreshSession instances.
        """
        now = datetime.now(timezone.utc)
        stmt = (
            select(RefreshSession)
            .where(
                RefreshSession.user_id == user_id,
                RefreshSession.is_revoked.is_(False),
                RefreshSession.expires_at > now,
            )
            .order_by(RefreshSession.created_at.desc())
        )
        result = await self.session.execute(stmt)
        return result.scalars().all()

    async def purge_expired_tombstones(self, grace_seconds: int = 300) -> int:
        """Deletes ONLY refresh session rows whose cryptographic expiration (expires_at)
        has passed beyond grace_seconds. NEVER deletes unexpired revoked rows,
        preserving replay detection tombstones (RFC 9700 Section 4.14.2 - fixes P04).

        Args:
            grace_seconds: Grace period in seconds to retain expired tombstones.

        Returns:
            The number of deleted records.
        """
        cutoff = datetime.now(timezone.utc) - timedelta(seconds=grace_seconds)
        stmt = delete(RefreshSession).where(RefreshSession.expires_at <= cutoff)
        result = await self.session.execute(stmt)
        return int(result.rowcount or 0)
