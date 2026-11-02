from typing import Literal, overload
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession
from src.database import BaseRepository

from .model import User


class UserRepository(BaseRepository[User]):
    def __init__(self, session: AsyncSession):
        super().__init__(class_=User, session=session)

    async def get_by_email(self, email: str) -> User | None:
        return await self.get_by_attr(email=email)

    @overload
    async def is_exist_by_email(
        self,
        email: str,
        return_orm: Literal[False] = False
    ) -> bool: ...

    @overload
    async def is_exist_by_email(
        self,
        email: str,
        return_orm: Literal[True]
    ) -> tuple[bool, User | None]: ...

    async def is_exist_by_email(
        self,
        email: str,
        return_orm: bool = False
    ) -> bool | tuple[bool, User | None]:
        user = await self.get_by_email(email)
        return user is not None, user if return_orm else user is not None

    async def is_active_by_id(self, id: int) -> bool:
        user = await self.get_by_id(id=id)
        return user.is_active if user is not None else False

    async def acquire_admin_governance_lock_and_count(self) -> int:
        """Acquires a governance lock on active admins and counts them atomically (fixes P11).

        In SQLite: executes an immediate dummy update to serialize concurrent transactions.
        In PostgreSQL/MySQL: uses SELECT ... WITH FOR UPDATE.
        """
        bind = self.session.get_bind()
        dialect_name = bind.dialect.name if bind is not None else ""
        if dialect_name == "sqlite":
            await self.session.execute(
                text(
                    "UPDATE users SET security_version = security_version "
                    "WHERE role = 'admin' AND is_active = 1"
                )
            )
        else:
            stmt_lock = (
                select(User.id)
                .where(User.role == "admin", User.is_active.is_(True))
                .with_for_update()
            )
            await self.session.execute(stmt_lock)

        stmt_count = (
            select(func.count())
            .select_from(User)
            .where(User.role == "admin", User.is_active.is_(True))
        )
        res = await self.session.execute(stmt_count)
        return int(res.scalar_one())
