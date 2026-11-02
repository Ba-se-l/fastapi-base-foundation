from typing import Any
from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.database import BaseRepository
from .model import AuditLog
from .schemas import LogQueryFilter


class AuditLogRepository(BaseRepository[AuditLog]):
    """Database repository for persisting and querying audit log entities."""

    def __init__(self, session: AsyncSession):
        super().__init__(class_=AuditLog, session=session)

    async def query_logs(
        self,
        filter_params: LogQueryFilter,
        *,
        offset: int = 0,
        limit: int = 50,
    ) -> tuple[list[AuditLog], int]:
        """Queries audit records based on dynamic filter parameters with pagination.

        Args:
            filter_params: Multi-field filtering criteria.
            offset: Number of records to skip.
            limit: Maximum records to return.

        Returns:
            Tuple of (records_list, total_matching_count).
        """
        stmt = select(AuditLog)
        count_stmt = select(func.count()).select_from(AuditLog)

        # Dynamic filter composition
        if filter_params.user_id:
            stmt = stmt.where(AuditLog.user_id == filter_params.user_id)
            count_stmt = count_stmt.where(AuditLog.user_id == filter_params.user_id)

        if filter_params.actor_id:
            stmt = stmt.where(AuditLog.actor_id == filter_params.actor_id)
            count_stmt = count_stmt.where(AuditLog.actor_id == filter_params.actor_id)

        if filter_params.entity_type:
            stmt = stmt.where(AuditLog.entity_type == filter_params.entity_type)
            count_stmt = count_stmt.where(AuditLog.entity_type == filter_params.entity_type)

        if filter_params.entity_id:
            stmt = stmt.where(AuditLog.entity_id == filter_params.entity_id)
            count_stmt = count_stmt.where(AuditLog.entity_id == filter_params.entity_id)

        if filter_params.domain_id:
            stmt = stmt.where(AuditLog.domain_id == filter_params.domain_id)
            count_stmt = count_stmt.where(AuditLog.domain_id == filter_params.domain_id)

        if filter_params.outcome:
            stmt = stmt.where(AuditLog.outcome == filter_params.outcome)
            count_stmt = count_stmt.where(AuditLog.outcome == filter_params.outcome)

        if filter_params.event_type:
            stmt = stmt.where(AuditLog.event_type == filter_params.event_type)
            count_stmt = count_stmt.where(AuditLog.event_type == filter_params.event_type)

        if filter_params.severity:
            stmt = stmt.where(AuditLog.severity == filter_params.severity.value)
            count_stmt = count_stmt.where(AuditLog.severity == filter_params.severity.value)

        if filter_params.from_date:
            stmt = stmt.where(AuditLog.created_at >= filter_params.from_date)
            count_stmt = count_stmt.where(AuditLog.created_at >= filter_params.from_date)

        if filter_params.to_date:
            stmt = stmt.where(AuditLog.created_at <= filter_params.to_date)
            count_stmt = count_stmt.where(AuditLog.created_at <= filter_params.to_date)

        if filter_params.search:
            pattern = f"%{filter_params.search}%"
            stmt = stmt.where(AuditLog.message.ilike(pattern))
            count_stmt = count_stmt.where(AuditLog.message.ilike(pattern))

        # Total count query
        total_res = await self.session.execute(count_stmt)
        total = total_res.scalar() or 0

        # Paginated items query (newest first)
        stmt = stmt.order_by(desc(AuditLog.created_at)).offset(offset).limit(limit)
        items_res = await self.session.execute(stmt)
        items = items_res.scalars().all()

        return list(items), total

    async def get_by_user(
        self,
        user_id: str,
        *,
        offset: int = 0,
        limit: int = 50,
    ) -> tuple[list[AuditLog], int]:
        """Convenience query for all audit records of a specific user.

        Args:
            user_id: Target user string identifier.
            offset: Records offset.
            limit: Maximum records.

        Returns:
            Tuple of (records_list, total_count).
        """
        filter_params = LogQueryFilter(user_id=user_id)
        return await self.query_logs(filter_params, offset=offset, limit=limit)

    async def get_all_matching(
        self,
        filter_params: LogQueryFilter,
        *,
        max_records: int = 1000,
    ) -> list[AuditLog]:
        """Retrieves matching records without offset pagination for file export.

        Args:
            filter_params: Filtering criteria.
            max_records: Safety limit on total exported rows.

        Returns:
            List of matched AuditLog entities.
        """
        items, _ = await self.query_logs(filter_params, offset=0, limit=max_records)
        return items

    async def update(self, instance: AuditLog, update_dict: dict[str, Any]) -> AuditLog:
        """Prohibits updating audit logs to preserve historical audit trail integrity.

        Args:
            instance: The target AuditLog instance.
            update_dict: Key-value attributes intended for update.

        Raises:
            NotImplementedError: Always, audit records are strictly immutable.
        """
        raise NotImplementedError("AuditLog records are immutable and cannot be updated.")

    async def delete(self, instance: AuditLog) -> bool:
        """Prohibits deleting audit logs to preserve historical audit trail integrity.

        Args:
            instance: The target AuditLog instance to delete.

        Raises:
            NotImplementedError: Always, audit records are strictly immutable.
        """
        raise NotImplementedError("AuditLog records are immutable and cannot be deleted.")
