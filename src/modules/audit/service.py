import asyncio
from datetime import datetime, timezone
import logging
from pathlib import Path
import re
from typing import Any

from fastapi.encoders import jsonable_encoder
from sqlalchemy import event as sa_event
from sqlalchemy.ext.asyncio import AsyncSession

from src.database import AsyncSessionLocal
from src.settings import settings
from src.share import AuditContext
from .enum import ExportFormat, LogAction, LogSeverity
from .formatters import get_formatter
from .model import AuditLog
from .repo import AuditLogRepository
from .schemas import LogEvent, LogExportParams, LogQueryFilter, LogResponse

logger = logging.getLogger(__name__)

_background_tasks: set[asyncio.Task[None]] = set()

SENSITIVE_KEY_PATTERN = re.compile(
    r"(password|passwd|pwd|secret|token|jwt|cookie|authorization|api_key|credit_card|access_token|refresh_token|hashed_password)",
    re.IGNORECASE,
)


def sanitize_audit_payload(payload: Any) -> Any:
    """Recursively redacts sensitive keys matching credentials, tokens, or secrets."""
    if isinstance(payload, dict):
        return {
            k: ("[REDACTED]" if isinstance(k, str) and SENSITIVE_KEY_PATTERN.search(k) else sanitize_audit_payload(v))
            for k, v in payload.items()
        }
    elif isinstance(payload, list):
        return [sanitize_audit_payload(item) for item in payload]
    elif isinstance(payload, tuple):
        return tuple(sanitize_audit_payload(item) for item in payload)
    return payload


def scrub_error_reason(error: Any) -> str:
    """Removes SQL code or credential strings from error details to avoid forensic leaks."""
    text = str(error)
    cleaned = re.sub(
        r"['\"][^'\"]*(?:password|token|secret)[^'\"]*['\"]",
        "'[REDACTED]'",
        text,
        flags=re.IGNORECASE,
    )
    if "SELECT " in cleaned or "INSERT INTO " in cleaned or "UPDATE " in cleaned:
        cleaned = re.sub(r"\[SQL:.*?\]", "[SQL: REDACTED]", cleaned, flags=re.DOTALL)
    return cleaned


def _schedule_file_write(response: LogResponse) -> None:
    """Schedules a non-blocking file append while holding a strong task reference."""
    task = asyncio.create_task(asyncio.to_thread(_append_to_file_sync, settings.log_dir, response))
    _background_tasks.add(task)
    task.add_done_callback(_background_tasks.discard)


async def drain_background_tasks(timeout: float = 5.0) -> None:
    """Awaits pending audit file writes during shutdown, logging any that time out."""
    if not _background_tasks:
        return
    tasks = list(_background_tasks)
    try:
        await asyncio.wait_for(asyncio.gather(*tasks, return_exceptions=True), timeout=timeout)
    except TimeoutError:
        logger.warning("Timed out draining audit background file tasks (%d pending)", len(_background_tasks))


def _append_to_file_sync(log_dir: str, log_resp: LogResponse) -> None:
    """Synchronous file writer invoked via worker thread to avoid event loop blocking."""
    try:
        dir_path = Path(log_dir)
        dir_path.mkdir(parents=True, exist_ok=True)

        date_str = datetime.now(timezone.utc).strftime('%Y-%m-%d')

        # 1. Append JSON Line
        json_file = dir_path / f"{date_str}.json"
        json_line = get_formatter(ExportFormat.JSON).format_single(log_resp) + '\n'
        with open(json_file, 'a', encoding='utf-8') as f:
            f.write(json_line)

        # 2. Append Human-readable TXT
        txt_file = dir_path / f"{date_str}.txt"
        txt_line = get_formatter(ExportFormat.TXT).format_single(log_resp) + '\n'
        with open(txt_file, 'a', encoding='utf-8') as f:
            f.write(txt_line)

        # 3. Append Markdown Row
        md_file = dir_path / f"{date_str}.md"
        md_row = get_formatter(ExportFormat.MARKDOWN).format_single(log_resp) + '\n'
        is_new = not md_file.exists() or md_file.stat().st_size == 0
        with open(md_file, 'a', encoding='utf-8') as f:
            if is_new:
                header = (
                    '# 📜 Daily Audit Log\n\n'
                    '| ID | Timestamp (UTC) | Severity | Event Type | User ID | Request ID | Message |\n'
                    '|---|---|---|---|---|---|---|\n'
                )
                f.write(header)
            f.write(md_row)
    except Exception as exc:
        logger.warning('Failed to append audit log to disk: %s', exc)


def _attach_post_commit_file_writer(session: AsyncSession, log_resp: LogResponse) -> None:
    """Registers transactional hooks on the session to flush or discard pending file logs."""
    if not settings.log_to_file or not settings.log_dir:
        return

    sync_sess = session.sync_session
    queue: list[LogResponse] = sync_sess.info.setdefault("_pending_audit_files", [])
    queue.append(log_resp)

    if not sync_sess.info.get("_audit_commit_hook_registered"):
        sync_sess.info["_audit_commit_hook_registered"] = True

        @sa_event.listens_for(sync_sess, "after_commit")
        def _flush_audit_files(s: Any) -> None:
            items: list[LogResponse] = s.info.pop("_pending_audit_files", [])
            for item in items:
                _schedule_file_write(item)

        @sa_event.listens_for(sync_sess, "after_rollback")
        def _clear_audit_files(s: Any) -> None:
            s.info.pop("_pending_audit_files", None)


async def log_event(
    event: LogEvent,
    session: AsyncSession | None = None,
) -> LogResponse:
    """Central maestro orchestrating audit logging across database and file storage.

    Args:
        event: Validated LogEvent payload.
        session: Optional active async database session. If None, an autonomous session is created and committed.

    Returns:
        Persisted LogResponse representation.
    """
    # Sanitize extra_data and changes_payload
    sanitized_extra_data = (
        sanitize_audit_payload(
            jsonable_encoder(event.extra_data, custom_encoder={Exception: str})
        )
        if event.extra_data is not None
        else None
    )

    sanitized_changes = (
        sanitize_audit_payload(event.changes_payload)
        if event.changes_payload is not None
        else None
    )

    # 1. Build audit entity
    audit_instance = AuditLog(
        event_type=event.event_type,
        severity=event.severity.value,
        message=event.message,
        user_id=event.user_id,
        actor_id=event.actor_id,
        actor_snapshot=event.actor_snapshot,
        entity_type=event.entity_type,
        entity_id=event.entity_id,
        domain_id=event.domain_id or "global",
        outcome=event.outcome or "SUCCESS",
        changes_payload=sanitized_changes,
        occurred_at=event.occurred_at or datetime.now(timezone.utc),
        request_id=event.request_id,
        ip_address=event.ip_address,
        user_agent=event.user_agent,
        extra_data=sanitized_extra_data,
    )

    if audit_instance.created_at is None:
        audit_instance.created_at = datetime.now(timezone.utc)

    if settings.log_to_db:
        try:
            if session is not None:
                repo = AuditLogRepository(session=session)
                audit_instance = await repo.create(audit_instance)
                await session.flush()
                log_response = LogResponse.model_validate(audit_instance)
                _attach_post_commit_file_writer(session, log_response)
                return log_response
            else:
                async with AsyncSessionLocal() as audit_session:
                    repo = AuditLogRepository(session=audit_session)
                    audit_instance = await repo.create(audit_instance)
                    await audit_session.commit()
                    await audit_session.refresh(audit_instance)
                    log_response = LogResponse.model_validate(audit_instance)
                    if settings.log_to_file and settings.log_dir:
                        _schedule_file_write(log_response)
                    return log_response
        except Exception:
            if settings.log_to_file and settings.log_dir:
                _schedule_file_write(LogResponse.model_validate(audit_instance))
            raise
    else:
        log_response = LogResponse.model_validate(audit_instance)
        if settings.log_to_file and settings.log_dir:
            _schedule_file_write(log_response)
        return log_response


async def save_success_event(
    message: str,
    *,
    session: AsyncSession | None = None,
    event_type: str | LogAction = LogAction.CUSTOM,
    user_id: str | None = None,
    actor_id: str | None = None,
    actor_snapshot: str | None = None,
    entity_type: str | None = None,
    entity_id: str | None = None,
    domain_id: str | None = "global",
    outcome: str = "SUCCESS",
    changes_payload: dict[str, Any] | None = None,
    occurred_at: datetime | None = None,
    ctx: AuditContext | None = None,
    request_id: str | None = None,
    ip_address: str | None = None,
    user_agent: str | None = None,
    extra_data: dict[str, Any] | None = None,
) -> LogResponse:
    """Specialist helper for recording successful state transitions with INFO severity."""
    action_str = event_type.value if isinstance(event_type, LogAction) else event_type
    event = LogEvent(
        event_type=action_str,
        severity=LogSeverity.INFO,
        message=message,
        user_id=user_id,
        actor_id=actor_id,
        actor_snapshot=actor_snapshot,
        entity_type=entity_type,
        entity_id=entity_id,
        domain_id=domain_id,
        outcome=outcome,
        changes_payload=changes_payload,
        occurred_at=occurred_at,
        request_id=request_id or (ctx.request_id if ctx else None),
        ip_address=ip_address or (ctx.ip_address if ctx else None),
        user_agent=user_agent or (ctx.user_agent if ctx else None),
        extra_data=extra_data,
    )
    return await log_event(event, session=session)


async def save_failed_event(
    message: str,
    *,
    session: AsyncSession | None = None,
    event_type: str | LogAction = LogAction.SYSTEM_ERROR,
    severity: LogSeverity = LogSeverity.ERROR,
    user_id: str | None = None,
    actor_id: str | None = None,
    actor_snapshot: str | None = None,
    entity_type: str | None = None,
    entity_id: str | None = None,
    domain_id: str | None = "global",
    outcome: str = "FAILURE",
    changes_payload: dict[str, Any] | None = None,
    occurred_at: datetime | None = None,
    ctx: AuditContext | None = None,
    request_id: str | None = None,
    ip_address: str | None = None,
    user_agent: str | None = None,
    extra_data: dict[str, Any] | None = None,
) -> LogResponse:
    """Specialist helper for recording failures or security warnings."""
    action_str = event_type.value if isinstance(event_type, LogAction) else event_type
    event = LogEvent(
        event_type=action_str,
        severity=severity,
        message=message,
        user_id=user_id,
        actor_id=actor_id,
        actor_snapshot=actor_snapshot,
        entity_type=entity_type,
        entity_id=entity_id,
        domain_id=domain_id,
        outcome=outcome,
        changes_payload=changes_payload,
        occurred_at=occurred_at,
        request_id=request_id or (ctx.request_id if ctx else None),
        ip_address=ip_address or (ctx.ip_address if ctx else None),
        user_agent=user_agent or (ctx.user_agent if ctx else None),
        extra_data=extra_data,
    )
    return await log_event(event, session=session)


async def query_audit_logs(
    filter_params: LogQueryFilter,
    session: AsyncSession,
    *,
    offset: int = 0,
    limit: int = 50,
) -> tuple[list[LogResponse], int]:
    """Retrieves paginated audit log entries matching filter parameters."""
    repo = AuditLogRepository(session=session)
    items, total = await repo.query_logs(filter_params, offset=offset, limit=limit)
    return [LogResponse.model_validate(item) for item in items], total


async def get_user_audit_logs(
    user_id: str,
    session: AsyncSession,
    *,
    offset: int = 0,
    limit: int = 50,
) -> tuple[list[LogResponse], int]:
    """Retrieves all audit entries linked specifically to a single user identifier."""
    repo = AuditLogRepository(session=session)
    items, total = await repo.get_by_user(user_id, offset=offset, limit=limit)
    return [LogResponse.model_validate(item) for item in items], total


async def export_audit_logs(
    params: LogExportParams,
    session: AsyncSession,
    *,
    max_records: int = 1000,
) -> tuple[str, str, str]:
    """Exports matching audit logs into a formatted document for download.

    Args:
        params: Export criteria and target format.
        session: Active database session.
        max_records: Upper threshold for exported records.

    Returns:
        Tuple of (content_string, media_type, download_filename).
    """
    filter_params = LogQueryFilter(
        user_id=params.user_id,
        actor_id=params.actor_id,
        entity_type=params.entity_type,
        entity_id=params.entity_id,
        domain_id=params.domain_id,
        outcome=params.outcome,
        event_type=params.event_type,
        severity=params.severity,
        from_date=params.from_date,
        to_date=params.to_date,
    )

    repo = AuditLogRepository(session=session)
    items = await repo.get_all_matching(filter_params, max_records=max_records)
    responses = [LogResponse.model_validate(item) for item in items]

    formatter = get_formatter(params.format)
    content = formatter.format_batch(responses)

    # Resolve filename & content type
    if params.user_id:
        sanitized_uid = re.sub(r'[^A-Za-z0-9_-]', '_', str(params.user_id))[:64]
        target_tag = f"user_{sanitized_uid}"
    else:
        target_tag = 'audit'
    now_str = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
    filename = f"{target_tag}_{now_str}.{params.format.value}"

    media_types = {
        ExportFormat.JSON: 'application/json',
        ExportFormat.TXT: 'text/plain; charset=utf-8',
        ExportFormat.MARKDOWN: 'text/markdown; charset=utf-8',
    }

    return content, media_types[params.format], filename
