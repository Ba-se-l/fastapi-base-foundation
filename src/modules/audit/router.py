from fastapi import APIRouter, Depends, Query, Response, status

from src.database import SessionDep
from src.modules.auth.dependencies import require_permission, require_role
from src.modules.user.model import User
from src.settings import settings
from src.share import (
    Action,
    PaginatedResponse,
    PaginationMeta,
    PaginationParams,
    Resource,
    Roles,
)
from . import service
from .enum import ExportFormat, LogSeverity
from .schemas import LogExportParams, LogQueryFilter, LogResponse

router = APIRouter(prefix=f"{settings.api_prefix}/audit", tags=['Audit & Logging'])


@router.get(
    '/logs',
    response_model=PaginatedResponse[LogResponse],
    status_code=status.HTTP_200_OK,
    summary='Query audit logs (Admin only)',
    description='Filters and paginates system-wide audit records.',
)
async def list_audit_logs_endpoint(
    pagination: PaginationParams = Depends(),
    user_id: str | None = Query(None, description='Filter by user identifier'),
    actor_id: str | None = Query(None, description='Filter by actor identifier'),
    entity_type: str | None = Query(None, description='Filter by entity type'),
    entity_id: str | None = Query(None, description='Filter by entity ID'),
    domain_id: str | None = Query(None, description='Filter by domain ID'),
    outcome: str | None = Query(None, description='Filter by outcome status'),
    event_type: str | None = Query(None, description='Filter by action tag'),
    severity: LogSeverity | None = Query(None, description='Filter by severity level'),
    search: str | None = Query(None, description='Search narrative message'),
    session: SessionDep = None,
    _: User = Depends(require_permission(resource=Resource.AUDIT, action=Action.READ)),
) -> PaginatedResponse[LogResponse]:
    """Retrieves filtered, paginated audit entries for administrators."""
    filter_params = LogQueryFilter(
        user_id=user_id,
        actor_id=actor_id,
        entity_type=entity_type,
        entity_id=entity_id,
        domain_id=domain_id,
        outcome=outcome,
        event_type=event_type,
        severity=severity,
        search=search,
    )
    logs, total = await service.query_audit_logs(
        filter_params=filter_params,
        session=session,
        offset=pagination.offset,
        limit=pagination.page_size,
    )
    return PaginatedResponse(
        data=logs,
        pagination=PaginationMeta.from_params(
            page=pagination.page,
            page_size=pagination.page_size,
            total=total,
        ),
    )


@router.get(
    '/users/{user_id}/logs',
    response_model=PaginatedResponse[LogResponse],
    status_code=status.HTTP_200_OK,
    summary='Get user audit trail (Admin only)',
    description='Returns a paginated list of all actions attributed to a specific user.',
)
async def get_user_logs_endpoint(
    user_id: str,
    pagination: PaginationParams = Depends(),
    session: SessionDep = None,
    _: User = Depends(require_permission(resource=Resource.AUDIT, action=Action.READ)),
) -> PaginatedResponse[LogResponse]:
    """Retrieves paginated audit log entries for a single user."""
    logs, total = await service.get_user_audit_logs(
        user_id=user_id,
        session=session,
        offset=pagination.offset,
        limit=pagination.page_size,
    )
    return PaginatedResponse(
        data=logs,
        pagination=PaginationMeta.from_params(
            page=pagination.page,
            page_size=pagination.page_size,
            total=total,
        ),
    )


@router.get(
    '/export',
    status_code=status.HTTP_200_OK,
    summary='Export audit logs (Admin only)',
    description='Exports matched audit records as a downloadable file (JSON, TXT, or Markdown).',
)
async def export_audit_logs_endpoint(
    format: ExportFormat = Query(ExportFormat.JSON, description='Output format (json, txt, md)'),
    user_id: str | None = Query(None, description='Filter export by user ID'),
    actor_id: str | None = Query(None, description='Filter export by actor ID'),
    entity_type: str | None = Query(None, description='Filter export by entity type'),
    entity_id: str | None = Query(None, description='Filter export by entity ID'),
    domain_id: str | None = Query(None, description='Filter export by domain ID'),
    outcome: str | None = Query(None, description='Filter export by outcome'),
    event_type: str | None = Query(None, description='Filter export by event category'),
    severity: LogSeverity | None = Query(None, description='Filter export by severity'),
    session: SessionDep = None,
    _: User = Depends(require_permission(resource=Resource.AUDIT, action=Action.EXPORT)),
) -> Response:
    """Streams a serialized audit export file to the client."""
    params = LogExportParams(
        format=format,
        user_id=user_id,
        actor_id=actor_id,
        entity_type=entity_type,
        entity_id=entity_id,
        domain_id=domain_id,
        outcome=outcome,
        event_type=event_type,
        severity=severity,
    )
    content, media_type, filename = await service.export_audit_logs(
        params=params,
        session=session,
    )
    return Response(
        content=content,
        media_type=media_type,
        headers={'Content-Disposition': f'attachment; filename="{filename}"'},
    )


@router.get(
    '/users/{user_id}/export',
    status_code=status.HTTP_200_OK,
    summary='Export user audit trail (Admin only)',
    description='Exports all logs for a specific user as a downloadable file in the selected format.',
)
async def export_user_logs_endpoint(
    user_id: str,
    format: ExportFormat = Query(ExportFormat.MARKDOWN, description='Output format (json, txt, md)'),
    session: SessionDep = None,
    _: User = Depends(require_permission(resource=Resource.AUDIT, action=Action.EXPORT)),
) -> Response:
    """Exports a specific user audit report as a downloadable file."""
    params = LogExportParams(
        format=format,
        user_id=user_id,
    )
    content, media_type, filename = await service.export_audit_logs(
        params=params,
        session=session,
    )
    return Response(
        content=content,
        media_type=media_type,
        headers={'Content-Disposition': f'attachment; filename="{filename}"'},
    )
