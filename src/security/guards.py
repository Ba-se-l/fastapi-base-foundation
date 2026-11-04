from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
import logging
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

from fastapi import Depends, Request

from src.exc import AccessDeniedException
from src.security.authorization import AuthorizationService, GLOBAL_DOMAIN
from src.share import Action, AuditContext, Resource, UserAction, event_bus, get_audit_context

if TYPE_CHECKING:
    from src.modules.user.model import User

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class DomainResolutionResult:
    """Resolved domain access context for authorization checks."""

    domain_id: str
    is_member: bool = False
    domain_role: str | None = None
    parent_valid: bool = True
    deny_reason: str | None = None


@runtime_checkable
class DomainAccessResolver(Protocol):
    """Protocol for abstract domain/tenant resolution across modules."""

    async def resolve_domain_access(
        self, user: Any, request: Request
    ) -> DomainResolutionResult:
        ...


class DefaultGlobalDomainResolver:
    """Fallback domain resolver failing closed when no explicit resolver is provided."""

    async def resolve_domain_access(
        self, user: Any, request: Request
    ) -> DomainResolutionResult:
        return DomainResolutionResult(
            domain_id=GLOBAL_DOMAIN,
            is_member=False,
            deny_reason="Explicit DomainAccessResolver is required for domain-scoped endpoints",
        )


def require_domain_permission(
    resource: str,
    action: str,
    resolver: DomainAccessResolver | None = None,
) -> Callable[..., Awaitable[Any]]:
    """FastAPI dependency factory enforcing 4-tuple domain Casbin permission check.

    Resolves domain membership and valid lineage via DomainAccessResolver,
    evaluating authorization through Casbin (sub, dom, obj, act).
    """
    domain_resolver = resolver or DefaultGlobalDomainResolver()
    # Lazy import to break circular import with domain modules
    from src.modules.auth.dependencies import get_current_user

    async def _dependency(
        request: Request,
        current_user: Any = Depends(get_current_user),
        audit_ctx: AuditContext = Depends(get_audit_context),
    ) -> Any:
        resolution = await domain_resolver.resolve_domain_access(current_user, request)

        if not resolution.parent_valid or not resolution.is_member:
            deny_reason = resolution.deny_reason or "Domain access denied or inactive membership."
            logger.warning(
                "Domain access denied: user_id=%s domain=%s reason=%s",
                current_user.id,
                resolution.domain_id,
                deny_reason,
            )
            from src.modules.user.events import UserAccessDenied

            await event_bus.publish(
                UserAccessDenied(
                    audit_ctx=audit_ctx,
                    actor_id=current_user.id,
                    actor_name=getattr(current_user, "name", str(current_user.id)),
                    target_user_id=current_user.id,
                    action=UserAction.VIEW,
                )
            )
            raise AccessDeniedException(deny_reason)

        effective_role = resolution.domain_role or current_user.role.value
        await AuthorizationService.check_and_refresh_cache()
        allowed = AuthorizationService.is_allowed(
            user_id=current_user.id,
            role=effective_role,
            resource=resource,
            action=action,
            domain=resolution.domain_id,
        )

        if not allowed:
            logger.warning(
                "Permission denied: user_id=%s role=%s domain=%s resource=%s action=%s",
                current_user.id,
                effective_role,
                resolution.domain_id,
                resource,
                action,
            )
            from src.modules.user.events import UserAccessDenied

            await event_bus.publish(
                UserAccessDenied(
                    audit_ctx=audit_ctx,
                    actor_id=current_user.id,
                    actor_name=getattr(current_user, "name", str(current_user.id)),
                    target_user_id=current_user.id,
                    action=UserAction.VIEW,
                )
            )
            raise AccessDeniedException(
                f"You do not have permission to perform '{action}' on '{resource}' in domain '{resolution.domain_id}'."
            )

        return current_user

    return _dependency
