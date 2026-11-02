from collections.abc import Sequence
import logging
from pathlib import Path
import time

import casbin
from casbin_async_sqlalchemy_adapter import Adapter
from sqlalchemy.ext.asyncio import AsyncEngine

from src.settings import settings
from .casbin_rule import CasbinRule

logger = logging.getLogger(__name__)

RBAC_MODEL_PATH: Path = Path(__file__).with_name('rbac_model.conf')
USER_SUBJECT_PREFIX: str = 'user:'
WILDCARD: str = '*'
GLOBAL_DOMAIN: str = 'global'

type PolicyRule = tuple[str, str, str, str]

DEFAULT_POLICIES: tuple[PolicyRule, ...] = (
    ('admin', GLOBAL_DOMAIN, WILDCARD, WILDCARD),
)


class AuthorizationNotInitializedError(RuntimeError):
    """Raised when an authorization check runs before AuthorizationService is initialized."""


class DomainAsyncEnforcer(casbin.AsyncEnforcer):
    """Domain-aware AsyncEnforcer subclass providing seamless 3-tuple and 4-tuple compatibility."""

    async def add_policy(self, *params: str) -> bool:
        if len(params) == 3:
            params = (params[0], GLOBAL_DOMAIN, params[1], params[2])
        return await super().add_policy(*params)

    async def remove_policy(self, *params: str) -> bool:
        if len(params) == 3:
            params = (params[0], GLOBAL_DOMAIN, params[1], params[2])
        return await super().remove_policy(*params)

    def has_policy(self, *params: str) -> bool:
        if len(params) == 3:
            params = (params[0], GLOBAL_DOMAIN, params[1], params[2])
        return super().has_policy(*params)

    async def add_grouping_policy(self, *params: str) -> bool:
        if len(params) == 2:
            params = (params[0], params[1], GLOBAL_DOMAIN)
        return await super().add_grouping_policy(*params)

    async def remove_grouping_policy(self, *params: str) -> bool:
        if len(params) == 2:
            params = (params[0], params[1], GLOBAL_DOMAIN)
        return await super().remove_grouping_policy(*params)

    def has_grouping_policy(self, *params: str) -> bool:
        if len(params) == 2:
            params = (params[0], params[1], GLOBAL_DOMAIN)
        return super().has_grouping_policy(*params)

    def enforce(self, *rvals: str) -> bool:
        if len(rvals) == 3:
            rvals = (rvals[0], GLOBAL_DOMAIN, rvals[1], rvals[2])
        return super().enforce(*rvals)


class AuthorizationService:
    """Process-wide facade over a single cached PyCasbin AsyncEnforcer instance."""

    _enforcer: DomainAsyncEnforcer | None = None
    _last_loaded: float = 0.0

    @classmethod
    async def initialize(cls, engine: AsyncEngine) -> DomainAsyncEnforcer:
        """Initializes the Casbin AsyncEnforcer bound to the specified database engine.

        Constructs the SQLAlchemy adapter using the existing CasbinRule model and
        loads all active policies from the database into RAM cache.

        Args:
            engine: The SQLAlchemy AsyncEngine instance to bind the adapter to.

        Returns:
            The initialized and loaded DomainAsyncEnforcer instance.
        """
        adapter = Adapter(
            engine=engine,
            db_class=CasbinRule,
        )

        enforcer = DomainAsyncEnforcer(str(RBAC_MODEL_PATH), adapter)
        await enforcer.load_policy()

        cls._enforcer = enforcer
        cls._last_loaded = time.monotonic()

        if not enforcer.get_policy():
            logger.warning(
                'AuthorizationService loaded zero policies from storage. '
                'All protected operations will fail closed.'
            )

        return enforcer

    @classmethod
    def get_enforcer(cls) -> DomainAsyncEnforcer:
        """Retrieves the active cached DomainAsyncEnforcer instance.

        Returns:
            The loaded DomainAsyncEnforcer singleton.

        Raises:
            AuthorizationNotInitializedError: If called before initialize().
        """
        if cls._enforcer is None:
            raise AuthorizationNotInitializedError(
                'AuthorizationService has not been initialized. '
                'Call AuthorizationService.initialize(engine) during application startup.'
            )
        return cls._enforcer

    @classmethod
    async def reload(cls) -> None:
        """Reloads all policies from the database into the in-memory cache."""
        enforcer = cls.get_enforcer()
        await enforcer.load_policy()
        cls._last_loaded = time.monotonic()

    @classmethod
    async def check_and_refresh_cache(cls) -> None:
        """Checks policy cache TTL and reloads if expired."""
        if cls._enforcer is not None:
            ttl = getattr(settings, "authz_cache_ttl_seconds", 5)
            if time.monotonic() - cls._last_loaded > ttl:
                await cls.reload()

    @classmethod
    async def seed_default_policies(cls) -> int:
        """Idempotently ensures baseline authorization policies are persisted in the database.

        Returns:
            The number of newly inserted policy rules.
        """
        enforcer = cls.get_enforcer()
        added_count = 0

        for rule in DEFAULT_POLICIES:
            if not enforcer.has_policy(*rule):
                await enforcer.add_policy(*rule)
                added_count += 1

        return added_count

    @staticmethod
    def user_subject(user_id: int) -> str:
        """Formats an integer user identifier into a Casbin subject token.

        Args:
            user_id: Integer primary key of the user.

        Returns:
            Namespaced user subject string (e.g. 'user:42').
        """
        return f'{USER_SUBJECT_PREFIX}{user_id}'

    @classmethod
    def is_allowed(
        cls,
        *,
        user_id: int,
        role: str,
        resource: str,
        action: str,
        domain: str = GLOBAL_DOMAIN,
    ) -> bool:
        """Evaluates whether an actor has permission to perform an action on a resource.

        Evaluates two identity vectors in sequence:
        1. Role-based check: Checks the user's primary role in target domain and global.
        2. Subject-based check: Checks user-specific grants or groupings ('user:<id>').

        Args:
            user_id: Primary key of the authenticated user.
            role: The primary role name of the user (e.g. 'admin', 'user').
            resource: Target resource token.
            action: Action token.
            domain: Target domain token (defaults to 'global').

        Returns:
            True if permission is granted by any active policy; False otherwise.
        """
        enforcer = cls.get_enforcer()

        # Fail-closed check: if policy store is empty, deny everything
        if not enforcer.get_policy():
            return False

        # 1. Compatibility projection: evaluate user's primary role
        if enforcer.enforce(role, domain, resource, action):
            return True
        if domain != GLOBAL_DOMAIN and enforcer.enforce(role, GLOBAL_DOMAIN, resource, action):
            return True

        # 2. Per-user grants: evaluate specific user token ('user:<id>')
        user_sub = cls.user_subject(user_id)
        if enforcer.enforce(user_sub, domain, resource, action):
            return True
        if domain != GLOBAL_DOMAIN and enforcer.enforce(user_sub, GLOBAL_DOMAIN, resource, action):
            return True

        return False

    @classmethod
    async def grant_permission(
        cls, subject: str, obj: str, act: str, domain: str = GLOBAL_DOMAIN
    ) -> bool:
        """Grants a permission rule to a subject/role with domain scoping."""
        enforcer = cls.get_enforcer()
        added = await enforcer.add_policy(subject, domain, obj, act)
        return bool(added)

    @classmethod
    async def revoke_permission(
        cls, subject: str, obj: str, act: str, domain: str = GLOBAL_DOMAIN
    ) -> bool:
        """Revokes a permission rule from a subject/role with domain scoping."""
        enforcer = cls.get_enforcer()
        removed = await enforcer.remove_policy(subject, domain, obj, act)
        return bool(removed)

    @classmethod
    async def assign_role(
        cls, user_subject: str, role: str, domain: str = GLOBAL_DOMAIN
    ) -> bool:
        """Assigns a role to a user subject within a domain."""
        enforcer = cls.get_enforcer()
        added = await enforcer.add_grouping_policy(user_subject, role, domain)
        return bool(added)

    @classmethod
    async def unassign_role(
        cls, user_subject: str, role: str, domain: str = GLOBAL_DOMAIN
    ) -> bool:
        """Removes a role assignment from a user subject within a domain."""
        enforcer = cls.get_enforcer()
        removed = await enforcer.remove_grouping_policy(user_subject, role, domain)
        return bool(removed)

    @classmethod
    def reset(cls) -> None:
        """Resets the singleton enforcer reference. Intended strictly for test teardown."""
        cls._enforcer = None
        cls._last_loaded = 0.0
