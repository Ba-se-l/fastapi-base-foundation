import argparse
import asyncio
from datetime import datetime, timezone
import getpass
import re
import sys
from typing import Any
import uuid

from pydantic import ValidationError
from sqlalchemy.ext.asyncio import AsyncSession

from src.database import AsyncEngineLocal, AsyncSessionLocal
from src.modules.audit.model import AuditLog
from src.modules.auth.schemas import RegisterRequest
from src.modules.user import User, UserRepository
from src.security import AuthorizationNotInitializedError, AuthorizationService, hash_password
from src.share import Action, Resource, Roles

ROLE_NAME_PATTERN = re.compile(r'^[a-z][a-z0-9_]{1,49}$')


async def get_or_init_enforcer():
    """Returns the cached enforcer or initializes with AsyncEngineLocal if uninitialized."""
    try:
        return AuthorizationService.get_enforcer()
    except AuthorizationNotInitializedError:
        return await AuthorizationService.initialize(AsyncEngineLocal)


async def record_cli_audit_event(
    session: AsyncSession,
    action: str,
    target_id: str | int | None,
    extra_data: dict[str, Any] | None = None,
    domain_id: str = "global",
    entity_type: str = "security",
) -> None:
    """Records an administrative action in audit_logs for forensic compliance."""
    os_user = getpass.getuser()
    now = datetime.now(timezone.utc)
    log_entry = AuditLog(
        event_type=action,
        severity="INFO",
        message=f"CLI command '{action}' executed by {os_user}.",
        user_id="system:cli",
        actor_id=f"cli:{os_user}",
        actor_snapshot=f"CLI User ({os_user})",
        entity_type=entity_type,
        entity_id=str(target_id) if target_id is not None else None,
        domain_id=domain_id,
        outcome="SUCCESS",
        occurred_at=now,
        created_at=now,
        ip_address="127.0.0.1",
        user_agent="manage.py-cli",
        request_id=uuid.uuid4().hex,
        extra_data=extra_data or {},
    )
    session.add(log_entry)


def validate_role_name(role: str) -> None:
    """Validates that a role name follows naming standards and does not collide with user subjects.

    Args:
        role: The role name string to validate.

    Raises:
        ValueError: If the role name is malformed or uses the reserved 'user:' prefix.
    """
    if role.startswith('user:'):
        raise ValueError("Role names cannot begin with the reserved prefix 'user:'.")
    if not ROLE_NAME_PATTERN.match(role):
        raise ValueError(
            f"Invalid role name '{role}'. Must be 2-50 characters, lowercase alphanumeric with underscores."
        )


def validate_resource(resource: str) -> None:
    """Validates that a resource token matches a known Resource or wildcard.

    Args:
        resource: Target resource string.

    Raises:
        ValueError: If resource is not recognized.
    """
    allowed = {r.value for r in Resource} | {'*'}
    if resource not in allowed:
        raise ValueError(f"Unknown resource '{resource}'. Allowed values: {sorted(allowed)}")


def validate_action(action: str) -> None:
    """Validates that an action token matches a known Action or wildcard.

    Args:
        action: Target action string.

    Raises:
        ValueError: If action is not recognized.
    """
    allowed = {a.value for a in Action} | {'*'}
    if action not in allowed:
        raise ValueError(f"Unknown action '{action}'. Allowed values: {sorted(allowed)}")


async def handle_seed_policies() -> None:
    """Seeds baseline authorization rules into the Casbin storage."""
    await get_or_init_enforcer()
    count = await AuthorizationService.seed_default_policies()
    async with AsyncSessionLocal() as session:
        await record_cli_audit_event(
            session=session,
            action="CLI_POLICIES_SEEDED",
            target_id="global",
            extra_data={"rules_added": count},
            entity_type="authorization_policy",
        )
        await session.commit()
    print(f"Successfully seeded default policies ({count} new rule(s) added).")


async def handle_create_admin(args: argparse.Namespace) -> None:
    """Creates a new user account with administrator privileges."""
    password = args.password
    if password:
        print(
            "WARNING: Passing passwords via CLI arguments exposes credentials in process lists "
            "and shell history. Prefer interactive prompt without --password.",
            file=sys.stderr,
        )
    else:
        password = getpass.getpass("Enter admin password: ")
        confirm_password = getpass.getpass("Confirm admin password: ")
        if password != confirm_password:
            print("Error: Passwords do not match.", file=sys.stderr)
            sys.exit(1)

    try:
        validated = RegisterRequest(
            name=args.name,
            email=args.email,
            password=password,
        )
    except ValidationError as exc:
        print("Validation Error:", file=sys.stderr)
        for err in exc.errors():
            loc = ' -> '.join(str(p) for p in err['loc'])
            print(f"  - {loc}: {err['msg']}", file=sys.stderr)
        sys.exit(1)

    async with AsyncSessionLocal() as session:
        user_repo = UserRepository(session=session)
        existing = await user_repo.get_by_email(validated.email)
        if existing:
            print(f"Error: A user with email '{validated.email}' already exists.", file=sys.stderr)
            sys.exit(1)

        admin_user = User(
            name=validated.name,
            email=validated.email,
            hashed_password=hash_password(validated.password),
            role=Roles.ADMIN,
            is_active=True,
            security_version=1,
        )
        created = await user_repo.create(admin_user)
        await session.flush()
        await record_cli_audit_event(
            session=session,
            action="CLI_ADMIN_CREATED",
            target_id=str(created.id),
            extra_data={"email": created.email, "role": Roles.ADMIN.value},
            entity_type="user",
        )
        await session.commit()
        print(f"Admin user successfully created with ID {created.id} (email: {created.email}).")


async def handle_promote_admin(args: argparse.Namespace) -> None:
    """Elevates an existing user account to administrator role."""
    async with AsyncSessionLocal() as session:
        user_repo = UserRepository(session=session)
        user = await user_repo.get_by_email(args.email.strip().lower())
        if not user:
            print(f"Error: No user found with email '{args.email}'.", file=sys.stderr)
            sys.exit(1)

        if not user.is_active:
            print(f"Error: User '{args.email}' is deactivated and cannot be promoted.", file=sys.stderr)
            sys.exit(1)

        await user_repo.update(instance=user, update_dict={'role': Roles.ADMIN})
        await record_cli_audit_event(
            session=session,
            action="CLI_ADMIN_PROMOTED",
            target_id=user.id,
            extra_data={"email": user.email, "promoted_role": Roles.ADMIN.value},
            entity_type="user",
        )
        await session.commit()
        print(f"User '{user.email}' (ID: {user.id}) successfully promoted to Admin.")


async def handle_grant(args: argparse.Namespace) -> None:
    """Grants a permission policy to a role."""
    validate_role_name(args.role)
    validate_resource(args.resource)
    validate_action(args.action)
    domain = getattr(args, "domain", "global")

    enforcer = await get_or_init_enforcer()
    if enforcer.has_policy(args.role, domain, args.resource, args.action):
        print(f"Policy already exists: ({args.role}, {domain}, {args.resource}, {args.action}).")
        return

    await enforcer.add_policy(args.role, domain, args.resource, args.action)
    async with AsyncSessionLocal() as session:
        await record_cli_audit_event(
            session=session,
            action="CLI_POLICY_GRANTED",
            target_id=f"{args.role}:{args.resource}:{args.action}",
            extra_data={"role": args.role, "resource": args.resource, "action": args.action},
            domain_id=domain,
            entity_type="authorization_policy",
        )
        await session.commit()
    print(f"Successfully granted: ({args.role}, {domain}, {args.resource}, {args.action}).")


async def handle_revoke(args: argparse.Namespace) -> None:
    """Revokes a permission policy from a role."""
    validate_role_name(args.role)
    validate_resource(args.resource)
    validate_action(args.action)
    domain = getattr(args, "domain", "global")

    if args.role == 'admin' and args.resource == '*' and args.action == '*' and not args.force:
        print(
            "Safety Warning: Revoking (admin, *, *) will lock out all administrators.\n"
            "If you really intend to do this, pass the --force flag.",
            file=sys.stderr,
        )
        sys.exit(1)

    enforcer = await get_or_init_enforcer()
    removed = await enforcer.remove_policy(args.role, domain, args.resource, args.action)
    if removed:
        async with AsyncSessionLocal() as session:
            await record_cli_audit_event(
                session=session,
                action="CLI_POLICY_REVOKED",
                target_id=f"{args.role}:{args.resource}:{args.action}",
                extra_data={"role": args.role, "resource": args.resource, "action": args.action},
                domain_id=domain,
                entity_type="authorization_policy",
            )
            await session.commit()
        print(f"Successfully revoked: ({args.role}, {domain}, {args.resource}, {args.action}).")
    else:
        print(f"Policy not found: ({args.role}, {domain}, {args.resource}, {args.action}).")


async def handle_assign_role(args: argparse.Namespace) -> None:
    """Assigns an authorization role to a specific user identifier."""
    validate_role_name(args.role)
    domain = getattr(args, "domain", "global")

    async with AsyncSessionLocal() as session:
        user_repo = UserRepository(session=session)
        user = await user_repo.get_by_id(args.user_id)
        if not user:
            print(f"Error: User with ID {args.user_id} does not exist.", file=sys.stderr)
            sys.exit(1)

    enforcer = await get_or_init_enforcer()
    subject = AuthorizationService.user_subject(args.user_id)
    if enforcer.has_grouping_policy(subject, args.role, domain):
        print(f"User {args.user_id} is already assigned to role '{args.role}' in domain '{domain}'.")
        return

    await enforcer.add_grouping_policy(subject, args.role, domain)
    async with AsyncSessionLocal() as session:
        await record_cli_audit_event(
            session=session,
            action="CLI_ROLE_ASSIGNED",
            target_id=args.user_id,
            extra_data={"user_id": args.user_id, "role": args.role, "subject": subject},
            domain_id=domain,
            entity_type="user_role",
        )
        await session.commit()
    print(f"Successfully assigned role '{args.role}' to user {args.user_id} ({subject}) in domain '{domain}'.")


async def handle_unassign_role(args: argparse.Namespace) -> None:
    """Removes a role assignment from a specific user identifier."""
    validate_role_name(args.role)
    domain = getattr(args, "domain", "global")
    enforcer = await get_or_init_enforcer()

    subject = AuthorizationService.user_subject(args.user_id)
    removed = await enforcer.remove_grouping_policy(subject, args.role, domain)
    if removed:
        async with AsyncSessionLocal() as session:
            await record_cli_audit_event(
                session=session,
                action="CLI_ROLE_UNASSIGNED",
                target_id=args.user_id,
                extra_data={"user_id": args.user_id, "role": args.role, "subject": subject},
                domain_id=domain,
                entity_type="user_role",
            )
            await session.commit()
        print(f"Successfully removed role '{args.role}' from user {args.user_id} in domain '{domain}'.")
    else:
        print(f"Role assignment not found for user {args.user_id} on role '{args.role}' in domain '{domain}'.")


async def handle_list_policies() -> None:
    """Prints all active Casbin permission policies and role grouping links."""
    enforcer = await get_or_init_enforcer()
    policies = enforcer.get_policy()
    groupings = enforcer.get_grouping_policy()

    print("\n--- Active Permission Policies ('p') ---")
    if not policies:
        print("  (No active policies)")
    else:
        print(f"  {'ROLE / SUBJECT':<20} {'DOMAIN':<15} {'RESOURCE':<15} {'ACTION':<15}")
        print("  " + "-" * 65)
        for p in policies:
            sub = p[0] if len(p) > 0 else ''
            dom = p[1] if len(p) > 1 else 'global'
            obj = p[2] if len(p) > 2 else ''
            act = p[3] if len(p) > 3 else ''
            print(f"  {sub:<20} {dom:<15} {obj:<15} {act:<15}")

    print("\n--- Active Role Groupings ('g') ---")
    if not groupings:
        print("  (No active groupings)")
    else:
        print(f"  {'MEMBER':<20} {'ROLE':<20} {'DOMAIN':<15}")
        print("  " + "-" * 55)
        for g in groupings:
            member = g[0] if len(g) > 0 else ''
            role = g[1] if len(g) > 1 else ''
            dom = g[2] if len(g) > 2 else 'global'
            print(f"  {member:<20} {role:<20} {dom:<15}")
    print()


async def handle_purge_sessions(args: argparse.Namespace) -> None:
    """Purges expired refresh session tombstones beyond grace period."""
    grace_seconds = getattr(args, "grace_seconds", 300)
    async with AsyncSessionLocal() as session:
        from src.modules.auth.repo import RefreshSessionRepository
        repo = RefreshSessionRepository(session=session)
        deleted = await repo.purge_expired_tombstones(grace_seconds=grace_seconds)
        await session.commit()
        print(f"Successfully purged {deleted} expired refresh session tombstone(s).")


def build_parser() -> argparse.ArgumentParser:
    """Constructs the CLI argument parser with all administrative commands."""
    parser = argparse.ArgumentParser(
        description="FastAPI Base Structure Administrative Management CLI"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # seed-policies
    subparsers.add_parser("seed-policies", help="Seed default authorization policies")

    # create-admin
    create_admin_p = subparsers.add_parser("create-admin", help="Create a new administrator user")
    create_admin_p.add_argument("--email", required=True, help="Administrator email address")
    create_admin_p.add_argument("--name", required=True, help="Administrator display name")
    create_admin_p.add_argument("--password", help="Administrator password (prompted if omitted)")

    # promote-admin
    promote_admin_p = subparsers.add_parser("promote-admin", help="Promote an existing user to admin")
    promote_admin_p.add_argument("--email", required=True, help="Target user email address")

    # grant
    grant_p = subparsers.add_parser("grant", help="Grant a permission rule to a role")
    grant_p.add_argument("role", help="Target role name (e.g. auditor, manager)")
    grant_p.add_argument("resource", help="Target resource or '*' (e.g. users, audit)")
    grant_p.add_argument("action", help="Target action or '*' (e.g. read, export)")
    grant_p.add_argument("--domain", default="global", help="Target authorization domain (default: global)")

    # revoke
    revoke_p = subparsers.add_parser("revoke", help="Revoke a permission rule from a role")
    revoke_p.add_argument("role", help="Target role name")
    revoke_p.add_argument("resource", help="Target resource or '*'")
    revoke_p.add_argument("action", help="Target action or '*'")
    revoke_p.add_argument("--domain", default="global", help="Target authorization domain (default: global)")
    revoke_p.add_argument("--force", action="store_true", help="Force revocation of critical policies")

    # assign-role
    assign_p = subparsers.add_parser("assign-role", help="Assign a role to a user ID")
    assign_p.add_argument("user_id", type=int, help="Target user integer ID")
    assign_p.add_argument("role", help="Role name to assign")
    assign_p.add_argument("--domain", default="global", help="Target authorization domain (default: global)")

    # unassign-role
    unassign_p = subparsers.add_parser("unassign-role", help="Remove a role assignment from a user ID")
    unassign_p.add_argument("user_id", type=int, help="Target user integer ID")
    unassign_p.add_argument("role", help="Role name to remove")
    unassign_p.add_argument("--domain", default="global", help="Target authorization domain (default: global)")

    # list-policies
    subparsers.add_parser("list-policies", help="List all policies and role groupings")

    # purge-sessions
    purge_p = subparsers.add_parser("purge-sessions", help="Purge expired refresh session tombstones")
    purge_p.add_argument("--grace-seconds", type=int, default=300, help="Grace period in seconds (default: 300)")

    return parser


def main() -> None:
    """Maestro entry point dispatching CLI subcommands."""
    parser = build_parser()
    args = parser.parse_args()

    command_handlers = {
        'seed-policies': lambda: handle_seed_policies(),
        'create-admin': lambda: handle_create_admin(args),
        'promote-admin': lambda: handle_promote_admin(args),
        'grant': lambda: handle_grant(args),
        'revoke': lambda: handle_revoke(args),
        'assign-role': lambda: handle_assign_role(args),
        'unassign-role': lambda: handle_unassign_role(args),
        'list-policies': lambda: handle_list_policies(),
        'purge-sessions': lambda: handle_purge_sessions(args),
    }

    handler = command_handlers.get(args.command)
    if not handler:
        parser.print_help()
        sys.exit(1)

    try:
        asyncio.run(handler())
    except (ValueError, RuntimeError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)
    finally:
        asyncio.run(AsyncEngineLocal.dispose())


if __name__ == '__main__':
    main()
