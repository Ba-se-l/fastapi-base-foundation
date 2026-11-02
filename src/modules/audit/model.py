from datetime import datetime, timezone
from typing import Any

from sqlalchemy import DateTime, Index, Integer, JSON, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from src.database import BaseModel as Base
from src.share import (
    AUDIT_IP_MAX,
    AUDIT_REQUEST_ID_MAX,
    AUDIT_USER_AGENT_MAX,
    AUDIT_USER_ID_MAX,
)


class AuditLog(Base):
    """Immutable audit log entity for security, compliance, and telemetry tracking.

    Designed to be completely portable and decoupled from user domain models;
    stores user_id as a generic indexed string identifier.

    Attributes:
        id: Primary key unique identifier.
        event_type: Machine-readable categorized action tag.
        severity: Severity level (DEBUG, INFO, WARNING, ERROR, CRITICAL).
        message: Human-readable narrative description.
        user_id: Optional string identifier of the responsible actor.
        actor_id: Explicit actor string identifier for dual-party action tracking.
        actor_snapshot: Display name or context snapshot of the actor.
        entity_type: Target resource category (e.g., 'user', 'refresh_session').
        entity_id: Target resource identifier.
        domain_id: Security domain partition (defaults to 'global').
        outcome: Action outcome status ('SUCCESS', 'FAILURE', 'DENIED', etc.).
        changes_payload: Redacted structured field-level diff.
        occurred_at: Immutable timestamp of event occurrence.
        request_id: Optional correlation ID for tracing.
        ip_address: Optional client IPv4 or IPv6 address.
        user_agent: Optional client device or browser string.
        extra_data: Flexible JSON dictionary for structured metadata.
        created_at: Immutable UTC timestamp of event creation.
    """

    __tablename__ = 'audit_logs'

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    event_type: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    severity: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    message: Mapped[str] = mapped_column(Text, nullable=False)

    user_id: Mapped[str | None] = mapped_column(String(AUDIT_USER_ID_MAX), nullable=True, index=True)
    actor_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    actor_snapshot: Mapped[str | None] = mapped_column(String(255), nullable=True)
    entity_type: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    entity_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    domain_id: Mapped[str | None] = mapped_column(String(64), nullable=True, default="global", server_default="global", index=True)
    outcome: Mapped[str] = mapped_column(String(32), nullable=False, default="SUCCESS", server_default="SUCCESS", index=True)
    changes_payload: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        server_default=func.now(),
        nullable=False,
    )

    request_id: Mapped[str | None] = mapped_column(String(AUDIT_REQUEST_ID_MAX), nullable=True, index=True)
    ip_address: Mapped[str | None] = mapped_column(String(AUDIT_IP_MAX), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(AUDIT_USER_AGENT_MAX), nullable=True)

    extra_data: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True,
    )

    __table_args__ = (
        Index('ix_audit_user_created', 'user_id', 'created_at'),
        Index('ix_audit_event_created', 'event_type', 'created_at'),
        Index('ix_audit_severity_created', 'severity', 'created_at'),
    )

    def __repr__(self) -> str:
        return (
            f"AuditLog(id={self.id}, event_type='{self.event_type}', "
            f"severity='{self.severity}', user_id='{self.user_id}', "
            f"actor_id='{self.actor_id}', entity_type='{self.entity_type}', "
            f"outcome='{self.outcome}')"
        )
