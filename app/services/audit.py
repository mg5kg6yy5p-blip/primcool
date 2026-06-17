"""Audit-log helpers.

Every create/update/status-change/install/remove writes an audit row in the
SAME transaction as the mutation. Callers add the audit row to the session and
let the surrounding commit persist both atomically — never commit the audit
separately.
"""
from datetime import date, datetime
from enum import Enum
from uuid import UUID

from sqlalchemy.orm import Session

from app.core.context import get_actor
from app.db.base import Base
from app.models.audit import AuditLog
from app.models.enums import AuditAction


def serialize(obj: Base | None) -> dict | None:
    """Snapshot a model's column values into a JSON-safe dict."""
    if obj is None:
        return None
    out: dict = {}
    for col in obj.__table__.columns:  # type: ignore[attr-defined]
        value = getattr(obj, col.name)
        out[col.name] = _to_jsonable(value)
    return out


def _to_jsonable(value: object) -> object:
    if isinstance(value, (UUID,)):
        return str(value)
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, Enum):
        return value.value
    return value


def record_audit(
    db: Session,
    *,
    entity_type: str,
    entity_id: UUID,
    action: AuditAction,
    before: dict | None = None,
    after: dict | None = None,
    actor_user_id: UUID | None = None,
) -> AuditLog:
    # Fall back to the session-scoped current user when the caller didn't pass
    # one explicitly. Service helpers (install/remove, workflow transitions)
    # may still pass an explicit actor.
    if actor_user_id is None:
        actor_user_id = get_actor(db)
    row = AuditLog(
        actor_user_id=actor_user_id,
        entity_type=entity_type,
        entity_id=entity_id,
        action=action,
        before=before,
        after=after,
    )
    db.add(row)
    return row
