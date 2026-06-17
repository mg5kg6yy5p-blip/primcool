from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.deps import require_admin_or_dispatcher
from app.db.session import get_db
from app.models.audit import AuditLog
from app.schemas.audit import AuditLogOut

router = APIRouter(
    prefix="/api/v1/audit", tags=["audit"],
    dependencies=[Depends(require_admin_or_dispatcher)],
)


@router.get("", response_model=list[AuditLogOut])
def list_audit(
    db: Annotated[Session, Depends(get_db)],
    entity_type: str | None = None,
    entity_id: UUID | None = None,
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
) -> list[AuditLog]:
    stmt = select(AuditLog).order_by(AuditLog.at.desc())
    if entity_type is not None:
        stmt = stmt.where(AuditLog.entity_type == entity_type)
    if entity_id is not None:
        stmt = stmt.where(AuditLog.entity_id == entity_id)
    return list(db.scalars(stmt.offset(skip).limit(limit)))
