from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import case, select
from sqlalchemy.orm import Session

from app.core.deps import require_admin_or_dispatcher
from app.db.session import get_db
from app.models.customer import Site
from app.models.enums import AuditAction, NotificationStatus, Severity
from app.models.workflow import Notification
from app.schemas.workflow import (
    CloseNoActionRequest,
    NotificationCreate,
    NotificationOut,
    WorkOrderOut,
)
from app.services.audit import record_audit, serialize
from app.services.workflow import (
    TransitionError,
    acknowledge_notification,
    close_notification_no_action,
    convert_notification_to_order,
)

router = APIRouter(
    prefix="/api/v1/notifications", tags=["notifications"],
    dependencies=[Depends(require_admin_or_dispatcher)],
)

# Triage inbox ordering: new first, then by severity (emergency -> low),
# then newest.
_SEVERITY_RANK = case(
    {Severity.emergency: 0, Severity.high: 1, Severity.medium: 2, Severity.low: 3},
    value=Notification.severity,
)
_STATUS_RANK = case({NotificationStatus.new: 0}, value=Notification.status, else_=1)


@router.get("", response_model=list[NotificationOut])
def list_notifications(
    db: Annotated[Session, Depends(get_db)],
    customer_account_id: UUID | None = None,
    status: NotificationStatus | None = None,
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
) -> list[Notification]:
    stmt = select(Notification).order_by(
        _STATUS_RANK, _SEVERITY_RANK, Notification.created_at.desc()
    )
    if customer_account_id is not None:
        stmt = stmt.where(Notification.customer_account_id == customer_account_id)
    if status is not None:
        stmt = stmt.where(Notification.status == status)
    return list(db.scalars(stmt.offset(skip).limit(limit)))


@router.post("", response_model=NotificationOut, status_code=201)
def create_notification(
    payload: NotificationCreate, db: Annotated[Session, Depends(get_db)]
) -> Notification:
    site = db.get(Site, payload.site_id)
    if site is None:
        raise HTTPException(status_code=422, detail="site_id does not exist")
    if site.customer_account_id != payload.customer_account_id:
        raise HTTPException(
            status_code=422, detail="site does not belong to that customer account"
        )
    row = Notification(**payload.model_dump())
    db.add(row)
    db.flush()
    record_audit(
        db, entity_type="notification", entity_id=row.id, action=AuditAction.create,
        after=serialize(row),
    )
    db.commit()
    db.refresh(row)
    return row


@router.get("/{notif_id}", response_model=NotificationOut)
def get_notification(notif_id: UUID, db: Annotated[Session, Depends(get_db)]) -> Notification:
    row = db.get(Notification, notif_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Notification not found")
    return row


@router.post("/{notif_id}/acknowledge", response_model=NotificationOut)
def acknowledge(notif_id: UUID, db: Annotated[Session, Depends(get_db)]) -> Notification:
    row = _get_or_404(db, notif_id)
    try:
        acknowledge_notification(db, row)
        db.commit()
    except TransitionError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail=str(exc))
    db.refresh(row)
    return row


@router.post("/{notif_id}/convert-to-order", response_model=WorkOrderOut, status_code=201)
def convert_to_order(notif_id: UUID, db: Annotated[Session, Depends(get_db)]):
    row = _get_or_404(db, notif_id)
    try:
        order = convert_notification_to_order(db, row)
        db.commit()
    except TransitionError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail=str(exc))
    db.refresh(order)
    return order


@router.post("/{notif_id}/close-no-action", response_model=NotificationOut)
def close_no_action(
    notif_id: UUID, payload: CloseNoActionRequest, db: Annotated[Session, Depends(get_db)]
) -> Notification:
    row = _get_or_404(db, notif_id)
    try:
        close_notification_no_action(db, row, payload.reason)
        db.commit()
    except TransitionError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail=str(exc))
    db.refresh(row)
    return row


def _get_or_404(db: Session, notif_id: UUID) -> Notification:
    row = db.get(Notification, notif_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Notification not found")
    return row
