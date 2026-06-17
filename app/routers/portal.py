"""Customer portal — read-only mirrors of notifications/orders/sites scoped
to the portal user's customer account. Plus the request portal:
POST /customer-portal/notifications."""
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.deps import require_portal_user
from app.db.session import get_db
from app.models.customer import Site, Space
from app.models.enums import AuditAction
from app.models.user import User
from app.models.workflow import Notification, WorkOrder
from app.schemas.workflow import NotificationOut, WorkOrderOut
from app.schemas.customer import SiteOut, SpaceOut
from app.schemas.auth import CurrentUser
from app.schemas.workflow import NotificationCreate
from app.services.audit import record_audit, serialize

router = APIRouter(prefix="/api/customer-portal", tags=["customer_portal"])


@router.get("/me", response_model=CurrentUser)
def portal_me(
    user: Annotated[User, Depends(require_portal_user)],
) -> User:
    return user


@router.get("/sites", response_model=list[SiteOut])
def portal_sites(
    user: Annotated[User, Depends(require_portal_user)],
    db: Annotated[Session, Depends(get_db)],
) -> list[Site]:
    return list(
        db.scalars(
            select(Site).where(Site.customer_account_id == user.customer_account_id)
            .order_by(Site.name)
        )
    )


@router.get("/spaces", response_model=list[SpaceOut])
def portal_spaces(
    user: Annotated[User, Depends(require_portal_user)],
    db: Annotated[Session, Depends(get_db)],
    site_id: UUID | None = None,
) -> list[Space]:
    # Spaces don't carry customer_account_id directly; scope via the site.
    site_ids = [
        s.id for s in db.scalars(
            select(Site).where(Site.customer_account_id == user.customer_account_id)
        )
    ]
    stmt = select(Space).where(Space.site_id.in_(site_ids))
    if site_id is not None:
        if site_id not in site_ids:
            raise HTTPException(status_code=404, detail="Site not found")
        stmt = stmt.where(Space.site_id == site_id)
    return list(db.scalars(stmt))


@router.get("/notifications", response_model=list[NotificationOut])
def portal_notifications(
    user: Annotated[User, Depends(require_portal_user)],
    db: Annotated[Session, Depends(get_db)],
) -> list[Notification]:
    return list(
        db.scalars(
            select(Notification)
            .where(Notification.customer_account_id == user.customer_account_id)
            .order_by(Notification.created_at.desc())
        )
    )


@router.post("/notifications", response_model=NotificationOut, status_code=201)
def portal_raise_request(
    payload: NotificationCreate,
    user: Annotated[User, Depends(require_portal_user)],
    db: Annotated[Session, Depends(get_db)],
) -> Notification:
    # The portal cannot raise a request for a different customer account.
    if payload.customer_account_id != user.customer_account_id:
        raise HTTPException(
            status_code=403,
            detail="Cannot raise a request for another customer account",
        )
    site = db.get(Site, payload.site_id)
    if site is None or site.customer_account_id != user.customer_account_id:
        raise HTTPException(status_code=404, detail="Site not found")

    row = Notification(**payload.model_dump(), created_by=user.id)
    db.add(row)
    db.flush()
    record_audit(
        db, entity_type="notification", entity_id=row.id,
        action=AuditAction.create, after=serialize(row),
    )
    db.commit()
    db.refresh(row)
    return row


@router.get("/work-orders", response_model=list[WorkOrderOut])
def portal_work_orders(
    user: Annotated[User, Depends(require_portal_user)],
    db: Annotated[Session, Depends(get_db)],
) -> list[WorkOrderOut]:
    rows = db.scalars(
        select(WorkOrder)
        .where(WorkOrder.customer_account_id == user.customer_account_id)
        .order_by(WorkOrder.created_at.desc())
    )
    # Portal view never offers transitions — return without legal_transitions.
    return [WorkOrderOut.model_validate(o) for o in rows]


@router.get("/work-orders/{order_id}", response_model=WorkOrderOut)
def portal_get_work_order(
    order_id: UUID,
    user: Annotated[User, Depends(require_portal_user)],
    db: Annotated[Session, Depends(get_db)],
) -> WorkOrderOut:
    order = db.get(WorkOrder, order_id)
    # Return 404 (not 403) for other-account rows so we don't leak existence.
    if order is None or order.customer_account_id != user.customer_account_id:
        raise HTTPException(status_code=404, detail="Work order not found")
    return WorkOrderOut.model_validate(order)
