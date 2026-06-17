from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import case, select
from sqlalchemy.orm import Session

from app.core.deps import require_admin_or_dispatcher, require_staff
from app.db.session import get_db
from app.models.enums import (
    AuditAction,
    OrderStatus,
    Severity,
)
from app.models.workflow import Operation, SavedView, WorkOrder
from app.schemas.workflow import (
    OperationCreate,
    OperationOut,
    TransitionRequest,
    WorkOrderCreate,
    WorkOrderOut,
    WorkOrderUpdate,
)
from app.services.audit import record_audit, serialize
from app.services.workflow import (
    TransitionError,
    legal_work_order_targets,
    transition_work_order,
)

router = APIRouter(
    prefix="/api/v1/work-orders", tags=["work_orders"],
    # GETs reachable to any staff member (technicians need their queue);
    # mutations carry an explicit admin/dispatcher dep at the route level.
    dependencies=[Depends(require_staff)],
)
_ADMIN_DEP = [Depends(require_admin_or_dispatcher)]

# Emergency sorts to the top of every queue, then by priority, then newest.
_PRIORITY_RANK = case(
    {Severity.emergency: 0, Severity.high: 1, Severity.medium: 2, Severity.low: 3},
    value=WorkOrder.priority,
)

_TERMINAL = {OrderStatus.tech_complete, OrderStatus.closed, OrderStatus.cancelled}


def _with_transitions(order: WorkOrder) -> WorkOrderOut:
    out = WorkOrderOut.model_validate(order)
    out.legal_transitions = sorted(legal_work_order_targets(order.status), key=lambda s: s.value)
    return out


@router.get("", response_model=list[WorkOrderOut])
def list_work_orders(
    db: Annotated[Session, Depends(get_db)],
    view_id: UUID | None = None,
    customer_account_id: UUID | None = None,
    site_id: UUID | None = None,
    status: OrderStatus | None = None,
    priority: Severity | None = None,
    assigned_to_user_id: UUID | None = None,
    include_closed: bool = False,
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
) -> list[WorkOrderOut]:
    # A saved view supplies filters; ad-hoc query params override/extend.
    if view_id is not None:
        view = db.get(SavedView, view_id)
        if view is None:
            raise HTTPException(status_code=404, detail="Saved view not found")
        f = view.filters or {}
        customer_account_id = customer_account_id or _as_uuid(f.get("customer_account_id"))
        site_id = site_id or _as_uuid(f.get("site_id"))
        priority = priority or (Severity(f["priority"]) if f.get("priority") else None)
        include_closed = include_closed or bool(f.get("include_closed"))

    stmt = select(WorkOrder)
    if status is not None:
        stmt = stmt.where(WorkOrder.status == status)
    elif not include_closed:
        # Default "exclude CNF" lens: hide closed and cancelled.
        stmt = stmt.where(
            WorkOrder.status.notin_([OrderStatus.closed, OrderStatus.cancelled])
        )
    if customer_account_id is not None:
        stmt = stmt.where(WorkOrder.customer_account_id == customer_account_id)
    if site_id is not None:
        stmt = stmt.where(WorkOrder.site_id == site_id)
    if priority is not None:
        stmt = stmt.where(WorkOrder.priority == priority)
    if assigned_to_user_id is not None:
        stmt = stmt.where(WorkOrder.assigned_to_user_id == assigned_to_user_id)

    stmt = stmt.order_by(_PRIORITY_RANK, WorkOrder.created_at.desc())
    orders = db.scalars(stmt.offset(skip).limit(limit))
    return [_with_transitions(o) for o in orders]


@router.post("", response_model=WorkOrderOut, status_code=201, dependencies=_ADMIN_DEP)
def create_work_order(
    payload: WorkOrderCreate, db: Annotated[Session, Depends(get_db)]
) -> WorkOrderOut:
    row = WorkOrder(**payload.model_dump())
    db.add(row)
    db.flush()
    record_audit(
        db, entity_type="work_order", entity_id=row.id, action=AuditAction.create,
        after=serialize(row),
    )
    db.commit()
    db.refresh(row)
    return _with_transitions(row)


@router.get("/{order_id}", response_model=WorkOrderOut)
def get_work_order(order_id: UUID, db: Annotated[Session, Depends(get_db)]) -> WorkOrderOut:
    row = _get_or_404(db, order_id)
    return _with_transitions(row)


@router.patch("/{order_id}", response_model=WorkOrderOut, dependencies=_ADMIN_DEP)
def update_work_order(
    order_id: UUID, payload: WorkOrderUpdate, db: Annotated[Session, Depends(get_db)]
) -> WorkOrderOut:
    row = _get_or_404(db, order_id)
    # After tech_complete the descriptive fields are frozen.
    if row.status in _TERMINAL:
        raise HTTPException(
            status_code=409,
            detail=f"Work order is {row.status.value}; descriptive fields are frozen",
        )
    before = serialize(row)
    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(row, field, value)
    db.flush()
    record_audit(
        db, entity_type="work_order", entity_id=row.id, action=AuditAction.update,
        before=before, after=serialize(row),
    )
    db.commit()
    db.refresh(row)
    return _with_transitions(row)


@router.post("/{order_id}/transition", response_model=WorkOrderOut, dependencies=_ADMIN_DEP)
def transition(
    order_id: UUID, payload: TransitionRequest, db: Annotated[Session, Depends(get_db)]
) -> WorkOrderOut:
    row = _get_or_404(db, order_id)
    try:
        transition_work_order(db, row, payload.target)
        db.commit()
    except TransitionError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail=str(exc))
    db.refresh(row)
    return _with_transitions(row)


# --- operations (nested) ---
@router.get("/{order_id}/operations", response_model=list[OperationOut])
def list_operations(order_id: UUID, db: Annotated[Session, Depends(get_db)]) -> list[Operation]:
    _get_or_404(db, order_id)
    return list(
        db.scalars(
            select(Operation)
            .where(Operation.work_order_id == order_id)
            .order_by(Operation.sequence)
        )
    )


@router.post("/{order_id}/operations", response_model=OperationOut, status_code=201,
              dependencies=_ADMIN_DEP)
def add_operation(
    order_id: UUID, payload: OperationCreate, db: Annotated[Session, Depends(get_db)]
) -> Operation:
    order = _get_or_404(db, order_id)
    if order.status in _TERMINAL:
        raise HTTPException(
            status_code=409, detail=f"Work order is {order.status.value}; cannot add operations"
        )
    row = Operation(work_order_id=order_id, **payload.model_dump())
    db.add(row)
    db.flush()
    record_audit(
        db, entity_type="operation", entity_id=row.id, action=AuditAction.create,
        after=serialize(row),
    )
    db.commit()
    db.refresh(row)
    return row


def _get_or_404(db: Session, order_id: UUID) -> WorkOrder:
    row = db.get(WorkOrder, order_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Work order not found")
    return row


def _as_uuid(value) -> UUID | None:
    return UUID(value) if value else None
