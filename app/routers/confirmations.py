from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.deps import require_staff
from app.db.session import get_db
from app.models.inventory import Confirmation, ConfirmationPart
from app.models.user import User
from app.schemas.inventory import (
    ConfirmationOut,
    ConfirmationPartOut,
    ConfirmRequest,
    ReverseRequest,
)
from app.services.confirmations import (
    ConfirmationError,
    PartUse,
    confirm_operation,
    reverse_confirmation,
)

router = APIRouter(
    prefix="/api/v1", tags=["confirmations"],
    dependencies=[Depends(require_staff)],  # admin, dispatcher, OR technician
)


def _serialize_with_parts(db: Session, cnf: Confirmation) -> ConfirmationOut:
    parts = list(
        db.scalars(select(ConfirmationPart).where(ConfirmationPart.confirmation_id == cnf.id))
    )
    out = ConfirmationOut.model_validate(cnf)
    out.parts = [ConfirmationPartOut.model_validate(p) for p in parts]
    return out


@router.get("/operations/{operation_id}/confirmations", response_model=list[ConfirmationOut])
def list_for_operation(
    operation_id: UUID, db: Annotated[Session, Depends(get_db)]
) -> list[ConfirmationOut]:
    rows = db.scalars(
        select(Confirmation)
        .where(Confirmation.operation_id == operation_id)
        .order_by(Confirmation.at)
    )
    return [_serialize_with_parts(db, c) for c in rows]


@router.post("/operations/{operation_id}/confirm", response_model=ConfirmationOut, status_code=201)
def confirm(
    operation_id: UUID,
    payload: ConfirmRequest,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(require_staff)],
) -> ConfirmationOut:
    try:
        cnf = confirm_operation(
            db,
            operation_id=operation_id,
            actual_hours=payload.actual_hours,
            is_final=payload.is_final,
            notes=payload.notes,
            technician_user_id=user.id,
            parts=[
                PartUse(
                    material_id=p.material_id,
                    stock_location_id=p.stock_location_id,
                    qty_used=p.qty_used,
                )
                for p in payload.parts
            ],
        )
        db.commit()
    except ConfirmationError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail=str(exc))
    db.refresh(cnf)
    return _serialize_with_parts(db, cnf)


@router.post("/confirmations/{confirmation_id}/reverse",
             response_model=ConfirmationOut, status_code=201)
def reverse(
    confirmation_id: UUID,
    payload: ReverseRequest,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(require_staff)],
) -> ConfirmationOut:
    try:
        reversal = reverse_confirmation(
            db, confirmation_id=confirmation_id, reason=payload.reason,
            actor_user_id=user.id,
        )
        db.commit()
    except ConfirmationError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail=str(exc))
    db.refresh(reversal)
    return _serialize_with_parts(db, reversal)


@router.get("/work-orders/{order_id}/my-tasks", response_model=list[ConfirmationOut])
def my_tasks_unused() -> list[ConfirmationOut]:
    # Placeholder stub kept here for future technician filtering; main mobile
    # surface uses the regular work-orders endpoints filtered server-side.
    return []
