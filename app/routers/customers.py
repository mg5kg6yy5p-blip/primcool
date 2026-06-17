from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.deps import require_admin_or_dispatcher
from app.db.session import get_db
from app.models.customer import CustomerAccount
from app.models.enums import AuditAction
from app.schemas.customer import (
    CustomerAccountCreate,
    CustomerAccountOut,
    CustomerAccountUpdate,
)
from app.services.audit import record_audit, serialize

router = APIRouter(
    prefix="/api/v1/customers", tags=["customers"],
    dependencies=[Depends(require_admin_or_dispatcher)],
)


@router.get("", response_model=list[CustomerAccountOut])
def list_customers(
    db: Annotated[Session, Depends(get_db)],
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
) -> list[CustomerAccount]:
    return list(
        db.scalars(
            select(CustomerAccount).order_by(CustomerAccount.name).offset(skip).limit(limit)
        )
    )


@router.post("", response_model=CustomerAccountOut, status_code=201)
def create_customer(
    payload: CustomerAccountCreate, db: Annotated[Session, Depends(get_db)]
) -> CustomerAccount:
    row = CustomerAccount(**payload.model_dump())
    db.add(row)
    db.flush()
    record_audit(
        db,
        entity_type="customer_account",
        entity_id=row.id,
        action=AuditAction.create,
        after=serialize(row),
    )
    db.commit()
    db.refresh(row)
    return row


@router.get("/{customer_id}", response_model=CustomerAccountOut)
def get_customer(
    customer_id: UUID, db: Annotated[Session, Depends(get_db)]
) -> CustomerAccount:
    row = db.get(CustomerAccount, customer_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Customer not found")
    return row


@router.patch("/{customer_id}", response_model=CustomerAccountOut)
def update_customer(
    customer_id: UUID,
    payload: CustomerAccountUpdate,
    db: Annotated[Session, Depends(get_db)],
) -> CustomerAccount:
    row = db.get(CustomerAccount, customer_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Customer not found")
    before = serialize(row)
    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(row, field, value)
    db.flush()
    record_audit(
        db,
        entity_type="customer_account",
        entity_id=row.id,
        action=AuditAction.update,
        before=before,
        after=serialize(row),
    )
    db.commit()
    db.refresh(row)
    return row
