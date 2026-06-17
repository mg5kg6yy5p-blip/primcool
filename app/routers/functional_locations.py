from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models.asset import FunctionalLocation
from app.models.customer import Site
from app.models.enums import AuditAction
from app.schemas.asset import (
    FunctionalLocationCreate,
    FunctionalLocationOut,
    FunctionalLocationUpdate,
)
from app.services.audit import record_audit, serialize

router = APIRouter(prefix="/api/v1/functional-locations", tags=["functional_locations"])


@router.get("", response_model=list[FunctionalLocationOut])
def list_fls(
    db: Annotated[Session, Depends(get_db)],
    site_id: UUID | None = None,
    parent_fl_id: UUID | None = None,
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
) -> list[FunctionalLocation]:
    stmt = select(FunctionalLocation).order_by(FunctionalLocation.name)
    if site_id is not None:
        stmt = stmt.where(FunctionalLocation.site_id == site_id)
    if parent_fl_id is not None:
        stmt = stmt.where(FunctionalLocation.parent_fl_id == parent_fl_id)
    return list(db.scalars(stmt.offset(skip).limit(limit)))


@router.post("", response_model=FunctionalLocationOut, status_code=201)
def create_fl(
    payload: FunctionalLocationCreate, db: Annotated[Session, Depends(get_db)]
) -> FunctionalLocation:
    if db.get(Site, payload.site_id) is None:
        raise HTTPException(status_code=422, detail="site_id does not exist")
    if payload.parent_fl_id is not None and db.get(FunctionalLocation, payload.parent_fl_id) is None:
        raise HTTPException(status_code=422, detail="parent_fl_id does not exist")
    row = FunctionalLocation(**payload.model_dump())
    db.add(row)
    db.flush()
    record_audit(
        db, entity_type="functional_location", entity_id=row.id,
        action=AuditAction.create, after=serialize(row),
    )
    db.commit()
    db.refresh(row)
    return row


@router.get("/{fl_id}", response_model=FunctionalLocationOut)
def get_fl(fl_id: UUID, db: Annotated[Session, Depends(get_db)]) -> FunctionalLocation:
    row = db.get(FunctionalLocation, fl_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Functional location not found")
    return row


@router.patch("/{fl_id}", response_model=FunctionalLocationOut)
def update_fl(
    fl_id: UUID, payload: FunctionalLocationUpdate, db: Annotated[Session, Depends(get_db)]
) -> FunctionalLocation:
    row = db.get(FunctionalLocation, fl_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Functional location not found")
    before = serialize(row)
    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(row, field, value)
    db.flush()
    record_audit(
        db, entity_type="functional_location", entity_id=row.id,
        action=AuditAction.update, before=before, after=serialize(row),
    )
    db.commit()
    db.refresh(row)
    return row
