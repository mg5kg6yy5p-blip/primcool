from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models.customer import Building, Site
from app.models.enums import AuditAction
from app.schemas.customer import BuildingCreate, BuildingOut, BuildingUpdate
from app.services.audit import record_audit, serialize

router = APIRouter(prefix="/api/v1/buildings", tags=["buildings"])


@router.get("", response_model=list[BuildingOut])
def list_buildings(
    db: Annotated[Session, Depends(get_db)],
    site_id: UUID | None = None,
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
) -> list[Building]:
    stmt = select(Building).order_by(Building.name)
    if site_id is not None:
        stmt = stmt.where(Building.site_id == site_id)
    return list(db.scalars(stmt.offset(skip).limit(limit)))


@router.post("", response_model=BuildingOut, status_code=201)
def create_building(
    payload: BuildingCreate, db: Annotated[Session, Depends(get_db)]
) -> Building:
    if db.get(Site, payload.site_id) is None:
        raise HTTPException(status_code=422, detail="site_id does not exist")
    row = Building(**payload.model_dump())
    db.add(row)
    db.flush()
    record_audit(
        db, entity_type="building", entity_id=row.id, action=AuditAction.create,
        after=serialize(row),
    )
    db.commit()
    db.refresh(row)
    return row


@router.get("/{building_id}", response_model=BuildingOut)
def get_building(building_id: UUID, db: Annotated[Session, Depends(get_db)]) -> Building:
    row = db.get(Building, building_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Building not found")
    return row


@router.patch("/{building_id}", response_model=BuildingOut)
def update_building(
    building_id: UUID, payload: BuildingUpdate, db: Annotated[Session, Depends(get_db)]
) -> Building:
    row = db.get(Building, building_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Building not found")
    before = serialize(row)
    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(row, field, value)
    db.flush()
    record_audit(
        db, entity_type="building", entity_id=row.id, action=AuditAction.update,
        before=before, after=serialize(row),
    )
    db.commit()
    db.refresh(row)
    return row
