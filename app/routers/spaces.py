from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.deps import require_admin_or_dispatcher
from app.db.session import get_db
from app.models.customer import Building, Site, Space
from app.models.enums import AuditAction
from app.schemas.customer import SpaceCreate, SpaceOut, SpaceUpdate
from app.services.audit import record_audit, serialize

router = APIRouter(
    prefix="/api/v1/spaces", tags=["spaces"],
    dependencies=[Depends(require_admin_or_dispatcher)],
)


@router.get("", response_model=list[SpaceOut])
def list_spaces(
    db: Annotated[Session, Depends(get_db)],
    site_id: UUID | None = None,
    building_id: UUID | None = None,
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
) -> list[Space]:
    stmt = select(Space).order_by(Space.identifier)
    if site_id is not None:
        stmt = stmt.where(Space.site_id == site_id)
    if building_id is not None:
        stmt = stmt.where(Space.building_id == building_id)
    return list(db.scalars(stmt.offset(skip).limit(limit)))


@router.post("", response_model=SpaceOut, status_code=201)
def create_space(payload: SpaceCreate, db: Annotated[Session, Depends(get_db)]) -> Space:
    if db.get(Site, payload.site_id) is None:
        raise HTTPException(status_code=422, detail="site_id does not exist")
    if payload.building_id is not None and db.get(Building, payload.building_id) is None:
        raise HTTPException(status_code=422, detail="building_id does not exist")
    row = Space(**payload.model_dump())
    db.add(row)
    db.flush()
    record_audit(
        db, entity_type="space", entity_id=row.id, action=AuditAction.create,
        after=serialize(row),
    )
    db.commit()
    db.refresh(row)
    return row


@router.get("/{space_id}", response_model=SpaceOut)
def get_space(space_id: UUID, db: Annotated[Session, Depends(get_db)]) -> Space:
    row = db.get(Space, space_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Space not found")
    return row


@router.patch("/{space_id}", response_model=SpaceOut)
def update_space(
    space_id: UUID, payload: SpaceUpdate, db: Annotated[Session, Depends(get_db)]
) -> Space:
    row = db.get(Space, space_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Space not found")
    before = serialize(row)
    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(row, field, value)
    db.flush()
    record_audit(
        db, entity_type="space", entity_id=row.id, action=AuditAction.update,
        before=before, after=serialize(row),
    )
    db.commit()
    db.refresh(row)
    return row
