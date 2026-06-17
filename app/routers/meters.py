from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models.asset import Equipment, Meter, MeterReading
from app.models.common import utcnow
from app.models.enums import AuditAction
from app.schemas.asset import (
    MeterCreate,
    MeterOut,
    MeterReadingCreate,
    MeterReadingOut,
)
from app.services.audit import record_audit, serialize

router = APIRouter(prefix="/api/v1/meters", tags=["meters"])


@router.get("", response_model=list[MeterOut])
def list_meters(
    db: Annotated[Session, Depends(get_db)],
    equipment_id: UUID | None = None,
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
) -> list[Meter]:
    stmt = select(Meter)
    if equipment_id is not None:
        stmt = stmt.where(Meter.equipment_id == equipment_id)
    return list(db.scalars(stmt.offset(skip).limit(limit)))


@router.post("", response_model=MeterOut, status_code=201)
def create_meter(payload: MeterCreate, db: Annotated[Session, Depends(get_db)]) -> Meter:
    if db.get(Equipment, payload.equipment_id) is None:
        raise HTTPException(status_code=422, detail="equipment_id does not exist")
    row = Meter(**payload.model_dump())
    db.add(row)
    db.flush()
    record_audit(
        db, entity_type="meter", entity_id=row.id, action=AuditAction.create,
        after=serialize(row),
    )
    db.commit()
    db.refresh(row)
    return row


@router.get("/{meter_id}/readings", response_model=list[MeterReadingOut])
def list_readings(
    meter_id: UUID, db: Annotated[Session, Depends(get_db)]
) -> list[MeterReading]:
    if db.get(Meter, meter_id) is None:
        raise HTTPException(status_code=404, detail="Meter not found")
    return list(
        db.scalars(
            select(MeterReading)
            .where(MeterReading.meter_id == meter_id)
            .order_by(MeterReading.read_at)
        )
    )


@router.post("/{meter_id}/readings", response_model=MeterReadingOut, status_code=201)
def add_reading(
    meter_id: UUID, payload: MeterReadingCreate, db: Annotated[Session, Depends(get_db)]
) -> MeterReading:
    if db.get(Meter, meter_id) is None:
        raise HTTPException(status_code=404, detail="Meter not found")
    row = MeterReading(
        meter_id=meter_id,
        reading_value=payload.reading_value,
        read_at=payload.read_at or utcnow(),
        source=payload.source,
    )
    db.add(row)
    db.flush()
    record_audit(
        db, entity_type="meter_reading", entity_id=row.id, action=AuditAction.create,
        after=serialize(row),
    )
    db.commit()
    db.refresh(row)
    return row
