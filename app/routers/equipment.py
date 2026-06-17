from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.deps import require_admin_or_dispatcher
from app.db.session import get_db
from app.models.asset import Equipment, EquipmentInstall, Meter, MeterReading
from app.models.enums import AuditAction
from app.schemas.asset import (
    EquipmentCreate,
    EquipmentHistory,
    EquipmentInstallOut,
    EquipmentOut,
    EquipmentUpdate,
    InstallRequest,
    RemoveRequest,
    TimelineEvent,
)
from app.services.audit import record_audit, serialize
from app.services.install import (
    InstallError,
    active_install_for_equipment,
    install_equipment,
    remove_equipment,
)

router = APIRouter(
    prefix="/api/v1/equipment", tags=["equipment"],
    dependencies=[Depends(require_admin_or_dispatcher)],
)


@router.get("", response_model=list[EquipmentOut])
def list_equipment(
    db: Annotated[Session, Depends(get_db)],
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
) -> list[Equipment]:
    return list(
        db.scalars(select(Equipment).order_by(Equipment.created_at).offset(skip).limit(limit))
    )


@router.post("", response_model=EquipmentOut, status_code=201)
def create_equipment(
    payload: EquipmentCreate, db: Annotated[Session, Depends(get_db)]
) -> Equipment:
    row = Equipment(**payload.model_dump())
    db.add(row)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="Serial already exists")
    record_audit(
        db, entity_type="equipment", entity_id=row.id, action=AuditAction.create,
        after=serialize(row),
    )
    db.commit()
    db.refresh(row)
    return row


@router.get("/{equipment_id}", response_model=EquipmentOut)
def get_equipment(equipment_id: UUID, db: Annotated[Session, Depends(get_db)]) -> Equipment:
    row = db.get(Equipment, equipment_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Equipment not found")
    return row


@router.patch("/{equipment_id}", response_model=EquipmentOut)
def update_equipment(
    equipment_id: UUID, payload: EquipmentUpdate, db: Annotated[Session, Depends(get_db)]
) -> Equipment:
    row = db.get(Equipment, equipment_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Equipment not found")
    before = serialize(row)
    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(row, field, value)
    db.flush()
    record_audit(
        db, entity_type="equipment", entity_id=row.id, action=AuditAction.update,
        before=before, after=serialize(row),
    )
    db.commit()
    db.refresh(row)
    return row


@router.post("/{equipment_id}/install", response_model=EquipmentInstallOut, status_code=201)
def install(
    equipment_id: UUID, payload: InstallRequest, db: Annotated[Session, Depends(get_db)]
) -> EquipmentInstall:
    try:
        install = install_equipment(
            db, equipment_id=equipment_id, fl_id=payload.fl_id,
            installed_at=payload.installed_at,
        )
        db.commit()
    except InstallError as exc:
        db.rollback()
        raise HTTPException(status_code=404, detail=str(exc))
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=409,
            detail="That equipment is already installed, or the slot is occupied. "
                   "Remove the current unit first.",
        )
    db.refresh(install)
    return install


@router.post("/{equipment_id}/remove", response_model=EquipmentInstallOut)
def remove(
    equipment_id: UUID, payload: RemoveRequest, db: Annotated[Session, Depends(get_db)]
) -> EquipmentInstall:
    try:
        install = remove_equipment(
            db, equipment_id=equipment_id, removed_at=payload.removed_at,
            new_status=payload.new_status,
        )
        db.commit()
    except InstallError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail=str(exc))
    db.refresh(install)
    return install


@router.get("/{equipment_id}/history", response_model=EquipmentHistory)
def history(equipment_id: UUID, db: Annotated[Session, Depends(get_db)]) -> EquipmentHistory:
    if db.get(Equipment, equipment_id) is None:
        raise HTTPException(status_code=404, detail="Equipment not found")

    events: list[TimelineEvent] = []

    installs = db.scalars(
        select(EquipmentInstall).where(EquipmentInstall.equipment_id == equipment_id)
    )
    for ins in installs:
        events.append(TimelineEvent(
            at=ins.installed_at, kind="install",
            detail={"install_id": str(ins.id),
                    "functional_location_id": str(ins.functional_location_id)},
        ))
        if ins.removed_at is not None:
            events.append(TimelineEvent(
                at=ins.removed_at, kind="remove",
                detail={"install_id": str(ins.id),
                        "functional_location_id": str(ins.functional_location_id)},
            ))

    readings = db.scalars(
        select(MeterReading)
        .join(Meter, Meter.id == MeterReading.meter_id)
        .where(Meter.equipment_id == equipment_id)
    )
    for r in readings:
        events.append(TimelineEvent(
            at=r.read_at, kind="meter_reading",
            detail={"meter_id": str(r.meter_id), "reading_value": r.reading_value,
                    "source": r.source.value},
        ))

    # Work orders & confirmations join here in Phases 2-3.
    events.sort(key=lambda e: e.at)
    return EquipmentHistory(equipment_id=equipment_id, events=events)


@router.get("/{equipment_id}/active-install", response_model=EquipmentInstallOut | None)
def active_install(
    equipment_id: UUID, db: Annotated[Session, Depends(get_db)]
) -> EquipmentInstall | None:
    return active_install_for_equipment(db, equipment_id)
