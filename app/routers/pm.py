from datetime import timedelta
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.deps import require_admin_or_dispatcher
from app.db.session import get_db
from app.models.asset import Meter
from app.models.common import utcnow
from app.models.customer import Site
from app.models.enums import AuditAction, PmTriggerKind
from app.models.pm import PmSchedule
from app.schemas.pm import (
    PmScanResult,
    PmScheduleCreate,
    PmScheduleOut,
    PmScheduleUpdate,
)
from app.services.audit import record_audit, serialize
from app.services.pm import generate_order_for, scan

router = APIRouter(
    prefix="/api/v1/pm-schedules", tags=["pm_schedules"],
    dependencies=[Depends(require_admin_or_dispatcher)],
)


@router.get("", response_model=list[PmScheduleOut])
def list_schedules(
    db: Annotated[Session, Depends(get_db)],
    site_id: UUID | None = None,
    equipment_id: UUID | None = None,
) -> list[PmSchedule]:
    stmt = select(PmSchedule).order_by(PmSchedule.name)
    if site_id is not None:
        stmt = stmt.where(PmSchedule.site_id == site_id)
    if equipment_id is not None:
        stmt = stmt.where(PmSchedule.equipment_id == equipment_id)
    return list(db.scalars(stmt))


@router.post("", response_model=PmScheduleOut, status_code=201)
def create_schedule(
    payload: PmScheduleCreate, db: Annotated[Session, Depends(get_db)]
) -> PmSchedule:
    if db.get(Site, payload.site_id) is None:
        raise HTTPException(status_code=422, detail="site_id does not exist")
    if payload.trigger_kind == PmTriggerKind.meter and db.get(Meter, payload.meter_id) is None:
        raise HTTPException(status_code=422, detail="meter_id does not exist")

    sched = PmSchedule(
        customer_account_id=payload.customer_account_id,
        site_id=payload.site_id,
        functional_location_id=payload.functional_location_id,
        equipment_id=payload.equipment_id,
        name=payload.name,
        description=payload.description,
        trigger_kind=payload.trigger_kind,
        interval_days=payload.interval_days,
        meter_id=payload.meter_id,
        interval_value=payload.interval_value,
        order_title=payload.order_title,
        billing_class=payload.billing_class,
        priority=payload.priority,
        service_contract_id=payload.service_contract_id,
        is_active=True,
    )

    # Seed the baseline + next-due anchors from the request (or defaults).
    if payload.trigger_kind == PmTriggerKind.calendar:
        start = payload.start_at or utcnow()
        sched.last_completed_at = start
        sched.next_due_at = start + timedelta(days=payload.interval_days)
    else:
        start_value = payload.start_value or 0.0
        sched.last_completed_value = start_value
        sched.next_due_value = start_value + payload.interval_value

    db.add(sched)
    db.flush()
    record_audit(
        db, entity_type="pm_schedule", entity_id=sched.id,
        action=AuditAction.create, after=serialize(sched),
    )
    db.commit()
    db.refresh(sched)
    return sched


@router.get("/{schedule_id}", response_model=PmScheduleOut)
def get_schedule(
    schedule_id: UUID, db: Annotated[Session, Depends(get_db)]
) -> PmSchedule:
    row = db.get(PmSchedule, schedule_id)
    if row is None:
        raise HTTPException(status_code=404, detail="PM schedule not found")
    return row


@router.patch("/{schedule_id}", response_model=PmScheduleOut)
def update_schedule(
    schedule_id: UUID,
    payload: PmScheduleUpdate,
    db: Annotated[Session, Depends(get_db)],
) -> PmSchedule:
    sched = db.get(PmSchedule, schedule_id)
    if sched is None:
        raise HTTPException(status_code=404, detail="PM schedule not found")
    before = serialize(sched)
    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(sched, field, value)
    db.flush()
    record_audit(
        db, entity_type="pm_schedule", entity_id=sched.id,
        action=AuditAction.update, before=before, after=serialize(sched),
    )
    db.commit()
    db.refresh(sched)
    return sched


@router.post("/{schedule_id}/scan", response_model=PmScanResult)
def scan_one(
    schedule_id: UUID, db: Annotated[Session, Depends(get_db)]
) -> PmScanResult:
    sched = db.get(PmSchedule, schedule_id)
    if sched is None:
        raise HTTPException(status_code=404, detail="PM schedule not found")
    order = generate_order_for(db, sched)
    db.commit()
    return PmScanResult(
        generated_work_order_ids=[order.id] if order is not None else []
    )


@router.post("/scan", response_model=PmScanResult)
def scan_all(db: Annotated[Session, Depends(get_db)]) -> PmScanResult:
    orders = scan(db)
    db.commit()
    return PmScanResult(generated_work_order_ids=[o.id for o in orders])
