"""PM trigger engine.

Two trigger kinds: calendar (interval_days) and meter (interval_value on a
specific meter). Invariants:

  * One open cycle per schedule: while a generated PM order is still
    non-terminal, no new order is created for that schedule.
  * Cadence-holds: when a PM order closes, the next-due anchor re-baselines
    to the actual completion (calendar) or the latest meter reading
    (meter). Late completions don't compound delays.
"""
from datetime import datetime, timedelta, timezone
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.asset import MeterReading
from app.models.common import utcnow


def _aware(dt: datetime | None) -> datetime | None:
    """SQLite roundtrips strip tzinfo; coerce naive datetimes back to UTC so
    comparisons against utcnow() don't blow up."""
    if dt is None:
        return None
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt
from app.models.enums import AuditAction, OrderStatus, OrderType
from app.models.pm import PmSchedule
from app.models.workflow import WorkOrder
from app.services.audit import record_audit, serialize


# --- helpers ---
def _latest_reading_value(db: Session, meter_id: UUID) -> float | None:
    row = db.scalar(
        select(MeterReading)
        .where(MeterReading.meter_id == meter_id)
        .order_by(MeterReading.read_at.desc())
        .limit(1)
    )
    return row.reading_value if row is not None else None


def _open_cycle(db: Session, schedule_id: UUID) -> WorkOrder | None:
    return db.scalar(
        select(WorkOrder).where(
            WorkOrder.pm_schedule_id == schedule_id,
            WorkOrder.status.notin_(
                [OrderStatus.closed, OrderStatus.cancelled]
            ),
        )
    )


def _is_due(db: Session, sched: PmSchedule) -> bool:
    if not sched.is_active:
        return False
    if sched.trigger_kind.value == "calendar":
        due = _aware(sched.next_due_at)
        return due is not None and utcnow() >= due
    # meter
    if sched.meter_id is None or sched.next_due_value is None:
        return False
    latest = _latest_reading_value(db, sched.meter_id)
    return latest is not None and latest >= sched.next_due_value


# --- engine entry points ---
def generate_order_for(db: Session, sched: PmSchedule) -> WorkOrder | None:
    """Generate a PM work order for one schedule if it's due AND has no
    open cycle. Returns the new order, or None when nothing was generated."""
    if _open_cycle(db, sched.id) is not None:
        return None
    if not _is_due(db, sched):
        return None

    order = WorkOrder(
        customer_account_id=sched.customer_account_id,
        site_id=sched.site_id,
        functional_location_id=sched.functional_location_id,
        equipment_id=sched.equipment_id,
        pm_schedule_id=sched.id,
        order_type=OrderType.preventive,
        billing_class=sched.billing_class,
        priority=sched.priority,
        title=sched.order_title,
        description=f"Auto-generated from PM schedule '{sched.name}'",
        status=OrderStatus.created,
    )
    db.add(order)
    db.flush()
    record_audit(
        db, entity_type="work_order", entity_id=order.id,
        action=AuditAction.create, after=serialize(order),
    )
    record_audit(
        db, entity_type="pm_schedule", entity_id=sched.id,
        action=AuditAction.update,
        after={"generated_work_order_id": str(order.id)},
    )
    return order


def scan(db: Session) -> list[WorkOrder]:
    """Scan every active schedule. Returns the list of newly-generated
    work orders (typically 0 in most scans)."""
    schedules = db.scalars(select(PmSchedule).where(PmSchedule.is_active.is_(True)))
    generated: list[WorkOrder] = []
    for sched in schedules:
        order = generate_order_for(db, sched)
        if order is not None:
            generated.append(order)
    return generated


def on_pm_order_closed(db: Session, order: WorkOrder) -> None:
    """Called from the work-order state machine when a PM-generated order
    closes. Re-baselines the schedule's next-due anchor."""
    if order.pm_schedule_id is None:
        return
    sched = db.get(PmSchedule, order.pm_schedule_id)
    if sched is None:
        return

    before = serialize(sched)
    now = utcnow()
    sched.last_completed_at = now

    if sched.trigger_kind.value == "calendar":
        if sched.interval_days is not None:
            sched.next_due_at = now + timedelta(days=sched.interval_days)
    else:
        latest = _latest_reading_value(db, sched.meter_id) if sched.meter_id else None
        if latest is not None and sched.interval_value is not None:
            sched.last_completed_value = latest
            sched.next_due_value = latest + sched.interval_value

    db.flush()
    record_audit(
        db, entity_type="pm_schedule", entity_id=sched.id,
        action=AuditAction.update, before=before, after=serialize(sched),
    )
