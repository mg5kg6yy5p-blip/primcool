from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy import (
    Boolean,
    DateTime,
    Enum as SAEnum,
    Float,
    ForeignKey,
    Integer,
    String,
    Uuid,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.models.common import TimestampMixin
from app.models.enums import BillingClass, PmTriggerKind, Severity


class PmSchedule(Base, TimestampMixin):
    """A preventive-maintenance cadence on an FL or equipment. The engine
    scans active schedules and materialises a work order when one is due.
    Cadence-holds: late completions re-baseline the next-due anchor to the
    actual completion, not the previous due. One-open-cycle: while an
    engine-generated order is still non-terminal, no new order is created."""
    __tablename__ = "pm_schedule"

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    customer_account_id: Mapped[UUID] = mapped_column(
        ForeignKey("customer_account.id"), nullable=False, index=True
    )
    site_id: Mapped[UUID] = mapped_column(ForeignKey("site.id"), nullable=False, index=True)
    functional_location_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("functional_location.id"), nullable=True, index=True
    )
    equipment_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("equipment.id"), nullable=True, index=True
    )

    name: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str] = mapped_column(String(2000), nullable=False, default="")

    trigger_kind: Mapped[PmTriggerKind] = mapped_column(
        SAEnum(PmTriggerKind, name="pm_trigger_kind"), nullable=False
    )

    # Calendar trigger.
    interval_days: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # Meter trigger.
    meter_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("meter.id"), nullable=True, index=True
    )
    interval_value: Mapped[float | None] = mapped_column(Float, nullable=True)

    # Baseline + next-due tracking. Both pairs nullable to support either kind.
    last_completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_completed_value: Mapped[float | None] = mapped_column(Float, nullable=True)
    next_due_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    next_due_value: Mapped[float | None] = mapped_column(Float, nullable=True)

    # Defaults applied to engine-generated work orders.
    order_title: Mapped[str] = mapped_column(String(200), nullable=False)
    billing_class: Mapped[BillingClass] = mapped_column(
        SAEnum(BillingClass, name="billing_class"),
        nullable=False, default=BillingClass.contract,
    )
    priority: Mapped[Severity] = mapped_column(
        SAEnum(Severity, name="severity"), nullable=False, default=Severity.medium,
    )

    # Phase 5 will link this to a contract for entitlement tracking.
    service_contract_id: Mapped[UUID | None] = mapped_column(
        Uuid(as_uuid=True), nullable=True, index=True
    )

    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
