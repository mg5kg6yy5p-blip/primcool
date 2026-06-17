from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.models.enums import BillingClass, PmTriggerKind, Severity


class PmScheduleCreate(BaseModel):
    customer_account_id: UUID
    site_id: UUID
    functional_location_id: UUID | None = None
    equipment_id: UUID | None = None

    name: str = Field(min_length=1, max_length=200)
    description: str = Field(default="", max_length=2000)

    trigger_kind: PmTriggerKind
    interval_days: int | None = Field(default=None, gt=0, le=3650)
    meter_id: UUID | None = None
    interval_value: float | None = Field(default=None, gt=0)

    # Anchors (one pair per kind).
    start_at: datetime | None = None
    start_value: float | None = None

    order_title: str = Field(min_length=1, max_length=200)
    billing_class: BillingClass = BillingClass.contract
    priority: Severity = Severity.medium
    service_contract_id: UUID | None = None

    @model_validator(mode="after")
    def _check_kind(self):
        if self.trigger_kind == PmTriggerKind.calendar:
            if self.interval_days is None:
                raise ValueError("interval_days required for calendar triggers")
        else:
            if self.meter_id is None or self.interval_value is None:
                raise ValueError(
                    "meter_id and interval_value required for meter triggers"
                )
        return self


class PmScheduleUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=2000)
    interval_days: int | None = Field(default=None, gt=0, le=3650)
    interval_value: float | None = Field(default=None, gt=0)
    order_title: str | None = Field(default=None, min_length=1, max_length=200)
    billing_class: BillingClass | None = None
    priority: Severity | None = None
    is_active: bool | None = None


class PmScheduleOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    customer_account_id: UUID
    site_id: UUID
    functional_location_id: UUID | None
    equipment_id: UUID | None
    name: str
    description: str
    trigger_kind: PmTriggerKind
    interval_days: int | None
    meter_id: UUID | None
    interval_value: float | None
    last_completed_at: datetime | None
    last_completed_value: float | None
    next_due_at: datetime | None
    next_due_value: float | None
    order_title: str
    billing_class: BillingClass
    priority: Severity
    service_contract_id: UUID | None
    is_active: bool


class PmScanResult(BaseModel):
    generated_work_order_ids: list[UUID]
