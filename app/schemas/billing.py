from datetime import date, datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from app.models.enums import (
    BillingClass,
    ContractStatus,
    InvoiceStatus,
    LineKind,
    UserRole,
)


# --- contracts ---
class ServiceContractCreate(BaseModel):
    customer_account_id: UUID
    name: str = Field(min_length=1, max_length=200)
    starts_on: date
    ends_on: date
    included_pm_visits_per_year: int = Field(default=0, ge=0)
    response_sla: dict = Field(default_factory=dict)
    terms_notes: str = Field(default="", max_length=4000)
    site_ids: list[UUID] = Field(default_factory=list)


class ServiceContractUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=200)
    ends_on: date | None = None
    included_pm_visits_per_year: int | None = Field(default=None, ge=0)
    response_sla: dict | None = None
    terms_notes: str | None = Field(default=None, max_length=4000)
    status: ContractStatus | None = None


class ServiceContractOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    customer_account_id: UUID
    name: str
    starts_on: date
    ends_on: date
    included_pm_visits_per_year: int
    response_sla: dict
    terms_notes: str
    status: ContractStatus
    site_ids: list[UUID] = []
    used_this_year: int = 0


# --- billing rates ---
class BillingRateOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    role: UserRole
    hourly_amount: float
    currency: str
    is_active: bool


class BillingRateUpdate(BaseModel):
    hourly_amount: float | None = Field(default=None, ge=0)
    currency: str | None = Field(default=None, min_length=3, max_length=3)
    is_active: bool | None = None


# --- BOM ---
class BomItemIn(BaseModel):
    material_id: UUID
    quantity: float = Field(gt=0)


class BomItemOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    material_id: UUID
    quantity: float


class EquipmentBomOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    equipment_id: UUID
    items: list[BomItemOut] = []


class EquipmentBomReplace(BaseModel):
    """Replace the entire BOM for an equipment in one call."""
    items: list[BomItemIn]


# --- invoices ---
class InvoiceDraftLineOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    kind: LineKind
    description: str
    qty: float
    unit_amount: float
    total: float
    source_confirmation_id: UUID | None
    source_part_id: UUID | None


class InvoiceDraftOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    work_order_id: UUID
    customer_account_id: UUID
    billing_class: BillingClass
    currency: str
    subtotal: float
    gct_rate: float
    gct_amount: float
    total: float
    status: InvoiceStatus
    issued_at: datetime | None
    lines: list[InvoiceDraftLineOut] = []
