from datetime import date, datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from app.models.enums import (
    BillingClass,
    NotificationCategory,
    NotificationStatus,
    OperationStatus,
    OrderStatus,
    OrderType,
    Severity,
)


# --- notification ---
class NotificationCreate(BaseModel):
    customer_account_id: UUID
    site_id: UUID
    space_id: UUID | None = None
    category: NotificationCategory
    severity: Severity
    title: str = Field(min_length=1, max_length=200)
    description: str = Field(default="", max_length=4000)
    photo_url: str | None = Field(default=None, max_length=1000)


class NotificationOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    customer_account_id: UUID
    site_id: UUID
    space_id: UUID | None
    category: NotificationCategory
    severity: Severity
    title: str
    description: str
    photo_url: str | None
    status: NotificationStatus
    acknowledged_at: datetime | None
    closed_at: datetime | None


class CloseNoActionRequest(BaseModel):
    reason: str = Field(min_length=1, max_length=1000)


# --- work_order ---
class WorkOrderCreate(BaseModel):
    customer_account_id: UUID
    site_id: UUID
    functional_location_id: UUID | None = None
    equipment_id: UUID | None = None
    order_type: OrderType
    billing_class: BillingClass = BillingClass.billable
    priority: Severity
    title: str = Field(min_length=1, max_length=200)
    description: str = Field(default="", max_length=4000)
    scheduled_date: date | None = None
    due_date: date | None = None


class WorkOrderUpdate(BaseModel):
    """Descriptive fields only — status changes go through /transition, and
    the router rejects edits once the order is tech_complete or terminal."""
    title: str | None = Field(default=None, min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=4000)
    billing_class: BillingClass | None = None
    priority: Severity | None = None
    functional_location_id: UUID | None = None
    equipment_id: UUID | None = None
    assigned_to_user_id: UUID | None = None
    scheduled_date: date | None = None
    due_date: date | None = None


class WorkOrderOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    notification_id: UUID | None
    customer_account_id: UUID
    site_id: UUID
    functional_location_id: UUID | None
    equipment_id: UUID | None
    pm_schedule_id: UUID | None
    order_type: OrderType
    billing_class: BillingClass
    priority: Severity
    title: str
    description: str
    status: OrderStatus
    assigned_to_user_id: UUID | None
    scheduled_date: date | None
    due_date: date | None
    closed_at: datetime | None
    legal_transitions: list[OrderStatus] = []


class TransitionRequest(BaseModel):
    target: OrderStatus


# --- operation ---
class OperationCreate(BaseModel):
    sequence: int = Field(default=10, ge=0)
    description: str = Field(default="", max_length=1000)
    planned_hours: float = Field(default=0.0, ge=0)


class OperationOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    work_order_id: UUID
    sequence: int
    description: str
    status: OperationStatus
    planned_hours: float


# --- saved_view ---
class SavedViewCreate(BaseModel):
    user_id: UUID | None = None
    name: str = Field(min_length=1, max_length=120)
    filters: dict = Field(default_factory=dict)
    columns: list = Field(default_factory=list)
    sort: dict = Field(default_factory=dict)
    is_default: bool = False


class SavedViewOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    user_id: UUID | None
    entity: str
    name: str
    filters: dict
    columns: list
    sort: dict
    is_default: bool
