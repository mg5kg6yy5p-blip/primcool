from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


# --- material ---
class MaterialCreate(BaseModel):
    part_number: str = Field(min_length=1, max_length=120)
    description: str = Field(default="", max_length=500)
    unit_cost: float = Field(default=0.0, ge=0)
    currency: str = Field(default="JMD", min_length=3, max_length=3)
    uom: str = Field(default="ea", max_length=20)


class MaterialOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    part_number: str
    description: str
    unit_cost: float
    currency: str
    uom: str
    status: str


# --- stock_location ---
class StockLocationCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    kind: str = Field(default="shop", max_length=40)


class StockLocationOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    name: str
    kind: str


# --- stock_quant ---
class StockQuantSet(BaseModel):
    material_id: UUID
    stock_location_id: UUID
    qty: float = Field(ge=0)


class StockQuantOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    material_id: UUID
    stock_location_id: UUID
    qty: float


# --- confirmations ---
class PartUseIn(BaseModel):
    material_id: UUID
    stock_location_id: UUID
    qty_used: float = Field(gt=0)


class ConfirmRequest(BaseModel):
    actual_hours: float = Field(ge=0)
    is_final: bool = False
    notes: str = Field(default="", max_length=2000)
    parts: list[PartUseIn] = Field(default_factory=list)


class ReverseRequest(BaseModel):
    reason: str = Field(min_length=1, max_length=1000)


class ConfirmationPartOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    confirmation_id: UUID
    material_id: UUID
    stock_location_id: UUID
    qty_used: float
    unit_cost_at_use: float


class ConfirmationOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    operation_id: UUID
    technician_user_id: UUID | None
    actual_hours: float
    started_at: datetime | None
    ended_at: datetime | None
    is_final: bool
    notes: str
    reversal_of_id: UUID | None
    at: datetime
    parts: list[ConfirmationPartOut] = []


# --- where-used ---
class WhereUsedRow(BaseModel):
    equipment_id: UUID
    serial: str | None
    qty: float
