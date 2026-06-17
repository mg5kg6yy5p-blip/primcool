from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from app.models.enums import (
    AssetClass,
    EquipmentStatus,
    FLStatus,
    MeterType,
    ReadingSource,
)


# --- functional_location ---
class FunctionalLocationCreate(BaseModel):
    site_id: UUID
    building_id: UUID | None = None
    space_id: UUID | None = None
    parent_fl_id: UUID | None = None
    name: str = Field(min_length=1, max_length=200)
    fl_class: AssetClass
    status: FLStatus = FLStatus.active


class FunctionalLocationUpdate(BaseModel):
    building_id: UUID | None = None
    space_id: UUID | None = None
    parent_fl_id: UUID | None = None
    name: str | None = Field(default=None, min_length=1, max_length=200)
    fl_class: AssetClass | None = None
    status: FLStatus | None = None


class FunctionalLocationOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    site_id: UUID
    building_id: UUID | None
    space_id: UUID | None
    parent_fl_id: UUID | None
    name: str
    fl_class: AssetClass
    status: FLStatus


# --- equipment ---
class EquipmentCreate(BaseModel):
    serial: str | None = Field(default=None, max_length=120)
    model: str = Field(default="", max_length=200)
    manufacturer: str = Field(default="", max_length=200)
    equipment_class: AssetClass
    status: EquipmentStatus = EquipmentStatus.in_storage
    warranty_months: int | None = Field(default=None, ge=0, le=600)
    notes: str = Field(default="", max_length=2000)


class EquipmentUpdate(BaseModel):
    serial: str | None = Field(default=None, max_length=120)
    model: str | None = Field(default=None, max_length=200)
    manufacturer: str | None = Field(default=None, max_length=200)
    equipment_class: AssetClass | None = None
    status: EquipmentStatus | None = None
    warranty_months: int | None = Field(default=None, ge=0, le=600)
    notes: str | None = Field(default=None, max_length=2000)


class EquipmentOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    serial: str | None
    model: str
    manufacturer: str
    equipment_class: AssetClass
    status: EquipmentStatus
    warranty_months: int | None
    notes: str


# --- equipment_install ---
class InstallRequest(BaseModel):
    fl_id: UUID
    installed_at: datetime | None = None


class RemoveRequest(BaseModel):
    removed_at: datetime | None = None
    new_status: EquipmentStatus = EquipmentStatus.in_storage


class EquipmentInstallOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    equipment_id: UUID
    functional_location_id: UUID
    installed_at: datetime
    removed_at: datetime | None
    installed_by_user_id: UUID | None
    warranty_expires_at: datetime | None = None


# --- meter ---
class MeterCreate(BaseModel):
    equipment_id: UUID
    meter_type: MeterType
    unit: str = Field(default="", max_length=40)


class MeterOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    equipment_id: UUID
    meter_type: MeterType
    unit: str


# --- meter_reading ---
class MeterReadingCreate(BaseModel):
    reading_value: float
    read_at: datetime | None = None
    source: ReadingSource = ReadingSource.manual


class MeterReadingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    meter_id: UUID
    reading_value: float
    read_at: datetime
    source: ReadingSource
    recorded_by: UUID | None


# --- equipment timeline / history ---
class TimelineEvent(BaseModel):
    at: datetime
    kind: str  # install | remove | meter_reading
    detail: dict


class EquipmentHistory(BaseModel):
    equipment_id: UUID
    events: list[TimelineEvent]
