from uuid import UUID

from pydantic import BaseModel, ConfigDict, EmailStr, Field

from app.models.enums import CustomerStatus, CustomerType, SpaceType


# --- customer_account ---
class CustomerAccountCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    type: CustomerType
    billing_currency: str = Field(default="JMD", min_length=3, max_length=3)
    contact_name: str = Field(default="", max_length=200)
    contact_email: EmailStr | str = Field(default="")
    contact_phone: str = Field(default="", max_length=40)
    status: CustomerStatus = CustomerStatus.active
    gct_rate: float = Field(default=0.0, ge=0, le=100)


class CustomerAccountUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=200)
    type: CustomerType | None = None
    billing_currency: str | None = Field(default=None, min_length=3, max_length=3)
    contact_name: str | None = Field(default=None, max_length=200)
    contact_email: EmailStr | str | None = None
    contact_phone: str | None = Field(default=None, max_length=40)
    status: CustomerStatus | None = None
    gct_rate: float | None = Field(default=None, ge=0, le=100)


class CustomerAccountOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    name: str
    type: CustomerType
    billing_currency: str
    contact_name: str
    contact_email: str
    contact_phone: str
    status: CustomerStatus
    gct_rate: float


# --- site ---
class SiteCreate(BaseModel):
    customer_account_id: UUID
    name: str = Field(min_length=1, max_length=200)
    address: str = Field(default="", max_length=500)
    geo_lat: float | None = None
    geo_lng: float | None = None


class SiteUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=200)
    address: str | None = Field(default=None, max_length=500)
    geo_lat: float | None = None
    geo_lng: float | None = None


class SiteOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    customer_account_id: UUID
    name: str
    address: str
    geo_lat: float | None
    geo_lng: float | None


# --- building ---
class BuildingCreate(BaseModel):
    site_id: UUID
    name: str = Field(min_length=1, max_length=200)


class BuildingUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=200)


class BuildingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    site_id: UUID
    name: str


# --- space ---
class SpaceCreate(BaseModel):
    site_id: UUID
    building_id: UUID | None = None
    identifier: str = Field(min_length=1, max_length=120)
    space_type: SpaceType


class SpaceUpdate(BaseModel):
    building_id: UUID | None = None
    identifier: str | None = Field(default=None, min_length=1, max_length=120)
    space_type: SpaceType | None = None


class SpaceOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    site_id: UUID
    building_id: UUID | None
    identifier: str
    space_type: SpaceType
