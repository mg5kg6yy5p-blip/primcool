from uuid import UUID, uuid4

from sqlalchemy import Enum as SAEnum
from sqlalchemy import Float, ForeignKey, String, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.models.common import TimestampMixin
from app.models.enums import CustomerStatus, CustomerType, SpaceType


class CustomerAccount(Base, TimestampMixin):
    __tablename__ = "customer_account"

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    type: Mapped[CustomerType] = mapped_column(
        SAEnum(CustomerType, name="customer_type"), nullable=False
    )
    billing_currency: Mapped[str] = mapped_column(String(3), nullable=False, default="JMD")
    contact_name: Mapped[str] = mapped_column(String(200), nullable=False, default="")
    contact_email: Mapped[str] = mapped_column(String(254), nullable=False, default="")
    contact_phone: Mapped[str] = mapped_column(String(40), nullable=False, default="")
    status: Mapped[CustomerStatus] = mapped_column(
        SAEnum(CustomerStatus, name="customer_status"),
        nullable=False,
        default=CustomerStatus.active,
    )


class Site(Base, TimestampMixin):
    __tablename__ = "site"

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    customer_account_id: Mapped[UUID] = mapped_column(
        ForeignKey("customer_account.id"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    address: Mapped[str] = mapped_column(String(500), nullable=False, default="")
    geo_lat: Mapped[float | None] = mapped_column(Float, nullable=True)
    geo_lng: Mapped[float | None] = mapped_column(Float, nullable=True)


class Building(Base, TimestampMixin):
    __tablename__ = "building"

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    site_id: Mapped[UUID] = mapped_column(
        ForeignKey("site.id"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(200), nullable=False)


class Space(Base, TimestampMixin):
    __tablename__ = "space"

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    site_id: Mapped[UUID] = mapped_column(
        ForeignKey("site.id"), nullable=False, index=True
    )
    building_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("building.id"), nullable=True, index=True
    )
    identifier: Mapped[str] = mapped_column(String(120), nullable=False)
    space_type: Mapped[SpaceType] = mapped_column(
        SAEnum(SpaceType, name="space_type"), nullable=False
    )
