from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy import DateTime, Enum as SAEnum
from sqlalchemy import Float, ForeignKey, Index, Integer, String, Uuid, text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.models.common import TimestampMixin, add_months
from app.models.enums import (
    AssetClass,
    EquipmentStatus,
    FLStatus,
    MeterType,
    ReadingSource,
)


class FunctionalLocation(Base, TimestampMixin):
    __tablename__ = "functional_location"

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    site_id: Mapped[UUID] = mapped_column(
        ForeignKey("site.id"), nullable=False, index=True
    )
    building_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("building.id"), nullable=True, index=True
    )
    space_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("space.id"), nullable=True, index=True
    )
    parent_fl_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("functional_location.id"), nullable=True, index=True
    )
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    fl_class: Mapped[AssetClass] = mapped_column(
        SAEnum(AssetClass, name="asset_class"), nullable=False
    )
    status: Mapped[FLStatus] = mapped_column(
        SAEnum(FLStatus, name="fl_status"), nullable=False, default=FLStatus.active
    )


class Equipment(Base, TimestampMixin):
    __tablename__ = "equipment"

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    serial: Mapped[str | None] = mapped_column(String(120), nullable=True, unique=True)
    model: Mapped[str] = mapped_column(String(200), nullable=False, default="")
    manufacturer: Mapped[str] = mapped_column(String(200), nullable=False, default="")
    equipment_class: Mapped[AssetClass] = mapped_column(
        SAEnum(AssetClass, name="asset_class"), nullable=False
    )
    status: Mapped[EquipmentStatus] = mapped_column(
        SAEnum(EquipmentStatus, name="equipment_status"),
        nullable=False,
        default=EquipmentStatus.in_storage,
    )
    warranty_months: Mapped[int | None] = mapped_column(Integer, nullable=True)
    notes: Mapped[str] = mapped_column(String(2000), nullable=False, default="")

    installs: Mapped[list["EquipmentInstall"]] = relationship(
        back_populates="equipment", order_by="EquipmentInstall.installed_at"
    )


class EquipmentInstall(Base):
    __tablename__ = "equipment_install"
    __table_args__ = (
        Index(
            "uq_active_install_per_fl",
            "functional_location_id",
            unique=True,
            postgresql_where=text("removed_at IS NULL"),
            sqlite_where=text("removed_at IS NULL"),
        ),
        Index(
            "uq_active_install_per_equipment",
            "equipment_id",
            unique=True,
            postgresql_where=text("removed_at IS NULL"),
            sqlite_where=text("removed_at IS NULL"),
        ),
    )

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    equipment_id: Mapped[UUID] = mapped_column(
        ForeignKey("equipment.id"), nullable=False, index=True
    )
    functional_location_id: Mapped[UUID] = mapped_column(
        ForeignKey("functional_location.id"), nullable=False, index=True
    )
    installed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    removed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    installed_by_user_id: Mapped[UUID | None] = mapped_column(
        Uuid(as_uuid=True), nullable=True
    )

    equipment: Mapped["Equipment"] = relationship(back_populates="installs")

    @property
    def warranty_expires_at(self) -> datetime | None:
        months = self.equipment.warranty_months if self.equipment else None
        if months is None:
            return None
        return add_months(self.installed_at, months)


class Meter(Base, TimestampMixin):
    __tablename__ = "meter"

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    equipment_id: Mapped[UUID] = mapped_column(
        ForeignKey("equipment.id"), nullable=False, index=True
    )
    meter_type: Mapped[MeterType] = mapped_column(
        SAEnum(MeterType, name="meter_type"), nullable=False
    )
    unit: Mapped[str] = mapped_column(String(40), nullable=False, default="")


class MeterReading(Base):
    """Append-only. DB triggers (Postgres) reject UPDATE/DELETE."""
    __tablename__ = "meter_reading"

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    meter_id: Mapped[UUID] = mapped_column(
        ForeignKey("meter.id"), nullable=False, index=True
    )
    reading_value: Mapped[float] = mapped_column(Float, nullable=False)
    read_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    source: Mapped[ReadingSource] = mapped_column(
        SAEnum(
            ReadingSource,
            name="reading_source",
            values_callable=lambda e: [m.value for m in e],
        ),
        nullable=False,
        default=ReadingSource.manual,
    )
    recorded_by: Mapped[UUID | None] = mapped_column(Uuid(as_uuid=True), nullable=True)
