from datetime import date, datetime
from uuid import UUID, uuid4

from sqlalchemy import (
    Boolean,
    Date,
    DateTime,
    Enum as SAEnum,
    Float,
    ForeignKey,
    Integer,
    JSON,
    String,
    Uuid,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.models.common import TimestampMixin
from app.models.enums import (
    BillingClass,
    ContractStatus,
    InvoiceStatus,
    LineKind,
    UserRole,
)

JSONType = JSON().with_variant(JSONB, "postgresql")


class ServiceContract(Base, TimestampMixin):
    __tablename__ = "service_contract"

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    customer_account_id: Mapped[UUID] = mapped_column(
        ForeignKey("customer_account.id"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    starts_on: Mapped[date] = mapped_column(Date, nullable=False)
    ends_on: Mapped[date] = mapped_column(Date, nullable=False)
    included_pm_visits_per_year: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    response_sla: Mapped[dict] = mapped_column(JSONType, nullable=False, default=dict)
    terms_notes: Mapped[str] = mapped_column(String(4000), nullable=False, default="")
    status: Mapped[ContractStatus] = mapped_column(
        SAEnum(ContractStatus, name="contract_status"),
        nullable=False, default=ContractStatus.active,
    )


class ContractSite(Base):
    __tablename__ = "contract_site"

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    service_contract_id: Mapped[UUID] = mapped_column(
        ForeignKey("service_contract.id"), nullable=False, index=True
    )
    site_id: Mapped[UUID] = mapped_column(
        ForeignKey("site.id"), nullable=False, index=True
    )


class BillingRate(Base, TimestampMixin):
    __tablename__ = "billing_rate"

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    role: Mapped[UserRole] = mapped_column(
        SAEnum(UserRole, name="user_role"), nullable=False, unique=True
    )
    hourly_amount: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    currency: Mapped[str] = mapped_column(String(3), nullable=False, default="JMD")
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)


class EquipmentBom(Base, TimestampMixin):
    """BOM header for a piece of equipment. One BOM per equipment."""
    __tablename__ = "equipment_bom"

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    equipment_id: Mapped[UUID] = mapped_column(
        ForeignKey("equipment.id"), nullable=False, unique=True, index=True
    )


class BomItem(Base):
    __tablename__ = "bom_item"

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    equipment_bom_id: Mapped[UUID] = mapped_column(
        ForeignKey("equipment_bom.id"), nullable=False, index=True
    )
    material_id: Mapped[UUID] = mapped_column(
        ForeignKey("material.id"), nullable=False, index=True
    )
    quantity: Mapped[float] = mapped_column(Float, nullable=False, default=1.0)


class InvoiceDraft(Base, TimestampMixin):
    __tablename__ = "invoice_draft"

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    work_order_id: Mapped[UUID] = mapped_column(
        ForeignKey("work_order.id"), nullable=False, index=True
    )
    customer_account_id: Mapped[UUID] = mapped_column(
        ForeignKey("customer_account.id"), nullable=False, index=True
    )
    billing_class: Mapped[BillingClass] = mapped_column(
        SAEnum(BillingClass, name="billing_class"), nullable=False
    )
    currency: Mapped[str] = mapped_column(String(3), nullable=False, default="JMD")
    subtotal: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    gct_rate: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    gct_amount: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    total: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    status: Mapped[InvoiceStatus] = mapped_column(
        SAEnum(InvoiceStatus, name="invoice_status"),
        nullable=False, default=InvoiceStatus.draft,
    )
    issued_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )


class InvoiceDraftLine(Base):
    __tablename__ = "invoice_draft_line"

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    invoice_draft_id: Mapped[UUID] = mapped_column(
        ForeignKey("invoice_draft.id"), nullable=False, index=True
    )
    kind: Mapped[LineKind] = mapped_column(
        SAEnum(LineKind, name="line_kind"), nullable=False
    )
    description: Mapped[str] = mapped_column(String(500), nullable=False, default="")
    qty: Mapped[float] = mapped_column(Float, nullable=False, default=1.0)
    unit_amount: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    total: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    source_confirmation_id: Mapped[UUID | None] = mapped_column(
        Uuid(as_uuid=True), nullable=True
    )
    source_part_id: Mapped[UUID | None] = mapped_column(Uuid(as_uuid=True), nullable=True)
