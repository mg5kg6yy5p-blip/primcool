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
    String,
    Uuid,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy import JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.models.common import TimestampMixin
from app.models.enums import (
    BillingClass,
    NotificationCategory,
    NotificationStatus,
    OperationStatus,
    OrderStatus,
    OrderType,
    Severity,
)

JSONType = JSON().with_variant(JSONB, "postgresql")


class Notification(Base, TimestampMixin):
    __tablename__ = "notification"

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    customer_account_id: Mapped[UUID] = mapped_column(
        ForeignKey("customer_account.id"), nullable=False, index=True
    )
    site_id: Mapped[UUID] = mapped_column(ForeignKey("site.id"), nullable=False, index=True)
    space_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("space.id"), nullable=True, index=True
    )
    category: Mapped[NotificationCategory] = mapped_column(
        SAEnum(NotificationCategory, name="notification_category"), nullable=False
    )
    severity: Mapped[Severity] = mapped_column(
        SAEnum(Severity, name="severity"), nullable=False
    )
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str] = mapped_column(String(4000), nullable=False, default="")
    photo_url: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    status: Mapped[NotificationStatus] = mapped_column(
        SAEnum(NotificationStatus, name="notification_status"),
        nullable=False,
        default=NotificationStatus.new,
        index=True,
    )
    created_by: Mapped[UUID | None] = mapped_column(Uuid(as_uuid=True), nullable=True)
    acknowledged_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class WorkOrder(Base, TimestampMixin):
    __tablename__ = "work_order"

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    notification_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("notification.id"), nullable=True, index=True
    )
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
    pm_schedule_id: Mapped[UUID | None] = mapped_column(Uuid(as_uuid=True), nullable=True)
    order_type: Mapped[OrderType] = mapped_column(
        SAEnum(OrderType, name="order_type"), nullable=False
    )
    billing_class: Mapped[BillingClass] = mapped_column(
        SAEnum(BillingClass, name="billing_class"),
        nullable=False,
        default=BillingClass.billable,
    )
    priority: Mapped[Severity] = mapped_column(
        SAEnum(Severity, name="severity"), nullable=False, index=True
    )
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str] = mapped_column(String(4000), nullable=False, default="")
    status: Mapped[OrderStatus] = mapped_column(
        SAEnum(OrderStatus, name="order_status"),
        nullable=False,
        default=OrderStatus.created,
        index=True,
    )
    assigned_to_user_id: Mapped[UUID | None] = mapped_column(Uuid(as_uuid=True), nullable=True)
    scheduled_date: Mapped[date | None] = mapped_column(Date, nullable=True)
    due_date: Mapped[date | None] = mapped_column(Date, nullable=True)
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    operations: Mapped[list["Operation"]] = relationship(
        back_populates="work_order", order_by="Operation.sequence"
    )


class Operation(Base, TimestampMixin):
    __tablename__ = "operation"

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    work_order_id: Mapped[UUID] = mapped_column(
        ForeignKey("work_order.id"), nullable=False, index=True
    )
    sequence: Mapped[int] = mapped_column(Integer, nullable=False, default=10)
    description: Mapped[str] = mapped_column(String(1000), nullable=False, default="")
    status: Mapped[OperationStatus] = mapped_column(
        SAEnum(OperationStatus, name="operation_status"),
        nullable=False,
        default=OperationStatus.open,
    )
    planned_hours: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)

    work_order: Mapped["WorkOrder"] = relationship(back_populates="operations")


class SavedView(Base, TimestampMixin):
    __tablename__ = "saved_view"

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    user_id: Mapped[UUID | None] = mapped_column(Uuid(as_uuid=True), nullable=True, index=True)
    entity: Mapped[str] = mapped_column(String(40), nullable=False, default="work_order_list")
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    filters: Mapped[dict] = mapped_column(JSONType, nullable=False, default=dict)
    columns: Mapped[list] = mapped_column(JSONType, nullable=False, default=list)
    sort: Mapped[dict] = mapped_column(JSONType, nullable=False, default=dict)
    is_default: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
