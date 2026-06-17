from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy import DateTime, Float, ForeignKey, String, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.models.common import TimestampMixin


class Material(Base, TimestampMixin):
    __tablename__ = "material"

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    part_number: Mapped[str] = mapped_column(String(120), nullable=False, unique=True)
    description: Mapped[str] = mapped_column(String(500), nullable=False, default="")
    unit_cost: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    currency: Mapped[str] = mapped_column(String(3), nullable=False, default="JMD")
    uom: Mapped[str] = mapped_column(String(20), nullable=False, default="ea")
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="active")


class StockLocation(Base, TimestampMixin):
    __tablename__ = "stock_location"

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    kind: Mapped[str] = mapped_column(String(40), nullable=False, default="shop")  # shop | van


class StockQuant(Base, TimestampMixin):
    """Quantity of a given material at a given stock location.
    Updated atomically alongside confirmation parts (decrement on consume,
    restore on reversal)."""
    __tablename__ = "stock_quant"

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    material_id: Mapped[UUID] = mapped_column(
        ForeignKey("material.id"), nullable=False, index=True
    )
    stock_location_id: Mapped[UUID] = mapped_column(
        ForeignKey("stock_location.id"), nullable=False, index=True
    )
    qty: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)


class Confirmation(Base):
    """Append-only.

    A reversal is a NEW row with reversal_of_id set. The reversed row is never
    touched. Effective state = fold over the chain."""
    __tablename__ = "confirmation"

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    operation_id: Mapped[UUID] = mapped_column(
        ForeignKey("operation.id"), nullable=False, index=True
    )
    technician_user_id: Mapped[UUID | None] = mapped_column(Uuid(as_uuid=True), nullable=True)
    actual_hours: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    is_final: Mapped[bool] = mapped_column(nullable=False, default=False)
    notes: Mapped[str] = mapped_column(String(2000), nullable=False, default="")
    reversal_of_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("confirmation.id"), nullable=True, index=True
    )
    at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False,
        default=lambda: __import__("app.models.common", fromlist=["utcnow"]).utcnow(),
    )


class ConfirmationPart(Base):
    """Append-only. Stock movement snapshot — unit_cost_at_use freezes
    the part cost at the moment of consumption so later cost edits don't
    rewrite history."""
    __tablename__ = "confirmation_part"

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    confirmation_id: Mapped[UUID] = mapped_column(
        ForeignKey("confirmation.id"), nullable=False, index=True
    )
    material_id: Mapped[UUID] = mapped_column(
        ForeignKey("material.id"), nullable=False, index=True
    )
    stock_location_id: Mapped[UUID] = mapped_column(
        ForeignKey("stock_location.id"), nullable=False
    )
    qty_used: Mapped[float] = mapped_column(Float, nullable=False)
    unit_cost_at_use: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
