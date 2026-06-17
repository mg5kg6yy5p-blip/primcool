"""Confirmation service: append-only confirm + reverse, with parts and stock.

One transaction per call:
  * insert confirmation
  * insert confirmation_part rows + decrement stock_quant (consume)
    -- or restore stock_quant (reverse)
  * write audit rows
  * if all operations on the work order have at least one non-reversed
    final confirmation, auto-transition the order to tech_complete.
"""
from dataclasses import dataclass
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.common import utcnow
from app.models.enums import AuditAction, OperationStatus, OrderStatus
from app.models.inventory import (
    Confirmation,
    ConfirmationPart,
    Material,
    StockLocation,
    StockQuant,
)
from app.models.workflow import Operation, WorkOrder
from app.services.audit import record_audit, serialize
from app.services.workflow import transition_work_order


class ConfirmationError(Exception):
    """Domain-level confirmation/reversal violation."""


@dataclass
class PartUse:
    material_id: UUID
    stock_location_id: UUID
    qty_used: float


def _effective_confirmations(db: Session, operation_id: UUID) -> list[Confirmation]:
    """All confirmations on an operation that are not themselves reversed."""
    rows = list(
        db.scalars(select(Confirmation).where(Confirmation.operation_id == operation_id))
    )
    reversed_ids = {r.reversal_of_id for r in rows if r.reversal_of_id is not None}
    return [r for r in rows if r.id not in reversed_ids and r.reversal_of_id is None]


def confirm_operation(
    db: Session,
    *,
    operation_id: UUID,
    actual_hours: float,
    is_final: bool,
    notes: str = "",
    technician_user_id: UUID | None = None,
    parts: list[PartUse] | None = None,
) -> Confirmation:
    op = db.get(Operation, operation_id)
    if op is None:
        raise ConfirmationError("Operation not found")

    order = db.get(WorkOrder, op.work_order_id)
    if order.status in (OrderStatus.closed, OrderStatus.cancelled, OrderStatus.tech_complete):
        raise ConfirmationError(
            f"Cannot confirm against an order in status {order.status.value}"
        )

    cnf = Confirmation(
        operation_id=operation_id,
        technician_user_id=technician_user_id,
        actual_hours=actual_hours,
        started_at=None,
        ended_at=utcnow(),
        is_final=is_final,
        notes=notes,
    )
    db.add(cnf)
    db.flush()
    record_audit(
        db, entity_type="confirmation", entity_id=cnf.id,
        action=AuditAction.create, after=serialize(cnf), actor_user_id=technician_user_id,
    )

    for use in parts or []:
        _consume_part(db, cnf, use, actor=technician_user_id)

    if is_final:
        before_op = serialize(op)
        op.status = OperationStatus.confirmed
        db.flush()
        record_audit(
            db, entity_type="operation", entity_id=op.id,
            action=AuditAction.status_change, before=before_op, after=serialize(op),
            actor_user_id=technician_user_id,
        )
        _maybe_auto_tech_complete(db, order, actor=technician_user_id)

    return cnf


def reverse_confirmation(
    db: Session,
    *,
    confirmation_id: UUID,
    reason: str,
    actor_user_id: UUID | None = None,
) -> Confirmation:
    original = db.get(Confirmation, confirmation_id)
    if original is None:
        raise ConfirmationError("Confirmation not found")
    if original.reversal_of_id is not None:
        raise ConfirmationError("Cannot reverse a reversal row")

    # Check this confirmation hasn't already been reversed.
    existing = db.scalar(
        select(Confirmation).where(Confirmation.reversal_of_id == confirmation_id)
    )
    if existing is not None:
        raise ConfirmationError("Confirmation has already been reversed")

    reversal = Confirmation(
        operation_id=original.operation_id,
        technician_user_id=actor_user_id,
        actual_hours=-original.actual_hours,
        is_final=False,
        notes=f"REVERSAL: {reason}",
        reversal_of_id=original.id,
    )
    db.add(reversal)
    db.flush()
    record_audit(
        db, entity_type="confirmation", entity_id=reversal.id,
        action=AuditAction.create, after=serialize(reversal),
        actor_user_id=actor_user_id,
    )

    # Restore any parts the original consumed.
    used_rows = list(
        db.scalars(
            select(ConfirmationPart).where(ConfirmationPart.confirmation_id == original.id)
        )
    )
    for row in used_rows:
        _restore_stock(db, row, actor=actor_user_id)

    # If the reversed row finalized the operation, walk it back to open
    # (provided no OTHER live final confirmation exists).
    if original.is_final:
        effective = _effective_confirmations(db, original.operation_id)
        if not any(c.is_final for c in effective):
            op = db.get(Operation, original.operation_id)
            before_op = serialize(op)
            op.status = OperationStatus.open
            db.flush()
            record_audit(
                db, entity_type="operation", entity_id=op.id,
                action=AuditAction.status_change, before=before_op, after=serialize(op),
                actor_user_id=actor_user_id,
            )

    return reversal


# --- helpers ---
def _consume_part(db: Session, cnf: Confirmation, use: PartUse, *, actor: UUID | None) -> None:
    if use.qty_used <= 0:
        raise ConfirmationError("qty_used must be positive")
    material = db.get(Material, use.material_id)
    if material is None:
        raise ConfirmationError("Material not found")
    if db.get(StockLocation, use.stock_location_id) is None:
        raise ConfirmationError("Stock location not found")

    quant = db.scalar(
        select(StockQuant).where(
            StockQuant.material_id == use.material_id,
            StockQuant.stock_location_id == use.stock_location_id,
        )
    )
    if quant is None or quant.qty < use.qty_used:
        raise ConfirmationError(
            f"Insufficient stock of {material.part_number} at this location"
        )

    quant.qty -= use.qty_used
    row = ConfirmationPart(
        confirmation_id=cnf.id,
        material_id=use.material_id,
        stock_location_id=use.stock_location_id,
        qty_used=use.qty_used,
        unit_cost_at_use=material.unit_cost,
    )
    db.add(row)
    db.flush()
    record_audit(
        db, entity_type="confirmation_part", entity_id=row.id,
        action=AuditAction.create, after=serialize(row), actor_user_id=actor,
    )


def _restore_stock(
    db: Session, used: ConfirmationPart, *, actor: UUID | None
) -> None:
    quant = db.scalar(
        select(StockQuant).where(
            StockQuant.material_id == used.material_id,
            StockQuant.stock_location_id == used.stock_location_id,
        )
    )
    if quant is None:
        quant = StockQuant(
            material_id=used.material_id, stock_location_id=used.stock_location_id, qty=0
        )
        db.add(quant)
        db.flush()
    quant.qty += used.qty_used
    record_audit(
        db, entity_type="stock_quant", entity_id=quant.id,
        action=AuditAction.update, after={"restored_qty": used.qty_used},
        actor_user_id=actor,
    )


def _maybe_auto_tech_complete(
    db: Session, order: WorkOrder, *, actor: UUID | None
) -> None:
    if order.status != OrderStatus.in_progress:
        return
    ops = list(db.scalars(select(Operation).where(Operation.work_order_id == order.id)))
    if not ops:
        return
    if all(o.status == OperationStatus.confirmed for o in ops):
        transition_work_order(db, order, OrderStatus.tech_complete, actor_user_id=actor)
