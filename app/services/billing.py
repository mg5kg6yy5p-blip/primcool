"""Invoice-draft generator.

Resolves the effective billing class (warranty > contract > whatever the
order had), then emits an invoice_draft + lines:

  * warranty | contract | goodwill : labor + parts at unit_amount=0, captured
    so the customer sees what was done. Contract decrements the per-year
    entitlement counter.
  * billable : labor = Σ confirmation.actual_hours × per-role hourly rate,
               parts = Σ qty_used × unit_cost_at_use × PARTS_MARKUP.

Reversed confirmations and their parts are excluded automatically.

A draft is regenerable until issued — calling this again voids any
draft-status draft for the same work order and writes a fresh one.
"""
import os
from datetime import date, datetime, timezone
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.asset import Equipment, EquipmentInstall
from app.models.billing import (
    BillingRate,
    InvoiceDraft,
    InvoiceDraftLine,
    ServiceContract,
)
from app.models.common import add_months, utcnow
from app.models.customer import CustomerAccount
from app.models.enums import (
    AuditAction,
    BillingClass,
    ContractStatus,
    InvoiceStatus,
    LineKind,
    OrderStatus,
    OrderType,
)
from app.models.inventory import Confirmation, ConfirmationPart, Material
from app.models.pm import PmSchedule
from app.models.user import User
from app.models.workflow import Operation, WorkOrder
from app.services.audit import record_audit, serialize


PARTS_MARKUP = float(os.environ.get("PARTS_MARKUP", "1.5"))


class BillingError(Exception):
    """Raised on a domain-level billing problem (wrong status, missing data)."""


# --- helpers ---
def _aware(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt


def _live_confirmations(db: Session, work_order_id: UUID) -> list[Confirmation]:
    """All non-reversed, non-reversal confirmations for an order's operations."""
    op_ids = [
        op.id for op in db.scalars(
            select(Operation).where(Operation.work_order_id == work_order_id)
        )
    ]
    if not op_ids:
        return []
    rows = list(
        db.scalars(select(Confirmation).where(Confirmation.operation_id.in_(op_ids)))
    )
    reversed_ids = {r.reversal_of_id for r in rows if r.reversal_of_id is not None}
    return [r for r in rows if r.id not in reversed_ids and r.reversal_of_id is None]


def _live_parts(db: Session, work_order_id: UUID) -> list[ConfirmationPart]:
    live = _live_confirmations(db, work_order_id)
    if not live:
        return []
    cnf_ids = [c.id for c in live]
    return list(
        db.scalars(
            select(ConfirmationPart).where(ConfirmationPart.confirmation_id.in_(cnf_ids))
        )
    )


def _equipment_under_warranty_at(
    db: Session, equipment_id: UUID, when: datetime
) -> bool:
    eq = db.get(Equipment, equipment_id)
    if eq is None or not eq.warranty_months:
        return False
    install = db.scalar(
        select(EquipmentInstall).where(
            EquipmentInstall.equipment_id == equipment_id,
            EquipmentInstall.installed_at <= when,
        ).order_by(EquipmentInstall.installed_at.desc()).limit(1)
    )
    if install is None:
        return False
    installed_at = _aware(install.installed_at) or install.installed_at
    when_aware = _aware(when) or when
    return when_aware <= add_months(installed_at, eq.warranty_months)


def _active_contract_for_pm(
    db: Session, schedule: PmSchedule, when: datetime
) -> ServiceContract | None:
    if schedule.service_contract_id is None:
        return None
    contract = db.get(ServiceContract, schedule.service_contract_id)
    if contract is None or contract.status != ContractStatus.active:
        return None
    d = (when.date() if isinstance(when, datetime) else when)
    if not (contract.starts_on <= d <= contract.ends_on):
        return None
    return contract


def _contract_usage_this_year(
    db: Session, contract_id: UUID, year: int, exclude_draft_id: UUID | None = None,
) -> int:
    """Count non-void invoice drafts in this calendar year billed against the
    contract. Voided drafts free up entitlement (regenerable property)."""
    stmt = select(InvoiceDraft).where(
        InvoiceDraft.billing_class == BillingClass.contract,
        InvoiceDraft.status != InvoiceStatus.void,
    )
    if exclude_draft_id is not None:
        stmt = stmt.where(InvoiceDraft.id != exclude_draft_id)
    n = 0
    for draft in db.scalars(stmt):
        order = db.get(WorkOrder, draft.work_order_id)
        if order is None or order.pm_schedule_id is None:
            continue
        sched = db.get(PmSchedule, order.pm_schedule_id)
        if sched is None or sched.service_contract_id != contract_id:
            continue
        when = _aware(draft.created_at) or utcnow()
        if when.year == year:
            n += 1
    return n


def _rate_for(db: Session, user_id: UUID | None) -> tuple[float, str]:
    if user_id is None:
        return (0.0, "JMD")
    user = db.get(User, user_id)
    if user is None:
        return (0.0, "JMD")
    rate = db.scalar(
        select(BillingRate).where(
            BillingRate.role == user.role, BillingRate.is_active.is_(True)
        )
    )
    return (rate.hourly_amount if rate else 0.0, rate.currency if rate else "JMD")


def _resolve_billing_class(db: Session, order: WorkOrder) -> BillingClass:
    when = _aware(order.created_at) or utcnow()
    if order.equipment_id and _equipment_under_warranty_at(db, order.equipment_id, when):
        return BillingClass.warranty
    if order.order_type == OrderType.preventive and order.pm_schedule_id:
        sched = db.get(PmSchedule, order.pm_schedule_id)
        if sched:
            contract = _active_contract_for_pm(db, sched, when)
            if contract is not None:
                used = _contract_usage_this_year(db, contract.id, when.year)
                if used < contract.included_pm_visits_per_year:
                    return BillingClass.contract
    return order.billing_class


# --- public API ---
def generate_invoice_draft(db: Session, work_order_id: UUID) -> InvoiceDraft:
    order = db.get(WorkOrder, work_order_id)
    if order is None:
        raise BillingError("Work order not found")
    if order.status not in (OrderStatus.tech_complete, OrderStatus.closed):
        raise BillingError(
            f"Invoice can only be generated for tech_complete or closed orders "
            f"(current: {order.status.value})"
        )

    # Void any prior draft for this order so it stays regenerable.
    for old in db.scalars(
        select(InvoiceDraft).where(
            InvoiceDraft.work_order_id == work_order_id,
            InvoiceDraft.status == InvoiceStatus.draft,
        )
    ):
        old.status = InvoiceStatus.void
        record_audit(
            db, entity_type="invoice_draft", entity_id=old.id,
            action=AuditAction.status_change, after={"status": "void"},
        )

    customer = db.get(CustomerAccount, order.customer_account_id)
    currency = customer.billing_currency if customer else "JMD"
    gct_rate = customer.gct_rate if customer else 0.0
    billing_class = _resolve_billing_class(db, order)

    draft = InvoiceDraft(
        work_order_id=work_order_id,
        customer_account_id=order.customer_account_id,
        billing_class=billing_class,
        currency=currency,
        gct_rate=gct_rate,
    )
    db.add(draft)
    db.flush()

    lines: list[InvoiceDraftLine] = []
    live_cnfs = _live_confirmations(db, work_order_id)
    live_parts = _live_parts(db, work_order_id)

    zero_charge = billing_class in (
        BillingClass.warranty, BillingClass.contract, BillingClass.goodwill,
    )

    # Labor lines
    for cnf in live_cnfs:
        if cnf.actual_hours <= 0:
            continue
        if zero_charge:
            rate, _ = 0.0, currency
        else:
            rate, _ = _rate_for(db, cnf.technician_user_id)
        line_total = cnf.actual_hours * rate
        lines.append(InvoiceDraftLine(
            invoice_draft_id=draft.id,
            kind=LineKind.labor,
            description=f"Labor — {cnf.actual_hours:g}h",
            qty=cnf.actual_hours,
            unit_amount=rate,
            total=line_total,
            source_confirmation_id=cnf.id,
        ))

    # Part lines
    for part in live_parts:
        material = db.get(Material, part.material_id)
        desc = material.part_number if material else "part"
        if zero_charge:
            unit = 0.0
        else:
            unit = part.unit_cost_at_use * PARTS_MARKUP
        line_total = part.qty_used * unit
        lines.append(InvoiceDraftLine(
            invoice_draft_id=draft.id,
            kind=LineKind.part,
            description=f"Part — {desc}",
            qty=part.qty_used,
            unit_amount=unit,
            total=line_total,
            source_part_id=part.id,
        ))

    subtotal = sum(line.total for line in lines)
    gct_amount = round(subtotal * gct_rate / 100, 2) if gct_rate > 0 else 0.0

    if gct_amount > 0:
        lines.append(InvoiceDraftLine(
            invoice_draft_id=draft.id,
            kind=LineKind.tax,
            description=f"GCT @ {gct_rate}%",
            qty=1, unit_amount=gct_amount, total=gct_amount,
        ))

    db.add_all(lines)
    draft.subtotal = subtotal
    draft.gct_amount = gct_amount
    draft.total = subtotal + gct_amount

    db.flush()
    record_audit(
        db, entity_type="invoice_draft", entity_id=draft.id,
        action=AuditAction.create, after=serialize(draft),
    )
    return draft


def issue_invoice(db: Session, draft_id: UUID) -> InvoiceDraft:
    draft = db.get(InvoiceDraft, draft_id)
    if draft is None:
        raise BillingError("Invoice draft not found")
    if draft.status != InvoiceStatus.draft:
        raise BillingError(f"Cannot issue an invoice in status {draft.status.value}")
    before = serialize(draft)
    draft.status = InvoiceStatus.issued
    draft.issued_at = utcnow()
    db.flush()
    record_audit(
        db, entity_type="invoice_draft", entity_id=draft.id,
        action=AuditAction.status_change, before=before, after=serialize(draft),
    )
    return draft
