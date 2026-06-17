"""Notification and work-order lifecycle.

All status changes go through these functions; the routers never set `status`
directly. Illegal transitions raise TransitionError (-> 409 at the edge).
"""
from uuid import UUID

from sqlalchemy.orm import Session

from app.models.common import utcnow
from app.models.enums import (
    AuditAction,
    NotificationStatus,
    OrderStatus,
    OrderType,
)
from app.models.workflow import Notification, WorkOrder
from app.services.audit import record_audit, serialize


class TransitionError(Exception):
    """Raised on an illegal lifecycle transition."""


# --- Work-order state machine -------------------------------------------------
# created -> scheduled -> in_progress -> tech_complete -> closed
# cancelled reachable from created/scheduled only; no backward moves;
# closed and cancelled are terminal.
WORK_ORDER_TRANSITIONS: dict[OrderStatus, set[OrderStatus]] = {
    OrderStatus.created: {OrderStatus.scheduled, OrderStatus.cancelled},
    OrderStatus.scheduled: {OrderStatus.in_progress, OrderStatus.cancelled},
    OrderStatus.in_progress: {OrderStatus.tech_complete},
    OrderStatus.tech_complete: {OrderStatus.closed},
    OrderStatus.closed: set(),
    OrderStatus.cancelled: set(),
}


def legal_work_order_targets(status: OrderStatus) -> set[OrderStatus]:
    return WORK_ORDER_TRANSITIONS[status]


def transition_work_order(
    db: Session, order: WorkOrder, target: OrderStatus, actor_user_id: UUID | None = None
) -> WorkOrder:
    if target not in WORK_ORDER_TRANSITIONS[order.status]:
        raise TransitionError(
            f"Cannot move work order from {order.status.value} to {target.value}"
        )
    before = serialize(order)
    order.status = target
    if target == OrderStatus.closed:
        order.closed_at = utcnow()
    db.flush()
    record_audit(
        db, entity_type="work_order", entity_id=order.id,
        action=AuditAction.status_change, before=before, after=serialize(order),
        actor_user_id=actor_user_id,
    )
    if target == OrderStatus.closed and order.pm_schedule_id is not None:
        # Lazy import — pm imports workflow's transition function.
        from app.services.pm import on_pm_order_closed
        on_pm_order_closed(db, order)
    return order


# --- Notification lifecycle ---------------------------------------------------
# new -> acknowledged -> converted | closed_no_action
def acknowledge_notification(
    db: Session, notif: Notification, actor_user_id: UUID | None = None
) -> Notification:
    if notif.status != NotificationStatus.new:
        raise TransitionError("Only a new notification can be acknowledged")
    before = serialize(notif)
    notif.status = NotificationStatus.acknowledged
    notif.acknowledged_at = utcnow()
    db.flush()
    record_audit(
        db, entity_type="notification", entity_id=notif.id,
        action=AuditAction.status_change, before=before, after=serialize(notif),
        actor_user_id=actor_user_id,
    )
    return notif


def close_notification_no_action(
    db: Session, notif: Notification, reason: str, actor_user_id: UUID | None = None
) -> Notification:
    if notif.status in (NotificationStatus.converted, NotificationStatus.closed_no_action):
        raise TransitionError("Notification is already terminal")
    before = serialize(notif)
    notif.status = NotificationStatus.closed_no_action
    notif.closed_at = utcnow()
    db.flush()
    after = serialize(notif)
    after["close_reason"] = reason  # captured in the audit record
    record_audit(
        db, entity_type="notification", entity_id=notif.id,
        action=AuditAction.status_change, before=before, after=after,
        actor_user_id=actor_user_id,
    )
    return notif


def convert_notification_to_order(
    db: Session, notif: Notification, actor_user_id: UUID | None = None
) -> WorkOrder:
    if notif.status in (NotificationStatus.converted, NotificationStatus.closed_no_action):
        raise TransitionError("Notification is already terminal")

    # Copy site/space/severity -> priority onto the new corrective order.
    order = WorkOrder(
        notification_id=notif.id,
        customer_account_id=notif.customer_account_id,
        site_id=notif.site_id,
        order_type=OrderType.corrective,
        priority=notif.severity,
        title=notif.title,
        description=notif.description,
        status=OrderStatus.created,
    )
    db.add(order)

    before = serialize(notif)
    notif.status = NotificationStatus.converted
    db.flush()

    record_audit(
        db, entity_type="work_order", entity_id=order.id,
        action=AuditAction.create, after=serialize(order), actor_user_id=actor_user_id,
    )
    record_audit(
        db, entity_type="notification", entity_id=notif.id,
        action=AuditAction.status_change, before=before, after=serialize(notif),
        actor_user_id=actor_user_id,
    )
    return order
