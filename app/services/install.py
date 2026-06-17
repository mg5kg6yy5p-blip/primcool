"""Equipment install / remove — the temporal swap.

Removing sets removed_at on the active install; installing creates a new row.
The partial unique indexes (uq_active_install_per_fl,
uq_active_install_per_equipment) are the referee: an illegal second active
install raises IntegrityError, which the router surfaces as a friendly 409.
"""
from datetime import datetime
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.asset import Equipment, EquipmentInstall, FunctionalLocation
from app.models.common import utcnow
from app.models.enums import AuditAction, EquipmentStatus
from app.services.audit import record_audit, serialize


class InstallError(Exception):
    """Raised for domain-level install/remove violations."""


def active_install_for_equipment(db: Session, equipment_id: UUID) -> EquipmentInstall | None:
    return db.scalar(
        select(EquipmentInstall).where(
            EquipmentInstall.equipment_id == equipment_id,
            EquipmentInstall.removed_at.is_(None),
        )
    )


def active_install_for_fl(db: Session, fl_id: UUID) -> EquipmentInstall | None:
    return db.scalar(
        select(EquipmentInstall).where(
            EquipmentInstall.functional_location_id == fl_id,
            EquipmentInstall.removed_at.is_(None),
        )
    )


def install_equipment(
    db: Session,
    *,
    equipment_id: UUID,
    fl_id: UUID,
    installed_at: datetime | None = None,
    installed_by_user_id: UUID | None = None,
) -> EquipmentInstall:
    equipment = db.get(Equipment, equipment_id)
    if equipment is None:
        raise InstallError("Equipment not found")
    fl = db.get(FunctionalLocation, fl_id)
    if fl is None:
        raise InstallError("Functional location not found")

    install = EquipmentInstall(
        equipment_id=equipment_id,
        functional_location_id=fl_id,
        installed_at=installed_at or utcnow(),
        installed_by_user_id=installed_by_user_id,
    )
    db.add(install)

    before = serialize(equipment)
    equipment.status = EquipmentStatus.installed
    db.flush()  # trip the partial unique indexes now, inside the txn

    record_audit(
        db,
        entity_type="equipment_install",
        entity_id=install.id,
        action=AuditAction.install,
        after=serialize(install),
        actor_user_id=installed_by_user_id,
    )
    record_audit(
        db,
        entity_type="equipment",
        entity_id=equipment.id,
        action=AuditAction.status_change,
        before=before,
        after=serialize(equipment),
        actor_user_id=installed_by_user_id,
    )
    return install


def remove_equipment(
    db: Session,
    *,
    equipment_id: UUID,
    removed_at: datetime | None = None,
    new_status: EquipmentStatus = EquipmentStatus.in_storage,
    actor_user_id: UUID | None = None,
) -> EquipmentInstall:
    install = active_install_for_equipment(db, equipment_id)
    if install is None:
        raise InstallError("Equipment has no active install")

    before_install = serialize(install)
    install.removed_at = removed_at or utcnow()

    equipment = db.get(Equipment, equipment_id)
    before_eq = serialize(equipment)
    equipment.status = new_status
    db.flush()

    record_audit(
        db,
        entity_type="equipment_install",
        entity_id=install.id,
        action=AuditAction.remove,
        before=before_install,
        after=serialize(install),
        actor_user_id=actor_user_id,
    )
    record_audit(
        db,
        entity_type="equipment",
        entity_id=equipment.id,
        action=AuditAction.status_change,
        before=before_eq,
        after=serialize(equipment),
        actor_user_id=actor_user_id,
    )
    return install
