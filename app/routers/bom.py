from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.deps import require_admin_or_dispatcher
from app.db.session import get_db
from app.models.asset import Equipment
from app.models.billing import BomItem, EquipmentBom
from app.models.enums import AuditAction
from app.models.inventory import Material
from app.schemas.billing import (
    BomItemOut,
    EquipmentBomOut,
    EquipmentBomReplace,
)
from app.services.audit import record_audit, serialize

router = APIRouter(
    prefix="/api/v1", tags=["bom"],
    dependencies=[Depends(require_admin_or_dispatcher)],
)


def _bom_with_items(db: Session, bom: EquipmentBom) -> EquipmentBomOut:
    items = list(db.scalars(select(BomItem).where(BomItem.equipment_bom_id == bom.id)))
    out = EquipmentBomOut.model_validate(bom)
    out.items = [BomItemOut.model_validate(i) for i in items]
    return out


@router.get("/equipment/{equipment_id}/bom", response_model=EquipmentBomOut)
def get_bom(
    equipment_id: UUID, db: Annotated[Session, Depends(get_db)]
) -> EquipmentBomOut:
    if db.get(Equipment, equipment_id) is None:
        raise HTTPException(status_code=404, detail="Equipment not found")
    bom = db.scalar(select(EquipmentBom).where(EquipmentBom.equipment_id == equipment_id))
    if bom is None:
        # Return an empty BOM so the UI can render "no parts yet".
        return EquipmentBomOut(
            id=UUID("00000000-0000-0000-0000-000000000000"),
            equipment_id=equipment_id, items=[],
        )
    return _bom_with_items(db, bom)


@router.put("/equipment/{equipment_id}/bom", response_model=EquipmentBomOut)
def replace_bom(
    equipment_id: UUID,
    payload: EquipmentBomReplace,
    db: Annotated[Session, Depends(get_db)],
) -> EquipmentBomOut:
    if db.get(Equipment, equipment_id) is None:
        raise HTTPException(status_code=404, detail="Equipment not found")
    for item in payload.items:
        if db.get(Material, item.material_id) is None:
            raise HTTPException(
                status_code=422, detail=f"Material {item.material_id} not found"
            )

    bom = db.scalar(select(EquipmentBom).where(EquipmentBom.equipment_id == equipment_id))
    if bom is None:
        bom = EquipmentBom(equipment_id=equipment_id)
        db.add(bom)
        db.flush()
        record_audit(
            db, entity_type="equipment_bom", entity_id=bom.id,
            action=AuditAction.create, after=serialize(bom),
        )

    # Replace items wholesale.
    for old in db.scalars(select(BomItem).where(BomItem.equipment_bom_id == bom.id)):
        db.delete(old)
    db.flush()
    for item in payload.items:
        db.add(BomItem(
            equipment_bom_id=bom.id,
            material_id=item.material_id,
            quantity=item.quantity,
        ))
    db.flush()
    record_audit(
        db, entity_type="equipment_bom", entity_id=bom.id,
        action=AuditAction.update, after={"item_count": len(payload.items)},
    )
    db.commit()
    return _bom_with_items(db, bom)
