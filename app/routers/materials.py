from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.deps import require_admin_or_dispatcher
from app.db.session import get_db
from app.models.enums import AuditAction
from app.models.inventory import Material, StockLocation, StockQuant
from app.schemas.inventory import (
    MaterialCreate,
    MaterialOut,
    StockLocationCreate,
    StockLocationOut,
    StockQuantOut,
    StockQuantSet,
    WhereUsedRow,
)
from app.services.audit import record_audit, serialize

router = APIRouter(
    prefix="/api/v1", tags=["inventory"],
    dependencies=[Depends(require_admin_or_dispatcher)],
)


# --- materials ---
@router.get("/materials", response_model=list[MaterialOut])
def list_materials(db: Annotated[Session, Depends(get_db)]) -> list[Material]:
    return list(db.scalars(select(Material).order_by(Material.part_number)))


@router.post("/materials", response_model=MaterialOut, status_code=201)
def create_material(
    payload: MaterialCreate, db: Annotated[Session, Depends(get_db)]
) -> Material:
    row = Material(**payload.model_dump())
    db.add(row)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="part_number already exists")
    record_audit(
        db, entity_type="material", entity_id=row.id, action=AuditAction.create,
        after=serialize(row),
    )
    db.commit()
    db.refresh(row)
    return row


@router.get("/materials/{material_id}/where-used", response_model=list[WhereUsedRow])
def where_used(
    material_id: UUID, db: Annotated[Session, Depends(get_db)]
) -> list[WhereUsedRow]:
    """Equipment whose BOM lists this material. BOM lands fully in Phase 5;
    until then this endpoint returns an empty list and exists so the API
    shape stays stable."""
    if db.get(Material, material_id) is None:
        raise HTTPException(status_code=404, detail="Material not found")
    return []


# --- stock locations ---
@router.get("/stock-locations", response_model=list[StockLocationOut])
def list_stock_locations(db: Annotated[Session, Depends(get_db)]) -> list[StockLocation]:
    return list(db.scalars(select(StockLocation).order_by(StockLocation.name)))


@router.post("/stock-locations", response_model=StockLocationOut, status_code=201)
def create_stock_location(
    payload: StockLocationCreate, db: Annotated[Session, Depends(get_db)]
) -> StockLocation:
    row = StockLocation(**payload.model_dump())
    db.add(row)
    db.flush()
    record_audit(
        db, entity_type="stock_location", entity_id=row.id, action=AuditAction.create,
        after=serialize(row),
    )
    db.commit()
    db.refresh(row)
    return row


# --- stock quants ---
@router.get("/stock", response_model=list[StockQuantOut])
def list_stock(
    db: Annotated[Session, Depends(get_db)],
    stock_location_id: UUID | None = None,
    material_id: UUID | None = None,
) -> list[StockQuant]:
    stmt = select(StockQuant)
    if stock_location_id is not None:
        stmt = stmt.where(StockQuant.stock_location_id == stock_location_id)
    if material_id is not None:
        stmt = stmt.where(StockQuant.material_id == material_id)
    return list(db.scalars(stmt))


@router.put("/stock", response_model=StockQuantOut)
def set_stock(
    payload: StockQuantSet, db: Annotated[Session, Depends(get_db)]
) -> StockQuant:
    if db.get(Material, payload.material_id) is None:
        raise HTTPException(status_code=422, detail="material_id does not exist")
    if db.get(StockLocation, payload.stock_location_id) is None:
        raise HTTPException(status_code=422, detail="stock_location_id does not exist")
    quant = db.scalar(
        select(StockQuant).where(
            StockQuant.material_id == payload.material_id,
            StockQuant.stock_location_id == payload.stock_location_id,
        )
    )
    if quant is None:
        quant = StockQuant(
            material_id=payload.material_id,
            stock_location_id=payload.stock_location_id,
            qty=payload.qty,
        )
        db.add(quant)
        action = AuditAction.create
    else:
        quant.qty = payload.qty
        action = AuditAction.update
    db.flush()
    record_audit(
        db, entity_type="stock_quant", entity_id=quant.id,
        action=action, after=serialize(quant),
    )
    db.commit()
    db.refresh(quant)
    return quant
