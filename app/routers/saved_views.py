from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models.enums import AuditAction
from app.models.workflow import SavedView
from app.schemas.workflow import SavedViewCreate, SavedViewOut
from app.services.audit import record_audit, serialize

router = APIRouter(prefix="/api/v1/saved-views", tags=["saved_views"])


@router.get("", response_model=list[SavedViewOut])
def list_saved_views(
    db: Annotated[Session, Depends(get_db)],
    user_id: UUID | None = None,
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
) -> list[SavedView]:
    stmt = select(SavedView).order_by(SavedView.name)
    if user_id is not None:
        stmt = stmt.where(SavedView.user_id == user_id)
    return list(db.scalars(stmt.offset(skip).limit(limit)))


@router.post("", response_model=SavedViewOut, status_code=201)
def create_saved_view(
    payload: SavedViewCreate, db: Annotated[Session, Depends(get_db)]
) -> SavedView:
    row = SavedView(entity="work_order_list", **payload.model_dump())
    db.add(row)
    db.flush()
    record_audit(
        db, entity_type="saved_view", entity_id=row.id, action=AuditAction.create,
        after=serialize(row),
    )
    db.commit()
    db.refresh(row)
    return row


@router.get("/{view_id}", response_model=SavedViewOut)
def get_saved_view(view_id: UUID, db: Annotated[Session, Depends(get_db)]) -> SavedView:
    row = db.get(SavedView, view_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Saved view not found")
    return row
