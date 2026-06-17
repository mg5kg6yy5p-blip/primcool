from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.deps import require_admin_or_dispatcher
from app.db.session import get_db
from app.models.customer import CustomerAccount, Site
from app.models.enums import AuditAction
from app.schemas.customer import SiteCreate, SiteOut, SiteUpdate
from app.services.audit import record_audit, serialize

router = APIRouter(
    prefix="/api/v1/sites", tags=["sites"],
    dependencies=[Depends(require_admin_or_dispatcher)],
)


@router.get("", response_model=list[SiteOut])
def list_sites(
    db: Annotated[Session, Depends(get_db)],
    customer_account_id: UUID | None = None,
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
) -> list[Site]:
    stmt = select(Site).order_by(Site.name)
    if customer_account_id is not None:
        stmt = stmt.where(Site.customer_account_id == customer_account_id)
    return list(db.scalars(stmt.offset(skip).limit(limit)))


@router.post("", response_model=SiteOut, status_code=201)
def create_site(payload: SiteCreate, db: Annotated[Session, Depends(get_db)]) -> Site:
    if db.get(CustomerAccount, payload.customer_account_id) is None:
        raise HTTPException(status_code=422, detail="customer_account_id does not exist")
    row = Site(**payload.model_dump())
    db.add(row)
    db.flush()
    record_audit(
        db, entity_type="site", entity_id=row.id, action=AuditAction.create, after=serialize(row)
    )
    db.commit()
    db.refresh(row)
    return row


@router.get("/{site_id}", response_model=SiteOut)
def get_site(site_id: UUID, db: Annotated[Session, Depends(get_db)]) -> Site:
    row = db.get(Site, site_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Site not found")
    return row


@router.patch("/{site_id}", response_model=SiteOut)
def update_site(
    site_id: UUID, payload: SiteUpdate, db: Annotated[Session, Depends(get_db)]
) -> Site:
    row = db.get(Site, site_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Site not found")
    before = serialize(row)
    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(row, field, value)
    db.flush()
    record_audit(
        db, entity_type="site", entity_id=row.id, action=AuditAction.update,
        before=before, after=serialize(row),
    )
    db.commit()
    db.refresh(row)
    return row
