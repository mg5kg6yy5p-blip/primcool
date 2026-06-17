from datetime import datetime, timezone
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.deps import require_admin_or_dispatcher
from app.db.session import get_db
from app.models.billing import ContractSite, ServiceContract
from app.models.enums import AuditAction
from app.models.pm import PmSchedule
from app.models.workflow import WorkOrder
from app.schemas.billing import (
    ServiceContractCreate,
    ServiceContractOut,
    ServiceContractUpdate,
)
from app.services.audit import record_audit, serialize
from app.services.billing import _contract_usage_this_year

router = APIRouter(
    prefix="/api/v1/contracts", tags=["contracts"],
    dependencies=[Depends(require_admin_or_dispatcher)],
)


def _to_out(db: Session, contract: ServiceContract) -> ServiceContractOut:
    site_ids = [
        cs.site_id for cs in db.scalars(
            select(ContractSite).where(ContractSite.service_contract_id == contract.id)
        )
    ]
    used = _contract_usage_this_year(
        db, contract.id, datetime.now(timezone.utc).year
    )
    out = ServiceContractOut.model_validate(contract)
    out.site_ids = site_ids
    out.used_this_year = used
    return out


@router.get("", response_model=list[ServiceContractOut])
def list_contracts(
    db: Annotated[Session, Depends(get_db)],
    customer_account_id: UUID | None = None,
) -> list[ServiceContractOut]:
    stmt = select(ServiceContract).order_by(ServiceContract.name)
    if customer_account_id is not None:
        stmt = stmt.where(ServiceContract.customer_account_id == customer_account_id)
    return [_to_out(db, c) for c in db.scalars(stmt)]


@router.post("", response_model=ServiceContractOut, status_code=201)
def create_contract(
    payload: ServiceContractCreate, db: Annotated[Session, Depends(get_db)]
) -> ServiceContractOut:
    contract = ServiceContract(
        customer_account_id=payload.customer_account_id,
        name=payload.name,
        starts_on=payload.starts_on,
        ends_on=payload.ends_on,
        included_pm_visits_per_year=payload.included_pm_visits_per_year,
        response_sla=payload.response_sla,
        terms_notes=payload.terms_notes,
    )
    db.add(contract)
    db.flush()
    for site_id in payload.site_ids:
        db.add(ContractSite(service_contract_id=contract.id, site_id=site_id))
    db.flush()
    record_audit(
        db, entity_type="service_contract", entity_id=contract.id,
        action=AuditAction.create, after=serialize(contract),
    )
    db.commit()
    db.refresh(contract)
    return _to_out(db, contract)


@router.get("/{contract_id}", response_model=ServiceContractOut)
def get_contract(
    contract_id: UUID, db: Annotated[Session, Depends(get_db)]
) -> ServiceContractOut:
    contract = db.get(ServiceContract, contract_id)
    if contract is None:
        raise HTTPException(status_code=404, detail="Contract not found")
    return _to_out(db, contract)


@router.patch("/{contract_id}", response_model=ServiceContractOut)
def update_contract(
    contract_id: UUID,
    payload: ServiceContractUpdate,
    db: Annotated[Session, Depends(get_db)],
) -> ServiceContractOut:
    contract = db.get(ServiceContract, contract_id)
    if contract is None:
        raise HTTPException(status_code=404, detail="Contract not found")
    before = serialize(contract)
    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(contract, field, value)
    db.flush()
    record_audit(
        db, entity_type="service_contract", entity_id=contract.id,
        action=AuditAction.update, before=before, after=serialize(contract),
    )
    db.commit()
    db.refresh(contract)
    return _to_out(db, contract)
