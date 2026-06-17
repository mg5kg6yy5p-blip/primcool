from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.deps import require_admin_or_dispatcher
from app.db.session import get_db
from app.models.billing import InvoiceDraft, InvoiceDraftLine
from app.schemas.billing import InvoiceDraftLineOut, InvoiceDraftOut
from app.services.billing import BillingError, generate_invoice_draft, issue_invoice

router = APIRouter(
    prefix="/api/v1", tags=["invoices"],
    dependencies=[Depends(require_admin_or_dispatcher)],
)


def _with_lines(db: Session, draft: InvoiceDraft) -> InvoiceDraftOut:
    lines = list(
        db.scalars(
            select(InvoiceDraftLine)
            .where(InvoiceDraftLine.invoice_draft_id == draft.id)
            .order_by(InvoiceDraftLine.kind)
        )
    )
    out = InvoiceDraftOut.model_validate(draft)
    out.lines = [InvoiceDraftLineOut.model_validate(line) for line in lines]
    return out


@router.post("/work-orders/{order_id}/invoice-draft",
             response_model=InvoiceDraftOut, status_code=201)
def make_draft(
    order_id: UUID, db: Annotated[Session, Depends(get_db)]
) -> InvoiceDraftOut:
    try:
        draft = generate_invoice_draft(db, order_id)
        db.commit()
    except BillingError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail=str(exc))
    db.refresh(draft)
    return _with_lines(db, draft)


@router.get("/work-orders/{order_id}/invoice-draft",
            response_model=InvoiceDraftOut)
def get_active_draft(
    order_id: UUID, db: Annotated[Session, Depends(get_db)]
) -> InvoiceDraftOut:
    """Latest non-void draft (or the issued one) for an order."""
    draft = db.scalar(
        select(InvoiceDraft)
        .where(InvoiceDraft.work_order_id == order_id,
               InvoiceDraft.status != "void")
        .order_by(InvoiceDraft.created_at.desc())
        .limit(1)
    )
    if draft is None:
        raise HTTPException(status_code=404, detail="No draft yet for this order")
    return _with_lines(db, draft)


@router.post("/invoices/{draft_id}/issue", response_model=InvoiceDraftOut)
def issue(
    draft_id: UUID, db: Annotated[Session, Depends(get_db)]
) -> InvoiceDraftOut:
    try:
        draft = issue_invoice(db, draft_id)
        db.commit()
    except BillingError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail=str(exc))
    db.refresh(draft)
    return _with_lines(db, draft)
