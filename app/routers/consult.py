import html
import secrets
from typing import Annotated

import resend as resend_lib
from fastapi import APIRouter, Depends, Header, HTTPException, Request
from sqlalchemy.orm import Session

from app.core.config import Settings, get_settings
from app.core.rate_limit import limiter
from app.db.session import get_db
from app.models import ConsultSubmission
from app.schemas.consult import (
    ConsultRequest,
    ConsultResponse,
    ConsultSubmissionList,
    ConsultSubmissionOut,
)

router = APIRouter(tags=["consult"])

TIER_LABELS = {
    "residential": "Residential — Home & Property",
    "commercial":  "Commercial — SME & Corporate",
    "industrial":  "Industrial — Process & Facility",
    "unsure":      "Not sure — need an assessment",
}


def _send_notification_email(req: ConsultRequest, settings: Settings) -> None:
    if not settings.resend_api_key or not settings.notify_email:
        return

    resend_lib.api_key = settings.resend_api_key
    tier_label = TIER_LABELS.get(req.tier, req.tier)
    e = html.escape

    msg_block = (
        f"<div style='margin-top:16px;padding:16px;background:#f5f7f9;"
        f"border-left:3px solid #22A08A;'>"
        f"<p style='margin:0 0 8px;color:#5A6472;font-size:12px;"
        f"text-transform:uppercase;letter-spacing:1px;'>Equipment / Facility Details</p>"
        f"<p style='margin:0;font-size:14px;'>{e(req.msg)}</p></div>"
        if req.msg else ""
    )

    body = f"""
    <div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;">
      <div style="background:#0B2545;padding:24px;color:white;">
        <h2 style="margin:0;color:#22A08A;">New Consultation Request</h2>
        <p style="margin:4px 0 0;color:#5A6472;font-size:13px;">PrimeCool Services Ltd.</p>
      </div>
      <div style="padding:24px;border:1px solid #e8ecf0;">
        <table style="width:100%;border-collapse:collapse;font-size:14px;">
          <tr><td style="padding:8px 0;color:#5A6472;width:140px;">Name</td>
              <td style="padding:8px 0;"><strong>{e(req.fname)} {e(req.lname)}</strong></td></tr>
          <tr><td style="padding:8px 0;color:#5A6472;">Email</td>
              <td style="padding:8px 0;"><a href="mailto:{e(req.email)}">{e(req.email)}</a></td></tr>
          <tr><td style="padding:8px 0;color:#5A6472;">Phone</td>
              <td style="padding:8px 0;">{e(req.phone) if req.phone else "—"}</td></tr>
          <tr><td style="padding:8px 0;color:#5A6472;">Company</td>
              <td style="padding:8px 0;">{e(req.company) if req.company else "—"}</td></tr>
          <tr><td style="padding:8px 0;color:#5A6472;">Service Tier</td>
              <td style="padding:8px 0;"><strong style="color:#22A08A;">{e(tier_label)}</strong></td></tr>
        </table>
        {msg_block}
      </div>
      <div style="padding:16px 24px;background:#f5f7f9;font-size:12px;color:#5A6472;">
        Submitted via primecoolservices.com
      </div>
    </div>
    """

    try:
        resend_lib.Emails.send({
            "from":    "PrimeCool Services <onboarding@resend.dev>",
            "to":      settings.notify_email,
            "subject": f"New Consultation Request — {req.fname} {req.lname} ({tier_label})",
            "html":    body,
        })
    except Exception as exc:
        print(f"EMAIL ERROR: {exc}")


@router.post("/api/consult", response_model=ConsultResponse)
@limiter.limit("5/hour")
def submit_consult(
    request: Request,
    req: ConsultRequest,
    db: Annotated[Session, Depends(get_db)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> ConsultResponse:
    row = ConsultSubmission(**req.model_dump())
    db.add(row)
    db.commit()

    _send_notification_email(req, settings)
    return ConsultResponse(ok=True)


@router.get("/api/submissions", response_model=ConsultSubmissionList)
def list_submissions(
    db: Annotated[Session, Depends(get_db)],
    settings: Annotated[Settings, Depends(get_settings)],
    authorization: Annotated[str, Header()] = "",
) -> ConsultSubmissionList:
    if not settings.admin_token:
        raise HTTPException(status_code=503, detail="Admin endpoint not configured")

    expected = f"Bearer {settings.admin_token}"
    if not secrets.compare_digest(authorization, expected):
        raise HTTPException(status_code=401, detail="Unauthorized")

    rows = (
        db.query(ConsultSubmission)
        .order_by(ConsultSubmission.created_at.desc())
        .all()
    )
    return ConsultSubmissionList(
        submissions=[ConsultSubmissionOut.from_model(r) for r in rows]
    )
