from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel
import os
import resend as resend_lib

from database import init_db, save_submission

TIER_LABELS = {
    "residential": "Residential — Home & Property",
    "commercial":  "Commercial — SME & Corporate",
    "industrial":  "Industrial — Process & Facility",
    "unsure":      "Not sure — need an assessment",
}


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


class ConsultRequest(BaseModel):
    fname:   str
    lname:   str
    email:   str
    phone:   str = ""
    company: str = ""
    tier:    str
    msg:     str = ""


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/api/consult")
async def submit_consult(req: ConsultRequest):
    save_submission(req.model_dump())

    api_key      = os.environ.get("RESEND_API_KEY")
    notify_email = os.environ.get("NOTIFY_EMAIL", "rjuggar@aol.com")

    if api_key:
        resend_lib.api_key = api_key
        tier_label = TIER_LABELS.get(req.tier, req.tier)

        msg_block = (
            f"<div style='margin-top:16px;padding:16px;background:#f5f7f9;"
            f"border-left:3px solid #22A08A;'>"
            f"<p style='margin:0 0 8px;color:#5A6472;font-size:12px;"
            f"text-transform:uppercase;letter-spacing:1px;'>Equipment / Facility Details</p>"
            f"<p style='margin:0;font-size:14px;'>{req.msg}</p></div>"
            if req.msg else ""
        )

        html = f"""
        <div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;">
          <div style="background:#0B2545;padding:24px;color:white;">
            <h2 style="margin:0;color:#22A08A;">New Consultation Request</h2>
            <p style="margin:4px 0 0;color:#5A6472;font-size:13px;">PrimeCool Services Ltd.</p>
          </div>
          <div style="padding:24px;border:1px solid #e8ecf0;">
            <table style="width:100%;border-collapse:collapse;font-size:14px;">
              <tr><td style="padding:8px 0;color:#5A6472;width:140px;">Name</td>
                  <td style="padding:8px 0;"><strong>{req.fname} {req.lname}</strong></td></tr>
              <tr><td style="padding:8px 0;color:#5A6472;">Email</td>
                  <td style="padding:8px 0;"><a href="mailto:{req.email}">{req.email}</a></td></tr>
              <tr><td style="padding:8px 0;color:#5A6472;">Phone</td>
                  <td style="padding:8px 0;">{req.phone or "—"}</td></tr>
              <tr><td style="padding:8px 0;color:#5A6472;">Company</td>
                  <td style="padding:8px 0;">{req.company or "—"}</td></tr>
              <tr><td style="padding:8px 0;color:#5A6472;">Service Tier</td>
                  <td style="padding:8px 0;"><strong style="color:#22A08A;">{tier_label}</strong></td></tr>
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
                "from":    "PrimeCool Site <onboarding@resend.dev>",
                "to":      notify_email,
                "subject": f"New Consultation Request — {req.fname} {req.lname} ({tier_label})",
                "html":    html,
            })
        except Exception as e:
            print(f"EMAIL ERROR: {e}")

    return {"ok": True}


@app.get("/")
def index():
    return FileResponse("index.html")
