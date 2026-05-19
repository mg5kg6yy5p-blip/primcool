from contextlib import asynccontextmanager
from datetime import datetime, timezone, timedelta

from typing import Optional
from datetime import datetime as _dt
from pathlib import Path
import uuid

from fastapi import FastAPI, HTTPException, Request, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
import jwt
import os
import resend as resend_lib

from database import (
    init_db, save_submission,
    get_customer_by_code, get_customer_by_id, get_all_customers,
    create_customer, delete_customer, verify_customer, set_customer_pin,
    get_customer_by_code_and_email, create_customer_pin_reset, consume_customer_pin_reset,
    get_customer_equipment, create_equipment, delete_equipment,
    get_customer_visits, get_all_visits, create_visit, update_visit, delete_visit,
    get_visit_by_id, update_visit_time, tech_complete_visit, get_tech_jobs,
    create_review, get_review_for_visit, get_customer_reviews,
    get_all_reviews, get_approved_reviews, update_review_status, delete_review,
    verify_tech, get_tech_by_id, get_all_techs, create_tech, update_tech,
    delete_tech, set_tech_pin,
    get_tech_by_code_and_email, create_pin_reset_token, consume_pin_reset_token,
    create_photo, get_visit_photos, get_photo_by_id, delete_photo,
)

PHOTOS_DIR = Path(os.environ.get("PHOTOS_DIR", "uploads/photos"))
PHOTOS_DIR.mkdir(parents=True, exist_ok=True)
MAX_PHOTO_SIZE = 12 * 1024 * 1024  # 12 MB
ALLOWED_PHOTO_EXTS = {".jpg", ".jpeg", ".png", ".webp", ".heic"}

TIER_LABELS = {
    "residential": "Residential — Home & Property",
    "commercial":  "Commercial — SME & Corporate",
    "industrial":  "Industrial — Process & Facility",
    "unsure":      "Not sure — need an assessment",
}

JWT_SECRET    = os.environ.get("JWT_SECRET", "change-me-in-production-set-JWT_SECRET-env-var")
JWT_ALGORITHM = "HS256"


def _make_token(payload: dict, expires: timedelta) -> str:
    return jwt.encode(
        {**payload, "exp": datetime.now(timezone.utc) + expires},
        JWT_SECRET, algorithm=JWT_ALGORITHM,
    )


def _require_customer(request: Request) -> int:
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(401, "Unauthorized")
    try:
        data = jwt.decode(auth[7:], JWT_SECRET, algorithms=[JWT_ALGORITHM])
        if data.get("type") != "customer":
            raise HTTPException(403, "Forbidden")
        return int(data["sub"])  # stored as str, return as int
    except jwt.ExpiredSignatureError:
        raise HTTPException(401, "Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(401, "Invalid token")


def _require_tech(request: Request) -> int:
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(401, "Unauthorized")
    try:
        data = jwt.decode(auth[7:], JWT_SECRET, algorithms=[JWT_ALGORITHM])
        if data.get("type") != "tech":
            raise HTTPException(403, "Forbidden")
        return int(data["sub"])
    except jwt.ExpiredSignatureError:
        raise HTTPException(401, "Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(401, "Invalid token")


def _require_admin(request: Request):
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(401, "Unauthorized")
    try:
        data = jwt.decode(auth[7:], JWT_SECRET, algorithms=[JWT_ALGORITHM])
        if data.get("type") != "admin":
            raise HTTPException(403, "Forbidden")
    except jwt.ExpiredSignatureError:
        raise HTTPException(401, "Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(401, "Invalid token")


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(lifespan=lifespan)

app.mount("/images", StaticFiles(directory="images"), name="images")
app.mount("/photos", StaticFiles(directory=str(PHOTOS_DIR)), name="photos")
app.mount("/icons",  StaticFiles(directory="icons"),  name="icons")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["*"],
)


# ── Pydantic models ───────────────────────────────────────────────────────────

class ConsultRequest(BaseModel):
    fname:   str
    lname:   str
    email:   str
    phone:   str = ""
    company: str = ""
    tier:    str
    msg:     str = ""


class PortalLoginRequest(BaseModel):
    code: str
    pin:  str


class PortalForgotPin(BaseModel):
    code:  str
    email: str


class PortalResetPin(BaseModel):
    token:       str
    pin:         str
    confirm_pin: str


class CustomerPinReset(BaseModel):
    pin: str


class AdminLoginRequest(BaseModel):
    password: str


class CustomerCreate(BaseModel):
    customer_code: str
    name:          str
    pin:           str = ""
    company:       str = ""
    email:         str = ""
    phone:         str = ""
    address:       str = ""
    notes:         str = ""


class EquipmentCreate(BaseModel):
    customer_id:   int
    name:          str
    type:          str = ""
    model:         str = ""
    serial_number: str = ""
    location:      str = ""
    notes:         str = ""


class VisitCreate(BaseModel):
    customer_id:      int
    equipment_id:     Optional[int] = None
    visit_type:       str
    status:           str = "scheduled"
    scheduled_date:   str = ""
    completed_date:   str = ""
    technician:       str = ""
    work_done:        str = ""
    parts_replaced:   str = ""
    notes:            str = ""
    assigned_tech_id: Optional[int] = None


class VisitUpdate(BaseModel):
    equipment_id:     Optional[int] = None
    visit_type:       str
    status:           str
    scheduled_date:   str = ""
    completed_date:   str = ""
    technician:       str = ""
    work_done:        str = ""
    parts_replaced:   str = ""
    notes:            str = ""
    assigned_tech_id: Optional[int] = None


class TechLogin(BaseModel):
    tech_code: str
    pin:       str


class TechCreate(BaseModel):
    tech_code: str
    pin:       str
    name:      str
    phone:     str = ""
    email:     str = ""


class TechUpdate(BaseModel):
    name:   str
    phone:  str = ""
    email:  str = ""
    active: bool = True


class TechPinReset(BaseModel):
    pin: str


class TechCompleteVisit(BaseModel):
    work_done:      str = ""
    parts_replaced: str = ""
    notes:          str = ""


class TechForgotPin(BaseModel):
    tech_code: str
    email:     str


class TechResetPin(BaseModel):
    token:       str
    pin:         str
    confirm_pin: str


class ReviewCreate(BaseModel):
    review_type: str            # "visit" or "company"
    visit_id:    Optional[int] = None
    rating:      int            # 1-5
    text:        str
    role:        str = ""


# ── Existing routes ───────────────────────────────────────────────────────────

@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/api/consult")
async def submit_consult(req: ConsultRequest):
    save_submission(req.model_dump())

    api_key      = os.environ.get("RESEND_API_KEY")
    notify_email = os.environ.get("NOTIFY_EMAIL", "juggarr@gmail.com")

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
                "from":    "PrimeCool Services <onboarding@resend.dev>",
                "to":      notify_email,
                "subject": f"New Consultation Request — {req.fname} {req.lname} ({tier_label})",
                "html":    html,
            })
        except Exception as e:
            print(f"EMAIL ERROR: {e}")

    return {"ok": True}


# ── Portal (customer) routes ──────────────────────────────────────────────────

@app.post("/api/portal/login")
def portal_login(req: PortalLoginRequest):
    customer = verify_customer(req.code, req.pin)
    if not customer:
        # Distinguish "no PIN set" so the customer can contact us, but only after code is valid
        existing = get_customer_by_code(req.code)
        if existing and not existing.get("pin_hash"):
            raise HTTPException(403, "No PIN set on your account yet. Please contact PrimeCool to set one up.")
        raise HTTPException(401, "Invalid customer ID or PIN")
    token = _make_token({"sub": str(customer["id"]), "type": "customer"}, timedelta(days=30))
    return {"token": token, "name": customer["name"]}


@app.post("/api/portal/forgot-pin")
async def portal_forgot_pin(request: Request, body: PortalForgotPin):
    # Always return ok — don't leak which (code, email) pairs exist
    customer = get_customer_by_code_and_email(body.code, body.email)
    if customer:
        token = create_customer_pin_reset(customer["id"])
        api_key = os.environ.get("RESEND_API_KEY")
        base_url = str(request.base_url).rstrip("/")
        reset_url = f"{base_url}/portal/reset?token={token}"
        if api_key and customer.get("email"):
            resend_lib.api_key = api_key
            try:
                resend_lib.Emails.send({
                    "from":    "PrimeCool Services <onboarding@resend.dev>",
                    "to":      customer["email"],
                    "subject": "PrimeCool Customer Portal — PIN Reset",
                    "html": f"""
                    <div style="font-family:Arial,sans-serif;max-width:520px;margin:0 auto;">
                      <div style="background:#0B2545;padding:22px;color:white;">
                        <h2 style="margin:0;color:#22A08A;">Reset Your PIN</h2>
                      </div>
                      <div style="padding:22px;border:1px solid #e8ecf0;line-height:1.6;color:#1a2533;">
                        <p>Hi {customer['name']},</p>
                        <p>We received a request to reset your PrimeCool Customer Portal PIN. Click the button below within <strong>30 minutes</strong> to set a new PIN.</p>
                        <p style="text-align:center;margin:24px 0;">
                          <a href="{reset_url}" style="display:inline-block;background:#22A08A;color:white;padding:12px 28px;text-decoration:none;font-weight:600;letter-spacing:0.5px;">Reset PIN →</a>
                        </p>
                        <p style="font-size:13px;color:#5A6472;">Or copy and paste this URL into your browser:<br>{reset_url}</p>
                        <p style="font-size:13px;color:#5A6472;">If you didn't request this, you can ignore this email — your PIN won't change.</p>
                      </div>
                    </div>
                    """,
                })
            except Exception as e:
                print(f"CUSTOMER PIN RESET EMAIL ERROR: {e}")
    return {"ok": True}


@app.post("/api/portal/reset-pin")
def portal_reset_pin(body: PortalResetPin):
    if not body.pin.isdigit() or not (4 <= len(body.pin) <= 8):
        raise HTTPException(400, "PIN must be 4–8 digits")
    if body.pin != body.confirm_pin:
        raise HTTPException(400, "PINs do not match")
    customer_id = consume_customer_pin_reset(body.token)
    if not customer_id:
        raise HTTPException(400, "Reset link is invalid or has expired")
    set_customer_pin(customer_id, body.pin)
    return {"ok": True}


@app.get("/api/portal/me")
def portal_me(request: Request):
    customer_id = _require_customer(request)
    customer    = get_customer_by_id(customer_id)
    if not customer:
        raise HTTPException(404, "Customer not found")
    equipment = get_customer_equipment(customer_id)
    visits    = get_customer_visits(customer_id)
    reviews   = get_customer_reviews(customer_id)
    for v in visits:
        v["photos"] = get_visit_photos(v["id"])
    return {"customer": customer, "equipment": equipment, "visits": visits, "reviews": reviews}


@app.post("/api/portal/reviews")
def portal_create_review(request: Request, body: ReviewCreate):
    customer_id = _require_customer(request)

    if body.review_type not in ("visit", "company"):
        raise HTTPException(400, "Invalid review_type")
    if not (1 <= body.rating <= 5):
        raise HTTPException(400, "Rating must be 1–5")
    if not body.text.strip():
        raise HTTPException(400, "Review text is required")

    payload = {
        "customer_id": customer_id,
        "review_type": body.review_type,
        "rating":      body.rating,
        "text":        body.text.strip(),
        "role":        body.role.strip(),
    }

    if body.review_type == "visit":
        if not body.visit_id:
            raise HTTPException(400, "visit_id is required for visit reviews")
        visits = get_customer_visits(customer_id)
        visit  = next((v for v in visits if v["id"] == body.visit_id), None)
        if not visit:
            raise HTTPException(404, "Visit not found")
        if visit["status"] != "completed":
            raise HTTPException(400, "You can only review completed visits")
        if get_review_for_visit(customer_id, body.visit_id):
            raise HTTPException(409, "You've already submitted a review for this visit")
        payload["visit_id"]            = body.visit_id
        payload["tech_snapshot"]       = visit.get("technician", "")
        payload["visit_type_snapshot"] = visit.get("visit_type", "")

    review_id = create_review(payload)
    return {"id": review_id, "status": "pending"}


# ── Public reviews ────────────────────────────────────────────────────────────

@app.get("/api/reviews/public")
def public_reviews(limit: Optional[int] = None):
    rows = get_approved_reviews(limit=limit)
    out  = []
    for r in rows:
        display_name = r["customer_name"] or ""
        parts = display_name.split()
        if len(parts) >= 2:
            display_name = f"{parts[0][0]}. {' '.join(parts[1:])}"
        sub = " · ".join([p for p in [r.get("role"), r.get("customer_company")] if p])
        out.append({
            "rating":        r["rating"],
            "text":          r["text"],
            "display_name":  display_name,
            "sub":           sub,
            "review_type":   r["review_type"],
            "tech":          r.get("tech_snapshot") or "",
            "visit_type":    r.get("visit_type_snapshot") or "",
            "date":          (r.get("approved_at") or r.get("created_at") or "")[:10],
        })
    return out


# ── Tech routes ───────────────────────────────────────────────────────────────

@app.post("/api/tech/login")
def tech_login(req: TechLogin):
    tech = verify_tech(req.tech_code, req.pin)
    if not tech:
        raise HTTPException(401, "Invalid tech code or PIN")
    token = _make_token({"sub": str(tech["id"]), "type": "tech"}, timedelta(days=7))
    return {"token": token, "name": tech["name"], "tech_code": tech["tech_code"]}


@app.post("/api/tech/forgot-pin")
async def tech_forgot_pin(request: Request, body: TechForgotPin):
    # Always return ok to avoid leaking which (code, email) pairs exist.
    tech = get_tech_by_code_and_email(body.tech_code, body.email)
    if tech:
        token = create_pin_reset_token(tech["id"])
        api_key = os.environ.get("RESEND_API_KEY")
        base_url = str(request.base_url).rstrip("/")
        reset_url = f"{base_url}/tech/reset?token={token}"
        if api_key:
            resend_lib.api_key = api_key
            try:
                resend_lib.Emails.send({
                    "from":    "PrimeCool Services <onboarding@resend.dev>",
                    "to":      tech["email"],
                    "subject": "PrimeCool Tech Portal — PIN Reset",
                    "html": f"""
                    <div style="font-family:Arial,sans-serif;max-width:520px;margin:0 auto;">
                      <div style="background:#0B2545;padding:22px;color:white;">
                        <h2 style="margin:0;color:#22A08A;">Reset Your PIN</h2>
                      </div>
                      <div style="padding:22px;border:1px solid #e8ecf0;line-height:1.6;color:#1a2533;">
                        <p>Hi {tech['name']},</p>
                        <p>We received a request to reset your PrimeCool Tech Portal PIN. Click the button below within <strong>30 minutes</strong> to set a new PIN.</p>
                        <p style="text-align:center;margin:24px 0;">
                          <a href="{reset_url}" style="display:inline-block;background:#22A08A;color:white;padding:12px 28px;text-decoration:none;font-weight:600;letter-spacing:0.5px;">Reset PIN →</a>
                        </p>
                        <p style="font-size:13px;color:#5A6472;">Or copy and paste this URL into your browser:<br>{reset_url}</p>
                        <p style="font-size:13px;color:#5A6472;">If you didn't request this, you can ignore this email — your PIN won't change.</p>
                      </div>
                    </div>
                    """,
                })
            except Exception as e:
                print(f"PIN RESET EMAIL ERROR: {e}")
    return {"ok": True}


@app.post("/api/tech/reset-pin")
def tech_reset_pin(body: TechResetPin):
    if not body.pin.isdigit() or not (4 <= len(body.pin) <= 8):
        raise HTTPException(400, "PIN must be 4–8 digits")
    if body.pin != body.confirm_pin:
        raise HTTPException(400, "PINs do not match")
    tech_id = consume_pin_reset_token(body.token)
    if not tech_id:
        raise HTTPException(400, "Reset link is invalid or has expired")
    set_tech_pin(tech_id, body.pin)
    return {"ok": True}


@app.get("/api/tech/me")
def tech_me(request: Request):
    tech_id = _require_tech(request)
    tech = get_tech_by_id(tech_id)
    if not tech:
        raise HTTPException(404, "Tech not found")
    jobs = get_tech_jobs(tech_id)
    for j in jobs:
        j["photos"] = get_visit_photos(j["id"])
    return {
        "tech": {"id": tech["id"], "name": tech["name"], "tech_code": tech["tech_code"]},
        "jobs": jobs,
    }


@app.get("/api/tech/jobs/{visit_id}")
def tech_get_job(request: Request, visit_id: int):
    tech_id = _require_tech(request)
    visit   = get_visit_by_id(visit_id)
    if not visit or visit.get("assigned_tech_id") != tech_id:
        raise HTTPException(404, "Job not found")
    visit["photos"] = get_visit_photos(visit_id)
    return visit


@app.put("/api/tech/jobs/{visit_id}/start")
def tech_start_job(request: Request, visit_id: int):
    tech_id = _require_tech(request)
    visit   = get_visit_by_id(visit_id)
    if not visit or visit.get("assigned_tech_id") != tech_id:
        raise HTTPException(404, "Job not found")
    if visit["status"] == "completed":
        raise HTTPException(400, "Job already completed")

    now_iso = _dt.now(timezone.utc).isoformat()
    update_visit_time(visit_id, "start_time", now_iso)
    # bump status to in_progress
    update_visit(visit_id, {
        **visit,
        "status":      "in_progress",
        "visit_type":  visit["visit_type"],
    })
    return {"ok": True, "start_time": now_iso}


@app.put("/api/tech/jobs/{visit_id}/complete")
def tech_complete_job(request: Request, visit_id: int, body: TechCompleteVisit):
    tech_id = _require_tech(request)
    visit   = get_visit_by_id(visit_id)
    if not visit or visit.get("assigned_tech_id") != tech_id:
        raise HTTPException(404, "Job not found")

    now      = _dt.now(timezone.utc)
    end_iso  = now.isoformat()
    today    = now.date().isoformat()
    tech_complete_visit(
        visit_id,
        body.work_done.strip(),
        body.parts_replaced.strip(),
        body.notes.strip(),
        end_iso,
        today,
    )
    return {"ok": True, "end_time": end_iso}


@app.post("/api/tech/jobs/{visit_id}/photos")
async def tech_upload_photo(
    request: Request,
    visit_id: int,
    category: str = Form(...),
    file:     UploadFile = File(...),
):
    tech_id = _require_tech(request)
    visit   = get_visit_by_id(visit_id)
    if not visit or visit.get("assigned_tech_id") != tech_id:
        raise HTTPException(404, "Job not found")

    if category not in ("before", "after"):
        raise HTTPException(400, "Invalid category — must be 'before' or 'after'")

    ext = Path(file.filename or "").suffix.lower()
    if ext not in ALLOWED_PHOTO_EXTS:
        raise HTTPException(400, f"Unsupported file type {ext}")

    body = await file.read()
    if len(body) > MAX_PHOTO_SIZE:
        raise HTTPException(413, "File too large (max 12 MB)")

    fname = f"v{visit_id}_{category}_{uuid.uuid4().hex[:12]}{ext}"
    out_path = PHOTOS_DIR / fname
    out_path.write_bytes(body)

    photo_id = create_photo(visit_id, category, fname, tech_id)
    return {"id": photo_id, "filename": fname, "url": f"/photos/{fname}", "category": category}


@app.delete("/api/tech/photos/{photo_id}")
def tech_delete_photo(request: Request, photo_id: int):
    tech_id = _require_tech(request)
    photo = get_photo_by_id(photo_id)
    if not photo:
        raise HTTPException(404, "Photo not found")
    visit = get_visit_by_id(photo["visit_id"])
    if not visit or visit.get("assigned_tech_id") != tech_id:
        raise HTTPException(403, "Forbidden")
    try:
        (PHOTOS_DIR / photo["filename"]).unlink(missing_ok=True)
    except Exception:
        pass
    delete_photo(photo_id)
    return {"ok": True}


# ── Admin routes ──────────────────────────────────────────────────────────────

@app.post("/api/admin/login")
def admin_login(req: AdminLoginRequest):
    admin_password = os.environ.get("ADMIN_PASSWORD", "primecool-admin")
    if req.password != admin_password:
        raise HTTPException(401, "Invalid password")
    token = _make_token({"sub": "admin", "type": "admin"}, timedelta(hours=12))
    return {"token": token}


@app.get("/api/admin/customers")
def admin_list_customers(request: Request):
    _require_admin(request)
    return get_all_customers()


@app.post("/api/admin/customers")
def admin_create_customer(request: Request, body: CustomerCreate):
    _require_admin(request)
    if body.pin and (not body.pin.isdigit() or not (4 <= len(body.pin) <= 8)):
        raise HTTPException(400, "PIN must be 4–8 digits")
    try:
        customer_id = create_customer(body.model_dump())
    except Exception as e:
        if "UNIQUE" in str(e):
            raise HTTPException(409, "Customer ID already exists")
        raise
    return {"id": customer_id}


@app.put("/api/admin/customers/{customer_id}/pin")
def admin_reset_customer_pin(request: Request, customer_id: int, body: CustomerPinReset):
    _require_admin(request)
    if not body.pin.isdigit() or not (4 <= len(body.pin) <= 8):
        raise HTTPException(400, "PIN must be 4–8 digits")
    if not get_customer_by_id(customer_id):
        raise HTTPException(404, "Customer not found")
    set_customer_pin(customer_id, body.pin)
    return {"ok": True}


@app.delete("/api/admin/customers/{customer_id}")
def admin_delete_customer(request: Request, customer_id: int):
    _require_admin(request)
    delete_customer(customer_id)
    return {"ok": True}


@app.get("/api/admin/customers/{customer_id}/equipment")
def admin_list_equipment(request: Request, customer_id: int):
    _require_admin(request)
    return get_customer_equipment(customer_id)


@app.post("/api/admin/equipment")
def admin_create_equipment(request: Request, body: EquipmentCreate):
    _require_admin(request)
    equipment_id = create_equipment(body.model_dump())
    return {"id": equipment_id}


@app.delete("/api/admin/equipment/{equipment_id}")
def admin_delete_equipment(request: Request, equipment_id: int):
    _require_admin(request)
    delete_equipment(equipment_id)
    return {"ok": True}


@app.get("/api/admin/visits")
def admin_list_visits(request: Request):
    _require_admin(request)
    return get_all_visits()


@app.post("/api/admin/visits")
def admin_create_visit(request: Request, body: VisitCreate):
    _require_admin(request)
    visit_id = create_visit(body.model_dump())
    return {"id": visit_id}


@app.put("/api/admin/visits/{visit_id}")
def admin_update_visit(request: Request, visit_id: int, body: VisitUpdate):
    _require_admin(request)
    update_visit(visit_id, body.model_dump())
    return {"ok": True}


@app.delete("/api/admin/visits/{visit_id}")
def admin_delete_visit(request: Request, visit_id: int):
    _require_admin(request)
    delete_visit(visit_id)
    return {"ok": True}


@app.get("/api/admin/reviews")
def admin_list_reviews(request: Request, status: Optional[str] = None):
    _require_admin(request)
    return get_all_reviews(status=status)


@app.put("/api/admin/reviews/{review_id}/approve")
def admin_approve_review(request: Request, review_id: int):
    _require_admin(request)
    update_review_status(review_id, "approved")
    return {"ok": True}


@app.put("/api/admin/reviews/{review_id}/reject")
def admin_reject_review(request: Request, review_id: int):
    _require_admin(request)
    update_review_status(review_id, "rejected")
    return {"ok": True}


@app.delete("/api/admin/reviews/{review_id}")
def admin_delete_review(request: Request, review_id: int):
    _require_admin(request)
    delete_review(review_id)
    return {"ok": True}


@app.get("/api/admin/techs")
def admin_list_techs(request: Request):
    _require_admin(request)
    return get_all_techs()


@app.post("/api/admin/techs")
def admin_create_tech(request: Request, body: TechCreate):
    _require_admin(request)
    if not body.pin.isdigit() or not (4 <= len(body.pin) <= 8):
        raise HTTPException(400, "PIN must be 4–8 digits")
    try:
        tech_id = create_tech(body.model_dump())
    except Exception as e:
        if "UNIQUE" in str(e):
            raise HTTPException(409, "Tech code already exists")
        raise
    return {"id": tech_id}


@app.put("/api/admin/techs/{tech_id}")
def admin_update_tech(request: Request, tech_id: int, body: TechUpdate):
    _require_admin(request)
    update_tech(tech_id, body.model_dump())
    return {"ok": True}


@app.put("/api/admin/techs/{tech_id}/pin")
def admin_reset_tech_pin(request: Request, tech_id: int, body: TechPinReset):
    _require_admin(request)
    if not body.pin.isdigit() or not (4 <= len(body.pin) <= 8):
        raise HTTPException(400, "PIN must be 4–8 digits")
    set_tech_pin(tech_id, body.pin)
    return {"ok": True}


@app.delete("/api/admin/techs/{tech_id}")
def admin_delete_tech(request: Request, tech_id: int):
    _require_admin(request)
    delete_tech(tech_id)
    return {"ok": True}


@app.get("/api/admin/visits/{visit_id}/photos")
def admin_get_visit_photos(request: Request, visit_id: int):
    _require_admin(request)
    return get_visit_photos(visit_id)


@app.delete("/api/admin/photos/{photo_id}")
def admin_delete_photo(request: Request, photo_id: int):
    _require_admin(request)
    photo = get_photo_by_id(photo_id)
    if not photo:
        raise HTTPException(404, "Photo not found")
    try:
        (PHOTOS_DIR / photo["filename"]).unlink(missing_ok=True)
    except Exception:
        pass
    delete_photo(photo_id)
    return {"ok": True}


# ── Page routes ───────────────────────────────────────────────────────────────

@app.get("/portal")
def portal_page():
    return FileResponse("portal.html")


@app.get("/portal/dashboard")
def portal_dashboard_page():
    return FileResponse("portal_dashboard.html")


@app.get("/portal/reset")
def portal_reset_page():
    return FileResponse("portal_reset.html")


@app.get("/admin")
def admin_page():
    return FileResponse("admin.html")


@app.get("/tech")
def tech_page():
    return FileResponse("tech.html")


@app.get("/tech/reset")
def tech_reset_page():
    return FileResponse("tech_reset.html")


# ── PWA assets ────────────────────────────────────────────────────────────────

@app.get("/manifest-portal.json")
def manifest_portal():
    return Response(
        content=Path("manifest-portal.json").read_bytes(),
        media_type="application/manifest+json",
    )


@app.get("/manifest-tech.json")
def manifest_tech():
    return Response(
        content=Path("manifest-tech.json").read_bytes(),
        media_type="application/manifest+json",
    )


@app.get("/sw.js")
def service_worker():
    return Response(
        content=Path("sw.js").read_bytes(),
        media_type="application/javascript",
        headers={"Cache-Control": "no-cache", "Service-Worker-Allowed": "/"},
    )


@app.get("/reviews")
def reviews_page():
    return FileResponse("reviews.html")


@app.get("/request")
def request_page():
    return FileResponse("request.html")


@app.get("/full")
def full_site_preview():
    return FileResponse("index.full.html")


@app.get("/")
def index():
    return FileResponse("index.html")
