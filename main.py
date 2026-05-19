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
    init_db, save_submission, bootstrap_super_admin,
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
    get_timesheet_data,
    # Admin users + audit
    verify_admin_user, get_admin_user_by_id, get_all_admin_users,
    create_admin_user, update_admin_user, set_admin_role, set_admin_active,
    set_admin_password, count_active_admins, get_admin_by_email,
    create_admin_password_reset, consume_admin_password_reset,
    log_audit, query_audit_log,
)

# ── Admin role → permission matrix ────────────────────────────────────────────
ADMIN_PERMS = {
    "super_admin": {
        "admin:create", "admin:update", "admin:delete", "admin:set_role",
        "admin:set_active", "admin:reset_password", "admin:view_all",
        "tech:create", "tech:update", "tech:delete", "tech:reset_pin",
        "customer:create", "customer:update", "customer:delete",
        "visit:create", "visit:update", "visit:delete",
        "review:approve", "review:reject", "review:delete",
        "audit:view_all",
        "timesheet:view_all",
        "schedule:view", "schedule:edit",
    },
    "supervisor_admin": {
        "admin:view_all",
        "tech:update",
        "customer:update",
        "visit:update",
        "audit:view_all",
        "timesheet:view_all",
        "schedule:view", "schedule:edit",
    },
    "system_admin": {
        "tech:create", "tech:update", "tech:reset_pin",
        "customer:create", "customer:update",
        "visit:create", "visit:update",
        "audit:view_self",
        "timesheet:view_all",
        "schedule:view", "schedule:edit",
    },
    "hr_admin": {
        "tech:create", "tech:update", "tech:reset_pin",
        "audit:view_self",
        "timesheet:view_all",
    },
    "ceo_assistant": {
        "audit:view_self",
    },
}


def _admin_can(role: str, perm: str) -> bool:
    return perm in ADMIN_PERMS.get(role, set())

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
    """Returns the admin_user dict for the authenticated admin."""
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
    admin_id = data.get("sub")
    if not admin_id:
        raise HTTPException(401, "Invalid token")
    admin = get_admin_user_by_id(int(admin_id))
    if not admin or not admin.get("active"):
        raise HTTPException(403, "Account inactive or deleted")
    return admin


def _require_perm(request: Request, perm: str):
    admin = _require_admin(request)
    if not _admin_can(admin["role"], perm):
        raise HTTPException(403, f"Your role ({admin['role']}) lacks permission: {perm}")
    return admin


def _audit_from(admin: dict, action: str, request: Request,
                target_type: str = None, target_id: int = None,
                target_label: str = None, before=None, after=None):
    log_audit(
        actor_type="admin",
        actor_id=admin["id"],
        actor_prid=admin.get("prid"),
        actor_label=admin.get("name"),
        actor_role=admin.get("role"),
        action=action,
        target_type=target_type,
        target_id=target_id,
        target_label=target_label,
        before_value=before,
        after_value=after,
        ip_address=request.client.host if request.client else None,
    )


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()

    # Bootstrap first super_admin if BOOTSTRAP_ADMIN_* env vars are set and no admins exist.
    bs_user  = os.environ.get("BOOTSTRAP_ADMIN_USERNAME")
    bs_pw    = os.environ.get("BOOTSTRAP_ADMIN_PASSWORD")
    bs_name  = os.environ.get("BOOTSTRAP_ADMIN_NAME",  "Super Admin")
    bs_email = os.environ.get("BOOTSTRAP_ADMIN_EMAIL")
    if bs_user and bs_pw and bs_email:
        result = bootstrap_super_admin(bs_user, bs_pw, bs_name, bs_email)
        if result:
            new_id, prid = result
            print(f"✓ Bootstrapped super_admin '{bs_user}' (id={new_id}, PRID={prid})")
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
    username: str = ""
    password: str


class AdminUserCreate(BaseModel):
    password:  str
    name:      str
    email:     str
    phone:     str = ""
    role:      str
    hire_date: str = ""


class AdminUserUpdate(BaseModel):
    name:  str
    email: str
    phone: str = ""


class AdminRoleChange(BaseModel):
    role: str


class AdminActiveChange(BaseModel):
    active: bool


class AdminPasswordSet(BaseModel):
    password: str


class AdminForgotPassword(BaseModel):
    email: str


class AdminResetPassword(BaseModel):
    token:            str
    password:         str
    confirm_password: str


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
    scheduled_time:   str = ""
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
    scheduled_time:   str = ""
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
    pin:       str
    name:      str
    phone:     str = ""
    email:     str = ""
    role:      str = "tech"   # 'lead_tech' | 'tech' | 'apprentice'
    hire_date: str = ""


class TechUpdate(BaseModel):
    name:   str
    phone:  str = ""
    email:  str = ""
    role:   str = "tech"
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
def admin_login(req: AdminLoginRequest, request: Request):
    if not req.username:
        raise HTTPException(400, "Username is required")
    admin = verify_admin_user(req.username, req.password)
    if not admin:
        raise HTTPException(401, "Invalid username or password")
    if not admin.get("active"):
        raise HTTPException(403, "Account is deactivated")
    token = _make_token({"sub": str(admin["id"]), "type": "admin"}, timedelta(hours=12))
    log_audit(
        actor_type="admin",
        actor_id=admin["id"],
        actor_prid=admin.get("prid"),
        actor_label=admin.get("name"),
        actor_role=admin.get("role"),
        action="admin.login",
        ip_address=request.client.host if request.client else None,
    )
    return {
        "token":    token,
        "name":     admin["name"],
        "username": admin["username"],
        "role":     admin["role"],
        "prid":     admin.get("prid"),
    }


@app.get("/api/admin/me")
def admin_me(request: Request):
    admin = _require_admin(request)
    return {
        "id":       admin["id"],
        "username": admin["username"],
        "name":     admin["name"],
        "email":    admin["email"],
        "phone":    admin.get("phone"),
        "role":     admin["role"],
        "prid":     admin.get("prid"),
    }


@app.post("/api/admin/forgot-password")
async def admin_forgot_password(request: Request, body: AdminForgotPassword):
    admin = get_admin_by_email(body.email)
    if admin:
        token = create_admin_password_reset(admin["id"])
        api_key  = os.environ.get("RESEND_API_KEY")
        base_url = str(request.base_url).rstrip("/")
        reset_url = f"{base_url}/admin/reset?token={token}"
        if api_key:
            resend_lib.api_key = api_key
            try:
                resend_lib.Emails.send({
                    "from":    "PrimeCool Services <onboarding@resend.dev>",
                    "to":      admin["email"],
                    "subject": "PrimeCool Admin — Password Reset",
                    "html": f"""
                    <div style="font-family:Arial,sans-serif;max-width:520px;margin:0 auto;">
                      <div style="background:#0B2545;padding:22px;color:white;">
                        <h2 style="margin:0;color:#22A08A;">Reset Your Admin Password</h2>
                      </div>
                      <div style="padding:22px;border:1px solid #e8ecf0;line-height:1.6;color:#1a2533;">
                        <p>Hi {admin['name']},</p>
                        <p>Click the button below within <strong>30 minutes</strong> to set a new password.</p>
                        <p style="text-align:center;margin:24px 0;">
                          <a href="{reset_url}" style="display:inline-block;background:#22A08A;color:white;padding:12px 28px;text-decoration:none;font-weight:600;letter-spacing:0.5px;">Reset Password →</a>
                        </p>
                        <p style="font-size:13px;color:#5A6472;">If you didn't request this, you can ignore this email.</p>
                      </div>
                    </div>
                    """,
                })
            except Exception as e:
                print(f"ADMIN PW RESET EMAIL ERROR: {e}")
    return {"ok": True}


@app.post("/api/admin/reset-password")
def admin_reset_password_endpoint(body: AdminResetPassword):
    if len(body.password) < 8:
        raise HTTPException(400, "Password must be at least 8 characters")
    if body.password != body.confirm_password:
        raise HTTPException(400, "Passwords do not match")
    admin_id = consume_admin_password_reset(body.token)
    if not admin_id:
        raise HTTPException(400, "Reset link is invalid or has expired")
    set_admin_password(admin_id, body.password)
    return {"ok": True}


# ── Admin user management (super_admin only for create/role/active/delete) ────

@app.get("/api/admin/users")
def admin_list_users(request: Request):
    _require_perm(request, "admin:view_all")
    return get_all_admin_users()


@app.post("/api/admin/users")
def admin_create_user(request: Request, body: AdminUserCreate):
    admin = _require_perm(request, "admin:create")
    if body.role not in ADMIN_PERMS:
        raise HTTPException(400, "Invalid role")
    if len(body.password) < 8:
        raise HTTPException(400, "Password must be at least 8 characters")
    # PRID is generated server-side and used as the username.
    data = body.model_dump()
    try:
        new_id, prid = create_admin_user(data, created_by=admin["id"])
    except Exception as e:
        if "UNIQUE" in str(e):
            raise HTTPException(409, "Email already exists")
        raise
    _audit_from(admin, "admin.create", request,
                target_type="admin", target_id=new_id, target_label=prid,
                after={"username": prid, "name": body.name, "email": body.email, "role": body.role})
    return {"id": new_id, "prid": prid, "username": prid}


@app.put("/api/admin/users/{user_id}")
def admin_update_user(request: Request, user_id: int, body: AdminUserUpdate):
    admin  = _require_admin(request)
    target = get_admin_user_by_id(user_id)
    if not target:
        raise HTTPException(404, "Admin not found")
    # An admin can update their own profile; super_admin can update anyone's
    if admin["id"] != user_id and not _admin_can(admin["role"], "admin:update"):
        raise HTTPException(403, "You can only update your own profile")
    before = {"name": target["name"], "email": target["email"], "phone": target.get("phone")}
    update_admin_user(user_id, body.model_dump())
    _audit_from(admin, "admin.update", request,
                target_type="admin", target_id=user_id, target_label=target["username"],
                before=before, after=body.model_dump())
    return {"ok": True}


@app.put("/api/admin/users/{user_id}/role")
def admin_change_role(request: Request, user_id: int, body: AdminRoleChange):
    admin = _require_perm(request, "admin:set_role")
    target = get_admin_user_by_id(user_id)
    if not target:
        raise HTTPException(404, "Admin not found")
    if body.role not in ADMIN_PERMS:
        raise HTTPException(400, "Invalid role")
    # Safety: prevent demoting the last active super_admin
    if target["role"] == "super_admin" and body.role != "super_admin":
        if count_active_admins("super_admin") <= 1:
            raise HTTPException(400, "Cannot demote the last active super_admin")
    before = {"role": target["role"]}
    set_admin_role(user_id, body.role)
    _audit_from(admin, "admin.set_role", request,
                target_type="admin", target_id=user_id, target_label=target["username"],
                before=before, after={"role": body.role})
    return {"ok": True}


@app.put("/api/admin/users/{user_id}/active")
def admin_change_active(request: Request, user_id: int, body: AdminActiveChange):
    admin = _require_perm(request, "admin:set_active")
    target = get_admin_user_by_id(user_id)
    if not target:
        raise HTTPException(404, "Admin not found")
    # Safety: prevent deactivating the last active super_admin
    if target["role"] == "super_admin" and not body.active:
        if count_active_admins("super_admin") <= 1:
            raise HTTPException(400, "Cannot deactivate the last active super_admin")
    # Safety: prevent admins from deactivating themselves
    if admin["id"] == user_id and not body.active:
        raise HTTPException(400, "You cannot deactivate your own account")
    before = {"active": bool(target["active"])}
    set_admin_active(user_id, body.active)
    _audit_from(admin, "admin.set_active", request,
                target_type="admin", target_id=user_id, target_label=target["username"],
                before=before, after={"active": body.active})
    return {"ok": True}


@app.put("/api/admin/users/{user_id}/password")
def admin_reset_user_password(request: Request, user_id: int, body: AdminPasswordSet):
    admin = _require_admin(request)
    target = get_admin_user_by_id(user_id)
    if not target:
        raise HTTPException(404, "Admin not found")
    # super_admin can reset anyone's; everyone else can reset only their own
    if admin["id"] != user_id and not _admin_can(admin["role"], "admin:reset_password"):
        raise HTTPException(403, "You can only reset your own password")
    if len(body.password) < 8:
        raise HTTPException(400, "Password must be at least 8 characters")
    set_admin_password(user_id, body.password)
    _audit_from(admin, "admin.reset_password", request,
                target_type="admin", target_id=user_id, target_label=target["username"])
    return {"ok": True}


# ── Timesheets ────────────────────────────────────────────────────────────────

@app.get("/api/admin/timesheets")
def admin_timesheets(request: Request,
                     start: str,
                     end:   str,
                     tech_id: Optional[int] = None):
    """Returns clock-in entries with start_time in [start, end). Dates are ISO YYYY-MM-DD."""
    _require_perm(request, "timesheet:view_all")
    try:
        # Convert to ISO datetime at UTC midnight
        start_iso = _dt.fromisoformat(start).replace(tzinfo=timezone.utc).isoformat()
        end_iso   = _dt.fromisoformat(end).replace(tzinfo=timezone.utc).isoformat()
    except ValueError:
        raise HTTPException(400, "start and end must be ISO dates (YYYY-MM-DD)")
    rows = get_timesheet_data(start_iso, end_iso, tech_id=tech_id)
    # Compute duration_minutes server-side so the client doesn't have to
    for r in rows:
        if r.get("start_time") and r.get("end_time"):
            try:
                s = _dt.fromisoformat(r["start_time"].replace("Z", "+00:00"))
                e = _dt.fromisoformat(r["end_time"].replace("Z", "+00:00"))
                r["duration_minutes"] = int((e - s).total_seconds() / 60)
            except Exception:
                r["duration_minutes"] = None
        else:
            r["duration_minutes"] = None
    return rows


# ── Audit log ─────────────────────────────────────────────────────────────────

@app.get("/api/admin/audit")
def admin_audit(request: Request,
                actor_id: Optional[int] = None,
                action_prefix: Optional[str] = None,
                target_type: Optional[str] = None,
                since: Optional[str] = None,
                until: Optional[str] = None,
                limit: int = 200):
    admin = _require_admin(request)
    if _admin_can(admin["role"], "audit:view_all"):
        return query_audit_log(actor_id=actor_id, action_prefix=action_prefix,
                               target_type=target_type, since=since, until=until, limit=limit)
    if _admin_can(admin["role"], "audit:view_self"):
        return query_audit_log(actor_id=admin["id"], action_prefix=action_prefix,
                               target_type=target_type, since=since, until=until, limit=limit)
    raise HTTPException(403, "Forbidden")


@app.get("/api/admin/customers")
def admin_list_customers(request: Request):
    _require_admin(request)
    return get_all_customers()


@app.post("/api/admin/customers")
def admin_create_customer(request: Request, body: CustomerCreate):
    admin = _require_perm(request, "customer:create")
    if body.pin and (not body.pin.isdigit() or not (4 <= len(body.pin) <= 8)):
        raise HTTPException(400, "PIN must be 4–8 digits")
    try:
        customer_id = create_customer(body.model_dump())
    except Exception as e:
        if "UNIQUE" in str(e):
            raise HTTPException(409, "Customer ID already exists")
        raise
    _audit_from(admin, "customer.create", request,
                target_type="customer", target_id=customer_id, target_label=body.customer_code,
                after={k: v for k, v in body.model_dump().items() if k != "pin"})
    return {"id": customer_id}


@app.put("/api/admin/customers/{customer_id}/pin")
def admin_reset_customer_pin(request: Request, customer_id: int, body: CustomerPinReset):
    admin = _require_perm(request, "customer:update")
    if not body.pin.isdigit() or not (4 <= len(body.pin) <= 8):
        raise HTTPException(400, "PIN must be 4–8 digits")
    cust = get_customer_by_id(customer_id)
    if not cust:
        raise HTTPException(404, "Customer not found")
    set_customer_pin(customer_id, body.pin)
    _audit_from(admin, "customer.reset_pin", request,
                target_type="customer", target_id=customer_id, target_label=cust["customer_code"])
    return {"ok": True}


@app.delete("/api/admin/customers/{customer_id}")
def admin_delete_customer(request: Request, customer_id: int):
    admin = _require_perm(request, "customer:delete")
    cust = get_customer_by_id(customer_id)
    delete_customer(customer_id)
    _audit_from(admin, "customer.delete", request,
                target_type="customer", target_id=customer_id,
                target_label=cust.get("customer_code") if cust else str(customer_id),
                before=cust)
    return {"ok": True}


@app.get("/api/admin/customers/{customer_id}/equipment")
def admin_list_equipment(request: Request, customer_id: int):
    _require_admin(request)
    return get_customer_equipment(customer_id)


@app.post("/api/admin/equipment")
def admin_create_equipment(request: Request, body: EquipmentCreate):
    admin = _require_perm(request, "customer:update")
    equipment_id = create_equipment(body.model_dump())
    _audit_from(admin, "equipment.create", request,
                target_type="equipment", target_id=equipment_id, target_label=body.name,
                after=body.model_dump())
    return {"id": equipment_id}


@app.delete("/api/admin/equipment/{equipment_id}")
def admin_delete_equipment(request: Request, equipment_id: int):
    admin = _require_perm(request, "customer:update")
    delete_equipment(equipment_id)
    _audit_from(admin, "equipment.delete", request,
                target_type="equipment", target_id=equipment_id)
    return {"ok": True}


@app.get("/api/admin/visits")
def admin_list_visits(request: Request):
    _require_admin(request)
    return get_all_visits()


@app.post("/api/admin/visits")
def admin_create_visit(request: Request, body: VisitCreate):
    admin = _require_perm(request, "visit:create")
    visit_id = create_visit(body.model_dump())
    _audit_from(admin, "visit.create", request,
                target_type="visit", target_id=visit_id,
                target_label=f"{body.visit_type} for cust {body.customer_id}",
                after=body.model_dump())
    return {"id": visit_id}


@app.put("/api/admin/visits/{visit_id}")
def admin_update_visit(request: Request, visit_id: int, body: VisitUpdate):
    admin = _require_perm(request, "visit:update")
    before = get_visit_by_id(visit_id)
    update_visit(visit_id, body.model_dump())
    _audit_from(admin, "visit.update", request,
                target_type="visit", target_id=visit_id,
                target_label=f"{body.visit_type} #{visit_id}",
                before=before, after=body.model_dump())
    return {"ok": True}


@app.delete("/api/admin/visits/{visit_id}")
def admin_delete_visit(request: Request, visit_id: int):
    admin = _require_perm(request, "visit:delete")
    before = get_visit_by_id(visit_id)
    delete_visit(visit_id)
    _audit_from(admin, "visit.delete", request,
                target_type="visit", target_id=visit_id,
                before=before)
    return {"ok": True}


@app.get("/api/admin/reviews")
def admin_list_reviews(request: Request, status: Optional[str] = None):
    _require_admin(request)
    return get_all_reviews(status=status)


@app.put("/api/admin/reviews/{review_id}/approve")
def admin_approve_review(request: Request, review_id: int):
    admin = _require_perm(request, "review:approve")
    update_review_status(review_id, "approved")
    _audit_from(admin, "review.approve", request,
                target_type="review", target_id=review_id)
    return {"ok": True}


@app.put("/api/admin/reviews/{review_id}/reject")
def admin_reject_review(request: Request, review_id: int):
    admin = _require_perm(request, "review:reject")
    update_review_status(review_id, "rejected")
    _audit_from(admin, "review.reject", request,
                target_type="review", target_id=review_id)
    return {"ok": True}


@app.delete("/api/admin/reviews/{review_id}")
def admin_delete_review(request: Request, review_id: int):
    admin = _require_perm(request, "review:delete")
    delete_review(review_id)
    _audit_from(admin, "review.delete", request,
                target_type="review", target_id=review_id)
    return {"ok": True}


@app.get("/api/admin/techs")
def admin_list_techs(request: Request):
    _require_admin(request)
    return get_all_techs()


@app.post("/api/admin/techs")
def admin_create_tech(request: Request, body: TechCreate):
    admin = _require_perm(request, "tech:create")
    if not body.pin.isdigit() or not (4 <= len(body.pin) <= 8):
        raise HTTPException(400, "PIN must be 4–8 digits")
    if body.role not in ("lead_tech", "tech", "apprentice"):
        raise HTTPException(400, "Invalid tech role")
    try:
        tech_id, prid = create_tech(body.model_dump())
    except Exception as e:
        if "UNIQUE" in str(e):
            raise HTTPException(409, "PRID conflict — try again")
        raise
    _audit_from(admin, "tech.create", request,
                target_type="tech", target_id=tech_id, target_label=prid,
                after={"name": body.name, "tech_code": prid,
                       "role": body.role, "email": body.email})
    return {"id": tech_id, "prid": prid, "tech_code": prid}


@app.put("/api/admin/techs/{tech_id}")
def admin_update_tech(request: Request, tech_id: int, body: TechUpdate):
    admin = _require_perm(request, "tech:update")
    if body.role not in ("lead_tech", "tech", "apprentice"):
        raise HTTPException(400, "Invalid tech role")
    tech = get_tech_by_id(tech_id)
    update_tech(tech_id, body.model_dump())
    _audit_from(admin, "tech.update", request,
                target_type="tech", target_id=tech_id,
                target_label=tech.get("tech_code") if tech else str(tech_id),
                before=tech, after=body.model_dump())
    return {"ok": True}


@app.put("/api/admin/techs/{tech_id}/pin")
def admin_reset_tech_pin(request: Request, tech_id: int, body: TechPinReset):
    admin = _require_perm(request, "tech:reset_pin")
    if not body.pin.isdigit() or not (4 <= len(body.pin) <= 8):
        raise HTTPException(400, "PIN must be 4–8 digits")
    tech = get_tech_by_id(tech_id)
    set_tech_pin(tech_id, body.pin)
    _audit_from(admin, "tech.reset_pin", request,
                target_type="tech", target_id=tech_id,
                target_label=tech.get("tech_code") if tech else str(tech_id))
    return {"ok": True}


@app.delete("/api/admin/techs/{tech_id}")
def admin_delete_tech(request: Request, tech_id: int):
    admin = _require_perm(request, "tech:delete")
    tech = get_tech_by_id(tech_id)
    delete_tech(tech_id)
    _audit_from(admin, "tech.delete", request,
                target_type="tech", target_id=tech_id,
                target_label=tech.get("tech_code") if tech else str(tech_id),
                before=tech)
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


@app.get("/admin/reset")
def admin_reset_page():
    return FileResponse("admin_reset.html")


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
