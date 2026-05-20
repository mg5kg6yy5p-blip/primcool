from contextlib import asynccontextmanager
from datetime import datetime, timezone, timedelta

from typing import Optional, List
from datetime import datetime as _dt
from pathlib import Path
from collections import deque
from threading import Lock
import time
import hmac
import hashlib
import uuid

from fastapi import FastAPI, HTTPException, Request, UploadFile, File, Form, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
import jwt
import os
import io
import base64
import json as _json
import secrets as _secrets
import resend as resend_lib
import pyotp
import qrcode

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
    get_all_parts, get_part_by_id, create_part, update_part, delete_part,
    adjust_part_quantity, get_part_movements,
    create_invoice, update_invoice, get_invoice_by_id, get_all_invoices,
    get_customer_invoices, set_invoice_status, delete_invoice, record_invoice_payment,
    get_visit_parts, add_visit_part, remove_visit_part, get_visit_part_by_id,
    build_invoice_lines_from_visit,
    # Admin users + audit
    verify_admin_user, get_admin_user_by_id, get_all_admin_users,
    create_admin_user, update_admin_user, set_admin_role, set_admin_active,
    set_admin_password, count_active_admins, get_admin_by_email,
    create_admin_password_reset, consume_admin_password_reset,
    set_admin_mfa_pending, activate_admin_mfa, disable_admin_mfa,
    replace_admin_backup_codes, consume_admin_backup_code,
    get_admin_backup_codes_status, _hash_pin,
    create_document, get_document_by_id, query_documents,
    touch_document_accessed, soft_delete_document, hard_delete_document,
    get_expiring_documents,
    log_audit, query_audit_log, verify_audit_chain,
    create_session, get_session_by_jti, is_session_active,
    revoke_session, revoke_all_sessions_for, get_active_sessions_for,
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
        "inventory:view", "inventory:create", "inventory:update",
        "inventory:adjust", "inventory:delete",
        "invoice:view", "invoice:create", "invoice:update", "invoice:delete",
        "invoice:record_payment",
        "documents:upload", "documents:view", "documents:view_highly_sensitive",
        "documents:delete", "documents:delete_highly_sensitive",
    },
    "supervisor_admin": {
        "admin:view_all",
        "tech:update",
        "customer:update",
        "visit:update",
        "audit:view_all",
        "timesheet:view_all",
        "schedule:view", "schedule:edit",
        "inventory:view", "inventory:adjust",
        "invoice:view", "invoice:update", "invoice:record_payment",
        "documents:upload", "documents:view", "documents:view_highly_sensitive",
        "documents:delete",
    },
    "system_admin": {
        "tech:create", "tech:update", "tech:reset_pin",
        "customer:create", "customer:update",
        "visit:create", "visit:update",
        "audit:view_self",
        "timesheet:view_all",
        "schedule:view", "schedule:edit",
        "inventory:view", "inventory:create", "inventory:update", "inventory:adjust",
        "invoice:view", "invoice:create", "invoice:update", "invoice:record_payment",
        "documents:upload", "documents:view",
    },
    "hr_admin": {
        "tech:create", "tech:update", "tech:reset_pin",
        "audit:view_self",
        "timesheet:view_all",
        "documents:upload", "documents:view", "documents:view_highly_sensitive",
    },
    "ceo_assistant": {
        "audit:view_self",
        "inventory:view",
        "invoice:view",
        "documents:view",
    },
}


def _admin_can(role: str, perm: str) -> bool:
    return perm in ADMIN_PERMS.get(role, set())

PHOTOS_DIR = Path(os.environ.get("PHOTOS_DIR", "uploads/photos"))
PHOTOS_DIR.mkdir(parents=True, exist_ok=True)
MAX_PHOTO_SIZE = 12 * 1024 * 1024  # 12 MB
ALLOWED_PHOTO_EXTS = {".jpg", ".jpeg", ".png", ".webp", ".heic"}

# ── Document Management System ────────────────────────────────────────────────
DOCUMENTS_DIR = Path(os.environ.get("DOCUMENTS_DIR", "uploads/documents"))
DOC_TIERS = ("public", "confidential", "highly_sensitive")
for _tier in DOC_TIERS:
    (DOCUMENTS_DIR / _tier).mkdir(parents=True, exist_ok=True)

MAX_DOC_SIZE = int(os.environ.get("MAX_DOC_SIZE_BYTES", str(25 * 1024 * 1024)))   # 25 MB
ALLOWED_DOC_EXTS = {
    ".jpg", ".jpeg", ".png", ".webp", ".heic", ".gif",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".txt", ".csv",
}
# Map file extension → expected magic-byte prefixes (for cheap content-type sanity check).
_DOC_MAGIC = {
    ".jpg":  [b"\xff\xd8\xff"],
    ".jpeg": [b"\xff\xd8\xff"],
    ".png":  [b"\x89PNG\r\n\x1a\n"],
    ".pdf":  [b"%PDF-"],
    ".gif":  [b"GIF87a", b"GIF89a"],
    ".docx": [b"PK\x03\x04"],   # zip-based office formats
    ".xlsx": [b"PK\x03\x04"],
    # extensions we don't sniff are accepted as-is (txt, csv, doc, xls, webp, heic)
}

DOC_TYPES = (
    "id", "trn", "nis", "drivers_license", "passport", "police_record",
    "certificate", "contract", "insurance", "invoice_receipt",
    "service_report", "photo", "other",
)
# Document types that are always Highly Sensitive — enforced server-side
HIGHLY_SENSITIVE_TYPES = {"trn", "passport", "police_record", "id", "nis"}


def _validate_doc_upload(filename: str, body: bytes) -> tuple:
    """Returns (ext, mime_type_guess). Raises HTTPException on failure."""
    if not filename:
        raise HTTPException(400, "Missing filename")
    safe = filename.replace("\\", "/").split("/")[-1]
    if not safe or safe.startswith(".") or len(safe) > 255:
        raise HTTPException(400, "Invalid filename")
    ext = Path(safe).suffix.lower()
    if ext not in ALLOWED_DOC_EXTS:
        raise HTTPException(400, f"File type {ext or '(none)'} not allowed")
    if len(body) > MAX_DOC_SIZE:
        raise HTTPException(413, f"File too large (max {MAX_DOC_SIZE // (1024*1024)} MB)")
    if len(body) == 0:
        raise HTTPException(400, "Empty file")
    # Magic-byte sniff for the formats we know
    if ext in _DOC_MAGIC:
        if not any(body.startswith(prefix) for prefix in _DOC_MAGIC[ext]):
            raise HTTPException(400, f"File content does not match a {ext} file")
    # Virus scan hook (stubbed). Wire to ClamAV daemon by setting CLAMD_HOST / CLAMD_PORT.
    # See https://github.com/CISOfy/python-clamd — out of scope for v1.
    mime = {
        ".pdf":  "application/pdf",
        ".jpg":  "image/jpeg", ".jpeg": "image/jpeg",
        ".png":  "image/png",  ".gif":  "image/gif",  ".webp": "image/webp", ".heic": "image/heic",
        ".doc":  "application/msword",
        ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        ".xls":  "application/vnd.ms-excel",
        ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        ".txt":  "text/plain", ".csv": "text/csv",
    }.get(ext, "application/octet-stream")
    return ext, mime


def _sign_document_url(stored_filename: str, tier: str, ttl_seconds: int = 600) -> str:
    """Same HMAC scheme as photos. 10-min default expiry for documents."""
    expires = int(time.time()) + ttl_seconds
    payload = f"doc:{tier}:{stored_filename}:{expires}"
    sig = hmac.new(PHOTO_URL_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()[:32]
    return f"/documents/{tier}/{stored_filename}?exp={expires}&sig={sig}"


def _verify_document_signature(stored_filename: str, tier: str, expires: int, sig: str) -> bool:
    if int(time.time()) > expires:
        return False
    payload = f"doc:{tier}:{stored_filename}:{expires}"
    expected = hmac.new(PHOTO_URL_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()[:32]
    return hmac.compare_digest(sig, expected)

INVOICE_CURRENCY = os.environ.get("INVOICE_CURRENCY", "JMD")
INVOICE_TAX_RATE = float(os.environ.get("INVOICE_TAX_RATE", "0.15"))   # Jamaica GCT standard

# ── Rate limiting (in-memory sliding window) ──────────────────────────────────
# Buckets reset on process restart. Single-process deployments only.
_rate_buckets: dict = {}
_rate_lock = Lock()


def _client_ip(request: Request) -> str:
    # Honor X-Forwarded-For when behind a proxy (Railway sets this)
    fwd = request.headers.get("x-forwarded-for", "")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.client.host if request.client else "?"


def _rate_check(key: str, max_attempts: int, window_seconds: int) -> bool:
    """Returns True if the request is allowed; False if it exceeds the limit.
    Records the attempt timestamp on success."""
    now = time.time()
    cutoff = now - window_seconds
    with _rate_lock:
        bucket = _rate_buckets.setdefault(key, deque())
        while bucket and bucket[0] < cutoff:
            bucket.popleft()
        if len(bucket) >= max_attempts:
            return False
        bucket.append(now)
        return True


def _enforce_login_rate(request: Request, identity: str = ""):
    """Raises 429 if too many login attempts from this IP+identity within window."""
    ip = _client_ip(request)
    key = f"login:{ip}:{identity.lower()}"
    if not _rate_check(key, max_attempts=8, window_seconds=15 * 60):
        raise HTTPException(
            status_code=429,
            detail="Too many sign-in attempts. Please wait 15 minutes and try again.",
        )


# Signed photo URL helpers are defined further down — after JWT_SECRET.

# Jamaica tax reference — values change annually, verify with Tax Administration Jamaica (TAJ).
# Used to auto-fill invoice GCT and as a reference for future payroll calculations.
JAMAICA_TAX_REFERENCE = {
    "currency": "JMD",
    "currency_symbol": "J$",
    "gct": {
        "standard_rate": 0.15,
        "tourism_rate":  0.10,
        "label":         "General Consumption Tax (GCT)",
    },
    "payroll": {
        "paye": {
            "annual_threshold":   1_700_000,  # tax-free annual income
            "band1_rate":         0.25,        # threshold → ~JMD 6M
            "band2_rate":         0.30,        # above ~JMD 6M
            "band2_min_annual":   6_000_000,
            "label":              "Pay-As-You-Earn (PAYE)",
        },
        "nis": {
            "employee_rate":      0.03,
            "employer_rate":      0.03,
            "label":              "National Insurance Scheme (NIS)",
        },
        "nht": {
            "employee_rate":      0.02,
            "employer_rate":      0.03,
            "label":              "National Housing Trust (NHT)",
        },
        "education_tax": {
            "employee_rate":      0.0225,
            "employer_rate":      0.035,
            "label":              "Education Tax",
        },
        "heart_trust": {
            "employer_rate":      0.03,
            "label":              "HEART Trust NTA",
        },
    },
    "disclaimer": "Rates above reflect publicly known Jamaica statutory rates and change annually. "
                  "Verify current rates with Tax Administration Jamaica (TAJ) before use.",
    "source":     "https://www.jamaicatax.gov.jm",
}

TIER_LABELS = {
    "residential": "Residential — Home & Property",
    "commercial":  "Commercial — SME & Corporate",
    "industrial":  "Industrial — Process & Facility",
    "unsure":      "Not sure — need an assessment",
}

JWT_SECRET    = os.environ.get("JWT_SECRET", "change-me-in-production-set-JWT_SECRET-env-var")
JWT_ALGORITHM = "HS256"
COOKIE_SECURE = os.environ.get("COOKIE_SECURE", "false").lower() == "true"  # set to true in prod (HTTPS)

COOKIE_ADMIN    = "pc_admin_session"
COOKIE_TECH     = "pc_tech_session"
COOKIE_CUSTOMER = "pc_customer_session"

PHOTO_URL_SECRET  = os.environ.get("PHOTO_URL_SECRET", JWT_SECRET)
PHOTO_URL_TTL_SEC = int(os.environ.get("PHOTO_URL_TTL_SEC", "1800"))   # 30 min default

MFA_ISSUER       = os.environ.get("MFA_ISSUER", "PrimeCool Services")
MFA_TOKEN_TTL    = timedelta(minutes=5)   # short-lived pre-MFA token


def _generate_backup_codes(n: int = 10):
    """Returns (plaintext_codes, hashed_codes). Plaintext shown to user once; hashed stored."""
    plain = []
    for _ in range(n):
        raw = _secrets.token_hex(4).upper()
        plain.append(f"{raw[:4]}-{raw[4:]}")
    hashed = [_hash_pin(c) for c in plain]
    return plain, hashed


def _verify_admin_totp_or_backup(admin: dict, code: str) -> bool:
    code = (code or "").strip().replace(" ", "").upper()
    if not code:
        return False
    # TOTP path (6 digits)
    if admin.get("mfa_secret"):
        totp = pyotp.TOTP(admin["mfa_secret"])
        if totp.verify(code, valid_window=1):
            return True
    # Backup code path (formatted like XXXX-XXXX)
    if "-" in code and admin.get("backup_codes"):
        if consume_admin_backup_code(admin["id"], code):
            return True
    return False


def _sign_photo_url(filename: str, ttl_seconds: int = None) -> str:
    ttl = ttl_seconds if ttl_seconds is not None else PHOTO_URL_TTL_SEC
    expires = int(time.time()) + ttl
    payload = f"{filename}:{expires}"
    sig = hmac.new(PHOTO_URL_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()[:32]
    return f"/photos/{filename}?exp={expires}&sig={sig}"


def _verify_photo_signature(filename: str, expires: int, sig: str) -> bool:
    if int(time.time()) > expires:
        return False
    payload = f"{filename}:{expires}"
    expected = hmac.new(PHOTO_URL_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()[:32]
    return hmac.compare_digest(sig, expected)


def _enrich_photos(photos: list) -> list:
    """Adds a freshly signed `url` to each photo dict."""
    out = []
    for p in (photos or []):
        p = dict(p)
        if p.get("filename"):
            p["url"] = _sign_photo_url(p["filename"])
        out.append(p)
    return out


def _make_token(payload: dict, expires: timedelta) -> str:
    return jwt.encode(
        {**payload, "exp": datetime.now(timezone.utc) + expires},
        JWT_SECRET, algorithm=JWT_ALGORITHM,
    )


def _issue_session(subject_type: str, subject_id: int, expires: timedelta,
                   request: Request, extra_claims: dict = None) -> tuple:
    """Creates a session row, embeds its jti in a JWT, and returns (token, jti).
    Use this for any session-bearing login. Pre-MFA tokens skip this."""
    jti = uuid.uuid4().hex
    now = datetime.now(timezone.utc)
    exp_at = now + expires
    claims = {
        "sub":  str(subject_id),
        "type": subject_type,
        "jti":  jti,
    }
    if extra_claims:
        claims.update(extra_claims)
    token = _make_token(claims, expires)
    create_session(
        jti=jti,
        subject_type=subject_type,
        subject_id=subject_id,
        expires_at=exp_at.isoformat(),
        ip_address=_client_ip(request),
        user_agent=(request.headers.get("user-agent", "") or "")[:255],
    )
    return token, jti


def _set_session_cookie(response: Response, name: str, token: str, max_age_seconds: int):
    """Sets an HttpOnly + SameSite=Strict session cookie."""
    response.set_cookie(
        key=name,
        value=token,
        max_age=max_age_seconds,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite="strict",
        path="/",
    )


def _clear_session_cookie(response: Response, name: str):
    response.delete_cookie(name, path="/", samesite="strict")


def _read_token(request: Request, cookie_name: str) -> Optional[str]:
    """Reads JWT from HttpOnly cookie first, then falls back to Authorization header."""
    cookie = request.cookies.get(cookie_name)
    if cookie:
        return cookie
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return auth[7:]
    return None


def _decode_token(token: str, expected_type: str, require_session: bool = True) -> dict:
    if not token:
        raise HTTPException(401, "Unauthorized")
    try:
        data = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(401, "Session expired")
    except jwt.InvalidTokenError:
        raise HTTPException(401, "Invalid session")
    if data.get("type") != expected_type:
        raise HTTPException(403, "Forbidden")
    # Server-side session check — a JWT whose row has been revoked or
    # never existed (legacy token from before this change) is rejected.
    if require_session:
        jti = data.get("jti")
        if not jti or not is_session_active(jti):
            raise HTTPException(401, "Session no longer valid — please sign in again")
    return data


def _require_customer(request: Request) -> int:
    data = _decode_token(_read_token(request, COOKIE_CUSTOMER), "customer")
    return int(data["sub"])


def _require_tech(request: Request) -> int:
    data = _decode_token(_read_token(request, COOKIE_TECH), "tech")
    return int(data["sub"])


def _require_admin(request: Request):
    """Returns the admin_user dict for the authenticated admin."""
    data = _decode_token(_read_token(request, COOKIE_ADMIN), "admin")
    admin_id = data.get("sub")
    if not admin_id:
        raise HTTPException(401, "Invalid session")
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
# /photos is intentionally NOT mounted as public static — it serves through
# /photos/{filename} below, which verifies a short-lived signature.
app.mount("/icons",  StaticFiles(directory="icons"),  name="icons")


@app.get("/photos/{filename}")
def serve_photo(filename: str, exp: int = 0, sig: str = ""):
    """Time-limited, signed photo access. URLs are generated server-side by
    _sign_photo_url() and embedded in API responses. Anyone with the URL has
    access until the expiry timestamp; refresh by re-fetching the parent
    resource."""
    # Block any path-traversal attempt
    if "/" in filename or ".." in filename or filename.startswith("."):
        raise HTTPException(400, "Invalid filename")
    if not exp or not sig or not _verify_photo_signature(filename, exp, sig):
        raise HTTPException(403, "Link expired or invalid")
    path = PHOTOS_DIR / filename
    if not path.exists():
        raise HTTPException(404, "Photo not found")
    return FileResponse(str(path))

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


class MfaVerify(BaseModel):
    mfa_token: str
    code:      str    # 6-digit TOTP or backup code


class MfaActivate(BaseModel):
    code: str


class MfaDisable(BaseModel):
    password: str
    code:     str    # current TOTP or backup code


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
    pin:         str
    name:        str
    phone:       str = ""
    email:       str = ""
    role:        str = "tech"   # 'lead_tech' | 'tech' | 'apprentice'
    hire_date:   str = ""
    hourly_rate: float = 0


class TechUpdate(BaseModel):
    name:        str
    phone:       str = ""
    email:       str = ""
    role:        str = "tech"
    hourly_rate: float = 0
    active:      bool = True


class TechAddPart(BaseModel):
    part_id:  int
    quantity: float
    notes:    str = ""


class TechPinReset(BaseModel):
    pin: str


class TechCompleteVisit(BaseModel):
    work_done:      str = ""
    parts_replaced: str = ""
    notes:          str = ""


class PartCreate(BaseModel):
    sku:           str
    name:          str
    description:   str = ""
    category:      str = ""
    unit:          str = "each"
    unit_cost:     float = 0
    quantity:      float = 0
    reorder_point: float = 0
    supplier:      str = ""


class PartUpdate(BaseModel):
    name:          str
    description:   str = ""
    category:      str = ""
    unit:          str = "each"
    unit_cost:     float = 0
    reorder_point: float = 0
    supplier:      str = ""
    active:        bool = True


class PartAdjust(BaseModel):
    movement_type:  str           # 'received' | 'used' | 'adjusted'
    quantity_delta: float          # signed: +receive, -use, ±adjust
    reason:         str = ""
    visit_id:       Optional[int] = None


class InvoiceLineItem(BaseModel):
    line_type:   str            # 'labor' | 'part' | 'other'
    part_id:     Optional[int] = None
    description: str
    quantity:    float = 1
    unit_price:  float = 0


class InvoiceCreate(BaseModel):
    customer_id: int
    visit_id:    Optional[int] = None
    issue_date:  str
    due_date:    str
    tax_rate:    float = 0.15
    currency:    str = "JMD"
    notes:       str = ""
    line_items:  List[InvoiceLineItem] = []


class InvoiceUpdate(BaseModel):
    customer_id: int
    visit_id:    Optional[int] = None
    issue_date:  str
    due_date:    str
    tax_rate:    float = 0.15
    notes:       str = ""
    line_items:  List[InvoiceLineItem] = []


class InvoiceStatusChange(BaseModel):
    status: str   # 'draft' | 'sent' | 'paid' | 'cancelled'


class InvoicePayment(BaseModel):
    payment_date: str
    amount:       float
    method:       str = ""
    reference:    str = ""
    notes:        str = ""


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
def portal_login(req: PortalLoginRequest, request: Request, response: Response):
    _enforce_login_rate(request, req.code)
    customer = verify_customer(req.code, req.pin)
    if not customer:
        existing = get_customer_by_code(req.code)
        if existing and not existing.get("pin_hash"):
            raise HTTPException(403, "No PIN set on your account yet. Please contact PrimeCool to set one up.")
        raise HTTPException(401, "Invalid customer ID or PIN")
    token, _ = _issue_session("customer", customer["id"], timedelta(days=30), request)
    _set_session_cookie(response, COOKIE_CUSTOMER, token, 30 * 24 * 3600)
    return {"token": token, "name": customer["name"]}


@app.post("/api/portal/logout")
def portal_logout(request: Request, response: Response):
    token = _read_token(request, COOKIE_CUSTOMER)
    if token:
        try:
            data = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM],
                              options={"verify_exp": False})
            if data.get("jti"):
                revoke_session(data["jti"])
        except Exception:
            pass
    _clear_session_cookie(response, COOKIE_CUSTOMER)
    return {"ok": True}


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
        v["photos"] = _enrich_photos(get_visit_photos(v["id"]))
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
def tech_login(req: TechLogin, request: Request, response: Response):
    _enforce_login_rate(request, req.tech_code)
    tech = verify_tech(req.tech_code, req.pin)
    if not tech:
        raise HTTPException(401, "Invalid tech code or PIN")
    token, _ = _issue_session("tech", tech["id"], timedelta(days=7), request)
    _set_session_cookie(response, COOKIE_TECH, token, 7 * 24 * 3600)
    return {"token": token, "name": tech["name"], "tech_code": tech["tech_code"]}


@app.post("/api/tech/logout")
def tech_logout(request: Request, response: Response):
    token = _read_token(request, COOKIE_TECH)
    if token:
        try:
            data = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM],
                              options={"verify_exp": False})
            if data.get("jti"):
                revoke_session(data["jti"])
        except Exception:
            pass
    _clear_session_cookie(response, COOKIE_TECH)
    return {"ok": True}


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
        j["photos"] = _enrich_photos(get_visit_photos(j["id"]))
    return {
        "tech": {"id": tech["id"], "name": tech["name"], "tech_code": tech["tech_code"]},
        "jobs": jobs,
    }


@app.get("/api/tech/jobs/{visit_id}")
def tech_get_job(request: Request, visit_id: int):
    tech_id = _require_tech(request)
    visit   = get_visit_by_id(visit_id, with_parts=True)
    if not visit or visit.get("assigned_tech_id") != tech_id:
        raise HTTPException(404, "Job not found")
    visit["photos"] = _enrich_photos(get_visit_photos(visit_id))
    return visit


@app.get("/api/tech/parts")
def tech_parts_catalog(request: Request):
    _require_tech(request)
    # Only active parts
    return [p for p in get_all_parts() if p.get("active")]


@app.post("/api/tech/jobs/{visit_id}/parts")
def tech_add_part(request: Request, visit_id: int, body: TechAddPart):
    tech_id = _require_tech(request)
    visit = get_visit_by_id(visit_id)
    if not visit or visit.get("assigned_tech_id") != tech_id:
        raise HTTPException(404, "Job not found")
    if visit["status"] == "completed":
        raise HTTPException(400, "Cannot add parts after job is completed")
    tech = get_tech_by_id(tech_id)
    try:
        vp_id = add_visit_part(
            visit_id, body.part_id, body.quantity,
            added_by_tech_id=tech_id,
            notes=body.notes,
            tech_prid=tech.get("prid") if tech else None,
            tech_label=tech.get("name") if tech else None,
        )
    except ValueError as e:
        raise HTTPException(400, str(e))
    return {"id": vp_id}


@app.delete("/api/tech/jobs/{visit_id}/parts/{vp_id}")
def tech_remove_part(request: Request, visit_id: int, vp_id: int):
    tech_id = _require_tech(request)
    visit = get_visit_by_id(visit_id)
    if not visit or visit.get("assigned_tech_id") != tech_id:
        raise HTTPException(404, "Job not found")
    vp = get_visit_part_by_id(vp_id)
    if not vp or vp["visit_id"] != visit_id:
        raise HTTPException(404, "Visit part not found")
    tech = get_tech_by_id(tech_id)
    remove_visit_part(
        vp_id,
        removed_by_tech_id=tech_id,
        tech_prid=tech.get("prid") if tech else None,
        tech_label=tech.get("name") if tech else None,
    )
    return {"ok": True}


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
    return {"id": photo_id, "filename": fname, "url": _sign_photo_url(fname), "category": category}


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
def admin_login(req: AdminLoginRequest, request: Request, response: Response):
    if not req.username:
        raise HTTPException(400, "Username is required")
    _enforce_login_rate(request, req.username)
    admin = verify_admin_user(req.username, req.password)
    if not admin:
        raise HTTPException(401, "Invalid username or password")
    if not admin.get("active"):
        raise HTTPException(403, "Account is deactivated")

    # MFA gate
    if admin.get("mfa_enabled"):
        # Step 1 of two-step login — return a short-lived MFA token,
        # NO session cookie set yet.
        mfa_token = _make_token(
            {"sub": str(admin["id"]), "type": "admin_pre_mfa"},
            MFA_TOKEN_TTL,
        )
        log_audit(
            actor_type="admin", actor_id=admin["id"],
            actor_prid=admin.get("prid"), actor_label=admin.get("name"),
            actor_role=admin.get("role"), action="admin.login.password_ok",
            ip_address=_client_ip(request),
        )
        return {"requires_mfa": True, "mfa_token": mfa_token, "name": admin["name"]}

    token, _ = _issue_session("admin", admin["id"], timedelta(hours=12), request)
    _set_session_cookie(response, COOKIE_ADMIN, token, 12 * 3600)
    log_audit(
        actor_type="admin", actor_id=admin["id"],
        actor_prid=admin.get("prid"), actor_label=admin.get("name"),
        actor_role=admin.get("role"), action="admin.login",
        ip_address=_client_ip(request),
    )
    return {
        "token":    token,
        "name":     admin["name"],
        "username": admin["username"],
        "role":     admin["role"],
        "prid":     admin.get("prid"),
        "requires_mfa": False,
    }


@app.post("/api/admin/mfa/verify")
def admin_mfa_verify(body: MfaVerify, request: Request, response: Response):
    # Decode the pre-MFA token
    try:
        data = jwt.decode(body.mfa_token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(401, "MFA window expired — please sign in again")
    except jwt.InvalidTokenError:
        raise HTTPException(401, "Invalid MFA token")
    if data.get("type") != "admin_pre_mfa":
        raise HTTPException(403, "Forbidden")

    _enforce_login_rate(request, f"mfa:{data.get('sub','')}")

    admin_id = int(data["sub"])
    admin = get_admin_user_by_id(admin_id)
    if not admin or not admin.get("active") or not admin.get("mfa_enabled"):
        raise HTTPException(401, "MFA not configured")

    if not _verify_admin_totp_or_backup(admin, body.code):
        log_audit(
            actor_type="admin", actor_id=admin["id"],
            actor_prid=admin.get("prid"), actor_label=admin.get("name"),
            actor_role=admin.get("role"), action="admin.mfa.fail",
            ip_address=_client_ip(request),
        )
        raise HTTPException(401, "Incorrect code")

    token, _ = _issue_session("admin", admin["id"], timedelta(hours=12), request)
    _set_session_cookie(response, COOKIE_ADMIN, token, 12 * 3600)
    log_audit(
        actor_type="admin", actor_id=admin["id"],
        actor_prid=admin.get("prid"), actor_label=admin.get("name"),
        actor_role=admin.get("role"), action="admin.login.mfa_ok",
        ip_address=_client_ip(request),
    )
    return {
        "token":    token,
        "name":     admin["name"],
        "username": admin["username"],
        "role":     admin["role"],
        "prid":     admin.get("prid"),
        "requires_mfa": False,
    }


@app.get("/api/admin/mfa/status")
def admin_mfa_status(request: Request):
    admin = _require_admin(request)
    return {
        "enabled": bool(admin.get("mfa_enabled")),
        "backup_codes": get_admin_backup_codes_status(admin["id"]),
    }


@app.post("/api/admin/mfa/setup")
def admin_mfa_setup(request: Request):
    """Generates a candidate secret + QR code. Does NOT enable MFA until /activate."""
    admin = _require_admin(request)
    if admin.get("mfa_enabled"):
        raise HTTPException(400, "MFA is already enabled. Disable it first to re-enroll.")
    secret = pyotp.random_base32()
    set_admin_mfa_pending(admin["id"], secret)
    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(name=admin["email"], issuer_name=MFA_ISSUER)
    # Generate QR PNG → base64 data URI
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    qr_data_uri = f"data:image/png;base64,{base64.b64encode(buf.getvalue()).decode()}"
    return {
        "secret":           secret,        # for manual entry if QR doesn't scan
        "provisioning_uri": uri,
        "qr_data_uri":      qr_data_uri,
        "issuer":           MFA_ISSUER,
        "account":          admin["email"],
    }


@app.post("/api/admin/mfa/activate")
def admin_mfa_activate(request: Request, body: MfaActivate):
    """Verifies the user can produce a code from the candidate secret,
    then enables MFA and returns one-time backup codes."""
    admin = _require_admin(request)
    if admin.get("mfa_enabled"):
        raise HTTPException(400, "MFA is already enabled")
    if not admin.get("mfa_secret"):
        raise HTTPException(400, "No setup in progress — call /mfa/setup first")
    totp = pyotp.TOTP(admin["mfa_secret"])
    if not totp.verify((body.code or "").strip(), valid_window=1):
        raise HTTPException(401, "Incorrect code — check your authenticator app and try again")
    plain, hashed = _generate_backup_codes(10)
    activate_admin_mfa(admin["id"], hashed)
    _audit_from(admin, "admin.mfa.activated", request,
                target_type="admin", target_id=admin["id"], target_label=admin["username"])
    return {"ok": True, "backup_codes": plain}


@app.post("/api/admin/mfa/regenerate-backup-codes")
def admin_mfa_regenerate(request: Request, body: MfaVerify):
    """Generates a new set of 10 backup codes (invalidates the old). Requires
    a current TOTP or unused backup code to prevent silent compromise."""
    admin = _require_admin(request)
    if not admin.get("mfa_enabled"):
        raise HTTPException(400, "MFA is not enabled")
    if not _verify_admin_totp_or_backup(admin, body.code):
        raise HTTPException(401, "Incorrect code")
    plain, hashed = _generate_backup_codes(10)
    replace_admin_backup_codes(admin["id"], hashed)
    _audit_from(admin, "admin.mfa.backup_regenerated", request,
                target_type="admin", target_id=admin["id"], target_label=admin["username"])
    return {"ok": True, "backup_codes": plain}


@app.post("/api/admin/mfa/disable")
def admin_mfa_disable(request: Request, body: MfaDisable):
    """Requires both the password AND a current TOTP/backup code."""
    admin = _require_admin(request)
    if not admin.get("mfa_enabled"):
        raise HTTPException(400, "MFA is not enabled")
    # Re-verify the password
    from database import _verify_password
    if not _verify_password(body.password, admin["password_hash"]):
        raise HTTPException(401, "Incorrect password")
    if not _verify_admin_totp_or_backup(admin, body.code):
        raise HTTPException(401, "Incorrect MFA code")
    disable_admin_mfa(admin["id"])
    _audit_from(admin, "admin.mfa.disabled", request,
                target_type="admin", target_id=admin["id"], target_label=admin["username"])
    return {"ok": True}


@app.post("/api/admin/logout")
def admin_logout(request: Request, response: Response):
    # Log the logout if a valid session exists (best-effort)
    admin = None
    try:
        admin = _require_admin(request)
        log_audit(
            actor_type="admin", actor_id=admin["id"],
            actor_prid=admin.get("prid"), actor_label=admin.get("name"),
            actor_role=admin.get("role"), action="admin.logout",
            ip_address=_client_ip(request),
        )
    except Exception:
        pass
    # Revoke the session row so the JWT can't be reused
    token = _read_token(request, COOKIE_ADMIN)
    if token:
        try:
            data = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM],
                              options={"verify_exp": False})
            if data.get("jti"):
                revoke_session(data["jti"])
        except Exception:
            pass
    _clear_session_cookie(response, COOKIE_ADMIN)
    return {"ok": True}


@app.post("/api/admin/logout-everywhere")
def admin_logout_everywhere(request: Request, response: Response):
    """Revokes all of the current admin's active sessions on every device."""
    admin = _require_admin(request)
    n = revoke_all_sessions_for("admin", admin["id"])
    _clear_session_cookie(response, COOKIE_ADMIN)
    log_audit(
        actor_type="admin", actor_id=admin["id"],
        actor_prid=admin.get("prid"), actor_label=admin.get("name"),
        actor_role=admin.get("role"), action="admin.logout_everywhere",
        ip_address=_client_ip(request),
        after_value={"revoked_count": n},
    )
    return {"ok": True, "revoked": n}


@app.get("/api/admin/sessions")
def admin_list_sessions(request: Request):
    """Returns the current admin's own active sessions."""
    admin = _require_admin(request)
    rows = get_active_sessions_for("admin", admin["id"])
    # Mark the current session
    current_jti = None
    token = _read_token(request, COOKIE_ADMIN)
    if token:
        try:
            data = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM],
                              options={"verify_exp": False})
            current_jti = data.get("jti")
        except Exception:
            pass
    for r in rows:
        r["is_current"] = (r["jti"] == current_jti)
    return rows


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


# ── Inventory ────────────────────────────────────────────────────────────────

@app.get("/api/admin/parts")
def admin_list_parts(request: Request, include_inactive: bool = False):
    _require_perm(request, "inventory:view")
    return get_all_parts(include_inactive=include_inactive)


@app.post("/api/admin/parts")
def admin_create_part(request: Request, body: PartCreate):
    admin = _require_perm(request, "inventory:create")
    if body.quantity < 0 or body.reorder_point < 0 or body.unit_cost < 0:
        raise HTTPException(400, "Quantities and cost must be non-negative")
    try:
        part_id = create_part(body.model_dump())
    except Exception as e:
        if "UNIQUE" in str(e):
            raise HTTPException(409, "SKU already exists")
        raise
    # Record the initial stock as a 'received' movement if non-zero
    if body.quantity > 0:
        adjust_part_quantity(
            part_id, "received", 0,  # 0 delta because create_part already stored it
            reason="Initial stock on creation",
            performed_by_type="admin", performed_by_id=admin["id"],
            performed_by_prid=admin.get("prid"), performed_by_label=admin.get("name"),
        )
    _audit_from(admin, "inventory.create", request,
                target_type="part", target_id=part_id, target_label=body.sku,
                after=body.model_dump())
    return {"id": part_id}


@app.put("/api/admin/parts/{part_id}")
def admin_update_part(request: Request, part_id: int, body: PartUpdate):
    admin = _require_perm(request, "inventory:update")
    before = get_part_by_id(part_id)
    if not before:
        raise HTTPException(404, "Part not found")
    update_part(part_id, body.model_dump())
    _audit_from(admin, "inventory.update", request,
                target_type="part", target_id=part_id, target_label=before["sku"],
                before=before, after=body.model_dump())
    return {"ok": True}


@app.delete("/api/admin/parts/{part_id}")
def admin_delete_part(request: Request, part_id: int):
    admin = _require_perm(request, "inventory:delete")
    before = get_part_by_id(part_id)
    if not before:
        raise HTTPException(404, "Part not found")
    delete_part(part_id)
    _audit_from(admin, "inventory.delete", request,
                target_type="part", target_id=part_id,
                target_label=before["sku"], before=before)
    return {"ok": True}


@app.post("/api/admin/parts/{part_id}/adjust")
def admin_adjust_part(request: Request, part_id: int, body: PartAdjust):
    admin = _require_perm(request, "inventory:adjust")
    if body.movement_type not in ("received", "used", "adjusted"):
        raise HTTPException(400, "movement_type must be received, used, or adjusted")
    part = get_part_by_id(part_id)
    if not part:
        raise HTTPException(404, "Part not found")
    try:
        result = adjust_part_quantity(
            part_id,
            body.movement_type,
            body.quantity_delta,
            reason=body.reason,
            visit_id=body.visit_id,
            performed_by_type="admin",
            performed_by_id=admin["id"],
            performed_by_prid=admin.get("prid"),
            performed_by_label=admin.get("name"),
        )
    except ValueError as e:
        raise HTTPException(400, str(e))
    _audit_from(admin, f"inventory.{body.movement_type}", request,
                target_type="part", target_id=part_id, target_label=part["sku"],
                before={"quantity": part["quantity"]},
                after={"quantity": result["new_quantity"], "delta": body.quantity_delta,
                       "reason": body.reason})
    return result


@app.get("/api/admin/parts/{part_id}/movements")
def admin_part_movements(request: Request, part_id: int):
    _require_perm(request, "inventory:view")
    return get_part_movements(part_id)


# ── Invoices ─────────────────────────────────────────────────────────────────

@app.get("/api/admin/tax-reference")
def admin_tax_reference(request: Request):
    _require_admin(request)
    return JAMAICA_TAX_REFERENCE


@app.get("/api/admin/visits/{visit_id}/invoice-prefill")
def admin_invoice_prefill(request: Request, visit_id: int):
    _require_perm(request, "invoice:create")
    payload = build_invoice_lines_from_visit(visit_id)
    if not payload:
        raise HTTPException(404, "Visit not found")
    return payload


@app.get("/api/admin/visits/{visit_id}/parts")
def admin_visit_parts(request: Request, visit_id: int):
    _require_perm(request, "visit:update")
    return get_visit_parts(visit_id)


@app.get("/api/admin/invoices")
def admin_list_invoices(request: Request, status: Optional[str] = None):
    _require_perm(request, "invoice:view")
    return get_all_invoices(status=status)


@app.get("/api/admin/invoices/{invoice_id}")
def admin_get_invoice(request: Request, invoice_id: int):
    _require_perm(request, "invoice:view")
    inv = get_invoice_by_id(invoice_id)
    if not inv:
        raise HTTPException(404, "Invoice not found")
    return inv


@app.post("/api/admin/invoices")
def admin_create_invoice(request: Request, body: InvoiceCreate):
    admin = _require_perm(request, "invoice:create")
    data = body.model_dump()
    data["line_items"] = [li if isinstance(li, dict) else li.model_dump()
                          for li in data.get("line_items", [])]
    invoice_id = create_invoice(data, created_by=admin["id"])
    inv = get_invoice_by_id(invoice_id, with_lines=False)
    _audit_from(admin, "invoice.create", request,
                target_type="invoice", target_id=invoice_id,
                target_label=inv["invoice_number"],
                after={"customer_id": body.customer_id, "total": inv["total"]})
    return {"id": invoice_id, "invoice_number": inv["invoice_number"]}


@app.put("/api/admin/invoices/{invoice_id}")
def admin_update_invoice(request: Request, invoice_id: int, body: InvoiceUpdate):
    admin = _require_perm(request, "invoice:update")
    before = get_invoice_by_id(invoice_id, with_lines=False)
    if not before:
        raise HTTPException(404, "Invoice not found")
    if before["status"] not in ("draft", "sent"):
        raise HTTPException(400, f"Cannot edit a {before['status']} invoice")
    data = body.model_dump()
    data["line_items"] = [li if isinstance(li, dict) else li.model_dump()
                          for li in data.get("line_items", [])]
    update_invoice(invoice_id, data)
    after = get_invoice_by_id(invoice_id, with_lines=False)
    _audit_from(admin, "invoice.update", request,
                target_type="invoice", target_id=invoice_id,
                target_label=before["invoice_number"],
                before={"total": before["total"]},
                after={"total": after["total"]})
    return {"ok": True}


@app.put("/api/admin/invoices/{invoice_id}/status")
def admin_invoice_status(request: Request, invoice_id: int, body: InvoiceStatusChange):
    admin = _require_perm(request, "invoice:update")
    inv = get_invoice_by_id(invoice_id, with_lines=False)
    if not inv:
        raise HTTPException(404, "Invoice not found")
    if body.status not in ("draft", "sent", "paid", "cancelled"):
        raise HTTPException(400, "Invalid status")
    set_invoice_status(invoice_id, body.status)
    _audit_from(admin, f"invoice.{body.status}", request,
                target_type="invoice", target_id=invoice_id,
                target_label=inv["invoice_number"],
                before={"status": inv["status"]}, after={"status": body.status})
    return {"ok": True}


@app.delete("/api/admin/invoices/{invoice_id}")
def admin_delete_invoice(request: Request, invoice_id: int):
    admin = _require_perm(request, "invoice:delete")
    inv = get_invoice_by_id(invoice_id, with_lines=False)
    if not inv:
        raise HTTPException(404, "Invoice not found")
    if inv["status"] not in ("draft", "cancelled"):
        raise HTTPException(400, "Only draft or cancelled invoices can be deleted")
    delete_invoice(invoice_id)
    _audit_from(admin, "invoice.delete", request,
                target_type="invoice", target_id=invoice_id,
                target_label=inv["invoice_number"], before=inv)
    return {"ok": True}


@app.post("/api/admin/invoices/{invoice_id}/payments")
def admin_record_payment(request: Request, invoice_id: int, body: InvoicePayment):
    admin = _require_perm(request, "invoice:record_payment")
    inv = get_invoice_by_id(invoice_id, with_lines=False)
    if not inv:
        raise HTTPException(404, "Invoice not found")
    if body.amount <= 0:
        raise HTTPException(400, "Payment amount must be positive")
    payment_id = record_invoice_payment(
        invoice_id, body.model_dump(),
        recorded_by=admin["id"],
        recorded_by_label=admin.get("name"),
        recorded_by_prid=admin.get("prid"),
    )
    after = get_invoice_by_id(invoice_id, with_lines=False)
    _audit_from(admin, "invoice.payment", request,
                target_type="invoice", target_id=invoice_id,
                target_label=inv["invoice_number"],
                after={"amount": body.amount, "method": body.method,
                       "new_balance": round(after["total"] - after["amount_paid"], 2)})
    return {"id": payment_id, "amount_paid": after["amount_paid"], "status": after["status"]}


# Customer-side invoice access
@app.get("/api/portal/invoices")
def portal_invoices(request: Request):
    customer_id = _require_customer(request)
    return get_customer_invoices(customer_id)


@app.get("/api/portal/invoices/{invoice_id}")
def portal_invoice_detail(request: Request, invoice_id: int):
    customer_id = _require_customer(request)
    inv = get_invoice_by_id(invoice_id)
    if not inv or inv["customer_id"] != customer_id:
        raise HTTPException(404, "Invoice not found")
    # Customers should not see drafts
    if inv["status"] == "draft":
        raise HTTPException(404, "Invoice not found")
    return inv


# ── Documents (DMS) ───────────────────────────────────────────────────────────

def _allowed_sensitivities_for(admin: dict) -> list:
    out = []
    if _admin_can(admin["role"], "documents:view"):
        out.extend(["public", "confidential"])
    if _admin_can(admin["role"], "documents:view_highly_sensitive"):
        out.append("highly_sensitive")
    return out


@app.post("/api/admin/documents")
async def admin_upload_document(
    request: Request,
    file:             UploadFile = File(...),
    title:            str  = Form(...),
    document_type:    str  = Form(...),
    sensitivity:      str  = Form(...),
    description:      str  = Form(""),
    linked_to_type:   str  = Form(""),
    linked_to_id:     int  = Form(0),
    expiry_date:      str  = Form(""),
):
    admin = _require_perm(request, "documents:upload")

    if document_type not in DOC_TYPES:
        raise HTTPException(400, f"Unknown document_type. Allowed: {', '.join(DOC_TYPES)}")
    if sensitivity not in DOC_TIERS:
        raise HTTPException(400, f"Unknown sensitivity. Allowed: {', '.join(DOC_TIERS)}")
    # Force minimum sensitivity for certain document types
    if document_type in HIGHLY_SENSITIVE_TYPES and sensitivity != "highly_sensitive":
        sensitivity = "highly_sensitive"
    if sensitivity == "highly_sensitive" and not _admin_can(admin["role"], "documents:view_highly_sensitive"):
        raise HTTPException(403, "Your role cannot upload Highly Sensitive documents")

    body = await file.read()
    ext, mime = _validate_doc_upload(file.filename, body)

    # Sanitize: rename to a random UUID. Original name kept in metadata only.
    stored_filename = f"{uuid.uuid4().hex}{ext}"
    out_path = DOCUMENTS_DIR / sensitivity / stored_filename
    out_path.write_bytes(body)
    # Lock down file permissions (owner read/write only)
    try:
        os.chmod(out_path, 0o600)
    except Exception:
        pass

    # Resolve linked entity label snapshot
    linked_label = None
    if linked_to_type and linked_to_id:
        if linked_to_type == "customer":
            c = get_customer_by_id(linked_to_id)
            if c: linked_label = f"{c['name']} ({c['customer_code']})"
        elif linked_to_type == "tech":
            t = get_tech_by_id(linked_to_id)
            if t: linked_label = f"{t['name']} ({t['tech_code']})"
        elif linked_to_type == "admin":
            a = get_admin_user_by_id(linked_to_id)
            if a: linked_label = f"{a['name']} ({a['username']})"
        elif linked_to_type == "visit":
            v = get_visit_by_id(linked_to_id)
            if v: linked_label = f"{v['visit_type']} visit for {v.get('customer_name','?')}"

    # Validate expiry date format if provided (YYYY-MM-DD)
    expiry_clean = (expiry_date or "").strip()
    if expiry_clean:
        try:
            _dt.fromisoformat(expiry_clean)
        except ValueError:
            raise HTTPException(400, "expiry_date must be YYYY-MM-DD")

    doc_id = create_document({
        "stored_filename":   stored_filename,
        "original_filename": file.filename,
        "mime_type":         mime,
        "size_bytes":        len(body),
        "sensitivity":       sensitivity,
        "document_type":     document_type,
        "title":             title.strip(),
        "description":       description.strip(),
        "linked_to_type":    linked_to_type or None,
        "linked_to_id":      linked_to_id   or None,
        "linked_to_label":   linked_label,
        "uploaded_by_type":  "admin",
        "uploaded_by_id":    admin["id"],
        "uploaded_by_prid":  admin.get("prid"),
        "uploaded_by_label": admin.get("name"),
        "expiry_date":       expiry_clean or None,
    })

    _audit_from(admin, "document.upload", request,
                target_type="document", target_id=doc_id, target_label=title,
                after={"document_type": document_type, "sensitivity": sensitivity,
                       "size_bytes": len(body), "linked_to": linked_label})
    return {"id": doc_id, "stored_filename": stored_filename}


@app.get("/api/admin/documents")
def admin_list_documents(
    request: Request,
    sensitivity:    Optional[str] = None,
    document_type:  Optional[str] = None,
    linked_to_type: Optional[str] = None,
    linked_to_id:   Optional[int] = None,
    search:         Optional[str] = None,
):
    admin = _require_perm(request, "documents:view")
    allowed = _allowed_sensitivities_for(admin)
    if not allowed:
        raise HTTPException(403, "Forbidden")
    # If user asks for a specific tier, intersect with what they're allowed to see
    if sensitivity:
        if sensitivity not in allowed:
            raise HTTPException(403, "Your role cannot see that sensitivity tier")
        tiers = [sensitivity]
    else:
        tiers = allowed
    return query_documents(
        sensitivity_in=tiers,
        document_type=document_type,
        linked_to_type=linked_to_type,
        linked_to_id=linked_to_id,
        search=search,
    )


@app.get("/api/admin/documents/expiring")
def admin_documents_expiring(request: Request, within_days: int = 30):
    """Returns documents with an expiry_date already past OR within `within_days`,
    scoped to the caller's allowed sensitivity tiers."""
    admin = _require_perm(request, "documents:view")
    allowed = _allowed_sensitivities_for(admin)
    if not allowed:
        return {"expired": [], "expiring_soon": [], "total": 0}
    rows = get_expiring_documents(allowed, within_days=max(1, min(within_days, 365)))
    expired = [r for r in rows if (r.get("days_to_expiry") is not None and r["days_to_expiry"] < 0)]
    soon    = [r for r in rows if (r.get("days_to_expiry") is not None and r["days_to_expiry"] >= 0)]
    return {"expired": expired, "expiring_soon": soon, "total": len(rows)}


@app.get("/api/admin/documents/{doc_id}/download")
def admin_document_download(request: Request, doc_id: int):
    """Returns a short-lived signed URL the browser can use to fetch the file.
    Every call is audit-logged as a view; highly_sensitive logs separately."""
    admin = _require_perm(request, "documents:view")
    doc = get_document_by_id(doc_id)
    if not doc:
        raise HTTPException(404, "Document not found")
    if doc["sensitivity"] == "highly_sensitive" and not _admin_can(admin["role"], "documents:view_highly_sensitive"):
        raise HTTPException(403, "Your role cannot view Highly Sensitive documents")

    touch_document_accessed(doc_id)
    signed = _sign_document_url(doc["stored_filename"], doc["sensitivity"])

    action = "document.view_highly_sensitive" if doc["sensitivity"] == "highly_sensitive" else "document.view"
    _audit_from(admin, action, request,
                target_type="document", target_id=doc_id, target_label=doc["title"],
                after={"sensitivity": doc["sensitivity"], "document_type": doc["document_type"]})
    return {
        "url":               signed,
        "original_filename": doc["original_filename"],
        "mime_type":         doc["mime_type"],
        "expires_in":        600,
    }


@app.delete("/api/admin/documents/{doc_id}")
def admin_delete_document(request: Request, doc_id: int):
    admin = _require_admin(request)
    doc = get_document_by_id(doc_id)
    if not doc:
        raise HTTPException(404, "Document not found")
    if doc["sensitivity"] == "highly_sensitive":
        if not _admin_can(admin["role"], "documents:delete_highly_sensitive"):
            raise HTTPException(403, "Only super_admin can delete Highly Sensitive documents")
        # Soft delete + audit (keep file on disk for forensic retention)
        soft_delete_document(doc_id)
        _audit_from(admin, "document.delete_highly_sensitive", request,
                    target_type="document", target_id=doc_id, target_label=doc["title"],
                    before=doc)
    else:
        if not _admin_can(admin["role"], "documents:delete"):
            raise HTTPException(403, "Your role cannot delete documents")
        # Hard delete the file + row
        try:
            (DOCUMENTS_DIR / doc["sensitivity"] / doc["stored_filename"]).unlink(missing_ok=True)
        except Exception:
            pass
        hard_delete_document(doc_id)
        _audit_from(admin, "document.delete", request,
                    target_type="document", target_id=doc_id, target_label=doc["title"],
                    before=doc)
    return {"ok": True}


@app.get("/documents/{tier}/{filename}")
def serve_document(tier: str, filename: str, exp: int = 0, sig: str = ""):
    """Time-limited signed document fetch. URLs generated by
    /api/admin/documents/{id}/download. No path traversal allowed."""
    if tier not in DOC_TIERS:
        raise HTTPException(404)
    if "/" in filename or ".." in filename or filename.startswith("."):
        raise HTTPException(400, "Invalid filename")
    if not exp or not sig or not _verify_document_signature(filename, tier, exp, sig):
        raise HTTPException(403, "Link expired or invalid")
    path = DOCUMENTS_DIR / tier / filename
    if not path.exists():
        raise HTTPException(404, "Document not found")
    return FileResponse(str(path))


# ── Audit log ─────────────────────────────────────────────────────────────────

@app.get("/api/admin/audit/verify")
def admin_audit_verify(request: Request):
    """Walks the audit chain and reports whether every row's stored hash
    matches the recomputed hash. Available to anyone with audit:view_all —
    those roles already see the underlying data, so verifying is no extra
    disclosure. Super_admin needs this when investigating a tampering claim."""
    admin = _require_admin(request)
    if not _admin_can(admin["role"], "audit:view_all"):
        raise HTTPException(403, "Only roles with audit:view_all can verify the chain")
    return verify_audit_chain()


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
    return _enrich_photos(get_visit_photos(visit_id))


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


@app.get("/admin/invoice/{invoice_id}")
def admin_invoice_print_page(invoice_id: int):
    return FileResponse("invoice_print.html")


@app.get("/portal/invoice/{invoice_id}")
def portal_invoice_print_page(invoice_id: int):
    return FileResponse("invoice_print.html")


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
