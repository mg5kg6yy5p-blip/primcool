from contextlib import asynccontextmanager
from collections import deque
from datetime import datetime, timezone, timedelta
from pathlib import Path
from threading import Lock
from typing import Optional, List

import base64
import hashlib
import hmac
import io
import json as _json
import os
import secrets as _secrets
import time
import uuid

from fastapi import FastAPI, HTTPException, Request, UploadFile, File, Form, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
import jwt
import pyotp
import qrcode
import resend as resend_lib

from database import (
    init_db, save_submission, bootstrap_super_admin,
    get_customer_by_code, get_customer_by_id, get_all_customers,
    create_customer, delete_customer, verify_customer, set_customer_pin,
    get_customer_by_code_and_email, create_customer_pin_reset, consume_customer_pin_reset,
    get_customer_equipment, get_equipment_by_id, create_equipment, delete_equipment,
    get_customer_visits, get_all_visits, create_visit, update_visit, delete_visit,
    get_visit_by_id, update_visit_time, tech_complete_visit, get_tech_jobs,
    add_visit_reading, get_visit_readings,
    set_visit_signature, get_visit_signature,
    set_visit_checklist, get_visit_checklist,
    set_part_image, set_visit_flag,
    get_recent_unit_cost_avg,
    create_purchase_order, list_purchase_orders, get_purchase_order,
    mark_po_sent, record_goods_received, close_purchase_order,
    create_physical_count, list_physical_counts, approve_physical_count,
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
    log_access, query_access_log, aggregate_access_by_target,
    purge_old_access_log, purge_old_audit_log,
    get_entity_history, watcher_should_log, query_audit_log_team,
    set_admin_supervisor, set_tech_supervisor, subordinate_ids_for,
    set_customer_password, verify_customer_password, set_customer_mfa,
    set_customer_type, mark_customer_deletion_requested,
    get_customer_full_export, get_customer_visits_portal,
    create_service_request, list_service_requests, get_service_request,
    update_service_request_status, set_visit_work_summary,
    bump_last_login, terminate_account, reinstate_account,
    find_dormant_accounts, get_account_exit_report,
    create_security_alert, recent_alert_exists, list_security_alerts,
    count_open_security_alerts, resolve_security_alert, detect_anomalies_for_actor,
    create_session, get_session_by_jti, is_session_active,
    revoke_session, revoke_all_sessions_for, get_active_sessions_for,
    mark_session_mfa_verified,
)

# ── Admin role → permission matrix ────────────────────────────────────────────
ADMIN_PERMS = {
    "super_admin": {
        "admin:create", "admin:update", "admin:delete", "admin:set_role",
        "admin:set_active", "admin:reset_password", "admin:view_all",
        "tech:view", "tech:create", "tech:update", "tech:delete", "tech:reset_pin", "tech:export",
        "customer:view", "customer:create", "customer:update", "customer:delete", "customer:export",
        "visit:view", "visit:create", "visit:update", "visit:delete", "visit:export",
        "review:view", "review:approve", "review:reject", "review:delete",
        "visit:view_photos", "visit:flag",
        "invoice:export",
        # Inventory + procurement controls (super_admin has everything)
        "inventory:export",
        "po:create", "po:send", "po:receive", "po:close_out", "po:approve_variance",
        "count:create", "count:approve",
        "security:view_alerts", "security:resolve_alerts",
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
        "tech:view", "tech:update", "tech:export",
        "customer:view", "customer:update", "customer:export",
        "visit:view", "visit:update", "visit:export",
        "review:view",
        "visit:view_photos", "visit:flag",
        "invoice:export",
        # Manager closes out POs and approves count variances — director also can.
        "inventory:export",
        "po:create", "po:send", "po:receive", "po:close_out", "po:approve_variance",
        "count:create", "count:approve",
        "security:view_alerts",
        "audit:view_all",
        "timesheet:view_all",
        "schedule:view", "schedule:edit",
        "inventory:view", "inventory:adjust",
        "invoice:view", "invoice:update", "invoice:record_payment",
        "documents:upload", "documents:view", "documents:view_highly_sensitive",
        "documents:delete",
    },
    "system_admin": {
        "tech:view", "tech:create", "tech:update", "tech:reset_pin",
        "customer:view", "customer:create", "customer:update",
        "visit:view", "visit:create", "visit:update",
        "review:view",
        "audit:view_self",
        "timesheet:view_all",
        "schedule:view", "schedule:edit",
        "inventory:view", "inventory:create", "inventory:update", "inventory:adjust",
        "invoice:view", "invoice:create", "invoice:update", "invoice:record_payment",
        "documents:upload", "documents:view",
    },
    "hr_admin": {
        "tech:view", "tech:create", "tech:update", "tech:reset_pin",
        "audit:view_self",
        "timesheet:view_all",
        "invoice:view",
        "documents:upload", "documents:view", "documents:view_highly_sensitive",
    },
    "ceo_assistant": {
        "audit:view_self",
        "inventory:view",
        "invoice:view",
        "documents:view",
    },
    # Inventory manager: full operational visibility on stock + suppliers +
    # POs, zero personnel visibility. Cannot close out POs (that requires
    # super/supervisor) and cannot approve count variances they discovered.
    "inventory_manager": {
        "inventory:view", "inventory:create", "inventory:update", "inventory:adjust",
        "po:create", "po:send", "po:receive",
        "count:create",
        "audit:view_self",
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


def _virus_scan(body: bytes) -> tuple:
    """Returns (clean: bool, reason: str). When CLAMD_HOST isn't set, returns
    (True, 'skipped') so dev/local installs aren't blocked.

    To enable in production:
      pip install clamd
      Run a clamd daemon (Docker image: clamav/clamav)
      Set env: CLAMD_HOST=clamav  CLAMD_PORT=3310
    """
    host = os.environ.get("CLAMD_HOST")
    if not host:
        return True, "skipped (CLAMD_HOST not configured)"
    try:
        import clamd as _clamd
        c = _clamd.ClamdNetworkSocket(host=host, port=int(os.environ.get("CLAMD_PORT", "3310")), timeout=10)
        result = c.instream(io.BytesIO(body))
        verdict, sig = result.get("stream", ("ERROR", "unknown"))
        if verdict == "OK":
            return True, "clean"
        if verdict == "FOUND":
            return False, f"virus detected: {sig}"
        return False, f"clamd error: {verdict}/{sig}"
    except ImportError:
        # clamd lib not installed → fail open with a clear note. In a regulated
        # environment, change this to fail closed.
        return True, "skipped (clamd lib not installed)"
    except Exception as e:
        # Network/daemon problem. Fail open by default; flip to fail-closed
        # by setting CLAMD_FAIL_CLOSED=true in production.
        if os.environ.get("CLAMD_FAIL_CLOSED", "false").lower() == "true":
            return False, f"clamd unreachable: {type(e).__name__}: {e}"
        return True, f"clamd unreachable (failing open): {e}"


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
    # Virus scan — runs against clamd if CLAMD_HOST is set; otherwise skipped.
    clean, reason = _virus_scan(body)
    if not clean:
        raise HTTPException(400, f"File rejected by virus scan: {reason}")
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


def _enforce_rate(request: Request, bucket: str, identity: str = "",
                  max_attempts: int = 10, window_seconds: int = 3600,
                  message: str = "Too many requests. Please slow down."):
    """Generic IP+identity rate-limit guard for non-auth endpoints."""
    ip = _client_ip(request)
    key = f"{bucket}:{ip}:{identity}"
    if not _rate_check(key, max_attempts, window_seconds):
        raise HTTPException(status_code=429, detail=message)


def _enforce_export_rate(request: Request, admin_id: int, resource: str):
    """Bulk exports get a tighter cap (10/hour per admin) — pulling all
    customer records is a meaningfully different action from opening one,
    and it should be visibly limited so a compromised account can't
    silently exfiltrate the database."""
    _enforce_rate(request, bucket=f"export:{resource}", identity=str(admin_id),
                  max_attempts=10, window_seconds=3600,
                  message=f"Export limit reached: max 10 {resource} exports per hour.")


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

# Per-role idle timeout (seconds). 0 disables idle expiry for that role.
# Admin defaults to 30 minutes (sensitive desk role). Techs in the field and
# customers checking infrequently rely on the hard expiry instead.
IDLE_TIMEOUT = {
    "admin":    int(os.environ.get("ADMIN_IDLE_TIMEOUT_SEC",    str(30 * 60))),
    "tech":     int(os.environ.get("TECH_IDLE_TIMEOUT_SEC",     "0")),
    # Customer portal is internet-facing — per spec, idle timeout is tighter
    # than internal. Default 20 minutes; commercial-account MFA covers theft.
    "customer": int(os.environ.get("CUSTOMER_IDLE_TIMEOUT_SEC", str(20 * 60))),
}

PHOTO_URL_SECRET  = os.environ.get("PHOTO_URL_SECRET", JWT_SECRET)
PHOTO_URL_TTL_SEC = int(os.environ.get("PHOTO_URL_TTL_SEC", "1800"))   # 30 min default

MFA_ISSUER       = os.environ.get("MFA_ISSUER", "PrimeCool Services")
MFA_TOKEN_TTL    = timedelta(minutes=5)   # short-lived pre-MFA token
# How recent does an MFA check need to be before Tier-3 (Highly Sensitive)
# document access is allowed? Default 15 min.
MFA_FRESH_TTL_SEC = int(os.environ.get("MFA_FRESH_TTL_SEC", str(15 * 60)))


def _generate_backup_codes(n: int = 10):
    """Returns (plaintext_codes, hashed_codes). Plaintext shown to user once; hashed stored."""
    plain = []
    for _ in range(n):
        raw = _secrets.token_hex(4).upper()
        plain.append(f"{raw[:4]}-{raw[4:]}")
    hashed = [_hash_pin(c) for c in plain]
    return plain, hashed


def _current_session_jti(request: Request, cookie_name: str) -> Optional[str]:
    """Reads the jti out of whichever token the request is presenting."""
    token = _read_token(request, cookie_name)
    if not token:
        return None
    try:
        data = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM],
                          options={"verify_exp": False})
        return data.get("jti")
    except Exception:
        return None


def _require_recent_mfa(request: Request, admin: dict, max_age_seconds: int = None):
    """Raises 401 with X-Require-MFA-Reauth header when the caller hasn't passed
    MFA recently. Caller (e.g. Highly Sensitive document download) is expected
    to handle that signal by prompting for the user's current TOTP."""
    if not admin.get("mfa_enabled"):
        # If MFA isn't even set up, there's nothing to re-verify against.
        # Block Tier-3 access entirely for these accounts — admin should enroll first.
        raise HTTPException(
            status_code=403,
            detail="Tier-3 access requires MFA enrollment. Enable Two-Factor Auth in Security first.",
        )
    jti = _current_session_jti(request, COOKIE_ADMIN)
    sess = get_session_by_jti(jti) if jti else None
    mfa_at = (sess or {}).get("mfa_verified_at")
    max_age = max_age_seconds if max_age_seconds is not None else MFA_FRESH_TTL_SEC
    if not mfa_at:
        raise HTTPException(status_code=401, detail="Recent MFA required",
                            headers={"X-Require-MFA-Reauth": "true"})
    try:
        last = datetime.fromisoformat(mfa_at.replace("Z", "+00:00"))
        age = (datetime.now(timezone.utc) - last).total_seconds()
    except Exception:
        age = max_age + 1
    if age > max_age:
        raise HTTPException(status_code=401, detail="MFA re-authentication required",
                            headers={"X-Require-MFA-Reauth": "true"})


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
    # Server-side session check — a JWT whose row has been revoked, expired,
    # or idled past its per-role limit is rejected.
    if require_session:
        jti = data.get("jti")
        if not jti or not is_session_active(jti, IDLE_TIMEOUT):
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


_COMMON_PASSWORDS = {
    "password", "password1", "password12", "password123", "password1234",
    "12345678", "123456789", "1234567890",
    "qwerty", "qwerty123", "qwertyuiop", "abc12345", "letmein", "welcome",
    "admin", "admin123", "administrator", "iloveyou", "primecool",
    "primecool1", "primecool123", "summer2025", "winter2025", "spring2025",
    "passw0rd", "p@ssw0rd", "p@ssword1", "trustno1",
}


def _validate_password_strength(pw: str) -> None:
    """Per portal spec: real password strength on the public-facing surface.
    Raises HTTPException(400) on weak input. ≥12 chars, must include letters
    and digits, must not match the common-password deny-list (case folded),
    and must not start with an obvious weak token."""
    if len(pw) < 12:
        raise HTTPException(400, "Password must be at least 12 characters")
    if not any(c.isalpha() for c in pw) or not any(c.isdigit() for c in pw):
        raise HTTPException(400, "Password must contain both letters and digits")
    low = pw.lower()
    if low in _COMMON_PASSWORDS:
        raise HTTPException(400, "That password is too common — please choose something less guessable")
    # Reject if a common password is a prefix that covers most of the string
    for bad in _COMMON_PASSWORDS:
        if len(bad) >= 6 and low.startswith(bad) and len(bad) >= len(low) * 0.6:
            raise HTTPException(400, "Password is based on a common pattern — please choose something less guessable")


def _audit_customer(customer: dict, action: str, request: Request,
                    target_type: str = None, target_id: int = None,
                    target_label: str = None, after=None):
    """Audit a portal-side action. Every client interaction belongs in the
    same chain as staff actions — the spec is explicit. Customer is the
    actor; their customer_code stands in for the PRID."""
    log_audit(
        actor_type="customer",
        actor_id=customer.get("id"),
        actor_prid=customer.get("customer_code"),
        actor_label=customer.get("name"),
        actor_role=customer.get("customer_type") or "residential",
        action=action,
        target_type=target_type,
        target_id=target_id,
        target_label=target_label,
        after_value=after,
        ip_address=request.client.host if request.client else None,
    )


def _audit_anon(action: str, request: Request, *,
                attempted_identity: str = "",
                actor_type: str = "anonymous",
                target_label: str = None):
    """Audit-log a sensitive event with no authenticated actor — failed
    logins, lockouts, etc. attempted_identity is the username/PRID the
    caller tried, preserved as actor_label for later forensics."""
    log_audit(
        actor_type=actor_type,
        actor_id=None,
        actor_prid=None,
        actor_label=(attempted_identity or "")[:80] or None,
        actor_role=None,
        action=action,
        target_label=target_label,
        ip_address=_client_ip(request),
    )


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

    # Data retention. Two-tier audit policy per spec:
    #   - financial/legal events (invoices, POs, counts, exports): 7 years
    #   - operational events (CRUD on records, schedule edits, etc):  24 months
    #   - access_log reads:                                            90 days
    # 'system' rows (login/logout/security/retention itself) are NEVER purged.
    # Each purge writes a system.retention_purge audit row so we keep the
    # record that the record was discarded.
    access_retain_days = int(os.environ.get("ACCESS_LOG_RETAIN_DAYS", "90"))
    fin_retain_days    = int(os.environ.get("AUDIT_FINANCIAL_RETAIN_DAYS",   str(365 * 7)))
    ops_retain_days    = int(os.environ.get("AUDIT_OPERATIONAL_RETAIN_DAYS", str(365 * 2)))
    try:
        n = purge_old_access_log(days=access_retain_days)
        print(f"✓ access_log retention: kept last {access_retain_days} days "
              f"({n} rows purged)")
        if n > 0:
            log_audit(actor_type="system", action="system.retention_purge",
                      target_type="access_log",
                      target_label=f"purged {n} rows older than {access_retain_days}d",
                      after_value={"count": n, "days": access_retain_days})
    except Exception as e:
        print(f"access_log purge skipped: {e}")
    # Dormant-account sweep. Surfaces inactive-but-still-credentialed
    # accounts so they can be reviewed for soft-close. Does NOT auto-suspend
    # — per spec, this flags, a human decides.
    dormant_days = int(os.environ.get("DORMANT_DAYS", "90"))
    try:
        dormant = find_dormant_accounts(days=dormant_days)
        total = sum(len(v) for v in dormant.values())
        if total > 0:
            print(f"⚠ {total} dormant account(s) (>{dormant_days}d): "
                  f"{len(dormant['admin'])} admin, {len(dormant['tech'])} tech, "
                  f"{len(dormant['customer'])} customer")
            try:
                create_security_alert(
                    kind="dormant_accounts", severity="medium",
                    summary=f"{total} active accounts have not logged in for "
                            f"{dormant_days}+ days",
                    actor_type="system", actor_id=None,
                    details={"counts": {k: len(v) for k, v in dormant.items()},
                             "threshold_days": dormant_days},
                )
            except Exception: pass
            log_audit(actor_type="system", action="system.dormant_flagged",
                      target_label=f"{total} accounts >{dormant_days}d idle",
                      after_value={k: [a["label"] for a in v] for k, v in dormant.items()})
        else:
            print(f"✓ dormant sweep: no accounts idle >{dormant_days}d")
    except Exception as e:
        print(f"dormant sweep skipped: {e}")

    try:
        r = purge_old_audit_log(financial_days=fin_retain_days,
                                 operational_days=ops_retain_days)
        if r["financial_purged"] or r["operational_purged"]:
            print(f"✓ audit_log retention: purged {r['financial_purged']} financial "
                  f"+ {r['operational_purged']} operational rows")
            log_audit(actor_type="system", action="system.retention_purge",
                      target_type="audit_log",
                      target_label=f"financial>{fin_retain_days}d → {r['financial_purged']}; "
                                   f"operational>{ops_retain_days}d → {r['operational_purged']}",
                      after_value=r)
        else:
            print(f"✓ audit_log retention: nothing to purge")
    except Exception as e:
        print(f"audit_log purge skipped: {e}")
    yield


app = FastAPI(lifespan=lifespan)

# ── Paths the access-log middleware skips (noise reduction) ──────────────────
_ACCESS_LOG_SKIP_PREFIXES = (
    "/health",
    "/manifest-", "/sw.js",
    "/icons/", "/images/", "/photos/", "/documents/",   # static + signed-URL paths
)
# Endpoints whose own purpose is reading the logs themselves — skipping them
# prevents the access log from filling up just from the Audit tab refreshing.
_ACCESS_LOG_SKIP_EXACT = {
    # These endpoints emit their OWN audit_log row (watcher logging) so they
    # don't need to clutter access_log too. Sessions probe is high-noise and
    # not security-sensitive.
    "/api/admin/security/alerts/summary",
    "/api/admin/sessions",
}

# Endpoints whose access we want recorded in audit_log (not just access_log)
# because looking at the audit trail must itself leave a footprint.
# Debounced per-actor by watcher_should_log() to avoid refresh-spam.
_AUDIT_WATCHER_PATHS = {
    "/api/admin/audit":                "audit.viewed",
    "/api/admin/audit/verify":         "audit.chain_verified",
    "/api/admin/access":               "audit.access_log_viewed",
    "/api/admin/access/aggregate":     "audit.aggregate_viewed",
    "/api/admin/security/alerts":      "audit.alerts_viewed",
}


def _identify_actor_silent(request: Request) -> dict:
    """Best-effort actor identification for the access log. Never raises —
    returns {} when the request is anonymous or the token is bad."""
    for ctype, cookie in (("admin", COOKIE_ADMIN), ("tech", COOKIE_TECH), ("customer", COOKIE_CUSTOMER)):
        token = _read_token(request, cookie)
        if not token:
            continue
        try:
            data = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        except Exception:
            continue
        if data.get("type") != ctype:
            continue
        out = {"actor_type": ctype, "actor_id": int(data["sub"])}
        if ctype == "admin":
            row = get_admin_user_by_id(out["actor_id"])
            if row:
                out["actor_prid"]  = row.get("prid")
                out["actor_label"] = row.get("name")
        elif ctype == "tech":
            row = get_tech_by_id(out["actor_id"])
            if row:
                out["actor_prid"]  = row.get("prid")
                out["actor_label"] = row.get("name")
        elif ctype == "customer":
            row = get_customer_by_id(out["actor_id"])
            if row:
                out["actor_prid"]  = row.get("customer_code")
                out["actor_label"] = row.get("name")
        return out
    return {}


def _send_security_alert_email(alert: dict):
    """Best-effort email notification for a newly-raised alert. Silent on
    failure — the alert is still in the DB and visible to super_admin."""
    api_key = os.environ.get("RESEND_API_KEY")
    to_addr = os.environ.get("SECURITY_ALERT_EMAIL")
    if not (api_key and to_addr):
        return
    try:
        resend_lib.api_key = api_key
        sev = (alert.get("severity") or "medium").upper()
        actor = f"{alert.get('actor_label') or ''} ({alert.get('actor_prid') or alert.get('actor_id')})"
        subject = f"[PrimeCool · {sev}] {alert.get('kind')}: {alert.get('summary')}"
        html = (
            f"<h2 style='color:#991b1b'>Security alert — {sev}</h2>"
            f"<p><strong>Kind:</strong> {alert.get('kind')}</p>"
            f"<p><strong>Actor:</strong> {actor}</p>"
            f"<p><strong>Summary:</strong> {alert.get('summary')}</p>"
            f"<pre style='background:#f3f4f6;padding:10px;border-radius:6px;font-size:12px'>"
            f"{alert.get('details') or ''}</pre>"
            f"<p style='color:#6b7280;font-size:12px'>Raised {alert.get('created_at')}. "
            f"Sign in to the admin panel to review or resolve.</p>"
        )
        resend_lib.Emails.send({
            "from":    "PrimeCool Services <onboarding@resend.dev>",
            "to":      to_addr,
            "subject": subject,
            "html":    html,
        })
    except Exception as e:
        print(f"SECURITY ALERT EMAIL ERROR: {e}")


def _run_anomaly_detector(actor_type: str, actor_id: int):
    """Check rules against this actor's recent activity. De-dupes by kind so
    a single burst doesn't fire repeatedly."""
    try:
        hits = detect_anomalies_for_actor(actor_type, actor_id)
        for kind, severity, summary, details in hits:
            if recent_alert_exists(kind, actor_id, within_minutes=30):
                continue
            aid = create_security_alert(
                kind=kind, summary=summary, severity=severity,
                actor_type=actor_type, actor_id=actor_id, details=details,
            )
            print(f"SECURITY ALERT #{aid} [{severity}] {kind}: {summary}")
            _send_security_alert_email({
                "kind": kind, "severity": severity, "summary": summary,
                "actor_id": actor_id, "actor_label": None, "actor_prid": None,
                "details": details, "created_at": datetime.now(timezone.utc).isoformat(),
            })
    except Exception as e:
        print(f"anomaly detector error: {e}")


@app.middleware("http")
async def access_log_middleware(request: Request, call_next):
    """Records every API read access to access_log so we can answer
    'who looked at this customer's data and when?' — the spec's audit-
    logging-middleware requirement. Writes happen anyway via _audit_from()
    on the routes themselves, so we skip non-GET here to avoid duplicating
    the trail. Filtered to /api/* with skip-list above."""
    response = await call_next(request)

    if request.method != "GET":
        return response
    path = request.url.path
    if not path.startswith("/api/"):
        return response
    if path in _ACCESS_LOG_SKIP_EXACT:
        return response
    if any(path.startswith(p) for p in _ACCESS_LOG_SKIP_PREFIXES):
        return response

    actor = _identify_actor_silent(request)
    if not actor:
        # Skip anonymous GETs to keep the log focused on actual user activity
        return response
    try:
        log_access(
            actor_type=actor.get("actor_type"),
            actor_id=actor.get("actor_id"),
            actor_prid=actor.get("actor_prid"),
            actor_label=actor.get("actor_label"),
            method=request.method,
            path=path,
            query=str(request.url.query)[:512],
            status_code=response.status_code,
            ip_address=_client_ip(request),
            user_agent=(request.headers.get("user-agent", "") or "")[:255],
        )
        _run_anomaly_detector(actor.get("actor_type"), actor.get("actor_id"))
        # Watcher logging: looking at the audit/security trail must leave a
        # footprint in the audit log itself. Debounced so refresh ≠ spam.
        if path in _AUDIT_WATCHER_PATHS and 200 <= response.status_code < 300:
            try:
                if watcher_should_log(actor.get("actor_id"), path):
                    log_audit(
                        actor_type=actor.get("actor_type"),
                        actor_id=actor.get("actor_id"),
                        actor_prid=actor.get("actor_prid"),
                        actor_label=actor.get("actor_label"),
                        action=_AUDIT_WATCHER_PATHS[path],
                        target_label=str(request.url.query)[:255] or None,
                        ip_address=_client_ip(request),
                    )
            except Exception as e:
                print(f"watcher_log error: {e}")
    except Exception as e:
        print(f"access_log error: {e}")
    return response


@app.middleware("http")
async def no_store_api_responses(request: Request, call_next):
    """Tell browsers never to cache /api/* responses. Without this, the back
    button can replay a previous user's data on a shared device after they
    sign out. Scenario 7."""
    response = await call_next(request)
    if request.url.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
        response.headers["Pragma"] = "no-cache"
    return response


@app.middleware("http")
async def csrf_origin_check(request: Request, call_next):
    """Lightweight CSRF defense for cookie-authenticated mutating requests.

    Logic:
      - Mutating methods only (POST/PUT/DELETE/PATCH)
      - Skip if no session cookie present (no CSRF risk — Bearer-only requests
        can't be forged cross-origin since attackers can't set custom headers)
      - Require Origin or Referer to match the request's Host
    """
    method = request.method.upper()
    if method in ("POST", "PUT", "DELETE", "PATCH"):
        has_cookie = any(
            request.cookies.get(c) for c in (COOKIE_ADMIN, COOKIE_TECH, COOKIE_CUSTOMER)
        )
        if has_cookie:
            host = request.headers.get("host", "").split(":")[0].lower()
            allowed_hosts = {host} | {h.strip().lower() for h in
                                       os.environ.get("CSRF_ALLOWED_HOSTS", "").split(",") if h.strip()}
            origin = request.headers.get("origin", "")
            referer = request.headers.get("referer", "")
            src = origin or referer
            ok = False
            if src:
                try:
                    from urllib.parse import urlparse
                    src_host = urlparse(src).hostname or ""
                    ok = src_host.lower() in allowed_hosts
                except Exception:
                    ok = False
            if not ok:
                return Response(
                    content=_json.dumps({"detail": "CSRF check failed: bad Origin/Referer"}),
                    status_code=403,
                    media_type="application/json",
                )
    return await call_next(request)


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
    code:     str
    pin:      str = ""        # used when auth_mode='pin' (residential default)
    password: str = ""        # used when auth_mode='password' (commercial)
    mfa_code: str = ""        # TOTP or backup code; required when MFA enrolled


class PortalForgotPin(BaseModel):
    code:  str
    email: str


class PortalResetPin(BaseModel):
    token:       str
    pin:         str
    confirm_pin: str


class CustomerPinReset(BaseModel):
    pin: str


class CustomerSetPassword(BaseModel):
    """Customer self-service: switch own account to password auth."""
    current_pin:      str = ""
    current_password: str = ""
    new_password:     str
    confirm:          str


class CustomerMfaEnable(BaseModel):
    code: str    # TOTP code from authenticator app to confirm enrolment


class CustomerServiceRequest(BaseModel):
    request_type:   str       # 'maintenance'|'repair'|'quote'|'question'
    subject:        str
    body:           str
    equipment_id:   Optional[int] = None
    preferred_date: Optional[str] = None


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
    customer_type: str = "residential"   # 'residential' | 'commercial' — commercial requires MFA


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
    # Phase 2 — in-field context
    scope_of_work:           str = ""
    estimated_duration_min:  Optional[int] = None
    contact_person_name:     str = ""
    contact_person_phone:    str = ""
    hazards:                 str = ""
    access_codes:            str = ""


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
    scope_of_work:           str = ""
    estimated_duration_min:  Optional[int] = None
    contact_person_name:     str = ""
    contact_person_phone:    str = ""
    hazards:                 str = ""
    access_codes:            str = ""


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
    next_pm_due:    Optional[str] = None


class TechReadingCreate(BaseModel):
    pressure_high: Optional[float] = None
    pressure_low:  Optional[float] = None
    temp_supply:   Optional[float] = None
    temp_return:   Optional[float] = None
    delta_t:       Optional[float] = None
    superheat:     Optional[float] = None
    subcool:       Optional[float] = None
    approach_temp: Optional[float] = None
    notes:         str = ""


class TechSignatureCreate(BaseModel):
    signer_name:   str
    signature_b64: str   # data:image/png;base64,...


class TechChecklistSet(BaseModel):
    items: List[dict]    # [{label, checked, note}]


class FlagForReview(BaseModel):
    flagged: bool
    note:    str = ""


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
    location:      str = ""


class PartUpdate(BaseModel):
    name:          str
    description:   str = ""
    category:      str = ""
    unit:          str = "each"
    unit_cost:     float = 0
    reorder_point: float = 0
    supplier:      str = ""
    location:      str = ""
    active:        bool = True


class PartAdjust(BaseModel):
    movement_type:  str           # 'received' | 'used' | 'adjusted'
    quantity_delta: float          # signed: +receive, -use, ±adjust
    reason:         str = ""
    visit_id:       Optional[int] = None
    # Cost-spike guard fields (only used when movement_type='received').
    unit_cost:                 Optional[float] = None
    cost_spike_approved_by:    Optional[int] = None


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
    existing = get_customer_by_code(req.code)
    # Constant-ish error message regardless of which failure case we hit,
    # to avoid enumerating valid customer codes.
    INVALID = "Invalid customer ID or credentials"

    # Soft-closed accounts (contract ended) return the same generic error
    # as a wrong code/PIN — no enumeration of inactive accounts.
    if existing and not existing.get("active", 1):
        _audit_anon("auth.login_failed", request,
                    attempted_identity=req.code, actor_type="customer",
                    target_label="account inactive")
        raise HTTPException(401, INVALID)

    customer = None
    if existing:
        if existing.get("auth_mode") == "password":
            customer = verify_customer_password(req.code, req.password)
        else:
            if not existing.get("pin_hash"):
                _audit_anon("auth.login_failed", request,
                            attempted_identity=req.code, actor_type="customer",
                            target_label="no PIN set")
                # Still generic-ish — don't reveal whether the code is real.
                raise HTTPException(401, INVALID)
            customer = verify_customer(req.code, req.pin)

    if not customer:
        _audit_anon("auth.login_failed", request,
                    attempted_identity=req.code, actor_type="customer",
                    target_label="invalid code or credentials")
        raise HTTPException(401, INVALID)

    # Commercial accounts MUST have MFA enrolled per spec. Block login
    # until they enrol (returning a one-shot enrolment token).
    if customer.get("customer_type") == "commercial" and not customer.get("mfa_enabled"):
        enrol_token = _make_token(
            {"sub": str(customer["id"]), "type": "customer_mfa_enrol"},
            MFA_TOKEN_TTL,
        )
        return {"requires_mfa_setup": True, "mfa_enrol_token": enrol_token,
                "name": customer["name"]}

    # MFA verification step if already enrolled.
    if customer.get("mfa_enabled"):
        if not req.mfa_code:
            mfa_token = _make_token(
                {"sub": str(customer["id"]), "type": "customer_pre_mfa"},
                MFA_TOKEN_TTL,
            )
            return {"requires_mfa": True, "mfa_token": mfa_token,
                    "name": customer["name"]}
        if not _verify_customer_totp(customer, req.mfa_code):
            _audit_anon("auth.mfa_failed", request,
                        attempted_identity=req.code, actor_type="customer")
            raise HTTPException(401, "Invalid MFA code")

    # Customer portal sessions are 24h (tighter than the legacy 30d), with a
    # 20-min idle limit enforced by IDLE_TIMEOUT["customer"].
    token, _ = _issue_session("customer", customer["id"], timedelta(hours=24), request)
    _set_session_cookie(response, COOKIE_CUSTOMER, token, 24 * 3600)
    bump_last_login("customer", customer["id"])
    _audit_customer(customer, "portal.login", request)
    return {"token": token, "name": customer["name"],
            "customer_type": customer.get("customer_type", "residential"),
            "auth_mode":     customer.get("auth_mode", "pin"),
            "mfa_enabled":   bool(customer.get("mfa_enabled"))}


def _verify_customer_totp(customer: dict, code: str) -> bool:
    """TOTP check + backup-code fallback. Mirrors the admin MFA flow but
    keyed off customers.mfa_secret / customers.backup_codes."""
    import pyotp as _pyotp
    code = (code or "").strip().replace(" ", "")
    secret = customer.get("mfa_secret")
    if secret:
        try:
            if _pyotp.TOTP(secret).verify(code, valid_window=1):
                return True
        except Exception:
            pass
    # Backup codes — Argon2-hashed, single-use.
    try:
        raw = customer.get("backup_codes")
        if not raw: return False
        codes = _json.loads(raw)
        for i, h in enumerate(codes):
            if h and _verify_pin(code, h):
                # Burn the used code.
                codes[i] = None
                set_customer_mfa(customer["id"], secret, True, codes)
                return True
    except Exception:
        pass
    return False


@app.post("/api/portal/login/mfa")
def portal_login_mfa(body: dict, request: Request, response: Response):
    """Second step of MFA login. body = {mfa_token, mfa_code}."""
    tok = body.get("mfa_token") or ""
    code = (body.get("mfa_code") or "").strip()
    if not tok or not code:
        raise HTTPException(400, "mfa_token and mfa_code required")
    try:
        data = jwt.decode(tok, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except Exception:
        raise HTTPException(401, "Token invalid or expired")
    if data.get("type") != "customer_pre_mfa":
        raise HTTPException(401, "Wrong token type")
    cust = get_customer_by_id(int(data["sub"]))
    if not cust or not cust.get("mfa_enabled"):
        raise HTTPException(401, "MFA not enrolled on this account")
    if not _verify_customer_totp(cust, code):
        _audit_anon("auth.mfa_failed", request,
                    attempted_identity=cust.get("customer_code"),
                    actor_type="customer")
        raise HTTPException(401, "Invalid MFA code")
    token, _ = _issue_session("customer", cust["id"], timedelta(hours=24), request)
    _set_session_cookie(response, COOKIE_CUSTOMER, token, 24 * 3600)
    bump_last_login("customer", cust["id"])
    _audit_customer(cust, "portal.login", request, target_label="mfa")
    return {"token": token, "name": cust["name"]}


@app.post("/api/portal/mfa/setup")
def portal_mfa_setup(request: Request):
    """Generate a TOTP secret + QR provisioning URL. The secret is stored
    immediately but mfa_enabled stays 0 until /mfa/confirm verifies a code.
    Authenticated either by a normal portal session OR a one-shot
    customer_mfa_enrol token issued at login for commercial accounts."""
    import pyotp as _pyotp
    cust = _portal_actor_for_mfa_setup(request)
    secret = _pyotp.random_base32()
    set_customer_mfa(cust["id"], secret, False, None)
    issuer = MFA_ISSUER
    uri = _pyotp.TOTP(secret).provisioning_uri(
        name=cust.get("email") or cust.get("customer_code"),
        issuer_name=issuer,
    )
    _audit_customer(cust, "portal.mfa_setup_started", request)
    return {"secret": secret, "provisioning_uri": uri}


@app.post("/api/portal/mfa/confirm")
def portal_mfa_confirm(body: CustomerMfaEnable, request: Request, response: Response):
    """Verify a TOTP code, flip mfa_enabled, generate one-time backup codes,
    and (if this was the commercial-account enrol flow) issue a session."""
    import pyotp as _pyotp
    cust, was_enrol = _portal_actor_for_mfa_setup(request, return_enrol=True)
    if not cust.get("mfa_secret"):
        raise HTTPException(400, "Call /portal/mfa/setup first to generate a secret")
    if not _pyotp.TOTP(cust["mfa_secret"]).verify(body.code.strip(), valid_window=1):
        raise HTTPException(401, "Invalid MFA code — try again")
    # Generate + hash 8 single-use backup codes.
    raw_codes = [_secrets.token_hex(4) for _ in range(8)]
    hashed = [_hash_pin(c) if (c := rc) else None for rc in raw_codes]
    set_customer_mfa(cust["id"], cust["mfa_secret"], True, hashed)
    _audit_customer(cust, "portal.mfa_enabled", request)
    out = {"ok": True, "backup_codes": raw_codes}
    if was_enrol:
        token, _ = _issue_session("customer", cust["id"], timedelta(hours=24), request)
        _set_session_cookie(response, COOKIE_CUSTOMER, token, 24 * 3600)
        bump_last_login("customer", cust["id"])
        out["token"] = token
        out["name"]  = cust["name"]
    return out


def _portal_actor_for_mfa_setup(request: Request, return_enrol: bool = False):
    """Accepts either a normal portal session OR a customer_mfa_enrol token.
    Returns (customer, was_enrol_flow) when return_enrol=True else customer."""
    # Try enrol token via Authorization: Bearer first, then normal session.
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        tok = auth.split(" ", 1)[1].strip()
        try:
            data = jwt.decode(tok, JWT_SECRET, algorithms=[JWT_ALGORITHM])
            if data.get("type") == "customer_mfa_enrol":
                cust = get_customer_by_id(int(data["sub"]))
                if not cust: raise HTTPException(401, "Account not found")
                return (cust, True) if return_enrol else cust
        except HTTPException:
            raise
        except Exception:
            pass
    customer_id = _require_customer(request)
    cust = get_customer_by_id(customer_id)
    if not cust:
        raise HTTPException(404, "Customer not found")
    return (cust, False) if return_enrol else cust


@app.post("/api/portal/password")
def portal_set_password(body: CustomerSetPassword, request: Request):
    """Customer self-service: switch their account to password auth.
    Requires the existing PIN/password to confirm identity, plus a strong
    new password. Logs the mode change."""
    customer_id = _require_customer(request)
    cust = get_customer_by_id(customer_id)
    if not cust:
        raise HTTPException(404, "Customer not found")
    # Verify current credential
    if cust.get("auth_mode") == "password":
        if not verify_customer_password(cust["customer_code"], body.current_password):
            raise HTTPException(401, "Current password is incorrect")
    else:
        if not body.current_pin or not verify_customer(cust["customer_code"], body.current_pin):
            raise HTTPException(401, "Current PIN is incorrect")
    if body.new_password != body.confirm:
        raise HTTPException(400, "Passwords do not match")
    _validate_password_strength(body.new_password)
    set_customer_password(customer_id, body.new_password)
    _audit_customer(cust, "portal.password_set", request)
    return {"ok": True, "auth_mode": "password"}


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
    # Strip server-side fields the customer should never see in their own
    # profile blob (auth hashes, MFA secrets, backup codes).
    safe_customer = {k: v for k, v in customer.items()
                     if k not in ("pin_hash", "password_hash",
                                  "mfa_secret", "backup_codes")}
    equipment = get_customer_equipment(customer_id)
    # Portal-shaped visit list — only client-facing fields, served from
    # work_done_summary (raw work_done stays internal per spec).
    visits = get_customer_visits_portal(customer_id)
    reviews = get_customer_reviews(customer_id)
    for v in visits:
        v["photos"] = _enrich_photos(get_visit_photos(v["id"]))
    _audit_customer(customer, "portal.viewed_dashboard", request)
    return {"customer": safe_customer, "equipment": equipment,
            "visits": visits, "reviews": reviews}


@app.post("/api/portal/reviews")
def portal_create_review(request: Request, body: ReviewCreate):
    customer_id = _require_customer(request)
    _enforce_rate(request, "review", str(customer_id),
                  max_attempts=3, window_seconds=3600,
                  message="Too many reviews submitted recently. Please try again in an hour.")

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
        _audit_anon("auth.login_failed", request,
                    attempted_identity=req.tech_code,
                    actor_type="tech",
                    target_label="invalid PRID or PIN")
        raise HTTPException(401, "Invalid tech code or PIN")
    token, _ = _issue_session("tech", tech["id"], timedelta(days=7), request)
    _set_session_cookie(response, COOKIE_TECH, token, 7 * 24 * 3600)
    bump_last_login("tech", tech["id"])
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


def _tech_redact_visit(visit: dict) -> dict:
    """Strip fields the tech is not supposed to see — client's primary phone,
    tech hourly_rate, anything cost/finance-adjacent that may live on the
    visit row in the future. Contact person fields are kept."""
    for k in ("customer_phone", "tech_hourly_rate"):
        visit.pop(k, None)
    if visit.get("parts_used"):
        for p in visit["parts_used"]:
            for k in ("unit_cost", "unit_price"):
                p.pop(k, None)
    return visit


@app.get("/api/tech/jobs/{visit_id}")
def tech_get_job(request: Request, visit_id: int):
    tech_id = _require_tech(request)
    visit   = get_visit_by_id(visit_id, with_parts=True)
    if not visit or visit.get("assigned_tech_id") != tech_id:
        raise HTTPException(404, "Job not found")
    visit["photos"]    = _enrich_photos(get_visit_photos(visit_id))
    visit["readings"]  = get_visit_readings(visit_id)
    sig = get_visit_signature(visit_id)
    visit["signature_captured"] = bool(sig)
    visit["signer_name"] = sig.get("signer_name") if sig else None
    cl = get_visit_checklist(visit_id)
    visit["checklist"] = cl.get("items") if cl else None
    return _tech_redact_visit(visit)


@app.get("/api/tech/parts")
def tech_parts_catalog(request: Request):
    """Active parts only, with image + location for visual confirmation.
    unit_cost and supplier are stripped — tech sees what to grab and where,
    not what it cost the company."""
    _require_tech(request)
    out = []
    for p in get_all_parts():
        if not p.get("active"):
            continue
        p = dict(p)
        p.pop("unit_cost", None)
        p.pop("supplier",  None)
        if p.get("image_filename"):
            p["image_url"] = _sign_photo_url(p["image_filename"])
        out.append(p)
    return out


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

    now_iso = datetime.now(timezone.utc).isoformat()
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
    # Submission lock — once submitted_at is set, the tech can't re-submit.
    # Manager can flag-for-review (separate endpoint) but no edits from here.
    if visit.get("submitted_at"):
        raise HTTPException(409, "Job report already submitted — locked. "
                                  "Ask a manager to flag for review if a correction is needed.")
    # Spec: client signature is part of the job report — block submission if missing.
    if not get_visit_signature(visit_id):
        raise HTTPException(400, "Client signature required before submission.")

    now      = datetime.now(timezone.utc)
    end_iso  = now.isoformat()
    today    = now.date().isoformat()
    tech_complete_visit(
        visit_id,
        body.work_done.strip(),
        body.parts_replaced.strip(),
        body.notes.strip(),
        end_iso,
        today,
        next_pm_due=(body.next_pm_due or None),
    )
    return {"ok": True, "end_time": end_iso, "submitted_at": end_iso}


@app.post("/api/tech/jobs/{visit_id}/readings")
def tech_add_reading(request: Request, visit_id: int, body: TechReadingCreate):
    tech_id = _require_tech(request)
    visit = get_visit_by_id(visit_id)
    if not visit or visit.get("assigned_tech_id") != tech_id:
        raise HTTPException(404, "Job not found")
    if visit.get("submitted_at"):
        raise HTTPException(409, "Job locked — cannot add readings after submission")
    rid = add_visit_reading(visit_id, tech_id, body.model_dump())
    return {"id": rid}


@app.post("/api/tech/jobs/{visit_id}/signature")
def tech_capture_signature(request: Request, visit_id: int, body: TechSignatureCreate):
    tech_id = _require_tech(request)
    visit = get_visit_by_id(visit_id)
    if not visit or visit.get("assigned_tech_id") != tech_id:
        raise HTTPException(404, "Job not found")
    if visit.get("submitted_at"):
        raise HTTPException(409, "Job locked — signature cannot be replaced")
    if get_visit_signature(visit_id):
        raise HTTPException(409, "Signature already captured for this visit")
    if not body.signer_name.strip():
        raise HTTPException(400, "signer_name is required")
    if not body.signature_b64.startswith("data:image/"):
        raise HTTPException(400, "signature_b64 must be a data:image/...;base64,... URL")
    if len(body.signature_b64) > 200_000:
        raise HTTPException(413, "signature payload too large")
    sid = set_visit_signature(visit_id, body.signer_name, body.signature_b64, tech_id)
    return {"id": sid}


@app.post("/api/tech/jobs/{visit_id}/checklist")
def tech_set_checklist(request: Request, visit_id: int, body: TechChecklistSet):
    tech_id = _require_tech(request)
    visit = get_visit_by_id(visit_id)
    if not visit or visit.get("assigned_tech_id") != tech_id:
        raise HTTPException(404, "Job not found")
    if visit.get("submitted_at"):
        raise HTTPException(409, "Job locked")
    set_visit_checklist(visit_id, body.items, tech_id)
    return {"ok": True}


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
        _audit_anon("auth.login_failed", request,
                    attempted_identity=req.username,
                    actor_type="admin",
                    target_label="invalid credentials")
        raise HTTPException(401, "Invalid username or password")
    if not admin.get("active"):
        _audit_anon("auth.login_failed", request,
                    attempted_identity=req.username,
                    actor_type="admin",
                    target_label="account deactivated")
        raise HTTPException(403, "Account is deactivated")

    # MFA gate
    if admin.get("mfa_enabled"):
        # Step 1 of two-step login — return a short-lived MFA token,
        # NO session cookie set yet.
        mfa_token = _make_token(
            {"sub": str(admin["id"]), "type": "admin_pre_mfa"},
            MFA_TOKEN_TTL,
        )
        _audit_from(admin, "admin.login.password_ok", request)
        return {"requires_mfa": True, "mfa_token": mfa_token, "name": admin["name"]}

    token, _ = _issue_session("admin", admin["id"], timedelta(hours=12), request)
    _set_session_cookie(response, COOKIE_ADMIN, token, 12 * 3600)
    bump_last_login("admin", admin["id"])
    _audit_from(admin, "admin.login", request)
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
        _audit_from(admin, "admin.mfa.fail", request)
        raise HTTPException(401, "Incorrect code")

    token, jti = _issue_session("admin", admin["id"], timedelta(hours=12), request)
    # Stamp the session as having just passed MFA — used to gate Tier-3 access.
    mark_session_mfa_verified(jti)
    _set_session_cookie(response, COOKIE_ADMIN, token, 12 * 3600)
    bump_last_login("admin", admin["id"])
    _audit_from(admin, "admin.login.mfa_ok", request)
    return {
        "token":    token,
        "name":     admin["name"],
        "username": admin["username"],
        "role":     admin["role"],
        "prid":     admin.get("prid"),
        "requires_mfa": False,
    }


@app.post("/api/admin/mfa/reauth")
def admin_mfa_reauth(request: Request, body: MfaActivate):
    """Step-up MFA re-verification for accessing Tier-3 data. Verifies the
    caller's current TOTP (or a backup code) and stamps the active session as
    freshly-verified. Sensitive endpoints check that timestamp via
    _require_recent_mfa()."""
    admin = _require_admin(request)
    if not admin.get("mfa_enabled"):
        raise HTTPException(400, "MFA is not enabled on this account")
    _enforce_rate(request, "mfa-reauth", str(admin["id"]),
                  max_attempts=10, window_seconds=15 * 60,
                  message="Too many MFA attempts. Please wait and try again.")
    if not _verify_admin_totp_or_backup(admin, body.code):
        _audit_from(admin, "admin.mfa.reauth_fail", request)
        raise HTTPException(401, "Incorrect MFA code")
    jti = _current_session_jti(request, COOKIE_ADMIN)
    if jti:
        mark_session_mfa_verified(jti)
    _audit_from(admin, "admin.mfa.reauth_ok", request,
                target_type="admin", target_id=admin["id"], target_label=admin["username"])
    return {"ok": True, "fresh_for_seconds": MFA_FRESH_TTL_SEC}


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
        _audit_from(admin, "admin.logout", request)
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
    _audit_from(admin, "admin.logout_everywhere", request,
                after={"revoked_count": n})
    return {"ok": True, "revoked": n}


@app.delete("/api/admin/sessions/{jti}")
def admin_revoke_session(request: Request, jti: str):
    """Revokes one of the caller's own sessions by JTI."""
    admin = _require_admin(request)
    sess = get_session_by_jti(jti)
    if not sess or sess["subject_type"] != "admin" or sess["subject_id"] != admin["id"]:
        raise HTTPException(404, "Session not found")
    revoke_session(jti)
    _audit_from(admin, "admin.session.revoke", request,
                target_type="session", target_id=sess["id"],
                target_label=(sess.get("user_agent") or "")[:50])
    return {"ok": True}


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
    sessions_killed = 0
    if not body.active:
        # Deactivation must take effect immediately — revoke every live
        # session for this principal so an existing JWT can't outlive the
        # set_active flip.
        sessions_killed = revoke_all_sessions_for("admin", user_id)
    _audit_from(admin, "admin.set_active", request,
                target_type="admin", target_id=user_id, target_label=target["username"],
                before=before, after={"active": body.active,
                                       "sessions_revoked": sessions_killed})
    return {"ok": True, "sessions_revoked": sessions_killed}


# ── Access lifecycle endpoints (cross-role transitions) ──────────────────────
class TerminateBody(BaseModel):
    reason: str = ""


@app.post("/api/admin/users/{user_id}/terminate")
def admin_terminate_admin(request: Request, user_id: int, body: TerminateBody):
    """Hard-off for an admin: active=0, terminated_at stamped, every session
    force-killed. The combined one-action control the spec mandates for
    Scenario 1. Restricted to admin:set_active (super_admin only)."""
    admin = _require_perm(request, "admin:set_active")
    target = get_admin_user_by_id(user_id)
    if not target:
        raise HTTPException(404, "Admin not found")
    if admin["id"] == user_id:
        raise HTTPException(400, "You cannot terminate your own account")
    if target["role"] == "super_admin" and count_active_admins("super_admin") <= 1:
        raise HTTPException(400, "Cannot terminate the last active super_admin")
    result = terminate_account("admin", user_id)
    _audit_from(admin, "account.terminated", request,
                target_type="admin", target_id=user_id,
                target_label=target.get("username") or target.get("prid"),
                after={"reason": body.reason, **result})
    return {"ok": True, **result}


@app.post("/api/admin/users/{user_id}/reinstate")
def admin_reinstate_admin(request: Request, user_id: int):
    admin = _require_perm(request, "admin:set_active")
    target = get_admin_user_by_id(user_id)
    if not target:
        raise HTTPException(404, "Admin not found")
    reinstate_account("admin", user_id)
    _audit_from(admin, "account.reinstated", request,
                target_type="admin", target_id=user_id,
                target_label=target.get("username") or target.get("prid"))
    return {"ok": True}


@app.post("/api/admin/techs/{tech_id}/terminate")
def admin_terminate_tech(request: Request, tech_id: int, body: TerminateBody):
    """Tech termination — the Scenario 1 show-stopper. Audit log surfaces
    the final 30d via /exit-report so the manager can spot 'preparing to
    walk' behavior."""
    admin = _require_perm(request, "tech:delete")
    target = get_tech_by_id(tech_id)
    if not target:
        raise HTTPException(404, "Tech not found")
    result = terminate_account("tech", tech_id)
    _audit_from(admin, "account.terminated", request,
                target_type="tech", target_id=tech_id,
                target_label=target.get("name") or target.get("prid"),
                after={"reason": body.reason, **result})
    return {"ok": True, **result}


@app.post("/api/admin/techs/{tech_id}/reinstate")
def admin_reinstate_tech(request: Request, tech_id: int):
    admin = _require_perm(request, "tech:delete")
    target = get_tech_by_id(tech_id)
    if not target:
        raise HTTPException(404, "Tech not found")
    reinstate_account("tech", tech_id)
    _audit_from(admin, "account.reinstated", request,
                target_type="tech", target_id=tech_id,
                target_label=target.get("name"))
    return {"ok": True}


@app.post("/api/admin/customers/{customer_id}/close")
def admin_close_customer(request: Request, customer_id: int, body: TerminateBody):
    """Soft-close at contract end (Scenario 4). active=0 + sessions revoked,
    but the record stays for statutory retention. Use deletion-request
    workflow if the customer asks for actual removal."""
    admin = _require_perm(request, "customer:delete")
    target = get_customer_by_id(customer_id)
    if not target:
        raise HTTPException(404, "Customer not found")
    result = terminate_account("customer", customer_id)
    _audit_from(admin, "account.terminated", request,
                target_type="customer", target_id=customer_id,
                target_label=target.get("name") or target.get("customer_code"),
                after={"reason": body.reason, **result})
    return {"ok": True, **result}


@app.post("/api/admin/customers/{customer_id}/reopen")
def admin_reopen_customer(request: Request, customer_id: int):
    admin = _require_perm(request, "customer:delete")
    target = get_customer_by_id(customer_id)
    if not target:
        raise HTTPException(404, "Customer not found")
    reinstate_account("customer", customer_id)
    _audit_from(admin, "account.reinstated", request,
                target_type="customer", target_id=customer_id,
                target_label=target.get("name") or target.get("customer_code"))
    return {"ok": True}


@app.get("/api/admin/users/{user_id}/exit-report")
def admin_exit_report_admin(request: Request, user_id: int, days: int = 30):
    """Final-30-days activity for a departing admin. The S3 'did they take
    anything' surface — counts, distinct customers viewed, exports, accounts
    they created or modified, last login. Visible to anyone with audit:view_all
    so the director and the manager doing the offboarding can both see it."""
    admin = _require_admin(request)
    if not (_admin_can(admin["role"], "audit:view_all") or admin["id"] == user_id):
        raise HTTPException(403, "Forbidden")
    return get_account_exit_report("admin", user_id, days=days)


@app.get("/api/admin/techs/{tech_id}/exit-report")
def admin_exit_report_tech(request: Request, tech_id: int, days: int = 30):
    admin = _require_admin(request)
    if not _admin_can(admin["role"], "audit:view_all"):
        raise HTTPException(403, "Forbidden")
    return get_account_exit_report("tech", tech_id, days=days)


@app.get("/api/admin/customers/{customer_id}/exit-report")
def admin_exit_report_customer(request: Request, customer_id: int, days: int = 30):
    admin = _require_admin(request)
    if not _admin_can(admin["role"], "audit:view_all"):
        raise HTTPException(403, "Forbidden")
    return get_account_exit_report("customer", customer_id, days=days)


@app.get("/api/admin/access-lifecycle/dormant")
def admin_list_dormant(request: Request, days: int = 90):
    """Active accounts (any type) that haven't logged in for >= days. Spec's
    Scenario 5. Does not auto-suspend — surfaces for review."""
    admin = _require_admin(request)
    if not _admin_can(admin["role"], "audit:view_all"):
        raise HTTPException(403, "Forbidden")
    return find_dormant_accounts(days=days)


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
        start_iso = datetime.fromisoformat(start).replace(tzinfo=timezone.utc).isoformat()
        end_iso   = datetime.fromisoformat(end).replace(tzinfo=timezone.utc).isoformat()
    except ValueError:
        raise HTTPException(400, "start and end must be ISO dates (YYYY-MM-DD)")
    rows = get_timesheet_data(start_iso, end_iso, tech_id=tech_id)
    # Compute duration_minutes server-side so the client doesn't have to
    for r in rows:
        if r.get("start_time") and r.get("end_time"):
            try:
                s = datetime.fromisoformat(r["start_time"].replace("Z", "+00:00"))
                e = datetime.fromisoformat(r["end_time"].replace("Z", "+00:00"))
                r["duration_minutes"] = int((e - s).total_seconds() / 60)
            except Exception:
                r["duration_minutes"] = None
        else:
            r["duration_minutes"] = None
    return rows


# ── Inventory ────────────────────────────────────────────────────────────────

@app.get("/api/admin/parts/export")
def admin_export_parts(request: Request):
    admin = _require_perm(request, "inventory:export")
    _enforce_export_rate(request, admin["id"], "inventory")
    rows = get_all_parts(include_inactive=True)
    _audit_from(admin, "inventory.export", request, target_type="part",
                target_label=f"exported {len(rows)} rows")
    cols = ["id", "sku", "name", "description", "category", "unit",
            "unit_cost", "quantity", "reorder_point", "supplier", "location",
            "active", "created_at"]
    return _csv_response(rows, cols, f"inventory-{datetime.now(timezone.utc).strftime('%Y%m%d')}.csv")


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
    # Reason is mandatory per inventory_manager spec — no silent adjustments.
    if not (body.reason or "").strip():
        raise HTTPException(400, "reason is required for any stock adjustment")
    part = get_part_by_id(part_id)
    if not part:
        raise HTTPException(404, "Part not found")

    # Cost-spike guard: if this is a 'received' movement and the caller hints
    # at a unit_cost via the reason metadata, flag >15% deviation. We surface
    # this in the response so the UI can require manager approval before retry.
    # (The PO/GRN flow is the canonical path — this is a safety net for the
    # legacy direct-adjust route.)
    if body.movement_type == "received" and body.unit_cost is not None:
        avg = get_recent_unit_cost_avg(part_id, days=90)
        # If no GRN history yet, fall back to the catalog unit_cost so the
        # guard still catches obvious spikes on early receipts.
        baseline = avg if (avg and avg > 0) else (part.get("unit_cost") or 0)
        if baseline > 0:
            deviation = abs(body.unit_cost - baseline) / baseline
            if deviation > 0.15 and not body.cost_spike_approved_by:
                src = "90-day average" if avg else "catalog cost"
                raise HTTPException(
                    409,
                    f"Unit cost ${body.unit_cost:.2f} deviates {deviation*100:.1f}% "
                    f"from {src} ${baseline:.2f}. Manager approval required "
                    f"(set cost_spike_approved_by to a super_admin/supervisor_admin id)."
                )

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
    """Stock movement history. For inventory_manager, actor identity is
    stripped — they see WHAT happened, not WHO did it. Manager/director see
    the full row."""
    admin = _require_perm(request, "inventory:view")
    rows = get_part_movements(part_id)
    if admin["role"] == "inventory_manager":
        for r in rows:
            for k in ("performed_by_id", "performed_by_prid", "performed_by_label",
                      "performed_by_type", "customer_name", "visit_id"):
                r.pop(k, None)
    return rows



# ── Purchase orders (Sprint B — three-way match) ─────────────────────────────
class POLineIn(BaseModel):
    part_id: int
    quantity: float
    expected_unit_cost: float = 0


class POCreate(BaseModel):
    supplier: str
    lines:    List[POLineIn]


class GRNCreate(BaseModel):
    po_line_id:        int
    quantity:          float
    actual_unit_cost:  float
    notes:             str = ""


class POCloseOut(BaseModel):
    invoice_number: str
    invoice_total:  float
    variance_note:  str = ""


@app.post("/api/admin/purchase-orders")
def admin_create_po(request: Request, body: POCreate):
    admin = _require_perm(request, "po:create")
    if not body.supplier.strip(): raise HTTPException(400, "supplier required")
    if not body.lines:            raise HTTPException(400, "at least one line required")
    po = create_purchase_order(body.supplier, [l.model_dump() for l in body.lines], admin["id"])
    _audit_from(admin, "po.create", request, target_type="purchase_order",
                target_id=po["id"], target_label=po["po_number"])
    return po


@app.get("/api/admin/purchase-orders")
def admin_list_pos(request: Request, status: Optional[str] = None):
    _require_perm(request, "inventory:view")
    return list_purchase_orders(status=status)


@app.get("/api/admin/purchase-orders/{po_id}")
def admin_get_po(request: Request, po_id: int):
    _require_perm(request, "inventory:view")
    po = get_purchase_order(po_id)
    if not po:
        raise HTTPException(404, "PO not found")
    return po


@app.put("/api/admin/purchase-orders/{po_id}/send")
def admin_send_po(request: Request, po_id: int):
    admin = _require_perm(request, "po:send")
    po = get_purchase_order(po_id)
    if not po: raise HTTPException(404, "PO not found")
    if po["status"] != "draft":
        raise HTTPException(409, f"PO is {po['status']}, can only send drafts")
    mark_po_sent(po_id)
    _audit_from(admin, "po.send", request, target_type="purchase_order",
                target_id=po_id, target_label=po["po_number"])
    return {"ok": True}


@app.post("/api/admin/purchase-orders/{po_id}/receive")
def admin_receive_po_line(request: Request, po_id: int, body: GRNCreate):
    """Records a goods-received entry against a PO line. Bumps stock and
    creates a part_movement so the inventory dashboard reflects it."""
    admin = _require_perm(request, "po:receive")
    po = get_purchase_order(po_id)
    if not po: raise HTTPException(404, "PO not found")
    if po["status"] not in ("sent", "draft"):
        raise HTTPException(409, f"Cannot receive against {po['status']} PO")
    line = next((l for l in po["lines"] if l["id"] == body.po_line_id), None)
    if not line: raise HTTPException(404, "PO line not found on this PO")
    remaining = float(line["quantity"]) - float(line["received_qty"])
    if body.quantity > remaining + 1e-9:
        raise HTTPException(409, f"Over-receipt: line has {remaining} remaining")
    if body.quantity <= 0:
        raise HTTPException(400, "quantity must be positive")
    grn_id = record_goods_received(po_id, body.po_line_id, line["part_id"],
                                    body.quantity, body.actual_unit_cost,
                                    admin["id"], body.notes)
    _audit_from(admin, "po.receive", request, target_type="goods_received",
                target_id=grn_id,
                target_label=f"PO {po['po_number']} part {line['sku']} qty {body.quantity}",
                after={"quantity": body.quantity, "actual_unit_cost": body.actual_unit_cost})
    return {"id": grn_id, "ok": True}


@app.put("/api/admin/purchase-orders/{po_id}/close")
def admin_close_po(request: Request, po_id: int, body: POCloseOut):
    """Three-way match closeout. Requires po:close_out which only
    super_admin and supervisor_admin hold — inventory_manager cannot
    close their own POs. Mismatch beyond 1% requires variance_note."""
    admin = _require_perm(request, "po:close_out")
    if not body.invoice_number.strip():
        raise HTTPException(400, "invoice_number required")
    try:
        result = close_purchase_order(po_id, body.invoice_number,
                                       body.invoice_total, body.variance_note,
                                       admin["id"])
    except ValueError as e:
        msg = str(e)
        code = 409 if "mismatch" in msg.lower() or "variance_note" in msg else 400
        raise HTTPException(code, msg)
    _audit_from(admin, "po.close_out", request, target_type="purchase_order",
                target_id=po_id,
                target_label=f"invoice {body.invoice_number} matched={result['matched']}",
                after=result)
    if not result["matched"]:
        # Variance noted but the spec says it must be visible — raise an alert.
        try:
            create_security_alert(
                kind="po_variance", severity="medium",
                summary=f"PO {po_id} closed with three-way mismatch: PO={result['expected']:.2f}, GRN={result['received_total']:.2f}, Invoice={result['invoice_total']:.2f}",
                actor_type="admin", actor_id=admin["id"],
                details=result,
            )
        except Exception:
            pass
    return result


# ── Physical counts (Sprint C) ───────────────────────────────────────────────
class PhysicalCountCreate(BaseModel):
    part_id:     int
    counted_qty: float


class PhysicalCountApprove(BaseModel):
    note:          str = ""
    adjust_stock:  bool = True


@app.post("/api/admin/physical-counts")
def admin_create_count(request: Request, body: PhysicalCountCreate):
    """Record a physical-count observation. ≥5% variance auto-escalates and
    fires a security_alert — the counter cannot suppress it."""
    admin = _require_perm(request, "count:create")
    try:
        result = create_physical_count(body.part_id, body.counted_qty, admin["id"])
    except ValueError as e:
        raise HTTPException(400, str(e))
    _audit_from(admin, "count.create", request, target_type="physical_count",
                target_id=result["id"], target_label=f"variance {result['variance_pct']}%",
                after=result)
    if result["status"] == "escalated":
        try:
            create_security_alert(
                kind="count_variance",
                severity="high" if result["variance_pct"] >= 10 else "medium",
                summary=f"Physical count #{result['id']} variance {result['variance_pct']}% "
                        f"(system {result['system_qty']}, counted {result['counted_qty']})",
                actor_type="admin", actor_id=admin["id"],
                details=result,
            )
        except Exception:
            pass
    return result


@app.get("/api/admin/physical-counts")
def admin_list_counts(request: Request, status: Optional[str] = None):
    _require_perm(request, "inventory:view")
    return list_physical_counts(status=status)


@app.put("/api/admin/physical-counts/{count_id}/approve")
def admin_approve_count(request: Request, count_id: int, body: PhysicalCountApprove):
    """Approve a count. Critical SoD rule: approved_by MUST differ from
    counted_by. If the counter was inventory_manager, only super_admin or
    supervisor_admin can approve — that's already enforced by the
    count:approve permission. The same-person check is a defense in depth."""
    admin = _require_perm(request, "count:approve")
    counts = list_physical_counts()
    cnt = next((c for c in counts if c["id"] == count_id), None)
    if not cnt:
        raise HTTPException(404, "count not found")
    if cnt["counted_by"] == admin["id"]:
        raise HTTPException(403, "You cannot approve a count you yourself recorded.")
    try:
        approve_physical_count(count_id, admin["id"], body.note, body.adjust_stock)
    except ValueError as e:
        raise HTTPException(400, str(e))
    _audit_from(admin, "count.approve", request, target_type="physical_count",
                target_id=count_id,
                target_label=f"variance {cnt['variance_pct']}% adjusted={body.adjust_stock}")
    return {"ok": True}


@app.post("/api/admin/parts/{part_id}/image")
async def admin_upload_part_image(request: Request, part_id: int, file: UploadFile = File(...)):
    """Upload a high-res photo for a part so techs can visually confirm
    they're pulling the right component. Stored under uploads/photos and
    served via the same signed-URL mechanism as visit photos."""
    admin = _require_perm(request, "inventory:update")
    part = get_part_by_id(part_id)
    if not part:
        raise HTTPException(404, "Part not found")
    body = await file.read()
    if not body:
        raise HTTPException(400, "empty upload")
    if len(body) > MAX_PHOTO_SIZE:
        raise HTTPException(413, f"file too large (max {MAX_PHOTO_SIZE // (1024*1024)} MB)")
    ext = (Path(file.filename or "").suffix or "").lower()
    if ext not in ALLOWED_PHOTO_EXTS:
        raise HTTPException(400, f"unsupported file type: {ext}")
    filename = f"part-{part_id}-{uuid.uuid4().hex}{ext}"
    (PHOTOS_DIR / filename).write_bytes(body)
    set_part_image(part_id, filename)
    _audit_from(admin, "part.image_uploaded", request, target_type="part",
                target_id=part_id, target_label=filename)
    return {"ok": True, "image_url": _sign_photo_url(filename)}


@app.put("/api/admin/visits/{visit_id}/flag")
def admin_flag_visit(request: Request, visit_id: int, body: FlagForReview):
    """Manager flag-for-review. A submitted visit stays locked from tech
    edits, but a manager can mark it for follow-up. This does NOT unlock
    the tech-side complete endpoint — corrections are admin-only by design."""
    admin = _require_perm(request, "visit:update")
    visit = get_visit_by_id(visit_id)
    if not visit:
        raise HTTPException(404, "Visit not found")
    set_visit_flag(visit_id, body.flagged, body.note)
    _audit_from(admin,
                "visit.flag" if body.flagged else "visit.unflag",
                request, target_type="visit", target_id=visit_id,
                target_label=body.note or "")
    return {"ok": True}


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


@app.get("/api/admin/invoices/export")
def admin_export_invoices(request: Request,
                          status: Optional[str] = None,
                          customer_id: Optional[int] = None):
    admin = _require_perm(request, "invoice:export")
    _enforce_export_rate(request, admin["id"], "invoice")
    rows = get_all_invoices(status=status, customer_id=customer_id)
    _audit_from(admin, "invoice.export", request, target_type="invoice",
                target_label=f"exported {len(rows)} rows")
    cols = ["id", "invoice_number", "customer_id", "visit_id", "issue_date",
            "due_date", "subtotal", "gct_amount", "total", "amount_paid",
            "status", "created_at"]
    return _csv_response(rows, cols, f"invoices-{datetime.now(timezone.utc).strftime('%Y%m%d')}.csv")


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
        # IDOR-safe: indistinguishable 404 whether the invoice doesn't exist
        # or belongs to a different customer.
        raise HTTPException(404, "Invoice not found")
    if inv["status"] == "draft":
        raise HTTPException(404, "Invoice not found")
    cust = get_customer_by_id(customer_id)
    _audit_customer(cust, "portal.viewed_invoice", request,
                    target_type="invoice", target_id=invoice_id,
                    target_label=inv.get("invoice_number"))
    return inv


# ── Service requests (client-portal triage queue) ────────────────────────────
@app.post("/api/portal/requests")
def portal_create_request(req: CustomerServiceRequest, request: Request):
    """A client request goes into a triage queue — it does NOT directly
    create a visit on the schedule. Staff with visit:create promotes the
    request into a real visit."""
    customer_id = _require_customer(request)
    _enforce_rate(request, "svcreq", str(customer_id),
                  max_attempts=10, window_seconds=3600,
                  message="Too many service requests in the last hour. Please try later.")
    if req.request_type not in ("maintenance", "repair", "quote", "question"):
        raise HTTPException(400, "Invalid request_type")
    if not req.subject.strip() or not req.body.strip():
        raise HTTPException(400, "Subject and body are required")
    # Verify equipment_id (if provided) belongs to this customer — IDOR check.
    if req.equipment_id is not None:
        eq = get_equipment_by_id(req.equipment_id)
        if not eq or eq["customer_id"] != customer_id:
            raise HTTPException(404, "Equipment not found")
    rid = create_service_request(customer_id, req.model_dump(), ip_address=_client_ip(request))
    cust = get_customer_by_id(customer_id)
    _audit_customer(cust, "portal.request_submitted", request,
                    target_type="service_request", target_id=rid,
                    target_label=req.subject[:60])
    return {"id": rid, "status": "new"}


@app.get("/api/portal/requests")
def portal_list_my_requests(request: Request):
    customer_id = _require_customer(request)
    return list_service_requests(customer_id=customer_id)


@app.get("/api/admin/service-requests")
def admin_list_service_requests(request: Request, status: Optional[str] = None):
    _require_perm(request, "visit:view")
    return list_service_requests(status=status)


class TriageBody(BaseModel):
    status:   str             # 'triaged'|'scheduled'|'closed'
    visit_id: Optional[int] = None
    note:     str = ""


@app.put("/api/admin/service-requests/{req_id}/triage")
def admin_triage_service_request(request: Request, req_id: int, body: TriageBody):
    admin = _require_perm(request, "visit:update")
    sr = get_service_request(req_id)
    if not sr:
        raise HTTPException(404, "Request not found")
    if body.status not in ("triaged", "scheduled", "closed"):
        raise HTTPException(400, "Invalid status")
    update_service_request_status(req_id, body.status, admin["id"],
                                   visit_id=body.visit_id)
    _audit_from(admin, f"service_request.{body.status}", request,
                target_type="service_request", target_id=req_id,
                target_label=body.note or sr.get("subject", "")[:60],
                after={"visit_id": body.visit_id, "note": body.note})
    return {"ok": True}


# ── Privacy: data export + deletion request ─────────────────────────────────
@app.get("/api/portal/me/export")
def portal_export_me(request: Request):
    """Customer self-service data export. JSON dump of every record the
    customer has visibility into. Designed for DPA / GDPR-style
    'right to portability' compliance. Rate-limited to 1/hour."""
    customer_id = _require_customer(request)
    _enforce_rate(request, "data_export", str(customer_id),
                  max_attempts=1, window_seconds=3600,
                  message="Data export limit reached: 1 per hour.")
    cust = get_customer_by_id(customer_id)
    data = get_customer_full_export(customer_id)
    _audit_customer(cust, "portal.data_exported", request,
                    target_type="customer", target_id=customer_id)
    return data


@app.post("/api/portal/me/deletion-request")
def portal_request_deletion(request: Request):
    """Marks the account as deletion-requested. Does NOT actually delete —
    spec is explicit that deletion is a triaged, audited operation, not a
    self-service hard delete. Staff completes the deletion under the
    relevant retention policy."""
    customer_id = _require_customer(request)
    cust = get_customer_by_id(customer_id)
    if not cust:
        raise HTTPException(404, "Customer not found")
    if cust.get("deletion_requested_at"):
        return {"ok": True, "already_requested": True,
                "requested_at": cust["deletion_requested_at"]}
    mark_customer_deletion_requested(customer_id)
    _audit_customer(cust, "portal.deletion_requested", request,
                    target_type="customer", target_id=customer_id)
    return {"ok": True}


# Visit work-summary editor (admin/manager only). Tech writes the raw
# work_done; admin polishes work_done_summary for the customer.
class VisitWorkSummaryBody(BaseModel):
    summary: str


@app.put("/api/admin/visits/{visit_id}/work-summary")
def admin_set_visit_summary(request: Request, visit_id: int, body: VisitWorkSummaryBody):
    admin = _require_perm(request, "visit:update")
    visit = get_visit_by_id(visit_id)
    if not visit:
        raise HTTPException(404, "Visit not found")
    set_visit_work_summary(visit_id, body.summary)
    _audit_from(admin, "visit.work_summary_set", request,
                target_type="visit", target_id=visit_id,
                target_label=(body.summary or "")[:80])
    return {"ok": True}


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
            datetime.fromisoformat(expiry_clean)
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
    Every call is audit-logged as a view; highly_sensitive logs separately
    AND requires a recent MFA verification (default: within 15 minutes)."""
    admin = _require_perm(request, "documents:view")
    doc = get_document_by_id(doc_id)
    if not doc:
        raise HTTPException(404, "Document not found")
    if doc["sensitivity"] == "highly_sensitive":
        if not _admin_can(admin["role"], "documents:view_highly_sensitive"):
            raise HTTPException(403, "Your role cannot view Highly Sensitive documents")
        # Tier-3 step-up: require a fresh MFA proof. Throws 401 with
        # X-Require-MFA-Reauth header that the client uses to prompt.
        _require_recent_mfa(request, admin)

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


@app.get("/api/admin/access")
def admin_access_log(request: Request,
                     actor_id: Optional[int] = None,
                     path_prefix: Optional[str] = None,
                     since: Optional[str] = None,
                     until: Optional[str] = None,
                     limit: int = 200):
    """Read-access trail (separate from audit_log so the chain stays focused
    on mutations). audit:view_all sees everything; audit:view_self sees only
    their own access events."""
    admin = _require_admin(request)
    if _admin_can(admin["role"], "audit:view_all"):
        return query_access_log(actor_id=actor_id, path_prefix=path_prefix,
                                since=since, until=until, limit=limit)
    if _admin_can(admin["role"], "audit:view_self"):
        return query_access_log(actor_id=admin["id"], path_prefix=path_prefix,
                                since=since, until=until, limit=limit)
    raise HTTPException(403, "Forbidden")


@app.get("/api/admin/access/aggregate")
def admin_access_aggregate(request: Request,
                            since: Optional[str] = None,
                            until: Optional[str] = None,
                            actor_id: Optional[int] = None,
                            target_type: Optional[str] = None,
                            min_views: int = 1,
                            limit: int = 200):
    """Aggregate read-access by (actor, target_type, target_id) so admins can
    spot patterns like "Tech X viewed Customer Y 47 times". Scoped the same
    way as /api/admin/access: view_all sees everyone, view_self only sees
    their own activity."""
    admin = _require_admin(request)
    if _admin_can(admin["role"], "audit:view_all"):
        return aggregate_access_by_target(since=since, until=until,
                                          actor_id=actor_id,
                                          target_type=target_type,
                                          min_views=min_views, limit=limit)
    if _admin_can(admin["role"], "audit:view_self"):
        return aggregate_access_by_target(since=since, until=until,
                                          actor_id=admin["id"],
                                          target_type=target_type,
                                          min_views=min_views, limit=limit)
    raise HTTPException(403, "Forbidden")


@app.get("/api/admin/security/alerts")
def admin_list_alerts(request: Request, status: Optional[str] = None, limit: int = 100):
    _require_perm(request, "security:view_alerts")
    return list_security_alerts(status=status, limit=limit)


@app.get("/api/admin/security/alerts/summary")
def admin_alerts_summary(request: Request):
    """Lightweight count for the dashboard banner — anyone with view_alerts
    perm sees this. Used by admin.html to render a red banner on login."""
    _require_perm(request, "security:view_alerts")
    return {"open": count_open_security_alerts()}


class AlertResolveBody(BaseModel):
    note: Optional[str] = None
    status: Optional[str] = "resolved"   # 'resolved' | 'dismissed'


@app.post("/api/admin/security/alerts/{alert_id}/resolve")
def admin_resolve_alert(request: Request, alert_id: int, body: AlertResolveBody):
    admin = _require_perm(request, "security:resolve_alerts")
    if body.status not in ("resolved", "dismissed"):
        raise HTTPException(400, "status must be 'resolved' or 'dismissed'")
    resolve_security_alert(alert_id, admin["id"], note=body.note or "", status=body.status)
    _audit_from(admin, f"security.alert_{body.status}", request,
                target_type="security_alert", target_id=alert_id,
                target_label=body.note or "")
    return {"ok": True}


def _csv_response(rows: list, columns: list, filename: str) -> PlainTextResponse:
    """Render rows to CSV with RFC 4180 escaping. `columns` is a list of dict
    keys to include, in order."""
    import csv as _csv
    buf = io.StringIO()
    w = _csv.writer(buf, quoting=_csv.QUOTE_MINIMAL)
    w.writerow(columns)
    for r in rows:
        w.writerow([r.get(c, "") if r.get(c) is not None else "" for c in columns])
    return PlainTextResponse(
        buf.getvalue(),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.get("/api/admin/customers/export")
def admin_export_customers(request: Request):
    admin = _require_perm(request, "customer:export")
    _enforce_export_rate(request, admin["id"], "customer")
    rows = get_all_customers()
    _audit_from(admin, "customer.export", request, target_type="customer",
                target_label=f"exported {len(rows)} rows")
    cols = ["id", "customer_type", "first_name", "last_name", "company_name",
            "email", "phone", "address", "parish", "created_at"]
    return _csv_response(rows, cols, f"customers-{datetime.now(timezone.utc).strftime('%Y%m%d')}.csv")


@app.get("/api/admin/techs/export")
def admin_export_techs(request: Request):
    admin = _require_perm(request, "tech:export")
    _enforce_export_rate(request, admin["id"], "tech")
    rows = get_all_techs()
    _audit_from(admin, "tech.export", request, target_type="tech",
                target_label=f"exported {len(rows)} rows")
    cols = ["id", "prid", "first_name", "last_name", "email", "phone",
            "tech_role", "is_active", "hire_date", "created_at"]
    return _csv_response(rows, cols, f"techs-{datetime.now(timezone.utc).strftime('%Y%m%d')}.csv")


@app.get("/api/admin/visits/export")
def admin_export_visits(request: Request):
    admin = _require_perm(request, "visit:export")
    _enforce_export_rate(request, admin["id"], "visit")
    rows = get_all_visits()
    _audit_from(admin, "visit.export", request, target_type="visit",
                target_label=f"exported {len(rows)} rows")
    cols = ["id", "customer_id", "technician_id", "scheduled_date",
            "service_type", "status", "equipment_name", "work_performed",
            "created_at"]
    return _csv_response(rows, cols, f"visits-{datetime.now(timezone.utc).strftime('%Y%m%d')}.csv")


@app.get("/api/admin/audit")
def admin_audit(request: Request,
                actor_id: Optional[int] = None,
                action_prefix: Optional[str] = None,
                target_type: Optional[str] = None,
                since: Optional[str] = None,
                until: Optional[str] = None,
                limit: int = 200):
    admin = _require_admin(request)
    # super_admin (director) sees everything. supervisor_admin (manager) sees
    # only actions by their subordinates — the spec requires the visibility
    # to drop one level. Others fall through to view_self.
    if admin["role"] == "super_admin" and _admin_can(admin["role"], "audit:view_all"):
        return query_audit_log(actor_id=actor_id, action_prefix=action_prefix,
                               target_type=target_type, since=since, until=until, limit=limit)
    if admin["role"] == "supervisor_admin" and _admin_can(admin["role"], "audit:view_all"):
        return query_audit_log_team(admin["id"], action_prefix=action_prefix,
                                     target_type=target_type, since=since, until=until, limit=limit)
    if _admin_can(admin["role"], "audit:view_all"):
        return query_audit_log(actor_id=actor_id, action_prefix=action_prefix,
                               target_type=target_type, since=since, until=until, limit=limit)
    if _admin_can(admin["role"], "audit:view_self"):
        return query_audit_log(actor_id=admin["id"], action_prefix=action_prefix,
                               target_type=target_type, since=since, until=until, limit=limit)
    raise HTTPException(403, "Forbidden")


@app.get("/api/admin/history/{target_type}/{target_id}")
def admin_entity_history(request: Request, target_type: str, target_id: int,
                          limit: int = 500):
    """Per-entity timeline: every mutation AND every read of this object,
    merged and time-sorted. The spec's "pull up any client/job/part/user
    and see its entire lifecycle" requirement. Same role gating as audit
    view — supervisor sees only their team's involvement; super_admin sees
    everything; view_self sees only the actor's own activity."""
    admin = _require_admin(request)
    rows = get_entity_history(target_type, target_id, limit=limit)
    if admin["role"] == "super_admin" and _admin_can(admin["role"], "audit:view_all"):
        return rows
    if admin["role"] == "supervisor_admin" and _admin_can(admin["role"], "audit:view_all"):
        subs = subordinate_ids_for(admin["id"])
        admin_ids = set(subs["admin_ids"] + [admin["id"]])
        tech_ids  = set(subs["tech_ids"])
        return [r for r in rows if
                (r.get("actor_type") == "admin" and r.get("actor_id") in admin_ids)
             or (r.get("actor_type") == "tech"  and r.get("actor_id") in tech_ids)
             or (r.get("actor_type") == "anonymous")]
    if _admin_can(admin["role"], "audit:view_self"):
        return [r for r in rows if r.get("actor_id") == admin["id"]]
    raise HTTPException(403, "Forbidden")


class SupervisorAssign(BaseModel):
    supervisor_id: Optional[int] = None


@app.put("/api/admin/users/{user_id}/supervisor")
def admin_set_admin_supervisor(request: Request, user_id: int, body: SupervisorAssign):
    """Assign or clear an admin's supervisor (manager). Used to drive
    team-scoped audit visibility. Only super_admin can change reporting lines."""
    admin = _require_perm(request, "admin:set_role")
    if user_id == body.supervisor_id:
        raise HTTPException(400, "An admin cannot supervise themselves.")
    set_admin_supervisor(user_id, body.supervisor_id)
    _audit_from(admin, "admin.set_supervisor", request,
                target_type="admin_user", target_id=user_id,
                after={"supervisor_id": body.supervisor_id})
    return {"ok": True}


@app.put("/api/admin/techs/{tech_id}/supervisor")
def admin_set_tech_supervisor(request: Request, tech_id: int, body: SupervisorAssign):
    admin = _require_perm(request, "tech:update")
    set_tech_supervisor(tech_id, body.supervisor_id)
    _audit_from(admin, "tech.set_supervisor", request,
                target_type="tech", target_id=tech_id,
                after={"supervisor_id": body.supervisor_id})
    return {"ok": True}


@app.get("/api/admin/customers")
def admin_list_customers(request: Request):
    _require_perm(request, "customer:view")
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
    if not cust:
        raise HTTPException(404, "Customer not found")
    delete_customer(customer_id)
    _audit_from(admin, "customer.delete", request,
                target_type="customer", target_id=customer_id,
                target_label=cust["customer_code"],
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
    eq = get_equipment_by_id(equipment_id)
    if not eq:
        raise HTTPException(404, "Equipment not found")
    delete_equipment(equipment_id)
    _audit_from(admin, "equipment.delete", request,
                target_type="equipment", target_id=equipment_id,
                target_label=eq.get("name"))
    return {"ok": True}


@app.get("/api/admin/visits")
def admin_list_visits(request: Request):
    _require_perm(request, "visit:view")
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
    if not before:
        raise HTTPException(404, "Visit not found")
    delete_visit(visit_id)
    _audit_from(admin, "visit.delete", request,
                target_type="visit", target_id=visit_id,
                target_label=f"{before.get('visit_type','?')} for {before.get('customer_name','?')}",
                before=before)
    return {"ok": True}


@app.get("/api/admin/reviews")
def admin_list_reviews(request: Request, status: Optional[str] = None):
    _require_perm(request, "review:view")
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
    # Look up before deleting so the audit row captures the snapshot
    existing = [r for r in get_all_reviews() if r["id"] == review_id]
    if not existing:
        raise HTTPException(404, "Review not found")
    delete_review(review_id)
    _audit_from(admin, "review.delete", request,
                target_type="review", target_id=review_id,
                target_label=f"{existing[0].get('customer_name','?')} — {existing[0].get('rating','?')}★",
                before=existing[0])
    return {"ok": True}


@app.get("/api/admin/techs")
def admin_list_techs(request: Request):
    _require_perm(request, "tech:view")
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
    if not tech:
        raise HTTPException(404, "Technician not found")
    delete_tech(tech_id)
    _audit_from(admin, "tech.delete", request,
                target_type="tech", target_id=tech_id,
                target_label=tech["tech_code"],
                before=tech)
    return {"ok": True}


@app.get("/api/admin/visits/{visit_id}/photos")
def admin_get_visit_photos(request: Request, visit_id: int):
    _require_perm(request, "visit:view_photos")
    return _enrich_photos(get_visit_photos(visit_id))


@app.delete("/api/admin/photos/{photo_id}")
def admin_delete_photo(request: Request, photo_id: int):
    _require_perm(request, "visit:view_photos")
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
