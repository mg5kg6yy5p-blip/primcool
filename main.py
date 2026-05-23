from contextlib import asynccontextmanager
from collections import deque
from datetime import datetime, timezone, timedelta
from pathlib import Path
from threading import Lock
from typing import Optional, List, Dict, Any

import base64
import hashlib
import hmac
import io
import json as _json
import logging
import os
import re
import secrets as _secrets
import time
import uuid

# ── Structured logger (replaces ad-hoc print() debug calls) ───────────────────
logger = logging.getLogger("primecool")
if not logger.handlers:
    _h = logging.StreamHandler()
    _h.setFormatter(logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    ))
    logger.addHandler(_h)
    logger.setLevel(logging.INFO)

from fastapi import FastAPI, HTTPException, Request, UploadFile, File, Form, Response, Query
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
    validate_pin_policy, record_pin_failure, reset_pin_failures,
    is_customer_pin_locked,
    get_customer_by_code_and_email, create_customer_pin_reset, consume_customer_pin_reset,
    get_customer_equipment, get_customer_equipment_portal_safe,
    get_equipment_by_id, create_equipment, delete_equipment,
    get_customer_with_decryption, update_customer_fields,
    get_customer_equipment_with_visits, get_customer_visits_paginated,
    get_visit_full_detail, get_visit_photos_for_admin,
    update_invoice_payment_status,
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
    create_pay_period, list_pay_periods, get_pay_period,
    upsert_payslip, list_payslips_for_period, list_payslips_for_subject,
    get_payslip, mark_payslip_viewed, approve_pay_period, mark_pay_period_paid,
    compute_payslip_amounts,
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
    list_hubs, get_hub_by_id, create_hub,
    get_ar_aging, get_cm_margin,
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
    # 5S workplace-discipline module
    create_asset as fs_create_asset, list_assets as fs_list_assets,
    get_asset_by_id as fs_get_asset_by_id, update_asset as fs_update_asset,
    add_asset_item as fs_add_asset_item, list_asset_items as fs_list_asset_items,
    remove_asset_item as fs_remove_asset_item,
    get_checklist_for_phase as fs_get_checklist_for_phase,
    submit_audit as fs_submit_audit,
    list_audits as fs_list_audits, get_audit_with_items as fs_get_audit_with_items,
    list_exceptions as fs_list_exceptions, get_exception as fs_get_exception,
    resolve_exception as fs_resolve_exception,
    escalate_exception as fs_escalate_exception,
    find_overdue_exceptions as fs_find_overdue_exceptions,
    compute_compliance_score as fs_compute_compliance_score,
    list_compliance_overview as fs_list_compliance_overview,
    correlate_5s_to_kpi as fs_correlate_5s_to_kpi,
    open_coaching as fs_open_coaching, close_coaching as fs_close_coaching,
    list_coaching as fs_list_coaching,
    fs_today_status_for_tech, fs_export_all,
    # Technician Detail View (super_admin)
    get_technician_with_decryption, update_technician_fields,
    get_technician_jobs_paginated,
    list_technician_reviews, create_technician_review, update_technician_review,
    list_kpi_threshold_overrides, create_kpi_threshold_override,
    list_5s_overrides, create_5s_override,
    get_technician_certifications, get_technician_payroll_summary,
    # Visit callback chain + 5S exception photo uploads
    set_visit_callback_link, get_visit_callback_chain,
    create_exception_photo, list_exception_photos,
    # PrimeCool Invoicing Module
    search_parts_catalog, get_active_fx_rate, set_fx_rate_manual,
    list_fx_rate_history, compute_fx_display,
    get_invoice_metrics, list_invoices, export_invoices_csv,
    get_invoice_full, record_invoice_payment_v2,
    transition_invoice_status, create_invoice_with_lines,
    update_invoice_with_lines,
    StaleWriteError,
    # Employee KPI Tracking Module
    get_or_create_period, ensure_period_exists, close_period,
    list_kpi_periods, list_kpi_definitions, list_kpi_thresholds,
    upsert_kpi_threshold, iso_week_key,
    recompute_kpi_scores, recompute_all_open_periods,
    get_kpi_scorecard, get_kpi_trend, get_team_scoreboard,
    list_kpi_flags_for_tech,
    # Phase 3 escalation engine
    list_kpi_flags, count_open_flags_by_severity, get_kpi_flag_detail,
    acknowledge_kpi_flag, start_kpi_flag_work, resolve_kpi_flag,
    override_kpi_flag,
    # Phase 5 KPI Notes
    create_kpi_note, get_kpi_note, update_kpi_note, archive_kpi_note,
    list_kpi_notes_for_tech, list_kpi_notes_for_flag, list_kpi_notes_for_score,
    list_kpi_notes_for_period, list_kpi_notes_filtered,
    count_open_tech_responses, _can_read_kpi_note,
    # Phase 6 KPI Goals + PIPs
    create_kpi_goal, get_kpi_goal, hr_acknowledge_pip, activate_pip,
    add_goal_checkin, list_goal_checkins, close_goal,
    list_goals_for_tech, list_active_pips, list_goals_filtered,
    suggest_pip_for_flag, tech_set_action_item_done,
    # Phase 7 Custom KPIs
    create_custom_kpi, archive_custom_kpi, set_manual_kpi_value,
    list_manual_kpi_history,
    # TP-1a tech portal remodel helpers
    set_tech_schedule_day, get_tech_schedule, get_tech_scheduled_end_today,
    is_tech_scheduled_today,
    is_tech_on_call_today, set_tech_on_call_override,
    delete_tech_on_call_override, list_tech_on_call_overrides,
    record_clock_in, record_clock_out, record_auto_clock_out,
    get_open_clock_in_today, list_clock_events_for_tech,
    list_clocked_in_techs_today,
    is_overtime_approved, approve_overtime,
    list_tech_certifications, create_tech_certification,
    list_certs_expiring_within,
    list_tech_cv_entries, append_tech_cv_entry, lock_tech_cv_entry,
    grant_cv_edit, cv_entry_is_editable, update_tech_cv_entry,
    consume_cv_edit_grant, request_cv_edit, get_pending_cv_edit_request,
    list_pending_cv_edit_requests, approve_cv_edit_request,
    deny_cv_edit_request,
    list_released_periods_for_tech, release_kpi_period_to_tech,
    create_company_message, list_active_company_messages,
    list_all_company_messages, hide_company_message,
)
import imghdr as _imghdr
import mimetypes as _mimetypes

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
        # Payroll — director sees everything and is the only approver.
        "payroll:generate", "payroll:view_all", "payroll:approve", "payroll:mark_paid",
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
        # 5S workplace-discipline
        "fs:audit_any", "fs:exception_resolve", "fs:exception_escalate_director",
        "fs:asset_manage", "fs:report_view", "fs:audit_override",
        "fs:coaching_manage",
        # Employee KPI Tracking
        "kpi:view_team", "kpi:edit_thresholds", "kpi:recompute",
        "kpi:view_definitions", "kpi:close_period",
        # Phase 3 escalation engine
        "kpi:flag_view", "kpi:flag_resolve", "kpi:flag_override",
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
        # 5S workplace-discipline (supervisor can audit anyone, resolve / escalate)
        "fs:audit_any", "fs:exception_resolve", "fs:exception_escalate_director",
        "fs:report_view", "fs:coaching_manage",
        # Employee KPI Tracking — supervisor manages team + can recompute,
        # but cannot edit thresholds or close periods (director-only).
        "kpi:view_team", "kpi:recompute", "kpi:view_definitions",
        # Phase 3 escalation engine — supervisor can view + resolve flags but
        # NOT override (override is super_admin-only per locked design).
        "kpi:flag_view", "kpi:flag_resolve",
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
        # 5S — system_admin manages the asset catalog + can view reports
        "fs:asset_manage", "fs:report_view",
        # KPI — read-only on team + definitions
        "kpi:view_team", "kpi:view_definitions",
        "kpi:flag_view",
    },
    "hr_admin": {
        "tech:view", "tech:create", "tech:update", "tech:reset_pin",
        "audit:view_self",
        "timesheet:view_all",
        "invoice:view",
        "documents:upload", "documents:view", "documents:view_highly_sensitive",
        # HR generates payroll; super_admin approves (separation of duties).
        "payroll:generate", "payroll:view_all",
        # 5S — HR sees reports for coaching/performance context (read-only).
        "fs:report_view",
        # KPI — read access for performance reviews
        "kpi:view_team", "kpi:view_definitions",
        "kpi:flag_view",
    },
    "ceo_assistant": {
        "audit:view_self",
        "inventory:view",
        "invoice:view",
        "documents:view",
        # 5S — read-only operational visibility.
        "fs:report_view",
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


# ── KPI Module phases 5–7 permission additions ───────────────────────────────
# Notes (Phase 5)
ADMIN_PERMS["super_admin"].update({
    "kpi:note_write_coaching", "kpi:note_write_recognition",
    "kpi:note_write_team_period", "kpi:note_write_score_annotation",
    "kpi:note_view",
    # Phase 6 — goals + PIPs
    "kpi:goal_create", "kpi:goal_close",
    "kpi:pip_create", "kpi:pip_activate", "kpi:goal_view",
    # Phase 7 — custom KPI
    "kpi:def_create", "kpi:def_archive", "kpi:manual_value_set",
})
ADMIN_PERMS["supervisor_admin"].update({
    "kpi:note_write_coaching", "kpi:note_write_recognition",
    "kpi:note_write_score_annotation", "kpi:note_view",
    "kpi:goal_create", "kpi:goal_close", "kpi:goal_view",
    "kpi:manual_value_set",
})
ADMIN_PERMS["system_admin"].update({
    "kpi:note_view",
})
ADMIN_PERMS["hr_admin"].update({
    "kpi:note_write_recognition", "kpi:note_view",
    "kpi:goal_view", "kpi:pip_acknowledge",
})

# ── TP-1b: tech portal remodel permissions ───────────────────────────────────
ADMIN_PERMS["super_admin"].update({
    "tech:approve_overtime", "company:post_message", "company:read_messages",
    "tech:manage_schedule", "tech:manage_certifications",
    "tech:release_kpi_period", "tech:grant_cv_edit",
})
ADMIN_PERMS["supervisor_admin"].update({
    "tech:approve_overtime", "company:read_messages",
    "tech:manage_schedule", "tech:manage_certifications",
    "tech:release_kpi_period",
})
ADMIN_PERMS["hr_admin"].update({
    "tech:approve_overtime", "company:read_messages",
    "tech:manage_certifications",
})
ADMIN_PERMS["system_admin"].update({"company:read_messages"})
ADMIN_PERMS["ceo_assistant"].update({"company:read_messages",
                                     "company:post_message"})
ADMIN_PERMS["inventory_manager"].update({"company:read_messages"})


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
    """Return the connecting client's IP.

    Pre-PC-003 fix this function read X-Forwarded-For directly, which
    let any internet client forge their own source IP — defeating the
    rate-limit per-IP bucket and polluting the audit ip_address column.

    Now we trust ONLY request.client.host. The proxy-header resolution
    is handled UPSTREAM by uvicorn's --proxy-headers flag (configured
    in railway.toml with --forwarded-allow-ips restricted to the
    Railway edge). If you deploy this app outside Railway and behind a
    different reverse proxy, you MUST also pass --proxy-headers with a
    matching --forwarded-allow-ips — otherwise client.host will be the
    proxy IP rather than the real client.

    See: docs/SECURITY.md, finding PC-003.
    """
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


def _enforce_pin_pacer(request: Request):
    """Phase 3: 1 PIN-login attempt per 5 seconds per source IP, across all
    accounts. Stops sub-second credential-spray attacks that the per-account
    lockout alone can't catch (because each attempt targets a different code).
    Returns 429 with a clear hint."""
    ip = _client_ip(request)
    if not _rate_check(f"pinpace:{ip}", max_attempts=1, window_seconds=5):
        raise HTTPException(429, "Slow down — wait a few seconds between sign-in attempts.")


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
        "standard_rate": INVOICE_TAX_RATE,
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

# Push the payroll rates into the database module so compute_payslip_amounts()
# reads from this dict as its single source of truth. When TAJ changes rates,
# edit JAMAICA_TAX_REFERENCE above and restart — no other surgery needed.
from database import set_payroll_rates as _set_payroll_rates
_set_payroll_rates(JAMAICA_TAX_REFERENCE.get("payroll", {}))

TIER_LABELS = {
    "residential": "Residential — Home & Property",
    "commercial":  "Commercial — SME & Corporate",
    "industrial":  "Industrial — Process & Facility",
    "unsure":      "Not sure — need an assessment",
}

JWT_ALGORITHM = "HS256"
COOKIE_SECURE = os.environ.get("COOKIE_SECURE", "false").lower() == "true"  # set to true in prod (HTTPS)
PROD_MODE     = os.environ.get("PROD_MODE", "false").lower() == "true"

# Placeholder/known-weak secrets — refuse to boot with any of these as JWT_SECRET.
# Keep this list small and explicit; a second reader should be able to confirm
# it covers the obvious bad values without surprises.
_JWT_PLACEHOLDER_SECRETS = {
    "change-me", "changeme", "change-me-in-production",
    "change-me-in-production-set-jwt_secret-env-var",  # legacy default
    "secret", "default", "test", "development", "dev",
    "insecure_please_change", "please_change_me",
    "your-secret-here", "your-256-bit-secret",
    "jwt_secret", "primecool", "primecool-secret",
}


def _preflight_check_jwt_secret(env_value):
    """Returns (ok, detail). Refuses missing, short, placeholder, or low-entropy secrets."""
    if not env_value:
        return False, "JWT_SECRET is not set"
    if len(env_value) < 32:
        return False, f"JWT_SECRET length {len(env_value)} < 32"
    if env_value.lower() in _JWT_PLACEHOLDER_SECRETS:
        return False, "JWT_SECRET matches a known placeholder/default — replace it"
    # Cheap entropy heuristic: a 32-char secret with <8 distinct characters is
    # almost certainly a typed-out placeholder ("aaaaaaaa...", "abc-abc-abc-").
    if len(set(env_value)) < 8:
        return False, f"JWT_SECRET has only {len(set(env_value))} distinct chars — too predictable"
    return True, f"len={len(env_value)} distinct={len(set(env_value))}"


def _preflight_check_cookie_secure():
    """In PROD_MODE, refuse if cookies aren't marked Secure (would send over plain HTTP)."""
    if PROD_MODE and not COOKIE_SECURE:
        return False, "PROD_MODE=true but COOKIE_SECURE=false — cookies would leak over HTTP"
    return True, f"PROD_MODE={PROD_MODE} COOKIE_SECURE={COOKIE_SECURE}"


def _preflight_check_datastore_encryption():
    """We can't reliably detect FDE from inside the app, so we make the operator
    declare it explicitly via DATASTORE_ENCRYPTION_CONFIRMED=yes. An escape
    hatch (DATASTORE_ENCRYPTION_OVERRIDE=yes) is allowed but logged loudly in
    the manifest so a deploy under override is forensically visible."""
    if not PROD_MODE:
        return True, "non-prod: skipped"
    confirmed = os.environ.get("DATASTORE_ENCRYPTION_CONFIRMED", "").lower() == "yes"
    override  = os.environ.get("DATASTORE_ENCRYPTION_OVERRIDE",  "").lower() == "yes"
    if confirmed:
        return True, "DATASTORE_ENCRYPTION_CONFIRMED=yes"
    if override:
        return True, "OVERRIDE — datastore encryption NOT confirmed; running anyway (operator override)"
    return False, ("PROD_MODE=true but DATASTORE_ENCRYPTION_CONFIRMED is not 'yes'. "
                   "Set it after verifying the datastore volume is encrypted at rest. "
                   "If you must boot without confirmation, set "
                   "DATASTORE_ENCRYPTION_OVERRIDE=yes (this is recorded in the boot manifest).")


def _preflight_check_field_encryption_key():
    """The app-layer field encryption key (Phase 2). HARD requirement now —
    Phase 2 columns hold ciphertext that cannot be decrypted without it."""
    val = os.environ.get("FIELD_ENCRYPTION_KEY", "")
    if not val:
        return False, ("FIELD_ENCRYPTION_KEY is not set. Phase 2 encrypted columns "
                       "cannot be read without it. Generate with: "
                       "python -c \"import secrets; print(secrets.token_urlsafe(48))\"")
    if len(val) < 32:
        return False, f"FIELD_ENCRYPTION_KEY length {len(val)} < 32"
    return True, f"FIELD_ENCRYPTION_KEY present (len={len(val)})"


def _preflight_run():
    """Runs every pre-flight gate, writes a manifest, refuses to boot on any
    hard failure. Returns the manifest dict on success."""
    import json as _json, sys as _sys, hashlib as _h
    checks = [
        ("jwt_secret",          _preflight_check_jwt_secret(os.environ.get("JWT_SECRET"))),
        ("cookie_secure",       _preflight_check_cookie_secure()),
        ("datastore_encryption", _preflight_check_datastore_encryption()),
        ("field_encryption_key", _preflight_check_field_encryption_key()),
    ]
    failures = [(name, detail) for name, (ok, detail) in checks if not ok]
    if failures:
        msg = "Pre-flight checks failed — refusing to start:\n" + "\n".join(
            f"  ✗ {name}: {detail}" for name, detail in failures
        )
        # Intentionally keep stderr print here — Railway / container deploy logs
        # surface stderr distinctly on crash, and we want the human-readable
        # failure visible even if logging handlers aren't attached yet.
        print(msg, file=_sys.stderr, flush=True)
        logger.critical(msg)
        raise RuntimeError(msg)
    # Manifest captures who/what/when of the boot — values themselves never
    # logged, only metadata (length, presence, distinct-count for JWT_SECRET).
    secret_val = os.environ.get("JWT_SECRET", "")
    manifest = {
        "boot_time_utc":     datetime.now(timezone.utc).isoformat(),
        "prod_mode":         PROD_MODE,
        "python_version":    _sys.version,
        "checks":            {name: {"ok": ok, "detail": detail} for name, (ok, detail) in checks},
        "cookie_secure":     COOKIE_SECURE,
        "jwt_secret_sha256_prefix": _h.sha256(secret_val.encode()).hexdigest()[:16],
        "datastore_override_used": os.environ.get("DATASTORE_ENCRYPTION_OVERRIDE", "").lower() == "yes",
    }
    try:
        from pathlib import Path as _P
        manifest_dir = _P(os.environ.get("BOOT_MANIFEST_DIR", "boot_manifests"))
        manifest_dir.mkdir(parents=True, exist_ok=True)
        path = manifest_dir / f"boot-{manifest['boot_time_utc'].replace(':','-')}.json"
        path.write_text(_json.dumps(manifest, indent=2, default=str))
        logger.info(f"Pre-flight passed; manifest written to {path}")
        # Defense in depth: once the preflight has confirmed the key,
        # flip the crypto Keyring out of "missing_ok" mode so any later
        # import path that tries to operate without a key will hard-fail
        # instead of silently passing through plaintext.
        try:
            from crypto import _Keyring as _Kr
            _Kr.lock_required()
        except Exception as _e:
            logger.warning(f"crypto.lock_required not engaged: {_e}")
    except Exception as e:
        # Manifest write failure is logged but non-fatal — the gate already passed.
        logger.warning(f"Pre-flight passed but manifest write failed: {e}")
    return manifest


# Run the gate now — before JWT_SECRET, before the app object exists.
_PREFLIGHT = _preflight_run()
JWT_SECRET = os.environ.get("JWT_SECRET")

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
    # idled past its per-role limit, OR whose subject_type doesn't match the
    # token's claimed type (i.e. someone with the signing key forged a
    # type-flipped token) is rejected.
    if require_session:
        jti = data.get("jti")
        if not jti or not is_session_active(jti, IDLE_TIMEOUT,
                                             expected_subject_type=expected_type):
            raise HTTPException(401, "Session no longer valid — please sign in again")
    return data


def _make_request_id() -> str:
    """Short opaque id stamped into 403 response bodies + audit metadata so
    support can correlate a user's "access denied" toast to an audit row."""
    return _secrets.token_hex(6)


def _audit_deny(viewer_kind, viewer_id, action, resource_type, resource_id,
                reason, request, request_id: str = None):
    """Write an access.denied audit row. Called from every _require_* helper
    BEFORE raising HTTPException(403). Never raises — wraps audit failures so
    a logging glitch doesn't accidentally allow the request through."""
    try:
        ip = None
        ua = None
        try:
            ip = request.client.host if request and request.client else None
            ua = (request.headers.get("user-agent", "")[:200]) if request else None
        except Exception:
            pass
        path = None
        method = None
        try:
            path = str(request.url.path) if request else None
            method = request.method if request else None
        except Exception:
            pass
        log_audit(
            actor_type=viewer_kind or "unauthenticated",
            actor_id=viewer_id,
            action="access.denied",
            target_type=resource_type,
            target_id=resource_id,
            after_value={
                "attempted_action": action,
                "reason": reason,
                "ip": ip,
                "user_agent": ua,
                "path": path,
                "method": method,
                "request_id": request_id,
            },
            ip_address=ip,
        )
    except Exception as e:
        logger.warning("audit_deny_failed: %s", e)


def _deny_response(reason: str, viewer_kind, viewer_id, action,
                   resource_type, resource_id, request, status: int = 403):
    """Build the standardized denial: write audit, raise HTTPException with
    {detail, code, request_id} body. Used by every _require_* helper."""
    rid = _make_request_id()
    _audit_deny(viewer_kind, viewer_id, action, resource_type, resource_id,
                reason, request, request_id=rid)
    code = "access_denied" if status == 403 else "unauthenticated"
    detail_msg = "Access denied" if status == 403 else "Authentication required"
    raise HTTPException(status_code=status,
                        detail={"detail": detail_msg, "code": code,
                                "request_id": rid})


def _require_customer(request: Request) -> int:
    try:
        data = _decode_token(_read_token(request, COOKIE_CUSTOMER), "customer")
    except HTTPException as he:
        _deny_response(reason="unauthenticated_customer",
                       viewer_kind="unauthenticated", viewer_id=None,
                       action="customer.session_required",
                       resource_type="portal", resource_id=None,
                       request=request, status=he.status_code or 401)
    return int(data["sub"])


def _require_tech(request: Request) -> int:
    try:
        data = _decode_token(_read_token(request, COOKIE_TECH), "tech")
    except HTTPException as he:
        _deny_response(reason="unauthenticated_tech",
                       viewer_kind="unauthenticated", viewer_id=None,
                       action="tech.session_required",
                       resource_type="tech_portal", resource_id=None,
                       request=request, status=he.status_code or 401)
    tid = int(data["sub"])
    # Defense-in-depth: terminated/suspended techs cannot use the portal.
    try:
        from database import get_tech_by_id as _get_tech_by_id
        t = _get_tech_by_id(tid)
        if t and (t.get("active") in (0, False)
                  or (t.get("employment_status") in ("terminated", "suspended"))):
            _deny_response(reason="tech_inactive",
                           viewer_kind="tech", viewer_id=tid,
                           action="tech.session_required",
                           resource_type="tech_portal", resource_id=tid,
                           request=request, status=403)
    except HTTPException:
        raise
    except Exception:
        pass
    return tid


def _require_admin(request: Request):
    """Returns the admin_user dict for the authenticated admin."""
    try:
        data = _decode_token(_read_token(request, COOKIE_ADMIN), "admin")
    except HTTPException as he:
        _deny_response(reason="unauthenticated_admin",
                       viewer_kind="unauthenticated", viewer_id=None,
                       action="admin.session_required",
                       resource_type="admin", resource_id=None,
                       request=request, status=he.status_code or 401)
    admin_id = data.get("sub")
    if not admin_id:
        _deny_response(reason="invalid_session",
                       viewer_kind="unauthenticated", viewer_id=None,
                       action="admin.session_required",
                       resource_type="admin", resource_id=None,
                       request=request, status=401)
    admin = get_admin_user_by_id(int(admin_id))
    if not admin or not admin.get("active"):
        _deny_response(reason="admin_inactive_or_deleted",
                       viewer_kind="admin", viewer_id=int(admin_id),
                       action="admin.session_required",
                       resource_type="admin", resource_id=int(admin_id),
                       request=request, status=403)
    return admin


def _require_perm(request: Request, perm: str):
    admin = _require_admin(request)
    if not _admin_can(admin["role"], perm):
        _deny_response(reason=f"role_missing_perm:{perm}",
                       viewer_kind="admin", viewer_id=admin["id"],
                       action=perm,
                       resource_type=None, resource_id=None,
                       request=request, status=403)
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
            logger.info(f"Bootstrapped super_admin '{bs_user}' (id={new_id}, PRID={prid})")

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
        logger.info(f"access_log retention: kept last {access_retain_days} days "
                    f"({n} rows purged)")
        if n > 0:
            log_audit(actor_type="system", action="system.retention_purge",
                      target_type="access_log",
                      target_label=f"purged {n} rows older than {access_retain_days}d",
                      after_value={"count": n, "days": access_retain_days})
    except Exception as e:
        logger.warning(f"access_log purge skipped: {e}")
    # Dormant-account sweep. Surfaces inactive-but-still-credentialed
    # accounts so they can be reviewed for soft-close. Does NOT auto-suspend
    # — per spec, this flags, a human decides.
    dormant_days = int(os.environ.get("DORMANT_DAYS", "90"))
    try:
        dormant = find_dormant_accounts(days=dormant_days)
        total = sum(len(v) for v in dormant.values())
        if total > 0:
            logger.warning(f"{total} dormant account(s) (>{dormant_days}d): "
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
            logger.info(f"dormant sweep: no accounts idle >{dormant_days}d")
    except Exception as e:
        logger.warning(f"dormant sweep skipped: {e}")

    try:
        r = purge_old_audit_log(financial_days=fin_retain_days,
                                 operational_days=ops_retain_days)
        if r["financial_purged"] or r["operational_purged"]:
            logger.info(f"audit_log retention: purged {r['financial_purged']} financial "
                        f"+ {r['operational_purged']} operational rows")
            log_audit(actor_type="system", action="system.retention_purge",
                      target_type="audit_log",
                      target_label=f"financial>{fin_retain_days}d → {r['financial_purged']}; "
                                   f"operational>{ops_retain_days}d → {r['operational_purged']}",
                      after_value=r)
        else:
            logger.info(f"audit_log retention: nothing to purge")
    except Exception as e:
        logger.warning(f"audit_log purge skipped: {e}")
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
        logger.error(f"SECURITY ALERT EMAIL ERROR: {e}")


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
            logger.warning(f"SECURITY ALERT #{aid} [{severity}] {kind}: {summary}")
            _send_security_alert_email({
                "kind": kind, "severity": severity, "summary": summary,
                "actor_id": actor_id, "actor_label": None, "actor_prid": None,
                "details": details, "created_at": datetime.now(timezone.utc).isoformat(),
            })
    except Exception as e:
        logger.error(f"anomaly detector error: {e}")


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
                logger.warning(f"watcher_log error: {e}")
    except Exception as e:
        logger.warning(f"access_log error: {e}")
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
# Shared frontend assets (pc_shared.js — toast, apiFetch, modal helpers used by all 3 SPAs).
# Loaded as <script src="/static/pc_shared.js"></script> from admin.html, tech.html, portal_dashboard.html.
app.mount("/static", StaticFiles(directory="static"), name="static")


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

# Generic response envelopes — used as response_model on endpoints whose
# returns are well-shaped enough to advertise in /docs without invasive
# per-endpoint typing. Tighter shapes can replace these incrementally.
# FIXME(docs/FIXMES.md): tighten response_model on Dict[str, Any] endpoints
# (admin customer/visit/invoice/technician/delegation detail routes use
# Dict[str, Any] as a transitional shape — see audit for the target schemas).
class OkResponse(BaseModel):
    ok: bool = True


class IdResponse(BaseModel):
    id: int


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


class CustomerProfileUpdate(BaseModel):
    """super_admin Customer Detail View — editable profile fields.
    All fields optional so the modal can submit a partial body. Server
    re-validates lengths + regexes regardless of client validation."""
    name:                  Optional[str] = None
    company:               Optional[str] = None
    email:                 Optional[str] = None
    phone:                 Optional[str] = None
    address:               Optional[str] = None
    notes:                 Optional[str] = None
    customer_type:         Optional[str] = None    # 'residential' | 'commercial'
    account_status:        Optional[str] = None    # 'active' | 'closed'
    status_change_reason:  Optional[str] = None    # free-text → audit only


class TechnicianProfileUpdate(BaseModel):
    """super_admin Technician Detail View — editable profile fields.
    Mirrors CustomerProfileUpdate pattern: all optional so the modal can
    submit a partial body; server re-validates and re-encrypts. The
    employment_status / role enums are validated server-side (see
    _validate_tech_profile)."""
    phone:              Optional[str] = None
    email:              Optional[str] = None
    role:               Optional[str] = None   # 'tech'|'lead_tech'|'apprentice' (existing schema)
    hourly_rate:        Optional[float] = None
    employment_status:  Optional[str] = None   # 'active'|'on_leave'|'terminated'


class TechnicianReviewCreate(BaseModel):
    review_type:    str
    summary:        str
    status:         Optional[str] = "open"
    action_items:   Optional[str] = None
    followup_date:  Optional[str] = None


class TechnicianReviewUpdate(BaseModel):
    status:         Optional[str] = None
    summary:        Optional[str] = None
    action_items:   Optional[str] = None
    followup_date:  Optional[str] = None


class TechnicianKpiThresholdOverride(BaseModel):
    kpi_key:           str
    green_threshold:   Optional[float] = None
    amber_threshold:   Optional[float] = None
    red_threshold:     Optional[float] = None
    reason:            str
    effective_from:    Optional[str] = None
    effective_until:   Optional[str] = None


class Technician5SOverride(BaseModel):
    exception_id:  int
    reason:        str


class InvoicePaymentUpdate(BaseModel):
    """super_admin Visit Detail View — invoice payment-status edit.
    Strictly the four payment fields. The server rejects any attempt to
    modify other invoice columns by routing through update_invoice_payment_status
    which only writes status / paid_at / notes / amount_paid (and the
    invoice_payments side-table)."""
    status:         str                          # 'unpaid' | 'partially_paid' | 'fully_paid'
    payment_method: Optional[str] = None         # 'cash'|'bank_transfer'|'check'|'card'|'other'
    payment_date:   Optional[str] = None         # ISO date — server treats as a hint only
    notes:          Optional[str] = None
    amount:         Optional[float] = None       # Required for status='partially_paid' (else ignored)


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
    tax_rate:    float = INVOICE_TAX_RATE
    currency:    str = "JMD"
    notes:       str = ""
    line_items:  List[InvoiceLineItem] = []


class InvoiceUpdate(BaseModel):
    customer_id: int
    visit_id:    Optional[int] = None
    issue_date:  str
    due_date:    str
    tax_rate:    float = INVOICE_TAX_RATE
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
async def submit_consult(req: ConsultRequest, request: Request):
    # PC-004 fix: rate limit a public endpoint that BOTH writes to disk AND
    # triggers an outbound Resend email per submission. Pre-fix this was
    # uncapped — a flood would (a) fill submissions.db, (b) burn Resend
    # quota, (c) compound with PC-002 to pollute plaintext PII rows. Two
    # layers: per-(IP+email) and a global circuit breaker.
    # Depends on PC-003 fix (railway.toml --proxy-headers) so the IP key
    # is the actual client, not a forged X-Forwarded-For value.
    _enforce_rate(request, bucket="consult",
                  identity=(req.email or "").strip().lower()[:120],
                  max_attempts=3, window_seconds=3600,
                  message="Too many submissions from this address. "
                          "Please try again later.")
    _enforce_rate(request, bucket="consult_global", identity="",
                  max_attempts=100, window_seconds=600,
                  message="Form is temporarily unavailable. "
                          "Please try again in a few minutes.")
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
            logger.error(f"EMAIL ERROR: {e}")

    return {"ok": True}


# ── Portal (customer) routes ──────────────────────────────────────────────────

@app.post("/api/portal/login")
def portal_login(req: PortalLoginRequest, request: Request, response: Response):
    # Phase 3 pacer first — pre-empts the more expensive rate-limit + DB hit.
    _enforce_pin_pacer(request)
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

    # Phase 3 per-account lockout. Done BEFORE password/PIN verification so a
    # locked account can't be probed with valid credentials inside the window.
    if existing:
        locked, locked_until = is_customer_pin_locked(existing["id"])
        if locked:
            _audit_anon("auth.login_failed", request,
                        attempted_identity=req.code, actor_type="customer",
                        target_label=f"account locked until {locked_until}")
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
        # Record failure → may flip the account into 30-min lockout.
        if existing:
            res = record_pin_failure(existing["id"])
            if res["locked"]:
                # Raise a security alert on the lockout itself — bursts of
                # these on different accounts from one IP are credential spray.
                try:
                    create_security_alert(
                        kind="account_lockout", severity="high",
                        summary=f"Customer {req.code} locked after {res['failed']} failed PIN attempts",
                        actor_type="customer", actor_id=existing["id"],
                        details={"locked_until": res["locked_until"],
                                 "ip": _client_ip(request)},
                    )
                except Exception:
                    pass
        raise HTTPException(401, INVALID)

    # Successful login resets the failure counter.
    if existing:
        reset_pin_failures(existing["id"])

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
                logger.error(f"CUSTOMER PIN RESET EMAIL ERROR: {e}")
    return {"ok": True}


@app.post("/api/portal/reset-pin")
def portal_reset_pin(body: PortalResetPin):
    if body.pin != body.confirm_pin:
        raise HTTPException(400, "PINs do not match")
    try:
        validate_pin_policy(body.pin)
    except ValueError as e:
        raise HTTPException(400, str(e))
    customer_id = consume_customer_pin_reset(body.token)
    if not customer_id:
        raise HTTPException(400, "Reset link is invalid or has expired")
    set_customer_pin(customer_id, body.pin)
    reset_pin_failures(customer_id)
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
    # Portal-safe equipment view: strips serial_number + notes so admin-
    # only PII never leaks into the customer-facing endpoint. See
    # get_customer_equipment_portal_safe in database.py.
    equipment = get_customer_equipment_portal_safe(customer_id)
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
                logger.error(f"PIN RESET EMAIL ERROR: {e}")
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
    # KPI lazy trigger — non-blocking. Failures are logged, not raised: the
    # tech's submission must NEVER be blocked by KPI scoring problems.
    try:
        recompute_kpi_scores(tech_id, get_or_create_period(),
                              triggered_by="visit_event",
                              triggered_by_id=tech_id)
    except Exception as e:
        logger.warning(f"kpi recompute deferred: {e}")
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
    # Chain-of-custody metadata — all OPTIONAL. The PWA captures and sends
    # what it can; we stamp the server-side fields regardless. Client values
    # are recorded as 'client-claimed', never trusted as authoritative on
    # their own.
    client_meta: Optional[str]  = Form(None),   # JSON blob, see schema in OpManual 8.10
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

    # ── Metadata assembly ────────────────────────────────────────────────
    # Server-authoritative fields are stamped here from the request; the
    # client payload (geo + device + camera) is parsed defensively and
    # promoted only for fields we recognise. Anything else lands in the
    # encrypted client_meta_json catch-all.
    meta = {
        "server_ip": _client_ip(request),
        "server_ua": (request.headers.get("user-agent") or "")[:512],
    }
    if client_meta:
        try:
            cm = _json.loads(client_meta)
            if not isinstance(cm, dict):
                cm = {}
        except Exception:
            cm = {}
        # Promote known keys to typed columns. Cap strings; reject absurd
        # values silently rather than 400 — we never let a bad meta payload
        # block a photo upload.
        def _s(v, n=255):
            try: return str(v)[:n] if v is not None else None
            except Exception: return None
        def _f(v):
            try: return float(v) if v is not None else None
            except Exception: return None
        def _i(v):
            try: return int(v) if v is not None else None
            except Exception: return None
        meta["client_captured_at"] = _s(cm.get("client_captured_at"), 40)
        meta["geo_lat"]            = _f(cm.get("geo", {}).get("lat") if isinstance(cm.get("geo"), dict) else None)
        meta["geo_lng"]            = _f(cm.get("geo", {}).get("lng") if isinstance(cm.get("geo"), dict) else None)
        meta["geo_accuracy_m"]     = _f(cm.get("geo", {}).get("accuracy_m") if isinstance(cm.get("geo"), dict) else None)
        meta["geo_captured_at"]    = _s(cm.get("geo", {}).get("captured_at") if isinstance(cm.get("geo"), dict) else None, 40)
        meta["device_platform"]    = _s(cm.get("device", {}).get("platform") if isinstance(cm.get("device"), dict) else None, 64)
        meta["device_model"]       = _s(cm.get("device", {}).get("model") if isinstance(cm.get("device"), dict) else None, 128)
        meta["device_screen"]      = _s(cm.get("device", {}).get("screen") if isinstance(cm.get("device"), dict) else None, 48)
        meta["camera_facing"]      = _s(cm.get("camera", {}).get("facing") if isinstance(cm.get("camera"), dict) else None, 32)
        meta["camera_width"]       = _i(cm.get("camera", {}).get("width") if isinstance(cm.get("camera"), dict) else None)
        meta["camera_height"]      = _i(cm.get("camera", {}).get("height") if isinstance(cm.get("camera"), dict) else None)
        meta["network_type"]       = _s(cm.get("network_type"), 32)
        meta["app_version"]        = _s(cm.get("app_version"), 32)
        # Anything else the client sent that we didn't promote — keep it.
        promoted = {"client_captured_at", "geo", "device", "camera",
                    "network_type", "app_version"}
        leftover = {k: v for k, v in cm.items() if k not in promoted}
        if leftover:
            meta["client_meta_json"] = _json.dumps(leftover)[:8000]

    photo_id = create_photo(visit_id, category, fname, tech_id, metadata=meta)
    return {"id": photo_id, "filename": fname,
            "url": _sign_photo_url(fname), "category": category}


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


# ── TP-1b: tech portal remodel endpoints ─────────────────────────────────

class TechSignInBody(BaseModel):
    dayoff_reason: Optional[str] = None


class TechCVAppendBody(BaseModel):
    company: str
    title: str
    start_date: Optional[str] = None
    end_date: Optional[str] = None
    description: Optional[str] = ""


class TechCVUpdateBody(BaseModel):
    company: Optional[str] = None
    title: Optional[str] = None
    start_date: Optional[str] = None
    end_date: Optional[str] = None
    description: Optional[str] = None


class TechCertBody(BaseModel):
    name: str
    issuer: str
    issued_date: Optional[str] = None
    expiry_date: Optional[str] = None


class TechScheduleDayBody(BaseModel):
    day_of_week: int
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    active: int = 1
    # When the weekday's `on_call` flag is set, the tech is permanently on
    # call that weekday — sign-in/sign-out outside the start/end window
    # generates no alarm and is not subject to the 2h auto-sign-out cutoff.
    on_call: int = 0


class TechOnCallOverrideBody(BaseModel):
    # ISO date (YYYY-MM-DD). Used for one-off on-call coverage on a date
    # that isn't a permanent on-call weekday — e.g. covering for a
    # colleague this Saturday only.
    work_date: str
    on_call: int = 1
    note: Optional[str] = None


class CompanyMessageBody(BaseModel):
    title: str
    body: str
    expires_at: Optional[str] = None


class GrantCVEditBody(BaseModel):
    grant_until: str


class OvertimeApproveBody(BaseModel):
    notes: Optional[str] = ""


def _tp1_raise_security_alert(kind: str, severity: str, summary: str,
                              actor_type: str = "system",
                              actor_id: int = None,
                              details: dict = None):
    try:
        create_security_alert(
            kind=kind, summary=summary, severity=severity,
            actor_type=actor_type, actor_id=actor_id,
            details=details or {},
        )
    except Exception as e:
        logger.warning(f"_tp1_raise_security_alert failed: {e}")


def _tech_self_actor(tech_id: int) -> dict:
    return {"id": tech_id, "kind": "tech", "name": f"tech#{tech_id}",
            "prid": None, "role": None}


def _tp1_tech_audit(tech_id: int, action: str, request: Request,
                    target_type: str = None, target_id: int = None,
                    target_label: str = None, after=None):
    try:
        log_audit(
            actor_type="tech", actor_id=tech_id, actor_prid=None,
            actor_label=f"tech#{tech_id}", actor_role=None,
            action=action,
            target_type=target_type, target_id=target_id,
            target_label=target_label, after_value=after,
            ip_address=request.client.host if request.client else None,
        )
    except Exception as _e:
        logger.debug(f"tech audit write failed: {_e}")


@app.get("/api/tech/me/today-overview")
def tp1_tech_today_overview(request: Request):
    from datetime import datetime as _dt, timezone as _tz, date as _date
    from database import _con as _dbcon
    tech_id = _require_tech(request)
    today_iso = _dt.now(_tz.utc).date().isoformat()
    con = _dbcon()
    rows = con.execute(
        "SELECT visit_type FROM maintenance_visits "
        "WHERE assigned_tech_id = ? AND scheduled_date = ?",
        (tech_id, today_iso),
    ).fetchall()
    con.close()
    pm = sum(1 for r in rows if (r["visit_type"] or "").upper() == "PM")
    cm = sum(1 for r in rows if (r["visit_type"] or "").upper() == "CM")
    from datetime import timedelta as _td
    sched_end = get_tech_scheduled_end_today(tech_id)
    sched = get_tech_schedule(tech_id)
    dow = _date.fromisoformat(today_iso).weekday()
    today_sched = sched[dow] if dow < len(sched) else None
    on_call = is_tech_on_call_today(tech_id)
    open_in = get_open_clock_in_today(tech_id)
    sign_in_status = "signed_in" if open_in else "not_signed_in"
    in_overtime = bool(open_in and sched_end and not on_call and
                       _dt.now(_tz.utc).isoformat() > sched_end)
    ot_approved = is_overtime_approved(tech_id) if in_overtime else False
    # Surface the 2h-grace deadline so the landing can render a countdown
    # like "auto sign-out in 1h 14m". Skipped for on-call (no cutoff).
    auto_signout_at = None
    if in_overtime and sched_end and not ot_approved:
        try:
            grace_min = int(os.environ.get("TECH_EOD_GRACE_MIN", "120"))
            auto_signout_at = (_dt.fromisoformat(sched_end) +
                               _td(minutes=grace_min)).isoformat()
        except Exception:
            auto_signout_at = None
    return {
        "jobs_today_total": len(rows),
        "pm_count": pm, "cm_count": cm,
        "schedule_today": ({
            "start": (today_sched or {}).get("start_time"),
            "end":   (today_sched or {}).get("end_time"),
            "active": bool((today_sched or {}).get("active")),
            "on_call": bool((today_sched or {}).get("on_call")),
        } if today_sched else None),
        "on_call_today": on_call,
        "sign_in_status": sign_in_status,
        "signed_in_at": (open_in or {}).get("event_at"),
        "in_overtime": in_overtime,
        "overtime_approved": ot_approved,
        "auto_signout_at": auto_signout_at,
    }


def _all_audits_done_for_today(tech_id: int, phase: str,
                               today_iso: str) -> bool:
    """Per the field spec the tech must complete the start- or end-shift
    audit for EVERY assigned auditable asset (vehicle + toolkit), not
    just one. Storage isn't audited per-shift, so it's excluded — same
    filter the 5S home page uses to render the asset list."""
    from database import _con as _dbcon
    con = _dbcon()
    assets = con.execute(
        "SELECT id FROM fs_assets WHERE assigned_tech_id = ? "
        "AND active = 1 AND asset_type IN ('vehicle','toolkit')",
        (tech_id,),
    ).fetchall()
    if not assets:
        # No auditable assets means there's nothing to gate on.
        con.close()
        return True
    for a in assets:
        done = con.execute(
            "SELECT 1 FROM fs_audits WHERE asset_id = ? AND auditor_id = ? "
            "AND auditor_kind = 'tech' AND phase = ? "
            "AND substr(audit_ts, 1, 10) = ? LIMIT 1",
            (a["id"], tech_id, phase, today_iso),
        ).fetchone()
        if not done:
            con.close()
            return False
    con.close()
    return True


@app.post("/api/tech/me/sign-in")
def tp1_tech_sign_in(request: Request, body: TechSignInBody):
    from datetime import datetime as _dt, timezone as _tz
    tech_id = _require_tech(request)
    today_iso = _dt.now(_tz.utc).date().isoformat()
    if not _all_audits_done_for_today(tech_id, "start_shift", today_iso):
        raise HTTPException(409, "5s_start_shift_required")
    scheduled = is_tech_scheduled_today(tech_id)
    on_call   = is_tech_on_call_today(tech_id)
    # On-call techs may sign in any time without justifying — the system
    # already expects them to be available outside operational hours.
    if not scheduled and not on_call and not (body.dayoff_reason or "").strip():
        raise HTTPException(409, "dayoff_reason_required")
    notes = (body.dayoff_reason or "").strip() or None
    eid = record_clock_in(tech_id, source="manual", notes=notes)
    if not scheduled and not on_call:
        _tp1_raise_security_alert(
            kind="tech_dayoff_signin", severity="medium",
            actor_type="tech", actor_id=tech_id,
            summary=f"Tech #{tech_id} signed in on a scheduled day off",
            details={"reason": notes, "work_date": today_iso,
                     "clock_in_id": eid},
        )
    _tp1_tech_audit(tech_id, "tech.sign_in", request,
                    target_type="technician", target_id=tech_id,
                    after={"clock_in_id": eid, "dayoff": not scheduled,
                           "reason": notes})
    return {"ok": True, "clock_in_id": eid}


@app.post("/api/tech/me/sign-out")
def tp1_tech_sign_out(request: Request):
    from datetime import datetime as _dt, timezone as _tz
    tech_id = _require_tech(request)
    today_iso = _dt.now(_tz.utc).date().isoformat()
    if not _all_audits_done_for_today(tech_id, "end_shift", today_iso):
        raise HTTPException(409, "5s_end_shift_required")
    if not get_open_clock_in_today(tech_id):
        raise HTTPException(409, "not_clocked_in")
    eid = record_clock_out(tech_id)
    _tp1_tech_audit(tech_id, "tech.sign_out", request,
                    target_type="technician", target_id=tech_id,
                    after={"clock_out_id": eid})
    return {"ok": True, "clock_out_id": eid}


@app.get("/api/tech/me/clock-status")
def tp1_tech_clock_status(request: Request):
    from datetime import datetime as _dt, timezone as _tz
    tech_id = _require_tech(request)
    open_in = get_open_clock_in_today(tech_id)
    sched_end = get_tech_scheduled_end_today(tech_id)
    in_ot = bool(open_in and sched_end and
                 _dt.now(_tz.utc).isoformat() > sched_end)
    return {
        "clocked_in": bool(open_in),
        "signed_in_at": (open_in or {}).get("event_at"),
        "schedule_today_end": sched_end,
        "in_overtime": in_ot,
        "overtime_approved": is_overtime_approved(tech_id) if in_ot else False,
    }


@app.get("/api/tech/me/profile")
def tp1_tech_profile(request: Request):
    tech_id = _require_tech(request)
    t = get_tech_by_id(tech_id)
    if not t:
        raise HTTPException(404, "Not found")
    return {k: v for k, v in dict(t).items() if k not in
            ("pin_hash", "mfa_secret", "backup_codes")}


@app.get("/api/tech/me/jobs-today")
def tp1_tech_jobs_today(request: Request):
    from datetime import datetime as _dt, timezone as _tz
    from database import _con as _dbcon, _dec_row as _dr
    tech_id = _require_tech(request)
    today_iso = _dt.now(_tz.utc).date().isoformat()
    con = _dbcon()
    rows = con.execute(
        "SELECT v.*, c.name AS customer_name, c.address AS customer_address, "
        "c.phone AS customer_phone, c.customer_code AS customer_code, "
        "e.name AS equipment_name "
        "FROM maintenance_visits v "
        "LEFT JOIN customers c ON c.id = v.customer_id "
        "LEFT JOIN equipment e ON e.id = v.equipment_id "
        "WHERE v.assigned_tech_id = ? AND v.scheduled_date = ? "
        "ORDER BY v.scheduled_time, v.id",
        (tech_id, today_iso),
    ).fetchall()
    con.close()
    out = []
    for r in rows:
        d = dict(r)
        if d.get("customer_address"):
            try:
                d["customer_address"] = _dr(
                    "customers", {"address": d["customer_address"]}
                )["address"]
            except Exception:
                pass
        if d.get("customer_phone"):
            try:
                d["customer_phone"] = _dr(
                    "customers", {"phone": d["customer_phone"]}
                )["phone"]
            except Exception:
                pass
        out.append(d)
    return out


@app.get("/api/tech/me/upcoming-counts")
def tp1_tech_upcoming_counts(request: Request, days: int = 7):
    from datetime import datetime as _dt, timezone as _tz, timedelta as _td
    from database import _con as _dbcon
    tech_id = _require_tech(request)
    today = _dt.now(_tz.utc).date()
    out = []
    con = _dbcon()
    for i in range(1, int(days) + 1):
        d = (today + _td(days=i)).isoformat()
        rows = con.execute(
            "SELECT visit_type FROM maintenance_visits "
            "WHERE assigned_tech_id = ? AND scheduled_date = ?",
            (tech_id, d),
        ).fetchall()
        pm = sum(1 for r in rows if (r["visit_type"] or "").upper() == "PM")
        cm = sum(1 for r in rows if (r["visit_type"] or "").upper() == "CM")
        out.append({"date": d, "pm_count": pm, "cm_count": cm,
                    "total": len(rows)})
    con.close()
    return out


@app.get("/api/tech/me/jobs-done")
def tp1_tech_jobs_done(request: Request, limit: int = 50):
    from database import _con as _dbcon
    tech_id = _require_tech(request)
    con = _dbcon()
    rows = con.execute(
        "SELECT v.id, v.visit_type, v.status, v.scheduled_date, "
        "v.completed_date, v.start_time, v.end_time, v.work_done_summary, "
        "v.equipment_id, e.name AS equipment_name "
        "FROM maintenance_visits v "
        "LEFT JOIN equipment e ON e.id = v.equipment_id "
        "WHERE v.assigned_tech_id = ? AND v.status = 'completed' "
        "ORDER BY COALESCE(v.completed_date, v.scheduled_date) DESC, v.id DESC "
        "LIMIT ?",
        (tech_id, int(limit)),
    ).fetchall()
    con.close()
    out = []
    for r in rows:
        d = dict(r)
        d["customer_name"] = "—"
        d["customer_address"] = "—"
        d["customer_phone"] = "—"
        d["customer_code"] = "—"
        out.append(d)
    return out


@app.get("/api/tech/me/cv")
def tp1_tech_cv_list(request: Request):
    tech_id = _require_tech(request)
    entries = list_tech_cv_entries(tech_id)
    for e in entries:
        e["editable"] = cv_entry_is_editable(e)
        # UI button state machine: if editable → "Edit"; else if there's
        # an open request → "Request pending…"; else → "Request Edit".
        e["pending_edit_request"] = bool(
            get_pending_cv_edit_request(tech_id, e["id"])
            if e.get("status") == "locked" and not e["editable"] else None
        )
    return entries


@app.post("/api/tech/me/cv")
def tp1_tech_cv_append(request: Request, body: TechCVAppendBody):
    tech_id = _require_tech(request)
    if not (body.company or "").strip() or not (body.title or "").strip():
        raise HTTPException(400, "company and title required")
    eid = append_tech_cv_entry(tech_id, body.company.strip(),
                               body.title.strip(),
                               body.start_date or None,
                               body.end_date or None,
                               body.description or "")
    _tp1_tech_audit(tech_id, "tech.cv_appended", request,
                    target_type="technician", target_id=tech_id,
                    after={"entry_id": eid, "company": body.company})
    return {"ok": True, "id": eid}


@app.post("/api/tech/me/cv/{entry_id}/lock")
def tp1_tech_cv_lock(request: Request, entry_id: int):
    tech_id = _require_tech(request)
    ok = lock_tech_cv_entry(entry_id, tech_id)
    if not ok:
        raise HTTPException(409, "not_owner_or_already_locked")
    _tp1_tech_audit(tech_id, "tech.cv_locked", request,
                    target_type="technician", target_id=tech_id,
                    after={"entry_id": entry_id})
    return {"ok": True}


@app.patch("/api/tech/me/cv/{entry_id}")
def tp1_tech_cv_update(request: Request, entry_id: int,
                       body: TechCVUpdateBody):
    tech_id = _require_tech(request)
    fields = {k: v for k, v in body.model_dump().items() if v is not None}
    # Snapshot whether the entry was locked-but-granted before we mutate
    # it — that's the case where we need to expire the grant on success.
    was_locked_with_grant = False
    try:
        existing = next((e for e in list_tech_cv_entries(tech_id)
                         if e["id"] == entry_id), None)
        if existing and existing.get("status") == "locked":
            was_locked_with_grant = cv_entry_is_editable(existing)
    except Exception:
        pass
    res = update_tech_cv_entry(entry_id, tech_id, fields)
    if res == "not_owner":
        raise HTTPException(404, "not_found")
    if res == "locked":
        raise HTTPException(409, "locked_no_grant")
    # Per spec: as soon as the tech finishes editing, the entry re-locks
    # and the button reverts to "Request Edit". Only consume the grant
    # if this update actually consumed one — drafts don't have grants
    # and we don't want a no-op PATCH to revoke a fresh approval.
    if was_locked_with_grant:
        consume_cv_edit_grant(entry_id, tech_id)
    _tp1_tech_audit(tech_id, "tech.cv_updated", request,
                    target_type="technician", target_id=tech_id,
                    after={"entry_id": entry_id,
                           "grant_consumed": was_locked_with_grant})
    return {"ok": True, "grant_consumed": was_locked_with_grant}


@app.post("/api/tech/me/cv/{entry_id}/request-edit")
def tp1_tech_cv_request_edit(request: Request, entry_id: int):
    """Tech opens an edit-request on a locked CV entry. Per the UX spec:
    a "Request Edit" button creates one of these; once an admin approves,
    the next page-load shows "Edit" on that entry; on PATCH success the
    grant is consumed and the button reverts to "Request Edit"."""
    tech_id = _require_tech(request)
    rid = request_cv_edit(tech_id, entry_id)
    if rid == -1:
        raise HTTPException(404, "not_found_or_not_locked")
    if rid is None:
        raise HTTPException(409, "request_already_pending")
    _tp1_raise_security_alert(
        kind="cv_edit_request", severity="low",
        actor_type="tech", actor_id=tech_id,
        summary=f"Tech #{tech_id} requested CV edit on entry #{entry_id}",
        details={"entry_id": entry_id, "request_id": rid},
    )
    _tp1_tech_audit(tech_id, "tech.cv_edit_requested", request,
                    target_type="technician", target_id=tech_id,
                    after={"entry_id": entry_id, "request_id": rid})
    return {"ok": True, "request_id": rid}


# ── Tech-side read-only schedule view ──────────────────────────────
@app.get("/api/tech/me/schedule")
def tp1_tech_my_schedule(request: Request):
    """Read-only Mon–Sun schedule for the signed-in tech, used by My
    Profile to show their weekly hours and on-call flags."""
    tech_id = _require_tech(request)
    return get_tech_schedule(tech_id)


@app.get("/api/tech/me/on-call-overrides")
def tp1_tech_my_on_call_overrides(request: Request,
                                  since: Optional[str] = None):
    """Read-only list of upcoming one-off on-call assignments."""
    tech_id = _require_tech(request)
    if since is None:
        since = datetime.now(timezone.utc).date().isoformat()
    return list_tech_on_call_overrides(tech_id, since_date=since)


@app.get("/api/tech/me/certifications")
def tp1_tech_certs_list(request: Request):
    tech_id = _require_tech(request)
    return list_tech_certifications(tech_id, active_only=True)


@app.get("/api/tech/me/certifications/expiring")
def tp1_tech_certs_expiring(request: Request, days: int = 60):
    tech_id = _require_tech(request)
    return list_certs_expiring_within(int(days), tech_id=tech_id)


@app.get("/api/tech/me/kpi/history")
def tp1_tech_kpi_history(request: Request):
    tech_id = _require_tech(request)
    return {"released_periods": list_released_periods_for_tech(tech_id)}


@app.get("/api/company/messages")
def tp1_company_messages_for_viewer(request: Request, limit: int = 10):
    try:
        _require_admin(request)
    except HTTPException:
        _require_tech(request)
    return list_active_company_messages(limit=int(limit))


# ── Admin-side TP-1b endpoints ───────────────────────────

@app.get("/api/admin/technicians/{tech_id}/schedule")
def tp1_admin_get_tech_schedule(request: Request, tech_id: int):
    _require_perm(request, "tech:manage_schedule")
    return get_tech_schedule(tech_id)


@app.post("/api/admin/technicians/{tech_id}/schedule")
def tp1_admin_set_tech_schedule_day(request: Request, tech_id: int,
                                    body: TechScheduleDayBody):
    admin = _require_perm(request, "tech:manage_schedule")
    if body.day_of_week not in range(7):
        raise HTTPException(400, "day_of_week must be 0..6")
    set_tech_schedule_day(tech_id, body.day_of_week,
                          body.start_time, body.end_time,
                          int(body.active), on_call=int(body.on_call),
                          updated_by_admin_id=admin["id"])
    _audit_from(admin, "tech.schedule_set", request,
                target_type="technician", target_id=tech_id,
                after=body.model_dump())
    return {"ok": True}


# ── On-call overrides (one-off date coverage) ────────────────────────
@app.get("/api/admin/technicians/{tech_id}/on-call-overrides")
def tp1_admin_list_on_call_overrides(request: Request, tech_id: int,
                                     since: Optional[str] = None):
    _require_perm(request, "tech:manage_schedule")
    return list_tech_on_call_overrides(tech_id, since_date=since)


@app.post("/api/admin/technicians/{tech_id}/on-call-overrides")
def tp1_admin_set_on_call_override(request: Request, tech_id: int,
                                   body: TechOnCallOverrideBody):
    admin = _require_perm(request, "tech:manage_schedule")
    try:
        # Light validation: YYYY-MM-DD.
        datetime.strptime(body.work_date, "%Y-%m-%d")
    except ValueError:
        raise HTTPException(400, "work_date must be YYYY-MM-DD")
    set_tech_on_call_override(tech_id, body.work_date,
                              on_call=int(body.on_call), note=body.note,
                              admin_id=admin["id"])
    _audit_from(admin, "tech.on_call_override_set", request,
                target_type="technician", target_id=tech_id,
                after=body.model_dump())
    return {"ok": True}


@app.delete("/api/admin/technicians/{tech_id}/on-call-overrides/{work_date}")
def tp1_admin_delete_on_call_override(request: Request, tech_id: int,
                                      work_date: str):
    admin = _require_perm(request, "tech:manage_schedule")
    delete_tech_on_call_override(tech_id, work_date)
    _audit_from(admin, "tech.on_call_override_cleared", request,
                target_type="technician", target_id=tech_id,
                after={"work_date": work_date})
    return {"ok": True}


@app.get("/api/admin/technicians/{tech_id}/certifications")
def tp1_admin_list_tech_certs(request: Request, tech_id: int):
    _require_perm(request, "tech:manage_certifications")
    return list_tech_certifications(tech_id, active_only=False)


@app.post("/api/admin/technicians/{tech_id}/certifications")
def tp1_admin_create_tech_cert(request: Request, tech_id: int,
                               body: TechCertBody):
    admin = _require_perm(request, "tech:manage_certifications")
    cid = create_tech_certification(tech_id, body.name.strip(),
                                    body.issuer.strip(),
                                    body.issued_date, body.expiry_date,
                                    created_by_admin_id=admin["id"])
    _audit_from(admin, "tech.cert_added", request,
                target_type="technician", target_id=tech_id,
                after={"cert_id": cid, "name": body.name,
                       "expiry": body.expiry_date})
    return {"ok": True, "id": cid}


@app.post("/api/admin/technicians/{tech_id}/cv/{entry_id}/grant-edit")
def tp1_admin_grant_cv_edit(request: Request, tech_id: int, entry_id: int,
                            body: GrantCVEditBody):
    admin = _require_perm(request, "tech:grant_cv_edit")
    ok = grant_cv_edit(entry_id, admin["id"], body.grant_until)
    if not ok:
        raise HTTPException(404, "not_found")
    _audit_from(admin, "tech.cv_edit_granted", request,
                target_type="technician", target_id=tech_id,
                after={"entry_id": entry_id, "grant_until": body.grant_until})
    return {"ok": True}


# ── CV edit-request approval queue ────────────────────────────────
@app.get("/api/admin/cv-edit-requests")
def tp1_admin_list_cv_edit_requests(request: Request,
                                    tech_id: Optional[int] = None):
    """List pending CV-edit requests across all techs (admin queue).
    Used by the tech-profile admin page to approve/deny."""
    _require_perm(request, "tech:grant_cv_edit")
    return list_pending_cv_edit_requests(tech_id=tech_id)


class CVEditApproveBody(BaseModel):
    grant_minutes: int = 60


@app.post("/api/admin/cv-edit-requests/{request_id}/approve")
def tp1_admin_approve_cv_edit_request(request: Request, request_id: int,
                                      body: CVEditApproveBody):
    admin = _require_perm(request, "tech:grant_cv_edit")
    out = approve_cv_edit_request(request_id, admin["id"],
                                  grant_minutes=body.grant_minutes)
    if not out:
        raise HTTPException(404, "not_found_or_not_pending")
    _audit_from(admin, "tech.cv_edit_request_approved", request,
                target_type="technician", target_id=out["tech_id"],
                after={"entry_id": out["entry_id"],
                       "grant_until": out["grant_until"],
                       "request_id": request_id})
    return {"ok": True, **out}


class CVEditDenyBody(BaseModel):
    note: Optional[str] = None


@app.post("/api/admin/cv-edit-requests/{request_id}/deny")
def tp1_admin_deny_cv_edit_request(request: Request, request_id: int,
                                   body: CVEditDenyBody):
    admin = _require_perm(request, "tech:grant_cv_edit")
    ok = deny_cv_edit_request(request_id, admin["id"], body.note)
    if not ok:
        raise HTTPException(404, "not_found_or_not_pending")
    _audit_from(admin, "tech.cv_edit_request_denied", request,
                target_type="cv_edit_request", target_id=request_id,
                after={"note": body.note})
    return {"ok": True}


@app.post("/api/admin/technicians/{tech_id}/kpi-period/{period_key}/release")
def tp1_admin_release_kpi_period(request: Request, tech_id: int,
                                 period_key: str):
    admin = _require_perm(request, "tech:release_kpi_period")
    rid = release_kpi_period_to_tech(tech_id, period_key, admin["id"])
    _audit_from(admin, "tech.kpi_period_released", request,
                target_type="technician", target_id=tech_id,
                target_label=period_key, after={"release_id": rid})
    return {"ok": True}


@app.post("/api/admin/technicians/{tech_id}/overtime/approve")
def tp1_admin_approve_overtime(request: Request, tech_id: int,
                               body: OvertimeApproveBody = None):
    admin = _require_perm(request, "tech:approve_overtime")
    aid = approve_overtime(tech_id, admin["id"],
                           notes=(body.notes if body else ""))
    _audit_from(admin, "tech.overtime_approved", request,
                target_type="technician", target_id=tech_id,
                after={"approval_id": aid})
    return {"ok": True, "id": aid}


@app.get("/api/admin/company/messages")
def tp1_admin_list_company_messages(request: Request, limit: int = 100):
    _require_perm(request, "company:read_messages")
    return list_all_company_messages(limit=int(limit))


@app.post("/api/admin/company/messages")
def tp1_admin_post_company_message(request: Request,
                                   body: CompanyMessageBody):
    admin = _require_perm(request, "company:post_message")
    if not (body.title or "").strip() or not (body.body or "").strip():
        raise HTTPException(400, "title and body required")
    mid = create_company_message(admin["id"], body.title.strip(),
                                 body.body, body.expires_at)
    _audit_from(admin, "company.message_posted", request,
                target_type="company_message", target_id=mid,
                target_label=body.title)
    return {"ok": True, "id": mid}


@app.delete("/api/admin/company/messages/{message_id}")
def tp1_admin_hide_company_message(request: Request, message_id: int):
    admin = _require_perm(request, "company:post_message")
    ok = hide_company_message(message_id, admin["id"])
    if not ok:
        raise HTTPException(404, "not_found_or_already_hidden")
    _audit_from(admin, "company.message_hidden", request,
                target_type="company_message", target_id=message_id)
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


@app.get("/api/admin/me/access-bundle")
def admin_access_bundle(request: Request, response: Response):
    """Effective access for the current admin: base role permissions plus
    active unexpired delegations. Lets the SPA render Stage 1 gates in one
    server-side roundtrip rather than each module rediscovering access.

    Per locked design: NOT cached server-side, recomputed every request,
    and not encoded in the JWT. 30s client cache hint matches decision B."""
    admin = _require_admin(request)
    role = admin["role"]
    role_grants = sorted(list(ADMIN_PERMS.get(role, set())))
    by_record_type: Dict[str, List[str]] = {}
    by_specific: List[Dict[str, Any]] = []
    has_power = False
    try:
        from database import list_active_delegations_for_recipient as _active_for
        for d in _active_for(admin["id"]):
            vu = d.get("valid_until")
            # Treat expired-but-not-yet-swept rows as inactive in the bundle.
            if vu:
                try:
                    if vu < datetime.now(timezone.utc).isoformat():
                        continue
                except Exception:
                    pass
            dtype = d.get("delegation_type")
            lvl   = (d.get("permission_level") or "read").lower()
            if dtype == "power":
                has_power = True
                continue
            if dtype == "record_type":
                rt = d.get("scope_record_type") or "?"
                by_record_type.setdefault(rt, [])
                if lvl not in by_record_type[rt]:
                    by_record_type[rt].append(lvl)
            elif dtype == "record":
                by_specific.append({
                    "resource_type": d.get("scope_record_type"),
                    "resource_id":   d.get("scope_record_id"),
                    "permission":    lvl,
                    "valid_until":   d.get("valid_until"),
                    "delegation_id": d.get("id"),
                })
    except Exception as _e:
        logger.warning(f"[access_bundle] delegations enumerate failed: {_e}")
    now = datetime.now(timezone.utc)
    payload = {
        "user_id":               admin["id"],
        "user_kind":             "admin",
        "role":                  role,
        "role_grants":           role_grants,
        "has_delegation_power":  has_power,
        "delegations": {
            "by_record_type":    by_record_type,
            "by_specific_record": by_specific,
        },
        "fetched_at": now.isoformat(),
        "expires_at": (now + timedelta(seconds=30)).isoformat(),
    }
    # 30s private client cache — Stage 1 gating is allowed to be slightly
    # stale; destination check (Stage 2) is always re-evaluated server-side.
    response.headers["Cache-Control"] = "private, max-age=30"
    return payload


@app.get("/api/portal/me/access-bundle")
def portal_access_bundle(request: Request, response: Response):
    """Customer-side access bundle. Customers always have read+write only on
    their own records — no delegations in v1 (locked decision)."""
    cid = _require_customer(request)
    payload = {
        "user_id":   cid,
        "user_kind": "customer",
        "role":      "customer",
        "scope":     "own_records_only",
        "role_grants": ["customer.self_view", "customer.self_edit",
                        "invoice.self_view", "visit.self_view"],
        "fetched_at": datetime.now(timezone.utc).isoformat(),
    }
    response.headers["Cache-Control"] = "private, max-age=30"
    return payload


@app.get("/api/tech/me/access-bundle")
def tech_access_bundle(request: Request, response: Response):
    """Tech-side access bundle. Techs see only assigned records — no
    delegations in v1 (locked decision: techs cannot be delegation
    recipients)."""
    tid = _require_tech(request)
    payload = {
        "user_id":   tid,
        "user_kind": "tech",
        "role":      "tech",
        "scope":     "assigned_records_only",
        "role_grants": ["visit.self_assigned", "payslip.self_view",
                        "kpi.self_view", "fs.self_audit"],
        "fetched_at": datetime.now(timezone.utc).isoformat(),
    }
    response.headers["Cache-Control"] = "private, max-age=30"
    return payload


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
                logger.error(f"ADMIN PW RESET EMAIL ERROR: {e}")
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


@app.post("/api/admin/customers/{customer_id}/close", response_model=OkResponse)
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


@app.post("/api/admin/customers/{customer_id}/reopen", response_model=OkResponse)
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


@app.get("/api/admin/customers/{customer_id}/exit-report", response_model=Dict[str, Any])
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


# ── Payroll (pay periods + payslips) ─────────────────────────────────────────
# Separation of duties: hr_admin GENERATES payslips for a period and
# super_admin (the only role with payroll:approve) APPROVES it. The same
# admin can never both create and approve a period — enforced at the DB
# layer AND at the endpoint. Employees see only their own payslips.

class PayPeriodCreate(BaseModel):
    period_start: str
    period_end:   str
    label:        str
    currency:     str = "JMD"


class PayslipUpsert(BaseModel):
    subject_type:        str                # 'admin' | 'tech'
    subject_id:          int
    hours_regular:       float = 0
    hours_overtime:      float = 0
    hourly_rate:         float = 0
    overtime_rate:       float = 0
    fixed_salary:        float = 0
    bonus:               float = 0
    other_deductions:    float = 0
    notes:               str   = ""
    pay_periods_per_year: int  = 26


@app.get("/api/admin/payroll/periods")
def admin_list_pay_periods(request: Request):
    _require_perm(request, "payroll:view_all")
    return list_pay_periods()


@app.post("/api/admin/payroll/periods")
def admin_create_pay_period(request: Request, body: PayPeriodCreate):
    admin = _require_perm(request, "payroll:generate")
    if not body.period_start or not body.period_end or not body.label.strip():
        raise HTTPException(400, "period_start, period_end, and label are required")
    if body.period_end < body.period_start:
        raise HTTPException(400, "period_end must be on or after period_start")
    try:
        pid = create_pay_period(body.period_start, body.period_end,
                                 body.label.strip(), admin["id"], body.currency)
    except Exception as e:
        # UNIQUE collision on (period_start, period_end) lands here.
        raise HTTPException(409, f"Could not create pay period: {e}")
    _audit_from(admin, "payroll.period_create", request,
                target_type="pay_period", target_id=pid,
                target_label=body.label,
                after={"period_start": body.period_start,
                       "period_end":   body.period_end,
                       "currency":     body.currency})
    return {"id": pid, "status": "draft"}


@app.get("/api/admin/payroll/periods/{period_id}")
def admin_get_pay_period(request: Request, period_id: int):
    # High-sensitivity: payroll periods reveal pay rates. Honor delegations
    # so a delegated supervisor can see a specific period scoped to them.
    admin = _require_record_access(request, "pay_period", period_id, write=False)
    pp = get_pay_period(period_id)
    if not pp:
        _audit_deny(viewer_kind="admin", viewer_id=admin["id"],
                    action="payroll.period_view",
                    resource_type="pay_period", resource_id=period_id,
                    reason="resource_not_found_or_no_access", request=request)
        raise HTTPException(404, "Pay period not found")
    pp["payslips"] = list_payslips_for_period(period_id)
    return pp


@app.post("/api/admin/payroll/periods/{period_id}/payslips")
def admin_upsert_payslip(request: Request, period_id: int, body: PayslipUpsert):
    """Create or update one payslip in a draft period. Once a period is
    approved, payslips lock — only the director can re-open by cancelling
    the period (not implemented; would be a future feature)."""
    admin = _require_perm(request, "payroll:generate")
    pp = get_pay_period(period_id)
    if not pp:
        raise HTTPException(404, "Pay period not found")
    if pp["status"] != "draft":
        raise HTTPException(409, f"Pay period is {pp['status']}, only draft is editable")
    if body.subject_type not in ("admin", "tech"):
        raise HTTPException(400, "subject_type must be 'admin' or 'tech'")
    # Resolve the subject's name + prid so the payslip holds a snapshot
    if body.subject_type == "admin":
        target = get_admin_user_by_id(body.subject_id)
        if not target:
            raise HTTPException(404, "admin not found")
        name, prid = target["name"], target.get("prid") or target.get("username")
    else:
        target = get_tech_by_id(body.subject_id)
        if not target:
            raise HTTPException(404, "tech not found")
        name, prid = target["name"], target.get("prid") or target.get("tech_code")
    pid = upsert_payslip(period_id, body.subject_type, body.subject_id,
                          name, prid, body.model_dump(), admin["id"])
    _audit_from(admin, "payslip.upsert", request,
                target_type="payslip", target_id=pid,
                target_label=f"{name} ({prid}) — {pp['label']}",
                after={"hours_regular": body.hours_regular,
                       "hours_overtime": body.hours_overtime,
                       "hourly_rate": body.hourly_rate,
                       "fixed_salary": body.fixed_salary,
                       "bonus": body.bonus,
                       "other_deductions": body.other_deductions,
                       # NOTE: 'notes' is intentionally NOT in the audit
                       # snapshot — payslips.notes is encrypted and we keep
                       # PII out of audit_log per Phase 2 redaction.
                       })
    return {"id": pid, "ok": True}


@app.put("/api/admin/payroll/periods/{period_id}/approve")
def admin_approve_pay_period(request: Request, period_id: int):
    """Director-only. Endpoint also enforces approved_by != created_by as
    defense in depth — HR can never approve their own batch even if
    granted payroll:approve in a future config error."""
    admin = _require_perm(request, "payroll:approve")
    pp = get_pay_period(period_id)
    if not pp:
        raise HTTPException(404, "Pay period not found")
    if pp.get("created_by") == admin["id"]:
        raise HTTPException(403, "You cannot approve a pay period you yourself created.")
    try:
        result = approve_pay_period(period_id, admin["id"])
    except ValueError as e:
        raise HTTPException(400, str(e))
    _audit_from(admin, "payroll.period_approve", request,
                target_type="pay_period", target_id=period_id,
                target_label=pp["label"], after=result)
    return result


@app.put("/api/admin/payroll/periods/{period_id}/paid")
def admin_mark_pay_period_paid(request: Request, period_id: int):
    admin = _require_perm(request, "payroll:mark_paid")
    pp = get_pay_period(period_id)
    if not pp:
        raise HTTPException(404, "Pay period not found")
    if pp["status"] != "approved":
        raise HTTPException(409, f"Cannot mark a {pp['status']} period as paid")
    mark_pay_period_paid(period_id)
    _audit_from(admin, "payroll.period_paid", request,
                target_type="pay_period", target_id=period_id,
                target_label=pp["label"])
    return {"ok": True}


@app.get("/api/admin/payslips/{payslip_id}")
def admin_get_payslip(request: Request, payslip_id: int):
    """Director sees everyone's payslip. Any other admin who has
    payroll:view_all also sees all (currently only hr_admin). Delegations
    on the underlying pay_period or specific payslip ALSO grant access."""
    admin = _require_record_access(request, "payslip", payslip_id, write=False)
    ps = get_payslip(payslip_id)
    if not ps:
        _audit_deny(viewer_kind="admin", viewer_id=admin["id"],
                    action="payslip.view",
                    resource_type="payslip", resource_id=payslip_id,
                    reason="resource_not_found_or_no_access", request=request)
        raise HTTPException(404, "Payslip not found")
    return ps


# ── Self-service: every employee sees only their own payslips ────────────────
@app.get("/api/admin/me/payslips")
def admin_my_payslips(request: Request):
    admin = _require_admin(request)
    return list_payslips_for_subject("admin", admin["id"])


@app.get("/api/admin/me/payslips/{payslip_id}")
def admin_my_payslip(request: Request, payslip_id: int):
    """IDOR-safe: the owner check is the gate — even with the right id, a
    different admin gets 404."""
    admin = _require_admin(request)
    ps = get_payslip(payslip_id)
    if (not ps
        or ps["subject_type"] != "admin"
        or ps["subject_id"] != admin["id"]
        or ps.get("period_status") not in ("approved", "paid")):
        _audit_deny(viewer_kind="admin", viewer_id=admin["id"],
                    action="payslip.self_view",
                    resource_type="payslip", resource_id=payslip_id,
                    reason="resource_not_found_or_no_access", request=request)
        raise HTTPException(404, "Payslip not found")
    mark_payslip_viewed(payslip_id)
    _audit_from(admin, "payslip.viewed", request,
                target_type="payslip", target_id=payslip_id,
                target_label=f"self ({ps['period_label']})")
    return ps


@app.get("/api/tech/me/payslips")
def tech_my_payslips(request: Request):
    tech_id = _require_tech(request)
    return list_payslips_for_subject("tech", tech_id)


@app.get("/api/tech/me/payslips/{payslip_id}")
def tech_my_payslip(request: Request, payslip_id: int):
    tech_id = _require_tech(request)
    ps = get_payslip(payslip_id)
    # Explicit IDOR check: payslip.tech_id must == request tech.id.
    # Any mismatch becomes a deny+audit (cannot distinguish "not yours"
    # vs "doesn't exist" in the response body).
    if (not ps
        or ps["subject_type"] != "tech"
        or ps["subject_id"] != tech_id
        or ps.get("period_status") not in ("approved", "paid")):
        _audit_deny(viewer_kind="tech", viewer_id=tech_id,
                    action="payslip.self_view",
                    resource_type="payslip", resource_id=payslip_id,
                    reason="resource_not_found_or_no_access", request=request)
        raise HTTPException(404, "Payslip not found")
    mark_payslip_viewed(payslip_id)
    # Build a customer-style audit row keyed on tech actor.
    log_audit(actor_type="tech", actor_id=tech_id,
              action="payslip.viewed",
              target_type="payslip", target_id=payslip_id,
              target_label=f"self ({ps['period_label']})",
              ip_address=_client_ip(request))
    return ps


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
    admin = _require_record_access(request, "part", part_id, write=True)
    before = get_part_by_id(part_id)
    if not before:
        _audit_deny(viewer_kind="admin", viewer_id=admin["id"],
                    action="inventory.update",
                    resource_type="part", resource_id=part_id,
                    reason="resource_not_found_or_no_access", request=request)
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
            if deviation > 0.15:  # 15% GRN unit-cost spike threshold (unrelated to GCT)
                src = "90-day average" if avg else "catalog cost"
                generic = (
                    f"Unit cost ${body.unit_cost:.2f} deviates {deviation*100:.1f}% "
                    f"from {src} ${baseline:.2f}. Manager approval required "
                    f"(set cost_spike_approved_by to a super_admin/supervisor_admin id)."
                )
                if not body.cost_spike_approved_by:
                    raise HTTPException(409, generic)
                # Validate the named approver: must be a different, active admin
                # with po:approve_variance (super_admin or supervisor_admin).
                if int(body.cost_spike_approved_by) == int(admin["id"]):
                    raise HTTPException(
                        403,
                        "Cost-spike approver cannot be the same person submitting the "
                        "receipt. Have a different super_admin or supervisor_admin approve."
                    )
                approver = get_admin_user_by_id(int(body.cost_spike_approved_by))
                if not approver or not approver.get("active"):
                    raise HTTPException(400, "cost_spike_approved_by is not a valid active admin id")
                if not _admin_can(approver["role"], "po:approve_variance"):
                    raise HTTPException(
                        403,
                        f"cost_spike_approved_by must be a super_admin or supervisor_admin "
                        f"(id {approver['id']} is {approver['role']})."
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


@app.put("/api/admin/visits/{visit_id}/flag", response_model=OkResponse)
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


@app.get("/api/admin/hubs")
def admin_list_hubs(request: Request):
    """Multi-hub picker source. Seeded with Kingston (id=1). Future hubs
    added via create_hub() — UI for hub admin will land when the second
    physical hub opens."""
    _require_admin(request)
    return list_hubs()


@app.get("/api/admin/visits/{visit_id}/invoice-prefill", response_model=Dict[str, Any])
def admin_invoice_prefill(request: Request, visit_id: int):
    _require_perm(request, "invoice:create")
    payload = build_invoice_lines_from_visit(visit_id)
    if not payload:
        raise HTTPException(404, "Visit not found")
    return payload


@app.get("/api/admin/visits/{visit_id}/parts", response_model=Dict[str, Any])
def admin_visit_parts(request: Request, visit_id: int):
    _require_perm(request, "visit:update")
    return get_visit_parts(visit_id)


@app.get("/api/admin/visits/cm-margin")
def admin_cm_margin(request: Request, start_date: Optional[str] = None,
                     end_date: Optional[str] = None):
    """Per-CM-visit gross margin + aggregate rollup. Revenue is invoice
    subtotal (net of GCT). Parts cost = quantity × parts.unit_cost.
    Labor cost = duration × tech.hourly_rate. Tier-0 doctrine organ:
    CM gross margin is the signal the doctrine assumes is 25–35%.

    Permission: visit:view (Director, Manager, System Admin)."""
    _require_perm(request, "visit:view")
    return get_cm_margin(start_date=start_date, end_date=end_date)


@app.get("/api/admin/invoices/aging")
def admin_invoice_aging(request: Request, as_of: Optional[str] = None):
    """Standard AR aging buckets: 0-30 / 31-60 / 61-90 / 90+ + not-yet-due.
    Computed from invoices with (total - amount_paid) > 0, excluding draft
    and cancelled. Tier-0 cash-discipline organ — answers 'what's owed and
    how old' in one query."""
    _require_perm(request, "invoice:view")
    return get_ar_aging(as_of=as_of)


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


# PrimeCool Invoicing Module — specific routes declared BEFORE the
# generic {invoice_id} route so FastAPI's prefix-matching doesn't try to
# coerce 'metrics', 'list', 'export.csv' into an int.
@app.get("/api/admin/invoices/metrics")
def admin_invoice_metrics_pre(request: Request):
    _require_super_admin(request)
    return get_invoice_metrics()


@app.get("/api/admin/invoices/list")
def admin_invoice_list_v2_pre(request: Request,
                                status: Optional[str] = None,
                                from_: Optional[str] = Query(None, alias="from"),
                                to: Optional[str] = None,
                                page: int = 1,
                                limit: int = 20):
    _require_super_admin(request)
    return list_invoices(
        {"status": status, "from": from_, "to": to},
        page=page, limit=limit,
    )


@app.get("/api/admin/invoices/export.csv")
def admin_invoice_export_csv_pre(request: Request,
                                   status: Optional[str] = None,
                                   from_: Optional[str] = Query(None, alias="from"),
                                   to: Optional[str] = None):
    admin = _require_super_admin(request)
    rows = export_invoices_csv({"status": status, "from": from_, "to": to})
    import io, csv as _csv
    buf = io.StringIO()
    cols = ["invoice_number", "customer_name", "company", "issue_date",
            "due_date", "total_jmd", "amount_paid_jmd", "outstanding_jmd",
            "status", "days_overdue", "display_currency"]
    w = _csv.DictWriter(buf, fieldnames=cols, extrasaction="ignore")
    w.writeheader()
    for r in rows:
        w.writerow(r)
    _audit_from(admin, "invoice.csv_export", request,
                target_type="invoice",
                target_label=f"exported {len(rows)} rows",
                after={"status": status, "from": from_, "to": to,
                       "count": len(rows)})
    fname = f"invoices-{datetime.now(timezone.utc).strftime('%Y%m%d')}.csv"
    return Response(
        content=buf.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{fname}"'},
    )


@app.get("/api/admin/parts/search")
def admin_parts_search_pre(request: Request,
                            q: Optional[str] = None,
                            limit: int = 20):
    """Searchable inventory lookup. Inventory NOT deducted here —
    see visit parts-used flow (canonical deduction point)."""
    _require_super_admin(request)
    return search_parts_catalog(q, limit=limit)


@app.get("/api/admin/fx-rates")
def admin_fx_rate_get_pre(request: Request,
                            currency: str,
                            effective_date: Optional[str] = None):
    _require_super_admin(request)
    cu = (currency or "").upper()
    if cu not in ("USD", "GBP"):
        raise HTTPException(400, "Invalid currency")
    rate = get_active_fx_rate(cu, effective_date)
    return rate or {}


@app.post("/api/admin/fx-rates")
async def admin_fx_rate_set_pre(request: Request):
    admin = _require_super_admin(request)
    body = await request.json()
    fc = (body.get("from_currency") or "").upper()
    if fc not in ("USD", "GBP"):
        raise HTTPException(400, "Invalid from_currency")
    try:
        buy_rate = float(body.get("buy_rate"))
    except (TypeError, ValueError):
        raise HTTPException(400, "buy_rate required")
    if buy_rate <= 0 or buy_rate > 1_000_000:
        raise HTTPException(400, "buy_rate out of range")
    eff_date = body.get("effective_date") or datetime.now(timezone.utc).date().isoformat()
    notes    = (body.get("notes") or "")[:500] or None
    rid = set_fx_rate_manual(fc, buy_rate, eff_date, admin["id"], notes=notes)
    _audit_from(admin, "invoice.fx_rate_overridden", request,
                target_type="fx_rate", target_id=rid,
                target_label=f"{fc}→JMD",
                after={"from_currency": fc, "buy_rate": buy_rate,
                       "effective_date": eff_date, "source": "manual"})
    return {"id": rid, "from_currency": fc, "buy_rate": buy_rate,
            "effective_date": eff_date, "source": "manual"}


@app.get("/api/admin/fx-rates/history")
def admin_fx_rate_history_pre(request: Request,
                                currency: str,
                                limit: int = 30):
    _require_super_admin(request)
    cu = (currency or "").upper()
    if cu not in ("USD", "GBP"):
        raise HTTPException(400, "Invalid currency")
    return list_fx_rate_history(cu, limit=limit)


@app.get("/api/admin/invoices/{invoice_id}", response_model=Dict[str, Any])
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


@app.put("/api/admin/invoices/{invoice_id}", response_model=Dict[str, Any])
def admin_update_invoice(request: Request, invoice_id: int, body: InvoiceUpdate):
    admin = _require_record_access(request, "invoice", invoice_id, write=True)
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


@app.put("/api/admin/invoices/{invoice_id}/status", response_model=Dict[str, Any])
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


@app.delete("/api/admin/invoices/{invoice_id}", response_model=OkResponse)
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


@app.post("/api/admin/invoices/{invoice_id}/payments", response_model=Dict[str, Any])
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


# ═══════════════════════════════════════════════════════════════════════════
# PrimeCool Invoicing Module — locked business defaults
# ═══════════════════════════════════════════════════════════════════════════
# GCT default — derived from INVOICE_TAX_RATE (env-overridable); configurable per-invoice via tax_rate column
DEFAULT_GCT_RATE_PCT = INVOICE_TAX_RATE * 100.0
# FX processing fee default — flat 2%, configurable per-invoice via fx_fee_pct
DEFAULT_FX_FEE_PCT = 2.0
# Supported foreign display currencies. Base currency is ALWAYS JMD.
_INVOICE_CURRENCIES = ("JMD", "USD", "GBP")
_PAYMENT_METHODS    = ("cash", "bank_transfer", "cheque", "card", "other")


def _redact_pii_for_audit_safe(payload):
    """Wrapper that uses the existing _redact_pii_for_audit helper if it
    exists, else falls back to identity. Keeps invoicing audit calls aligned
    with the established admin/customer/visit audit patterns."""
    try:
        return _redact_pii_for_audit(payload)  # noqa: F821 — defined elsewhere
    except Exception:
        return payload


# ── Full detail (super_admin Edit View loader) ─────────────────────────────
@app.get("/api/admin/invoices/{invoice_id}/full", response_model=Dict[str, Any])
def admin_invoice_full(request: Request, invoice_id: int):
    """Full invoice payload for the Edit View: header + lines + payments +
    customer + visit ref + active fx rate. Honours delegation."""
    _require_record_access(request, "invoice", invoice_id, write=False)
    inv = get_invoice_full(invoice_id)
    if not inv:
        raise HTTPException(404, "Invoice not found")
    return inv


# ── Invoice create / update / send / cancel (v2 — supports new columns) ────
@app.post("/api/admin/invoices/v2")
async def admin_invoice_create_v2(request: Request):
    """Spec §5 invoice.created. Honours display_currency, fx_fee_pct, fx_rate.
    Lines support labor (tech_id/hours/hourly_rate), part (part_id/part_sku),
    and other."""
    admin = _require_super_admin(request)
    body = await request.json()
    # Server-side validation
    if not body.get("customer_id"):
        raise HTTPException(400, "customer_id required")
    dc = (body.get("display_currency") or "JMD").upper()
    if dc not in _INVOICE_CURRENCIES:
        raise HTTPException(400, "Invalid display_currency")
    tax_rate = float(body.get("tax_rate")
                     if body.get("tax_rate") is not None
                     else DEFAULT_GCT_RATE_PCT)
    if tax_rate < 0 or tax_rate > 100:
        raise HTTPException(400, "tax_rate must be 0–100")
    fx_fee = float(body.get("fx_fee_pct")
                   if body.get("fx_fee_pct") is not None
                   else DEFAULT_FX_FEE_PCT)
    if fx_fee < 0 or fx_fee > 50:
        raise HTTPException(400, "fx_fee_pct must be 0–50")
    body["tax_rate"]   = tax_rate
    body["fx_fee_pct"] = fx_fee
    body["display_currency"] = dc
    invoice_id = create_invoice_with_lines(body, created_by=admin["id"])
    inv = get_invoice_by_id(invoice_id, with_lines=False)
    _audit_from(admin, "invoice.created", request,
                target_type="invoice", target_id=invoice_id,
                target_label=inv["invoice_number"],
                after={"customer_id": body.get("customer_id"),
                       "total":          inv["total"],
                       "display_currency": dc})
    return {"id": invoice_id, "invoice_number": inv["invoice_number"]}


@app.patch("/api/admin/invoices/{invoice_id}", response_model=Dict[str, Any])
async def admin_invoice_patch(request: Request, invoice_id: int):
    """Atomic header + line replacement for the new column set."""
    admin = _require_super_admin(request)
    before = get_invoice_by_id(invoice_id, with_lines=False)
    if not before:
        raise HTTPException(404, "Invoice not found")
    if before["status"] not in ("draft", "sent"):
        raise HTTPException(400, f"Cannot edit a {before['status']} invoice")
    body = await request.json()
    dc = (body.get("display_currency") or before.get("display_currency") or "JMD").upper()
    if dc not in _INVOICE_CURRENCIES:
        raise HTTPException(400, "Invalid display_currency")
    body["display_currency"] = dc
    if "tax_rate" in body:
        tr = float(body["tax_rate"])
        if tr < 0 or tr > 100:
            raise HTTPException(400, "tax_rate must be 0–100")
    if "fx_fee_pct" in body:
        ff = float(body["fx_fee_pct"])
        if ff < 0 or ff > 50:
            raise HTTPException(400, "fx_fee_pct must be 0–50")
    if_match = request.headers.get("if-match") or request.headers.get("If-Match")
    try:
        update_invoice_with_lines(invoice_id, body, if_match=if_match)
    except StaleWriteError:
        raise HTTPException(409, "Row was updated by another admin. Refresh to see latest.")
    after = get_invoice_by_id(invoice_id, with_lines=False)
    _audit_from(admin, "invoice.updated", request,
                target_type="invoice", target_id=invoice_id,
                target_label=before["invoice_number"],
                before={"total": before["total"],
                        "display_currency": before.get("display_currency")},
                after={"total": after["total"],
                       "display_currency": after.get("display_currency")})
    return {"ok": True}


@app.post("/api/admin/invoices/{invoice_id}/send", response_model=OkResponse)
def admin_invoice_send(request: Request, invoice_id: int):
    """draft → sent transition with sent_at stamp."""
    admin = _require_super_admin(request)
    inv = get_invoice_by_id(invoice_id, with_lines=False)
    if not inv:
        raise HTTPException(404, "Invoice not found")
    try:
        transition_invoice_status(invoice_id, "sent", actor_id=admin["id"])
    except ValueError as e:
        raise HTTPException(400, str(e))
    _audit_from(admin, "invoice.sent", request,
                target_type="invoice", target_id=invoice_id,
                target_label=inv["invoice_number"],
                before={"status": inv["status"]},
                after={"status": "sent"})
    return {"ok": True, "status": "sent"}


@app.post("/api/admin/invoices/{invoice_id}/cancel", response_model=OkResponse)
async def admin_invoice_cancel(request: Request, invoice_id: int):
    """Cancel an invoice. Reason is required and encrypted at rest."""
    admin = _require_super_admin(request)
    body = await request.json()
    reason = (body.get("reason") or "").strip()
    if not reason:
        raise HTTPException(400, "reason required")
    inv = get_invoice_by_id(invoice_id, with_lines=False)
    if not inv:
        raise HTTPException(404, "Invoice not found")
    try:
        transition_invoice_status(invoice_id, "cancelled",
                                   actor_id=admin["id"], reason=reason)
    except ValueError as e:
        raise HTTPException(400, str(e))
    _audit_from(admin, "invoice.canceled", request,
                target_type="invoice", target_id=invoice_id,
                target_label=inv["invoice_number"],
                before={"status": inv["status"]},
                after={"status": "cancelled", "reason": reason[:120]})
    return {"ok": True, "status": "cancelled"}


@app.post("/api/admin/invoices/{invoice_id}/payments/v2", response_model=Dict[str, Any])
async def admin_invoice_payment_v2(request: Request, invoice_id: int):
    """Append-only, chain-hashed payment row. Body matches the modal:
       amount, payment_currency, payment_method, payment_date, notes,
       fx_rate_used (if foreign), fx_fee_pct_used (if foreign)."""
    admin = _require_super_admin(request)
    inv = get_invoice_by_id(invoice_id, with_lines=False)
    if not inv:
        raise HTTPException(404, "Invoice not found")
    body = await request.json()
    amount = float(body.get("amount") or 0)
    if amount <= 0:
        raise HTTPException(400, "Payment amount must be positive")
    method = (body.get("payment_method") or "other").lower()
    if method not in _PAYMENT_METHODS:
        raise HTTPException(400, "Invalid payment_method")
    pay_cur = (body.get("payment_currency") or "JMD").upper()
    if pay_cur not in _INVOICE_CURRENCIES:
        raise HTTPException(400, "Invalid payment_currency")
    # Overpayment policy — the operator must choose what to do with any
    # excess. The frontend sends 'overpay_action' when it detects the
    # amount exceeds outstanding. Two valid actions:
    #   'credit'  — excess goes to customers.credit_balance as a positive
    #               account credit (kind=overpayment in the ledger)
    #   'refund'  — excess is logged as money owed back to the customer
    #               (kind=refund_owed, negative ledger entry). Operator
    #               processes the actual refund outside the app.
    # When amount <= outstanding the field is ignored.
    overpay_action = (body.get("overpay_action") or "").lower() or None
    if overpay_action and overpay_action not in ("credit", "refund"):
        raise HTTPException(400, "overpay_action must be 'credit' or 'refund'")

    foreign_amount = foreign_currency = None
    fx_rate_used = fx_fee_pct_used = effective_rate = None
    amount_jmd = amount
    if pay_cur != "JMD":
        fx_rate_used   = float(body.get("fx_rate_used") or 0)
        fx_fee_pct_used = float(body.get("fx_fee_pct_used")
                                if body.get("fx_fee_pct_used") is not None
                                else DEFAULT_FX_FEE_PCT)
        if fx_rate_used <= 0:
            raise HTTPException(400, "fx_rate_used required for foreign payment")
        if fx_fee_pct_used < 0 or fx_fee_pct_used > 50:
            raise HTTPException(400, "fx_fee_pct_used must be 0–50")
        effective_rate = fx_rate_used * (1 + fx_fee_pct_used / 100.0)
        foreign_amount   = amount
        foreign_currency = pay_cur
        amount_jmd       = round(amount * effective_rate, 2)

    # Server-side overpay-action gate: if the amount JMD exceeds the
    # invoice's current outstanding by more than a rounding penny, the
    # caller MUST have specified overpay_action. This stops a stray UI
    # bug (or scripted client) from silently dumping money into the
    # account without the operator choosing the disposition.
    outstanding_now = round(float(inv["total"]) - float(inv["amount_paid"]), 2)
    if amount_jmd > outstanding_now + 0.005 and not overpay_action:
        raise HTTPException(
            400,
            f"Payment exceeds outstanding (J${outstanding_now:.2f}) by "
            f"J${(amount_jmd - outstanding_now):.2f}. Specify "
            f"overpay_action='credit' or 'refund'.",
        )

    payload = {
        "amount_jmd":           amount_jmd,
        "payment_method":       method,
        "payment_date":         body.get("payment_date") or datetime.now(timezone.utc).date().isoformat(),
        "notes":                (body.get("notes") or "")[:1000],
        "foreign_amount":       foreign_amount,
        "foreign_currency":     foreign_currency,
        "fx_rate_used":         fx_rate_used,
        "fx_fee_pct_used":      fx_fee_pct_used,
        "effective_rate_used":  effective_rate,
        "overpay_action":       overpay_action,
    }
    result = record_invoice_payment_v2(
        invoice_id, payload,
        recorded_by=admin["id"],
        recorded_by_label=admin.get("name"),
        recorded_by_prid=admin.get("prid"),
    )
    after = get_invoice_by_id(invoice_id, with_lines=False)
    excess = float(result.get("overpayment_excess") or 0)
    if result.get("duplicate"):
        _audit_from(admin, "invoice.payment_recorded.duplicate_blocked",
                    request, target_type="invoice", target_id=invoice_id,
                    target_label=inv["invoice_number"],
                    after={"amount_jmd": amount_jmd, "method": method})
    else:
        _audit_from(admin, "invoice.payment_recorded", request,
                    target_type="invoice", target_id=invoice_id,
                    target_label=inv["invoice_number"],
                    after={"amount_jmd": amount_jmd,
                           "payment_currency": pay_cur,
                           "method": method,
                           "fx_rate_used": fx_rate_used,
                           "new_balance": round(
                               after["total"] - after["amount_paid"], 2),
                           "overpayment_excess": excess,
                           "overpay_action": overpay_action})
        if excess > 0.005:
            # Audit the overpayment disposition as its own event so the
            # operator can search the audit log for credit_applied vs
            # refund_owed events independent of payment_recorded.
            disposition = "customer.credit_applied" if (overpay_action or "credit") == "credit" \
                else "customer.refund_owed"
            _audit_from(admin, disposition, request,
                        target_type="customer", target_id=inv["customer_id"],
                        target_label=inv["invoice_number"],
                        after={"excess_jmd": excess,
                               "source_invoice_id": invoice_id,
                               "source_payment_id": result["id"]})
    return {
        "id":                 result["id"],
        "duplicate":          result.get("duplicate", False),
        "amount_paid":        after["amount_paid"],
        "status":             after["status"],
        "paid_at":            after.get("paid_at"),
        "overpayment_excess": excess,
        "overpay_action":     overpay_action,
        "credit_movement_id": result.get("credit_movement_id"),
    }


@app.get("/api/admin/invoices/{invoice_id}/payments", response_model=Dict[str, Any])
def admin_invoice_payments_list(request: Request, invoice_id: int):
    _require_super_admin(request)
    inv = get_invoice_full(invoice_id)
    if not inv:
        raise HTTPException(404, "Invoice not found")
    return inv.get("payments", [])


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


@app.put("/api/admin/visits/{visit_id}/work-summary", response_model=OkResponse)
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


@app.get("/api/admin/audit/access-denied")
def admin_audit_access_denied(request: Request,
                              since: Optional[str] = None,
                              actor_kind: Optional[str] = None,
                              actor_id: Optional[int] = None,
                              limit: int = 200):
    """Support tool: pull recent access.denied rows so a user who reports a
    'access denied' toast (with their request_id) can have the row located.
    super_admin only by default — denial metadata may include attempted
    target_type/id which is sensitive enumeration evidence."""
    admin = _require_super_admin(request)
    rows = query_audit_log(action_prefix="access.denied", since=since,
                           limit=max(1, min(int(limit), 1000)))
    if actor_kind:
        rows = [r for r in rows if r.get("actor_type") == actor_kind]
    if actor_id is not None:
        rows = [r for r in rows if r.get("actor_id") == int(actor_id)]
    _audit_from(admin, "audit.access_denied_query", request,
                target_type="audit_log",
                after={"count": len(rows), "since": since,
                       "actor_kind": actor_kind, "actor_id": actor_id})
    return rows


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
    if body.pin:
        try:
            validate_pin_policy(body.pin)
        except ValueError as e:
            raise HTTPException(400, str(e))
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


@app.put("/api/admin/customers/{customer_id}/pin", response_model=OkResponse)
def admin_reset_customer_pin(request: Request, customer_id: int, body: CustomerPinReset):
    admin = _require_perm(request, "customer:update")
    try:
        validate_pin_policy(body.pin)
    except ValueError as e:
        raise HTTPException(400, str(e))
    cust = get_customer_by_id(customer_id)
    if not cust:
        raise HTTPException(404, "Customer not found")
    set_customer_pin(customer_id, body.pin)
    _audit_from(admin, "customer.reset_pin", request,
                target_type="customer", target_id=customer_id, target_label=cust["customer_code"])
    return {"ok": True}


@app.delete("/api/admin/customers/{customer_id}", response_model=OkResponse)
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


# ── Customer Detail View (super_admin only) ──────────────────────────────────
# Full read of customer profile + equipment + service history, plus editable
# profile via POST. Hard role check (not _require_perm) per spec — these
# endpoints are super_admin-only, never delegated to supervisor or system.

_CUSTOMER_DETAIL_PII_FIELDS = ("phone", "email", "address", "notes")


def _require_super_admin(request: Request):
    admin = _require_admin(request)
    if admin["role"] != "super_admin":
        _deny_response(reason="not_super_admin",
                       viewer_kind="admin", viewer_id=admin["id"],
                       action="super_admin_only",
                       resource_type=None, resource_id=None,
                       request=request, status=403)
    return admin


# ── Delegation-aware record access guard ───────────────────────────────────
# Path A: super_admin OR role-perm holder → ALLOW (audit access.role_allow).
# Path B: active delegation matching this record (record / record_type /
# power) with permission_level ≥ required → ALLOW (audit delegation.accessed
# when DELEGATION_VERBOSE_AUDIT != "0").
# Otherwise 403. Audit-write failures NEVER raise — they log to stderr.
# FIXME(docs/FIXMES.md): delegation retrofit gap — only customer/visit/invoice/technician detail+edit endpoints honor delegation; other endpoints retain super_admin gate.
def _require_record_access(request: Request, record_type: str,
                           record_id: int, write: bool = False):
    from database import lookup_record_delegation as _lookup_deleg
    admin = _require_admin(request)
    verbose = os.environ.get("DELEGATION_VERBOSE_AUDIT", "1") != "0"
    # Path A — role check.
    if admin.get("role") == "super_admin":
        try:
            _audit_from(admin, "access.role_allow", request,
                        target_type=record_type, target_id=record_id)
        except Exception as _e:
            logger.warning(f"[delegation] audit-write failed: {_e}")
        return admin
    # Tech recipients of delegations are rejected entirely (locked design).
    # Path B — delegation lookup. Per-request, no caching.
    deleg = None
    saw_expired = False
    try:
        # Check if any rows for this admin were just auto-revoked (expired)
        # during this lookup so we can distinguish that reason for the
        # audit row (per Phase 3.2). lookup_record_delegation handles the
        # auto-revoke itself; we just sniff for the case where a once-valid
        # row no longer applies.
        deleg = _lookup_deleg(admin["id"], record_type, int(record_id))
    except Exception as _e:
        logger.warning(f"[delegation] lookup failed: {_e}")
    if deleg:
        # Power grants imply read+write. Record/record_type honour permission_level.
        if deleg["delegation_type"] == "power":
            ok = True
        else:
            lvl = (deleg.get("permission_level") or "read").lower()
            ok = (lvl == "read_write") if write else (lvl in ("read", "read_write"))
        if ok:
            if verbose:
                try:
                    _audit_from(admin, "delegation.accessed", request,
                                target_type=record_type, target_id=record_id,
                                after={"delegation_id": deleg["id"],
                                       "delegation_type": deleg["delegation_type"],
                                       "write": bool(write)})
                except Exception as _e:
                    logger.warning(f"[delegation] audit-write failed: {_e}")
            return admin
        else:
            # Delegation exists but the permission level is insufficient
            # (e.g. read-only delegate attempting a write).
            _deny_response(reason="delegation_insufficient_level",
                           viewer_kind="admin", viewer_id=admin["id"],
                           action=("record.write" if write else "record.read"),
                           resource_type=record_type, resource_id=record_id,
                           request=request, status=403)
    # No active delegation. Distinguish "had one, just expired" vs "never had".
    # The lookup helper auto-revokes expired rows and writes
    # delegation.auto_expired audit rows, so we can scan recent revocations.
    reason = "no_access"
    try:
        from database import list_cascade_revoked_recent as _cascade
        # Cheap check — were any of this admin's delegations auto-expired in
        # the last 60s? If so, prefer the expired-reason.
        import sqlite3 as _sql3
        from database import _con as _dbcon  # type: ignore
        con = _dbcon()
        try:
            row = con.execute(
                "SELECT 1 FROM delegations WHERE recipient_id=? "
                "AND revoke_kind='auto_expiry' "
                "AND revoked_at >= datetime('now','-60 seconds') LIMIT 1",
                (admin["id"],),
            ).fetchone()
            if row:
                reason = "delegation_expired"
        finally:
            try: con.close()
            except Exception: pass
    except Exception:
        pass
    _deny_response(reason=reason,
                   viewer_kind="admin", viewer_id=admin["id"],
                   action=("record.write" if write else "record.read"),
                   resource_type=record_type, resource_id=record_id,
                   request=request, status=403)


def _validate_customer_profile(body: CustomerProfileUpdate) -> list:
    """Returns a list of {field, message} dicts. Empty list = OK."""
    errs = []
    if body.name is not None:
        n = (body.name or "").strip()
        if len(n) < 2 or len(n) > 100:
            errs.append({"field": "name", "message": "Full name must be 2–100 characters"})
    if body.company is not None and len(body.company or "") > 100:
        errs.append({"field": "company", "message": "Company must be at most 100 characters"})
    if body.phone:
        if not re.fullmatch(r"[\d\+\-\(\) ]+", body.phone):
            errs.append({"field": "phone", "message": "Phone may contain digits, +, -, (), and spaces only"})
    if body.email:
        e = body.email.strip()
        if "@" not in e or "." not in e.split("@", 1)[-1]:
            errs.append({"field": "email", "message": "Enter a valid email address"})
    if body.address is not None and len(body.address or "") > 500:
        errs.append({"field": "address", "message": "Address must be at most 500 characters"})
    if body.notes is not None and len(body.notes or "") > 2000:
        errs.append({"field": "notes", "message": "Notes must be at most 2000 characters"})
    if body.customer_type is not None and body.customer_type not in ("residential", "commercial"):
        errs.append({"field": "customer_type", "message": "Must be 'residential' or 'commercial'"})
    if body.account_status is not None and body.account_status not in ("active", "closed"):
        errs.append({"field": "account_status", "message": "Must be 'active' or 'closed'"})
    return errs


@app.get("/api/admin/customers/{customer_id}", response_model=Dict[str, Any])
def admin_customer_detail(request: Request, customer_id: int):
    """super_admin OR delegate-with-read: full decrypted customer profile."""
    admin = _require_record_access(request, "customer", customer_id, write=False)
    cust = get_customer_with_decryption(customer_id)
    if not cust:
        raise HTTPException(404, "Customer not found")
    _audit_from(admin, "customer.detail_view", request,
                target_type="customer", target_id=customer_id,
                target_label=cust.get("customer_code"))
    _audit_from(admin, "customer.decrypted_data_accessed", request,
                target_type="customer", target_id=customer_id,
                target_label=cust.get("customer_code"),
                after={"field_names": list(_CUSTOMER_DETAIL_PII_FIELDS)})
    return cust


@app.post("/api/admin/customers/{customer_id}", response_model=Dict[str, Any])
def admin_customer_update(request: Request, customer_id: int, body: CustomerProfileUpdate):
    """super_admin OR delegate-with-read_write: edit customer profile."""
    admin = _require_record_access(request, "customer", customer_id, write=True)
    before = get_customer_with_decryption(customer_id)
    if not before:
        raise HTTPException(404, "Customer not found")

    errs = _validate_customer_profile(body)
    if errs:
        raise HTTPException(400, errs)

    # Build the set of fields actually changing. Account status maps to
    # the existing `active` column (1 = active, 0 = closed) — we do NOT
    # touch equipment / visits / payments on close (statutory retention).
    updates = {}
    if body.name is not None:           updates["name"] = body.name.strip()
    if body.company is not None:        updates["company"] = (body.company or "").strip()
    if body.email is not None:          updates["email"] = (body.email or "").strip()
    if body.phone is not None:          updates["phone"] = (body.phone or "").strip()
    if body.address is not None:        updates["address"] = (body.address or "").strip()
    if body.notes is not None:          updates["notes"] = (body.notes or "").strip()
    if body.customer_type is not None:  updates["customer_type"] = body.customer_type
    if body.account_status is not None:
        updates["active"] = 1 if body.account_status == "active" else 0

    # Optimistic concurrency via If-Match: client echoes the row's
    # updated_at; mismatch → 409. Absent header = last-writer-wins
    # (backwards-compat for older admin clients).
    if_match = request.headers.get("if-match") or request.headers.get("If-Match")
    try:
        after = update_customer_fields(customer_id, updates, if_match=if_match)
    except StaleWriteError:
        raise HTTPException(409, "Row was updated by another admin. Refresh to see latest.")
    except Exception as e:
        raise HTTPException(500, f"Unable to save: {type(e).__name__}")

    # Primary audit — before/after sensitive fields are redacted at the
    # log_audit layer via _redact_pii_for_audit.
    _audit_from(admin, "customer.update", request,
                target_type="customer", target_id=customer_id,
                target_label=before.get("customer_code"),
                before=before, after=after)

    # Account-type transition → portal MFA flag. We honor the existing
    # mfa_enabled column if commercial → residential downgrade happens;
    # the residential→commercial path leaves enforcement to the portal
    # login flow (which already requires MFA for commercial accounts).
    if body.customer_type and before.get("customer_type") != body.customer_type:
        _audit_from(admin, "customer.account_type_changed", request,
                    target_type="customer", target_id=customer_id,
                    target_label=before.get("customer_code"),
                    before={"customer_type": before.get("customer_type")},
                    after={"customer_type": body.customer_type})
        # TODO(mfa_required): No dedicated mfa_required flag on customers —
        # commercial accounts are enforced to set up MFA at portal login by
        # the existing portal flow. If a stricter pre-enforcement is needed,
        # add a column and toggle it here.

    # Account-status transition → write a dedicated audit row with reason.
    if body.account_status:
        was_active = (before.get("active") in (1, True, None))
        going_closed = body.account_status == "closed"
        if was_active and going_closed:
            _audit_from(admin, "customer.status_closed", request,
                        target_type="customer", target_id=customer_id,
                        target_label=before.get("customer_code"),
                        after={"reason": body.status_change_reason or ""})
        elif (not was_active) and (not going_closed):
            _audit_from(admin, "customer.status_reopened", request,
                        target_type="customer", target_id=customer_id,
                        target_label=before.get("customer_code"),
                        after={"reason": body.status_change_reason or ""})

    return {"ok": True, "customer": after}


@app.get("/api/admin/customers/{customer_id}/equipment", response_model=Dict[str, Any])
def admin_list_equipment(request: Request, customer_id: int):
    """super_admin sees the enriched view (PM/CM dates + decrypted serial/
    location/notes) and an audit row is written. Other roles fall back to
    the legacy basic equipment list — needed because the existing Customers
    tab "View" button is wired to this endpoint for all admin roles."""
    admin = _require_admin(request)
    if admin["role"] == "super_admin":
        cust = get_customer_by_id(customer_id)
        if not cust:
            raise HTTPException(404, "Customer not found")
        _audit_from(admin, "customer.equipment_view", request,
                    target_type="customer", target_id=customer_id,
                    target_label=cust.get("customer_code"))
        return get_customer_equipment_with_visits(customer_id)
    if not _admin_can(admin["role"], "customer:view"):
        raise HTTPException(403, "Forbidden")
    return get_customer_equipment(customer_id)


@app.get("/api/admin/customers/{customer_id}/visits", response_model=Dict[str, Any])
def admin_customer_visits(request: Request, customer_id: int,
                          page: int = 1, limit: int = 10):
    """super_admin-only: paginated reverse-chronological service history."""
    admin = _require_super_admin(request)
    cust = get_customer_by_id(customer_id)
    if not cust:
        raise HTTPException(404, "Customer not found")
    _audit_from(admin, "customer.visits_view", request,
                target_type="customer", target_id=customer_id,
                target_label=cust.get("customer_code"),
                after={"page": page, "limit": limit})
    return get_customer_visits_paginated(customer_id, page=page, limit=limit)


# ── Visit Detail View (super_admin only) ─────────────────────────────────────
# Mirrors the Customer Detail View pattern: hard role check, decrypted full
# read with field-name audit, narrow surgical update for invoice payment
# state only. Photo URLs reuse the existing _sign_photo_url infrastructure
# so we don't invent a parallel signed-URL system.

_VISIT_DETAIL_PII_FIELDS = (
    # Visit-level encrypted columns
    "work_done", "parts_replaced", "notes",
    "contact_person_phone", "hazards", "access_codes",
    # Joined-in customer columns
    "customer_phone", "customer_address", "customer_email",
    # Joined-in equipment column
    "equipment_location",
)

_PAYMENT_STATUS_VALUES  = ("unpaid", "partially_paid", "fully_paid")
_PAYMENT_METHOD_VALUES  = ("cash", "bank_transfer", "check", "card", "other")


def _validate_invoice_payment(body: InvoicePaymentUpdate) -> list:
    errs = []
    if body.status not in _PAYMENT_STATUS_VALUES:
        errs.append({"field": "status",
                     "message": "Must be 'unpaid', 'partially_paid', or 'fully_paid'"})
    if body.payment_method is not None and body.payment_method not in _PAYMENT_METHOD_VALUES:
        errs.append({"field": "payment_method",
                     "message": "Must be one of: cash, bank_transfer, check, card, other"})
    if body.status in ("fully_paid", "partially_paid") and not body.payment_method:
        errs.append({"field": "payment_method",
                     "message": "Payment method is required when status is paid/partially paid"})
    if body.payment_date:
        # Accept YYYY-MM-DD only (no time component per spec)
        if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", body.payment_date):
            errs.append({"field": "payment_date",
                         "message": "Payment date must be ISO date (YYYY-MM-DD)"})
    if body.notes is not None and len(body.notes) > 1000:
        errs.append({"field": "notes", "message": "Notes must be at most 1000 characters"})
    return errs


@app.get("/api/admin/visits/{visit_id}", response_model=Dict[str, Any])
def admin_visit_detail(request: Request, visit_id: int):
    """super_admin OR delegate-with-read: full decrypted visit detail."""
    admin = _require_record_access(request, "visit", visit_id, write=False)
    detail = get_visit_full_detail(visit_id)
    if not detail:
        raise HTTPException(404, "Visit not found")
    _audit_from(admin, "visit.detail_view", request,
                target_type="visit", target_id=visit_id,
                target_label=f"Visit #{visit_id}")
    _audit_from(admin, "visit.decrypted_data_accessed", request,
                target_type="visit", target_id=visit_id,
                target_label=f"Visit #{visit_id}",
                after={"field_names": list(_VISIT_DETAIL_PII_FIELDS)})
    return detail


@app.get("/api/admin/visits/{visit_id}/photos")
def admin_visit_photos(request: Request, visit_id: int):
    """super_admin-only: photo metadata + signed URLs for the Visit
    Detail View. We reuse the existing _sign_photo_url HMAC infra rather
    than inventing a parallel admin-only blob endpoint — signatures are
    short-lived (PHOTO_URL_TTL) and tied to the filename."""
    admin = _require_super_admin(request)
    # 404 if no such visit at all (avoids silent empty list for bad ids)
    v = get_visit_by_id(visit_id)
    if not v:
        raise HTTPException(404, "Visit not found")
    photos = get_visit_photos_for_admin(visit_id)
    out = []
    for p in photos:
        fname = p.get("filename") or ""
        out.append({
            "photo_id":      p["id"],
            "url":           _sign_photo_url(fname) if fname else None,
            "label":         (p.get("category") or "Photo").replace("_", " ").title(),
            "category":      p.get("category"),
            "timestamp":     p.get("client_captured_at") or p.get("uploaded_at"),
            "uploader_name": p.get("uploader_name") or "Technician",
            "filename":      fname,
        })
    _audit_from(admin, "visit.photos_view", request,
                target_type="visit", target_id=visit_id,
                target_label=f"Visit #{visit_id}",
                after={"count": len(out)})
    return out


@app.post("/api/admin/visits/{visit_id}/invoice-payment")
def admin_visit_invoice_payment(request: Request, visit_id: int,
                                body: InvoicePaymentUpdate):
    """super_admin-only: edit ONLY the invoice payment fields for the
    invoice attached to this visit.

    Both visit-side and invoice-side payment edits flow through
    record_invoice_payment_v2 — single source of truth. The header status
    text gets reconciled afterward; payment rows themselves are
    append-only and chain-hashed. Voids (status='unpaid') append a
    negative-amount marker row with voided_at set, keeping the chain
    intact."""
    admin = _require_super_admin(request)

    # Resolve the invoice for this visit. We deliberately do not accept an
    # invoice_id in the URL — the contract is "the invoice for this visit".
    detail = get_visit_full_detail(visit_id)
    if not detail:
        raise HTTPException(404, "Visit not found")
    if not detail.get("invoice"):
        raise HTTPException(404, "No invoice has been generated for this visit yet")
    invoice_id = detail["invoice"]["id"]

    errs = _validate_invoice_payment(body)
    if errs:
        raise HTTPException(400, errs)

    # Snapshot before for audit. Pull the same payload the UI sees so the
    # before/after diff is meaningful.
    before_inv = dict(detail["invoice"])

    if_match = request.headers.get("if-match") or request.headers.get("If-Match")
    try:
        after_header = update_invoice_payment_status(
            invoice_id,
            status=body.status,
            payment_method=body.payment_method,
            payment_date=body.payment_date,
            notes=body.notes,
            amount=body.amount,
            if_match=if_match,
            actor_id=admin["id"],
            actor_label=admin.get("name"),
            actor_prid=admin.get("prid"),
        )
    except StaleWriteError:
        raise HTTPException(409, "Row was updated by another admin. Refresh to see latest.")
    except Exception as e:
        raise HTTPException(500, f"Unable to save payment status: {type(e).__name__}")

    if not after_header:
        raise HTTPException(404, "Invoice disappeared mid-update")

    # Rebuild the surfaced invoice block for the audit trail.
    after_detail = get_visit_full_detail(visit_id)
    after_inv = after_detail.get("invoice") if after_detail else after_header

    _audit_from(admin, "visit.invoice_payment_status_updated", request,
                target_type="invoice", target_id=invoice_id,
                target_label=before_inv.get("invoice_number"),
                before={
                    "payment_status":    before_inv.get("payment_status"),
                    "amount_paid":       before_inv.get("amount_paid"),
                    "notes":             before_inv.get("notes"),
                    "last_payment_method": before_inv.get("last_payment_method"),
                    "last_payment_date":   before_inv.get("last_payment_date"),
                },
                after={
                    "payment_status":    body.status,
                    "payment_method":    body.payment_method,
                    "payment_date":      body.payment_date,
                    "notes":             body.notes,
                    "amount_paid":       (after_inv or {}).get("amount_paid"),
                })

    return {"ok": True, "invoice": after_inv}


# ── Technician Detail View (super_admin only) ────────────────────────────────
# Mirrors the Customer Detail / Visit Detail pattern: hard role gate, full
# decrypted read with field-name audit, surgical updates with PII-redacted
# before/after audit rows. The KPI module isn't shipped yet, so the
# read-side KPI endpoint degrades gracefully while the threshold-override
# endpoint still persists (so when KPI ships, the overrides are already
# there).
_TECH_DETAIL_PII_FIELDS  = ("phone", "email")
_TECH_REVIEW_PII_FIELDS  = ("summary", "action_items")
_TECH_KPI_OV_PII_FIELDS  = ("reason",)
_TECH_5S_OV_PII_FIELDS   = ("reason",)

# Existing role values in the technicians table are 'tech' | 'lead_tech' |
# 'apprentice'. The product spec asks for level_1/level_2/level_3/lead, but
# changing the enum mid-flight would break the existing tech-management UI
# and the verify_tech / get_all_techs surface. We accept the legacy enum
# here and surface the spec labels in the UI dropdown.
# FIXME(docs/FIXMES.md): role-rename migration (legacy tech/lead_tech/apprentice → level_1/2/3/lead) pending HR sign-off.
_TECH_ROLE_VALUES         = ("tech", "lead_tech", "apprentice")
_TECH_EMPLOYMENT_VALUES   = ("active", "on_leave", "terminated")


def _validate_tech_profile(body: TechnicianProfileUpdate) -> list:
    errs = []
    if body.phone:
        if not re.fullmatch(r"[\d\+\-\(\) ]+", body.phone):
            errs.append({"field": "phone",
                         "message": "Phone may contain digits, +, -, (), and spaces only"})
    if body.email:
        e = body.email.strip()
        if "@" not in e or "." not in e.split("@", 1)[-1]:
            errs.append({"field": "email",
                         "message": "Enter a valid email address"})
    if body.role is not None and body.role not in _TECH_ROLE_VALUES:
        errs.append({"field": "role",
                     "message": f"Must be one of: {', '.join(_TECH_ROLE_VALUES)}"})
    if body.hourly_rate is not None:
        try:
            if float(body.hourly_rate) <= 0:
                errs.append({"field": "hourly_rate",
                             "message": "Hourly rate must be greater than 0"})
        except (TypeError, ValueError):
            errs.append({"field": "hourly_rate",
                         "message": "Hourly rate must be numeric"})
    if body.employment_status is not None and body.employment_status not in _TECH_EMPLOYMENT_VALUES:
        errs.append({"field": "employment_status",
                     "message": "Must be one of: active, on_leave, terminated"})
    return errs


def _redact_tech_for_audit(d: dict) -> dict:
    """Drop sensitive fields from a tech-row dict before stamping into audit
    before/after JSON. The audit layer also re-applies _PII_RAND redaction,
    but doing it here keeps the audit row small and intentional."""
    if not d:
        return d
    out = dict(d)
    for k in _TECH_DETAIL_PII_FIELDS:
        if k in out:
            out[k] = "[REDACTED]"
    out.pop("pin_hash", None)
    return out


@app.get("/api/admin/technicians/{tech_id}", response_model=Dict[str, Any])
def admin_technician_detail(request: Request, tech_id: int):
    """super_admin OR delegate-with-read: full decrypted technician profile
    + lightweight rollups (last job, last review)."""
    admin = _require_record_access(request, "technician", tech_id, write=False)
    t = get_technician_with_decryption(tech_id)
    if not t:
        raise HTTPException(404, "Technician not found")
    _audit_from(admin, "technician.detail_view", request,
                target_type="technician", target_id=tech_id,
                target_label=t.get("name"))
    _audit_from(admin, "technician.decrypted_data_accessed", request,
                target_type="technician", target_id=tech_id,
                target_label=t.get("name"),
                after={"field_names": list(_TECH_DETAIL_PII_FIELDS)})
    return t


@app.post("/api/admin/technicians/{tech_id}", response_model=Dict[str, Any])
def admin_technician_update(request: Request, tech_id: int,
                            body: TechnicianProfileUpdate):
    """super_admin OR delegate-with-read_write: edit the four-surface tech
    info card. Termination is NOT routed through here — the dedicated
    /api/admin/techs/{id}/terminate flow handles the full offboarding
    side-effects. We accept employment_status='terminated' only to surface
    a 409 with a clear redirect message."""
    admin = _require_record_access(request, "technician", tech_id, write=True)
    before = get_technician_with_decryption(tech_id)
    if not before:
        raise HTTPException(404, "Technician not found")

    errs = _validate_tech_profile(body)
    if errs:
        raise HTTPException(400, errs)

    # Termination guard — must go through the offboard flow.
    if body.employment_status == "terminated":
        raise HTTPException(
            409,
            "Use the dedicated offboarding flow to terminate this technician — "
            "this endpoint does not perform the full offboarding side-effects."
        )

    updates = {}
    if body.phone is not None:        updates["phone"]       = (body.phone or "").strip()
    if body.email is not None:        updates["email"]       = (body.email or "").strip()
    if body.role is not None:         updates["role"]        = body.role
    if body.hourly_rate is not None:  updates["hourly_rate"] = float(body.hourly_rate)
    if body.employment_status is not None:
        # Tri-state employment lifecycle now has its own column. The helper
        # keeps `active` in sync (terminated → 0; active/on_leave → 1) so the
        # legacy login gate keeps working without a second app-level branch.
        updates["employment_status"] = body.employment_status

    try:
        after = update_technician_fields(tech_id, updates)
    except Exception as e:
        raise HTTPException(500, f"Unable to save: {type(e).__name__}")

    _audit_from(admin, "technician.update", request,
                target_type="technician", target_id=tech_id,
                target_label=before.get("name"),
                before=_redact_tech_for_audit(before),
                after=_redact_tech_for_audit(after))
    return {"ok": True, "technician": after}


@app.get("/api/admin/technicians/{tech_id}/jobs", response_model=Dict[str, Any])
def admin_technician_jobs(request: Request, tech_id: int,
                          page: int = 1, limit: int = 20,
                          visit_type: Optional[str] = None,
                          date_from: Optional[str] = None,
                          date_to: Optional[str] = None,
                          callbacks_only: bool = False,
                          status: Optional[str] = None):
    """super_admin-only: paginated reverse-chronological job history."""
    admin = _require_super_admin(request)
    t = get_tech_by_id(tech_id)
    if not t:
        raise HTTPException(404, "Technician not found")
    _audit_from(admin, "technician.jobs_view", request,
                target_type="technician", target_id=tech_id,
                target_label=t.get("name"),
                after={"page": page, "limit": limit, "visit_type": visit_type,
                       "date_from": date_from, "date_to": date_to,
                       "callbacks_only": bool(callbacks_only), "status": status})
    return get_technician_jobs_paginated(
        tech_id, page=page, limit=limit,
        filters={"visit_type": visit_type, "date_from": date_from,
                 "date_to": date_to, "status": status,
                 "callbacks_only": bool(callbacks_only)},
    )


def _kpi_scorecard_payload(tech_id: int, period_key: str = None,
                            windows: int = 4) -> Dict[str, Any]:
    """Shared payload builder for both /api/admin/technicians/{id}/kpi and
    /api/admin/kpi/technician/{id}/scorecard. Recomputes the current period
    on demand if no rows exist yet so the Tech Detail UI shows live data
    instead of an empty card."""
    if period_key is None:
        period_key = get_or_create_period()
    current = get_kpi_scorecard(tech_id, period_key)
    if not current.get("kpis"):
        try:
            recompute_kpi_scores(tech_id, period_key, triggered_by="manual")
            current = get_kpi_scorecard(tech_id, period_key)
        except Exception as e:
            logger.warning(f"kpi lazy recompute failed: {e}")
    trend = get_kpi_trend(tech_id, windows=windows)
    flags = list_kpi_flags_for_tech(tech_id, status=None, limit=20)
    return {
        "available":     True,
        "tech_id":       tech_id,
        "period_key":    period_key,
        "current_period": {
            "composite": current.get("composite"),
            "kpis":      current.get("kpis"),
        },
        "trend":         trend,
        "recent_flags":  flags,
        "overrides":     list_kpi_threshold_overrides(tech_id, active_only=True),
        "kpi_keys": [
            "callback_rate", "documentation_quality", "pm_completion",
            "utilization", "sla_adherence", "safety_compliance",
            "first_time_fix", "revenue_per_tech",
        ],
    }


@app.get("/api/admin/technicians/{tech_id}/kpi", response_model=Dict[str, Any])
def admin_technician_kpi(request: Request, tech_id: int, window: int = 30):
    """Tech Detail View KPI card. Thin alias that delegates to the canonical
    /api/admin/kpi/technician/{tech_id}/scorecard endpoint. The legacy
    `window` query param maps to the number of trailing periods returned
    (default 4)."""
    admin = _require_perm(request, "kpi:view_team")
    t = get_tech_by_id(tech_id)
    if not t:
        raise HTTPException(404, "Technician not found")
    payload = _kpi_scorecard_payload(tech_id, period_key=None, windows=4)
    _audit_from(admin, "technician.kpi_view", request,
                target_type="technician", target_id=tech_id,
                target_label=t.get("name"),
                after={"period_key": payload["period_key"]})
    return payload


@app.get("/api/admin/technicians/{tech_id}/5s", response_model=Dict[str, Any])
def admin_technician_5s(request: Request, tech_id: int, window: int = 30):
    """super_admin-only: 5S compliance score + recent audits + open
    exceptions for the tech. Wraps the existing 5S helpers."""
    admin = _require_super_admin(request)
    t = get_tech_by_id(tech_id)
    if not t:
        raise HTTPException(404, "Technician not found")
    score = fs_compute_compliance_score(tech_id, window_days=window)
    audits = fs_list_audits(tech_id=tech_id, limit=50)
    excs   = fs_list_exceptions(tech_id=tech_id, limit=100)
    overrides = list_5s_overrides(tech_id)
    _audit_from(admin, "technician.5s_view", request,
                target_type="technician", target_id=tech_id,
                target_label=t.get("name"),
                after={"window_days": window,
                       "audits_n": len(audits), "exc_n": len(excs)})
    return {
        "score":      score,
        "audits":     audits,
        "exceptions": excs,
        "overrides":  overrides,
    }


@app.post("/api/admin/technicians/{tech_id}/kpi-threshold")
def admin_technician_kpi_threshold(request: Request, tech_id: int,
                                   body: TechnicianKpiThresholdOverride):
    """super_admin-only: persist a KPI threshold override row. Will surface
    in the UI once the KPI module reads from technician_kpi_overrides."""
    admin = _require_super_admin(request)
    t = get_tech_by_id(tech_id)
    if not t:
        raise HTTPException(404, "Technician not found")
    if not (body.kpi_key or "").strip():
        raise HTTPException(400, [{"field": "kpi_key",
                                   "message": "KPI key is required"}])
    if not (body.reason or "").strip():
        raise HTTPException(400, [{"field": "reason",
                                   "message": "Override reason is required"}])
    try:
        new_id = create_kpi_threshold_override(
            tech_id=tech_id,
            kpi_key=body.kpi_key.strip(),
            green_threshold=body.green_threshold,
            amber_threshold=body.amber_threshold,
            red_threshold=body.red_threshold,
            reason=body.reason.strip(),
            effective_from=body.effective_from,
            effective_until=body.effective_until,
            created_by=admin["id"],
        )
    except ValueError as ve:
        raise HTTPException(400, str(ve))
    except Exception as e:
        raise HTTPException(500, f"Unable to save: {type(e).__name__}")
    _audit_from(admin, "technician.kpi_threshold_override", request,
                target_type="technician", target_id=tech_id,
                target_label=t.get("name"),
                after={"kpi_key": body.kpi_key,
                       "green_threshold": body.green_threshold,
                       "amber_threshold": body.amber_threshold,
                       "red_threshold":   body.red_threshold,
                       "effective_from":  body.effective_from,
                       "effective_until": body.effective_until,
                       "override_id":     new_id,
                       # Reason is encrypted at rest via _PII_RAND on
                       # technician_kpi_overrides.reason; only the audit
                       # row's audit_pii redaction needs to drop it. The
                       # log_audit layer handles that automatically.
                       })
    return {"ok": True, "override_id": new_id}


# ═══════════════════════════════════════════════════════════════════════════
# Employee KPI Tracking Module — endpoints (Phase 2)
# ═══════════════════════════════════════════════════════════════════════════

@app.get("/api/admin/kpi/definitions", response_model=Dict[str, Any])
def admin_kpi_definitions(request: Request):
    """Return the 8 KPI definitions and their per-tier thresholds."""
    _require_perm(request, "kpi:view_definitions")
    defs = list_kpi_definitions(active_only=True)
    thrs = list_kpi_thresholds(active_only=True)
    by_kpi = {}
    for t in thrs:
        by_kpi.setdefault(t["kpi_key"], {})[t["tier"]] = {
            "green_threshold": t["green_threshold"],
            "amber_band":      t["amber_band"],
            "red_floor":       t["red_floor"],
            "effective_from":  t["effective_from"],
        }
    out = []
    for d in defs:
        d["thresholds"] = by_kpi.get(d["kpi_key"], {})
        out.append(d)
    return {"definitions": out}


class KpiThresholdUpdate(BaseModel):
    kpi_key:        str
    tier:           str
    green:          float
    amber_band:     float
    red_floor:      float
    effective_from: Optional[str] = None


@app.post("/api/admin/kpi/thresholds", response_model=Dict[str, Any])
def admin_kpi_threshold_update(request: Request, body: KpiThresholdUpdate):
    """Director-only: deactivate the prior active threshold row for
    (kpi_key, tier) and insert a new one. Always audit-logged."""
    admin = _require_perm(request, "kpi:edit_thresholds")
    if body.tier not in ("level_1", "level_2", "level_3", "ops_manager"):
        raise HTTPException(400, [{"field": "tier", "message": "invalid tier"}])
    new_id = upsert_kpi_threshold(
        kpi_key=body.kpi_key, tier=body.tier,
        green=body.green, amber_band=body.amber_band,
        red_floor=body.red_floor, effective_from=body.effective_from,
    )
    _audit_from(admin, "kpi.threshold_updated", request,
                target_type="kpi_threshold", target_id=new_id,
                target_label=f"{body.kpi_key}/{body.tier}",
                after={"green": body.green, "amber_band": body.amber_band,
                       "red_floor": body.red_floor,
                       "effective_from": body.effective_from})
    return {"ok": True, "threshold_id": new_id}


@app.get("/api/admin/kpi/periods", response_model=Dict[str, Any])
def admin_kpi_periods_list(request: Request, status: Optional[str] = None,
                            limit: int = 100):
    _require_perm(request, "kpi:view_definitions")
    return {"periods": list_kpi_periods(status=status, limit=limit)}


@app.post("/api/admin/kpi/periods/{period_key}/close",
          response_model=Dict[str, Any])
def admin_kpi_period_close(request: Request, period_key: str):
    """Director-only: close a period. Closed periods are immutable for the
    recompute path."""
    admin = _require_perm(request, "kpi:close_period")
    ok = close_period(period_key, closed_by=admin["id"])
    if not ok:
        raise HTTPException(409, "Period missing or already closed")
    _audit_from(admin, "kpi.period_closed", request,
                target_type="kpi_period", target_label=period_key)
    return {"ok": True}


class KpiRecomputeBody(BaseModel):
    tech_id:    Optional[int] = None
    period_key: Optional[str] = None


@app.post("/api/admin/kpi/recompute", response_model=Dict[str, Any])
def admin_kpi_recompute(request: Request, body: KpiRecomputeBody):
    """Recompute scores. Body shapes:
      - {} → recompute current period × all active techs (cron-equivalent)
      - {tech_id} → recompute current period for one tech
      - {period_key} → recompute that period × all active techs
      - {tech_id, period_key} → recompute one (tech, period)
    """
    admin = _require_perm(request, "kpi:recompute")
    if body.tech_id and body.period_key:
        out = recompute_kpi_scores(body.tech_id, body.period_key,
                                    triggered_by="manual",
                                    triggered_by_id=admin["id"])
        scope = "one_tech_one_period"
    elif body.tech_id:
        pk = get_or_create_period()
        out = recompute_kpi_scores(body.tech_id, pk,
                                    triggered_by="manual",
                                    triggered_by_id=admin["id"])
        scope = "one_tech_current_period"
    else:
        # All techs over either the given period or current period.
        out = recompute_all_open_periods(triggered_by="manual",
                                          triggered_by_id=admin["id"])
        scope = "all_open"
    _audit_from(admin, "kpi.recompute_triggered", request,
                target_type="kpi", target_label=scope,
                after={"tech_id": body.tech_id, "period_key": body.period_key})
    return {"ok": True, "scope": scope, "result": out}


@app.get("/api/admin/kpi/team-scoreboard", response_model=Dict[str, Any])
def admin_kpi_team_scoreboard(request: Request,
                                period_key: Optional[str] = None,
                                tier: Optional[str] = None,
                                zone: Optional[str] = None):
    """Per-tech composite + KPI band map for a period. Techs whose composite
    is insufficient_data are excluded (spec)."""
    _require_perm(request, "kpi:view_team")
    pk = period_key or get_or_create_period()
    rows = get_team_scoreboard(pk, tier_filter=tier)
    return {"period_key": pk, "tier": tier, "zone": zone, "rows": rows}


@app.get("/api/admin/kpi/technician/{tech_id}/scorecard",
         response_model=Dict[str, Any])
def admin_kpi_tech_scorecard(request: Request, tech_id: int,
                              period_key: Optional[str] = None,
                              windows: int = 4):
    """Full detail for last N periods including composite trend, per-KPI
    history, recent flags. RBAC: super_admin / supervisor (kpi:view_team)
    OR a delegate on this technician. Honors record-level delegation so a
    delegated supervisor can drill into a tech's scorecard."""
    admin = _require_record_access(request, "technician", tech_id, write=False)
    t = get_tech_by_id(tech_id)
    if not t:
        _audit_deny(viewer_kind="admin", viewer_id=admin["id"],
                    action="kpi.scorecard_view",
                    resource_type="technician", resource_id=tech_id,
                    reason="resource_not_found_or_no_access", request=request)
        raise HTTPException(404, "Technician not found")
    payload = _kpi_scorecard_payload(tech_id, period_key=period_key,
                                      windows=max(1, min(windows, 26)))
    _audit_from(admin, "kpi.scorecard_view", request,
                target_type="technician", target_id=tech_id,
                target_label=t.get("name"),
                after={"period_key": payload["period_key"]})
    return payload


@app.get("/api/tech/me/kpi", response_model=Dict[str, Any])
def tech_me_kpi(request: Request, windows: int = 4):
    """Tech viewing own scorecard. Returns ONLY this tech's data. No
    drilldown into other techs allowed via this endpoint."""
    tech_id = _require_tech(request)
    payload = _kpi_scorecard_payload(tech_id, period_key=None,
                                      windows=max(1, min(windows, 26)))
    return payload


# ════════════════════════════════════════════════════════════════════════════
# Phase 3 — KPI escalation engine endpoints
# ════════════════════════════════════════════════════════════════════════════

def _redact_flag_for_tech(flag: dict) -> dict:
    """Strip override text + manager-only context before returning a flag to
    the tech who is its subject. The tech sees that an override exists, but
    not the reason text — that's per locked design."""
    d = dict(flag)
    has_override = bool(d.get("override_reason"))
    d.pop("override_reason", None)
    d.pop("resolution_notes", None)  # internal manager notes hidden from tech
    d["has_override"] = has_override
    if has_override:
        d["override_note"] = "Override on file; see Ops Manager"
    return d


@app.get("/api/admin/kpi/flags", response_model=Dict[str, Any])
def admin_kpi_flags_list(request: Request,
                          status: Optional[str] = None,
                          severity: Optional[str] = None,
                          tech_id: Optional[int] = None,
                          period_key: Optional[str] = None,
                          hub_id: Optional[int] = None,
                          date_from: Optional[str] = None,
                          date_to: Optional[str] = None,
                          limit: int = 100,
                          offset: int = 0):
    """Paginated flag list. Filters available for the team dashboard."""
    _require_perm(request, "kpi:flag_view")
    rows = list_kpi_flags({
        "status": status, "severity": severity, "tech_id": tech_id,
        "period_key": period_key, "hub_id": hub_id,
        "date_from": date_from, "date_to": date_to,
        "limit": max(1, min(limit, 500)),
        "offset": max(0, offset),
    })
    return {"flags": rows, "count": len(rows)}


@app.get("/api/admin/kpi/flags/summary", response_model=Dict[str, Any])
def admin_kpi_flags_summary(request: Request, hub_id: Optional[int] = None):
    """Open-flag counts by severity for the Ops Manager dashboard tiles."""
    _require_perm(request, "kpi:flag_view")
    return {"hub_id": hub_id, "counts": count_open_flags_by_severity(hub_id)}


@app.get("/api/admin/kpi/flags/queue", response_model=Dict[str, Any])
def admin_kpi_flags_queue(request: Request, hub_id: Optional[int] = None):
    """Open-flag queue grouped by severity for the Ops Manager queue UI."""
    _require_perm(request, "kpi:flag_view")
    open_rows = list_kpi_flags({
        "hub_id": hub_id, "limit": 200, "offset": 0,
    })
    open_rows = [r for r in open_rows if r["status"] in
                  ("open", "acknowledged", "in_progress")]
    grouped = {s: [] for s in (
        "immediate_escalation", "written_warning_recommended",
        "coaching_required", "coaching_suggested",
    )}
    for r in open_rows:
        grouped.setdefault(r["severity"], []).append(r)
    return {"hub_id": hub_id, "groups": grouped,
            "total_open": len(open_rows)}


@app.get("/api/admin/kpi/flags/{flag_id}", response_model=Dict[str, Any])
def admin_kpi_flag_detail(request: Request, flag_id: int):
    """Full flag detail with embedded audit trail."""
    admin = _require_record_access(request, "kpi_flag", flag_id, write=False)
    d = get_kpi_flag_detail(flag_id)
    if not d:
        _audit_deny(viewer_kind="admin", viewer_id=admin["id"],
                    action="kpi.flag_view",
                    resource_type="kpi_flag", resource_id=flag_id,
                    reason="resource_not_found_or_no_access", request=request)
        raise HTTPException(404, "Flag not found")
    return d


class KpiFlagNotesBody(BaseModel):
    notes: Optional[str] = None


class KpiFlagResolveBody(BaseModel):
    resolution_notes: str


class KpiFlagOverrideBody(BaseModel):
    override_reason: str


@app.post("/api/admin/kpi/flags/{flag_id}/acknowledge",
          response_model=Dict[str, Any])
def admin_kpi_flag_acknowledge(request: Request, flag_id: int,
                                body: KpiFlagNotesBody):
    admin = _require_record_access(request, "kpi_flag", flag_id, write=True)
    try:
        out = acknowledge_kpi_flag(flag_id, admin["id"])
    except ValueError as ve:
        msg = str(ve)
        if msg == "flag_not_found":
            raise HTTPException(404, "Flag not found")
        raise HTTPException(409, msg)
    _audit_from(admin, "kpi.flag_acknowledged", request,
                target_type="kpi_flag", target_id=flag_id,
                target_label=out.get("severity"))
    return {"ok": True, "flag": out}


@app.post("/api/admin/kpi/flags/{flag_id}/start",
          response_model=Dict[str, Any])
def admin_kpi_flag_start(request: Request, flag_id: int,
                          body: KpiFlagNotesBody):
    admin = _require_record_access(request, "kpi_flag", flag_id, write=True)
    if not (body.notes or "").strip():
        raise HTTPException(400, [{"field": "notes",
                                   "message": "Coaching notes required"}])
    try:
        out = start_kpi_flag_work(flag_id, admin["id"], body.notes.strip())
    except ValueError as ve:
        msg = str(ve)
        if msg == "flag_not_found":
            raise HTTPException(404, "Flag not found")
        if msg == "notes_too_long":
            raise HTTPException(400, [{"field": "notes",
                                       "message": "Notes must be ≤ 2000 chars"}])
        raise HTTPException(409, msg)
    _audit_from(admin, "kpi.flag_in_progress", request,
                target_type="kpi_flag", target_id=flag_id,
                target_label=out.get("severity"))
    return {"ok": True, "flag": out}


@app.post("/api/admin/kpi/flags/{flag_id}/resolve",
          response_model=Dict[str, Any])
def admin_kpi_flag_resolve(request: Request, flag_id: int,
                            body: KpiFlagResolveBody):
    admin = _require_record_access(request, "kpi_flag", flag_id, write=True)
    if not (body.resolution_notes or "").strip():
        raise HTTPException(400, [{"field": "resolution_notes",
                                   "message": "Resolution notes required"}])
    try:
        out = resolve_kpi_flag(flag_id, admin["id"],
                                body.resolution_notes.strip())
    except ValueError as ve:
        msg = str(ve)
        if msg == "flag_not_found":
            raise HTTPException(404, "Flag not found")
        if msg == "resolution_notes_too_long":
            raise HTTPException(400, [{"field": "resolution_notes",
                                       "message": "Notes must be ≤ 2000 chars"}])
        raise HTTPException(409, msg)
    _audit_from(admin, "kpi.flag_resolved", request,
                target_type="kpi_flag", target_id=flag_id,
                target_label=out.get("severity"))
    return {"ok": True, "flag": out}


@app.post("/api/admin/kpi/flags/{flag_id}/override",
          response_model=Dict[str, Any])
def admin_kpi_flag_override(request: Request, flag_id: int,
                             body: KpiFlagOverrideBody):
    """Manager override — super_admin only. Original flag is never deleted;
    only its status flips to 'overridden' with the encrypted reason persisted.
    """
    admin = _require_perm(request, "kpi:flag_override")
    if not (body.override_reason or "").strip():
        raise HTTPException(400, [{"field": "override_reason",
                                   "message": "Override reason is required"}])
    try:
        out = override_kpi_flag(flag_id, admin["id"],
                                 body.override_reason.strip())
    except ValueError as ve:
        msg = str(ve)
        if msg == "flag_not_found":
            raise HTTPException(404, "Flag not found")
        if msg == "override_reason_too_long":
            raise HTTPException(400, [{"field": "override_reason",
                                       "message": "Reason must be ≤ 1000 chars"}])
        raise HTTPException(409, msg)
    _audit_from(admin, "kpi.flag_overridden", request,
                target_type="kpi_flag", target_id=flag_id,
                target_label=out.get("severity"),
                # IMPORTANT: never log the plaintext reason — only its length.
                after={"reason_len": len(body.override_reason or "")})
    return {"ok": True, "flag": out}


@app.get("/api/tech/me/kpi/flags", response_model=Dict[str, Any])
def tech_me_kpi_flags(request: Request, status: Optional[str] = None,
                        limit: int = 50):
    """Tech viewing own flags. Override reason text is redacted to the
    recipient — they see has_override:true but not the actual note."""
    tech_id = _require_tech(request)
    rows = list_kpi_flags({"tech_id": tech_id, "status": status,
                            "limit": max(1, min(limit, 100))})
    return {"flags": [_redact_flag_for_tech(r) for r in rows]}


class KpiFlashEmailBody(BaseModel):
    period_key: Optional[str] = None


@app.post("/api/admin/kpi/flash-report/email", response_model=Dict[str, Any])
def admin_kpi_flash_report_email(request: Request, body: KpiFlashEmailBody):
    """Phase 4 — weekly flash report email path. super_admin-only.
    If RESEND_API_KEY + NOTIFY_EMAIL are set we'd send via Resend; otherwise
    we audit-log a 'skipped' event and tell the UI to fall back to screen
    rendering. This endpoint never auto-sends — it requires an explicit
    super_admin button click per locked design."""
    admin = _require_perm(request, "kpi:flag_override")  # super_admin only
    pk = body.period_key or get_or_create_period()
    api_key = os.environ.get("RESEND_API_KEY")
    notify_email = os.environ.get("NOTIFY_EMAIL")
    if not api_key or not notify_email:
        _audit_from(admin, "kpi.flash_report.emit_skipped", request,
                    target_type="kpi_flash_report", target_label=pk,
                    after={"reason": "email_not_configured"})
        return {"ok": True, "skipped": True,
                "reason": "email_not_configured"}
    # Email path: render a one-line summary; the UI already shows the full
    # report. The detailed HTML body is built client-side; here we send a
    # notification with a deep link.
    try:
        rows = get_team_scoreboard(pk)
        red = [r["name"] for r in rows if r.get("composite_band") == "red"]
        amber = [r["name"] for r in rows if r.get("composite_band") == "amber"]
        counts = count_open_flags_by_severity()
        html = (f"<h2>PrimeCool Weekly Flash — {pk}</h2>"
                f"<p>RED: {len(red)} · AMBER: {len(amber)}</p>"
                f"<p>Open flags: {counts}</p>"
                f"<p>Open the admin console to view the full report.</p>")
        import resend as resend_lib
        resend_lib.api_key = api_key
        resend_lib.Emails.send({
            "from": "primecool@no-reply.primecool.com",
            "to":  [notify_email],
            "subject": f"PrimeCool weekly KPI flash — {pk}",
            "html": html,
        })
    except Exception as e:
        logger.warning(f"kpi flash email failed: {e}")
        _audit_from(admin, "kpi.flash_report.emit_skipped", request,
                    target_type="kpi_flash_report", target_label=pk,
                    after={"reason": "send_error", "error": str(e)[:200]})
        return {"ok": False, "skipped": True, "reason": "send_error"}
    _audit_from(admin, "kpi.flash_report.emit", request,
                target_type="kpi_flash_report", target_label=pk,
                after={"recipient_email_hash": "redacted"})
    return {"ok": True, "skipped": False}


# ════════════════════════════════════════════════════════════════════════════
# Phase 5 — KPI Notes endpoints
# Five note kinds: coaching, tech_response, recognition, team_period,
# score_annotation. Bodies encrypted. Audit-logged. Tech-readable subset.
# ════════════════════════════════════════════════════════════════════════════

_KPI_NOTE_PERM_BY_KIND = {
    "coaching":         "kpi:note_write_coaching",
    "recognition":      "kpi:note_write_recognition",
    "team_period":      "kpi:note_write_team_period",
    "score_annotation": "kpi:note_write_score_annotation",
}


def _kpi_verbose_audit() -> bool:
    return bool(os.environ.get("DELEGATION_VERBOSE_AUDIT"))


class KpiNoteCreateBody(BaseModel):
    note_kind:  str
    tech_id:    Optional[int] = None
    period_key: Optional[str] = None
    flag_id:    Optional[int] = None
    score_id:   Optional[int] = None
    body:       str


class KpiNoteUpdateBody(BaseModel):
    body: str


@app.post("/api/admin/kpi/notes", response_model=Dict[str, Any])
def admin_kpi_note_create(request: Request, body: KpiNoteCreateBody):
    if body.note_kind == "tech_response":
        # Tech-response notes must use the tech endpoint.
        raise HTTPException(400, "Use /api/tech/me/kpi/notes/tech-response")
    perm = _KPI_NOTE_PERM_BY_KIND.get(body.note_kind)
    if not perm:
        raise HTTPException(400, "invalid note_kind")
    admin = _require_perm(request, perm)
    try:
        note = create_kpi_note(
            note_kind=body.note_kind, tech_id=body.tech_id,
            period_key=body.period_key, flag_id=body.flag_id,
            score_id=body.score_id, author_id=admin["id"],
            author_kind="admin", body=body.body,
        )
    except ValueError as ve:
        raise HTTPException(400, str(ve))
    _audit_from(admin, "kpi.note.created", request,
                target_type="kpi_note", target_id=note.get("id"),
                target_label=body.note_kind,
                after={"note_kind": body.note_kind, "tech_id": body.tech_id,
                       "flag_id": body.flag_id, "score_id": body.score_id,
                       "period_key": body.period_key,
                       "body_len": len(body.body or "")})
    return {"ok": True, "note": note}


@app.patch("/api/admin/kpi/notes/{note_id}", response_model=Dict[str, Any])
def admin_kpi_note_update(request: Request, note_id: int,
                          body: KpiNoteUpdateBody):
    admin = _require_admin(request)
    note = get_kpi_note(note_id)
    if not note:
        raise HTTPException(404, "Note not found")
    perm = _KPI_NOTE_PERM_BY_KIND.get(note["note_kind"])
    if not perm or not _admin_can(admin["role"], perm):
        # Only writer or super_admin can edit
        if not (admin["role"] == "super_admin" or
                (note.get("author_kind") == "admin" and
                 note.get("author_id") == admin["id"])):
            raise HTTPException(403, "Not permitted to edit this note")
    try:
        updated = update_kpi_note(note_id, admin["id"], body.body)
    except ValueError as ve:
        raise HTTPException(409, str(ve))
    _audit_from(admin, "kpi.note.updated", request,
                target_type="kpi_note", target_id=note_id,
                target_label=note["note_kind"],
                after={"body_len": len(body.body or "")})
    return {"ok": True, "note": updated}


@app.post("/api/admin/kpi/notes/{note_id}/archive",
          response_model=Dict[str, Any])
def admin_kpi_note_archive(request: Request, note_id: int):
    admin = _require_perm(request, "kpi:note_view")
    note = get_kpi_note(note_id)
    if not note:
        raise HTTPException(404, "Note not found")
    # writer or super_admin
    if admin["role"] != "super_admin" and not (
        note.get("author_kind") == "admin" and note.get("author_id") == admin["id"]
    ):
        raise HTTPException(403, "Only the writer or super_admin may archive")
    try:
        archive_kpi_note(note_id, admin["id"])
    except ValueError as ve:
        raise HTTPException(409, str(ve))
    _audit_from(admin, "kpi.note.archived", request,
                target_type="kpi_note", target_id=note_id,
                target_label=note["note_kind"])
    return {"ok": True}


@app.get("/api/admin/kpi/notes", response_model=Dict[str, Any])
def admin_kpi_notes_list(request: Request,
                         tech_id: Optional[int] = None,
                         note_kind: Optional[str] = None,
                         period_key: Optional[str] = None,
                         flag_id: Optional[int] = None,
                         score_id: Optional[int] = None,
                         page: int = 1, limit: int = 50):
    admin = _require_perm(request, "kpi:note_view")
    rows = list_kpi_notes_filtered(
        tech_id=tech_id, note_kind=note_kind, period_key=period_key,
        flag_id=flag_id, score_id=score_id,
        page=max(1, page), limit=max(1, min(limit, 200)),
    )
    visible = [r for r in rows
               if _can_read_kpi_note(r, admin["id"], "admin", admin["role"])]
    if _kpi_verbose_audit():
        _audit_from(admin, "kpi.note.viewed", request,
                    target_type="kpi_note", target_label="list",
                    after={"count": len(visible)})
    return {"notes": visible, "count": len(visible)}


@app.get("/api/admin/kpi/notes/{note_id}", response_model=Dict[str, Any])
def admin_kpi_note_detail(request: Request, note_id: int):
    admin = _require_perm(request, "kpi:note_view")
    note = get_kpi_note(note_id)
    if not note:
        raise HTTPException(404, "Note not found")
    if not _can_read_kpi_note(note, admin["id"], "admin", admin["role"]):
        raise HTTPException(403, "Not permitted to view this note")
    if _kpi_verbose_audit():
        _audit_from(admin, "kpi.note.viewed", request,
                    target_type="kpi_note", target_id=note_id,
                    target_label=note["note_kind"])
    return {"note": note}


class TechResponseBody(BaseModel):
    flag_id: int
    body:    str


@app.post("/api/tech/me/kpi/notes/tech-response",
          response_model=Dict[str, Any])
def tech_kpi_note_response_create(request: Request, body: TechResponseBody):
    tech_id = _require_tech(request)
    # Validate that the flag exists and belongs to this tech, and is open.
    flag = get_kpi_flag_detail(body.flag_id)
    if not flag:
        raise HTTPException(404, "Flag not found")
    if flag.get("tech_id") != tech_id:
        raise HTTPException(403, "Not your flag")
    if flag.get("status") in ("resolved", "overridden"):
        raise HTTPException(409, "Parent flag is closed")
    # Dedup: existing tech_response by this tech for this flag?
    existing = list_kpi_notes_for_flag(body.flag_id)
    for n in existing:
        if (n.get("note_kind") == "tech_response"
                and n.get("author_id") == tech_id
                and n.get("author_kind") == "tech"
                and n.get("status") != "archived"):
            raise HTTPException(409, "You already responded to this flag")
    try:
        note = create_kpi_note(
            note_kind="tech_response", tech_id=tech_id,
            period_key=flag.get("period_key"), flag_id=body.flag_id,
            score_id=None, author_id=tech_id, author_kind="tech",
            body=body.body,
        )
    except ValueError as ve:
        raise HTTPException(400, str(ve))
    log_audit(actor_type="tech", actor_id=tech_id,
              action="kpi.note.created",
              target_type="kpi_note", target_id=note.get("id"),
              target_label="tech_response",
              after_value={"flag_id": body.flag_id,
                           "body_len": len(body.body or "")},
              ip_address=request.client.host if request.client else None)
    return {"ok": True, "note": note}


@app.patch("/api/tech/me/kpi/notes/{note_id}", response_model=Dict[str, Any])
def tech_kpi_note_update(request: Request, note_id: int,
                         body: KpiNoteUpdateBody):
    tech_id = _require_tech(request)
    note = get_kpi_note(note_id)
    if not note:
        raise HTTPException(404, "Note not found")
    if not (note.get("author_kind") == "tech" and note.get("author_id") == tech_id):
        raise HTTPException(403, "Not your note")
    if note.get("note_kind") != "tech_response":
        raise HTTPException(403, "Only tech responses are editable here")
    try:
        updated = update_kpi_note(note_id, tech_id, body.body)
    except ValueError as ve:
        raise HTTPException(409, str(ve))
    log_audit(actor_type="tech", actor_id=tech_id,
              action="kpi.note.updated",
              target_type="kpi_note", target_id=note_id,
              after_value={"body_len": len(body.body or "")},
              ip_address=request.client.host if request.client else None)
    return {"ok": True, "note": updated}


@app.get("/api/tech/me/kpi/notes", response_model=Dict[str, Any])
def tech_kpi_notes_list(request: Request, limit: int = 50):
    tech_id = _require_tech(request)
    # Coaching + recognition about self + tech_responses by self.
    self_notes = list_kpi_notes_for_tech(
        tech_id, note_kinds=["coaching", "recognition", "tech_response"],
        limit=max(1, min(limit, 200)),
    )
    # Team-period notes for periods where self has scores
    try:
        import sqlite3
        con = sqlite3.connect("submissions.db")
        con.row_factory = sqlite3.Row
        period_keys = [r["period_key"] for r in con.execute(
            "SELECT DISTINCT period_key FROM kpi_scores WHERE tech_id=? "
            "ORDER BY period_key DESC LIMIT 12", (tech_id,),
        ).fetchall()]
        con.close()
    except Exception:
        period_keys = []
    team_notes = []
    for pk in period_keys:
        team_notes.extend(list_kpi_notes_for_period(pk))
    # Visibility filter for safety
    filtered_self = [n for n in self_notes
                     if _can_read_kpi_note(n, tech_id, "tech")]
    filtered_team = [n for n in team_notes
                     if _can_read_kpi_note(n, tech_id, "tech")]
    return {"self_notes": filtered_self, "team_notes": filtered_team}


# ════════════════════════════════════════════════════════════════════════════
# Phase 6 — KPI Goals + PIPs endpoints
# ════════════════════════════════════════════════════════════════════════════

class KpiGoalCreateBody(BaseModel):
    goal_kind:        str
    tech_id:          int
    title:            str
    description:      str
    start_date:       str
    target_date:      str
    related_kpi_keys: Optional[str] = None
    action_items:     Optional[List[Any]] = None
    pip_severity:     Optional[str] = None
    pip_review_dates: Optional[List[str]] = None
    triggering_flag_id: Optional[int] = None


@app.post("/api/admin/kpi/goals", response_model=Dict[str, Any])
def admin_kpi_goal_create(request: Request, body: KpiGoalCreateBody):
    if body.goal_kind == "pip":
        admin = _require_perm(request, "kpi:pip_create")
    else:
        admin = _require_perm(request, "kpi:goal_create")
    try:
        goal = create_kpi_goal(
            goal_kind=body.goal_kind, tech_id=body.tech_id,
            title=body.title, description=body.description,
            start_date=body.start_date, target_date=body.target_date,
            opened_by_id=admin["id"],
            related_kpi_keys=body.related_kpi_keys,
            action_items=body.action_items,
            pip_severity=body.pip_severity,
            pip_review_dates=body.pip_review_dates,
            triggering_flag_id=body.triggering_flag_id,
        )
    except ValueError as ve:
        raise HTTPException(400, str(ve))
    _audit_from(admin, "kpi.goal.created", request,
                target_type="kpi_goal", target_id=goal.get("id"),
                target_label=body.goal_kind,
                after={"tech_id": body.tech_id,
                       "title_len": len(body.title or ""),
                       "pip_severity": body.pip_severity})
    return {"ok": True, "goal": goal}


class KpiGoalUpdateBody(BaseModel):
    title:       Optional[str] = None
    description: Optional[str] = None


@app.patch("/api/admin/kpi/goals/{goal_id}", response_model=Dict[str, Any])
def admin_kpi_goal_update(request: Request, goal_id: int,
                          body: KpiGoalUpdateBody):
    """Edits only allowed while status is 'draft'."""
    admin = _require_perm(request, "kpi:goal_create")
    g = get_kpi_goal(goal_id)
    if not g:
        raise HTTPException(404, "Goal not found")
    if g["status"] != "draft":
        raise HTTPException(409, "Only draft goals are editable")
    import sqlite3
    updates = {}
    if body.title is not None:
        updates["title"] = body.title.strip()
    if body.description is not None:
        updates["description"] = body.description.strip()
    if not updates:
        return {"ok": True, "goal": g}
    # Encrypt then update
    from database import _enc_dict as _enc_d
    enc = _enc_d("kpi_goals", updates)
    sets = ", ".join(f"{k}=?" for k in enc.keys())
    args = list(enc.values()) + [goal_id]
    con = sqlite3.connect("submissions.db")
    con.execute(f"UPDATE kpi_goals SET {sets} WHERE id=?", args)
    con.commit(); con.close()
    _audit_from(admin, "kpi.goal.updated", request,
                target_type="kpi_goal", target_id=goal_id,
                target_label=g.get("goal_kind"),
                after={"fields": list(updates.keys())})
    return {"ok": True, "goal": get_kpi_goal(goal_id)}


@app.post("/api/admin/kpi/goals/{goal_id}/activate",
          response_model=Dict[str, Any])
def admin_kpi_goal_activate(request: Request, goal_id: int):
    admin = _require_perm(request, "kpi:pip_activate")
    try:
        goal = activate_pip(goal_id, admin["id"])
    except ValueError as ve:
        msg = str(ve)
        if msg == "goal_not_found":
            raise HTTPException(404, msg)
        raise HTTPException(409, msg)
    _audit_from(admin, "kpi.pip.activated", request,
                target_type="kpi_goal", target_id=goal_id,
                target_label="pip")
    return {"ok": True, "goal": goal}


@app.post("/api/admin/kpi/goals/{goal_id}/hr-acknowledge",
          response_model=Dict[str, Any])
def admin_kpi_goal_hr_ack(request: Request, goal_id: int):
    admin = _require_perm(request, "kpi:pip_acknowledge")
    try:
        goal = hr_acknowledge_pip(goal_id, admin["id"])
    except ValueError as ve:
        msg = str(ve)
        if msg == "goal_not_found":
            raise HTTPException(404, msg)
        raise HTTPException(409, msg)
    _audit_from(admin, "kpi.pip.hr_acknowledged", request,
                target_type="kpi_goal", target_id=goal_id,
                target_label="pip")
    return {"ok": True, "goal": goal}


class KpiGoalCheckinBody(BaseModel):
    checkin_date: str
    status:       str
    notes:        str


@app.post("/api/admin/kpi/goals/{goal_id}/checkins",
          response_model=Dict[str, Any])
def admin_kpi_goal_checkin(request: Request, goal_id: int,
                            body: KpiGoalCheckinBody):
    admin = _require_perm(request, "kpi:goal_create")
    try:
        ci = add_goal_checkin(goal_id, body.checkin_date, body.status,
                              body.notes, admin["id"])
    except ValueError as ve:
        msg = str(ve)
        if msg == "goal_not_found":
            raise HTTPException(404, msg)
        raise HTTPException(400, msg)
    _audit_from(admin, "kpi.goal.checkin_added", request,
                target_type="kpi_goal_checkin", target_id=ci.get("id"),
                target_label=body.status,
                after={"goal_id": goal_id, "notes_len": len(body.notes or "")})
    return {"ok": True, "checkin": ci}


class KpiGoalCloseBody(BaseModel):
    outcome_status:  str
    outcome_summary: str


@app.post("/api/admin/kpi/goals/{goal_id}/close",
          response_model=Dict[str, Any])
def admin_kpi_goal_close(request: Request, goal_id: int,
                          body: KpiGoalCloseBody):
    admin = _require_perm(request, "kpi:goal_close")
    try:
        goal = close_goal(goal_id, body.outcome_status,
                          body.outcome_summary, admin["id"])
    except ValueError as ve:
        msg = str(ve)
        if msg == "goal_not_found":
            raise HTTPException(404, msg)
        raise HTTPException(409, msg)
    _audit_from(admin, "kpi.goal.closed", request,
                target_type="kpi_goal", target_id=goal_id,
                target_label=body.outcome_status,
                after={"outcome_summary_len": len(body.outcome_summary or "")})
    return {"ok": True, "goal": goal}


@app.get("/api/admin/kpi/goals", response_model=Dict[str, Any])
def admin_kpi_goals_list(request: Request,
                          tech_id: Optional[int] = None,
                          goal_kind: Optional[str] = None,
                          status: Optional[str] = None,
                          page: int = 1, limit: int = 50):
    _require_perm(request, "kpi:goal_view")
    rows = list_goals_filtered(tech_id=tech_id, goal_kind=goal_kind,
                                status=status, page=max(1, page),
                                limit=max(1, min(limit, 200)))
    return {"goals": rows, "count": len(rows)}


@app.get("/api/admin/kpi/goals/{goal_id}", response_model=Dict[str, Any])
def admin_kpi_goal_detail(request: Request, goal_id: int):
    admin = _require_record_access(request, "kpi_goal", goal_id, write=False)
    g = get_kpi_goal(goal_id)
    if not g:
        _audit_deny(viewer_kind="admin", viewer_id=admin["id"],
                    action="kpi.goal_view",
                    resource_type="kpi_goal", resource_id=goal_id,
                    reason="resource_not_found_or_no_access", request=request)
        raise HTTPException(404, "Goal not found")
    g["checkins"] = list_goal_checkins(goal_id)
    return {"goal": g}


@app.get("/api/admin/kpi/pips/active", response_model=Dict[str, Any])
def admin_kpi_pips_active(request: Request, hub_id: Optional[int] = None):
    _require_perm(request, "kpi:goal_view")
    return {"pips": list_active_pips(hub_id=hub_id)}


@app.get("/api/tech/me/kpi/goals", response_model=Dict[str, Any])
def tech_kpi_goals_list(request: Request):
    tech_id = _require_tech(request)
    return {"goals": list_goals_for_tech(tech_id)}


@app.post("/api/tech/me/kpi/goals/{goal_id}/action-items/{idx}/done",
          response_model=Dict[str, Any])
def tech_kpi_goal_action_item_done(request: Request, goal_id: int, idx: int):
    tech_id = _require_tech(request)
    try:
        goal = tech_set_action_item_done(goal_id, tech_id, idx, True)
    except ValueError as ve:
        msg = str(ve)
        if msg == "goal_not_found":
            raise HTTPException(404, msg)
        raise HTTPException(400, msg)
    log_audit(actor_type="tech", actor_id=tech_id,
              action="kpi.goal.action_item_done",
              target_type="kpi_goal", target_id=goal_id,
              after_value={"idx": idx},
              ip_address=request.client.host if request.client else None)
    return {"ok": True, "goal": goal}


# ════════════════════════════════════════════════════════════════════════════
# Phase 7 — Custom KPI definitions + manual values
# ════════════════════════════════════════════════════════════════════════════

class KpiThresholdSpec(BaseModel):
    tier:       str
    green:      float
    amber_band: float
    red_floor:  float


class CustomKpiCreateBody(BaseModel):
    kpi_key:               str
    display_name:          str
    description:           Optional[str] = ""
    direction:             str
    in_composite:          int = 0
    composite_weight_pct:  float = 0
    safety_critical:       int = 0
    thresholds:            List[KpiThresholdSpec] = []


@app.post("/api/admin/kpi/definitions/custom", response_model=Dict[str, Any])
def admin_kpi_custom_create(request: Request, body: CustomKpiCreateBody):
    admin = _require_perm(request, "kpi:def_create")
    try:
        out = create_custom_kpi(
            kpi_key=body.kpi_key, display_name=body.display_name,
            description=body.description or "", direction=body.direction,
            in_composite=body.in_composite,
            composite_weight_pct=body.composite_weight_pct,
            safety_critical=body.safety_critical,
            thresholds=[t.dict() for t in body.thresholds],
            creator_id=admin["id"],
        )
    except ValueError as ve:
        raise HTTPException(400, str(ve))
    _audit_from(admin, "kpi.definition.created_custom", request,
                target_type="kpi_definition", target_label=body.kpi_key,
                after={"in_composite": body.in_composite,
                       "weight_pct": body.composite_weight_pct,
                       "rebalanced": out.get("rebalanced")})
    if out.get("rebalanced"):
        _audit_from(admin, "kpi.composite_weights_rebalanced", request,
                    target_type="kpi_definition", target_label=body.kpi_key,
                    after={"after_weights": out.get("rebalanced")})
    return {"ok": True, "result": out}


@app.post("/api/admin/kpi/definitions/{kpi_key}/archive",
          response_model=Dict[str, Any])
def admin_kpi_custom_archive(request: Request, kpi_key: str):
    admin = _require_perm(request, "kpi:def_archive")
    try:
        archive_custom_kpi(kpi_key)
    except ValueError as ve:
        msg = str(ve)
        if msg == "kpi_not_found":
            raise HTTPException(404, msg)
        raise HTTPException(409, msg)
    _audit_from(admin, "kpi.definition.archived", request,
                target_type="kpi_definition", target_label=kpi_key)
    return {"ok": True}


class ManualKpiValueBody(BaseModel):
    tech_id:     int
    period_key:  str
    kpi_key:     str
    raw_value:   float
    sample_size: Optional[int] = 1


@app.post("/api/admin/kpi/scores/manual", response_model=Dict[str, Any])
def admin_kpi_score_manual(request: Request, body: ManualKpiValueBody):
    admin = _require_perm(request, "kpi:manual_value_set")
    try:
        out = set_manual_kpi_value(
            tech_id=body.tech_id, period_key=body.period_key,
            kpi_key=body.kpi_key, raw_value=body.raw_value,
            sample_size=body.sample_size or 1, author_id=admin["id"],
        )
    except ValueError as ve:
        msg = str(ve)
        if msg == "kpi_not_found":
            raise HTTPException(404, msg)
        raise HTTPException(400, msg)
    _audit_from(admin, "kpi.score.manual_set", request,
                target_type="kpi_score", target_id=out.get("score_id"),
                target_label=f"{body.kpi_key}/{body.period_key}",
                after={"tech_id": body.tech_id, "kpi_key": body.kpi_key,
                       "raw_value": body.raw_value,
                       "sample_size": body.sample_size or 1})
    return {"ok": True, "score": out}


@app.get("/api/admin/kpi/definitions/{kpi_key}/manual-history",
         response_model=Dict[str, Any])
def admin_kpi_manual_history(request: Request, kpi_key: str,
                              period_key: Optional[str] = None,
                              limit: int = 100):
    _require_perm(request, "kpi:view_definitions")
    return {"history": list_manual_kpi_history(
        kpi_key, period_key=period_key, limit=max(1, min(limit, 500)),
    )}


# ── KPI weekly recompute loop ───────────────────────────────────────────────
# Mirrors the _fs_escalation_loop pattern. Runs every 24h: ensures the
# current ISO-week period exists and recomputes scores for all active techs
# in all open periods.
import asyncio as _kpi_asyncio


async def _kpi_weekly_recompute_loop():
    while True:
        try:
            pk = get_or_create_period()
            ensure_period_exists(pk)
            res = recompute_all_open_periods(triggered_by="cron",
                                              triggered_by_id=None)
            logger.info(f"kpi recompute cron: {res} (current={pk})")
        except Exception as _e:
            logger.error(f"kpi recompute cron error: {_e}")
        await _kpi_asyncio.sleep(24 * 60 * 60)


@app.on_event("startup")
async def _start_kpi_weekly_recompute_loop():
    _kpi_asyncio.create_task(_kpi_weekly_recompute_loop())


@app.post("/api/admin/technicians/{tech_id}/5s-override")
def admin_technician_5s_override(request: Request, tech_id: int,
                                 body: Technician5SOverride):
    """super_admin-only: persist a forensic override row for a 5S exception.
    Does NOT mutate the original fs_exceptions row — that row stays for the
    audit trail. The override is a parallel forensic record."""
    admin = _require_super_admin(request)
    t = get_tech_by_id(tech_id)
    if not t:
        raise HTTPException(404, "Technician not found")
    if not (body.reason or "").strip():
        raise HTTPException(400, [{"field": "reason",
                                   "message": "Override reason is required"}])
    try:
        new_id = create_5s_override(
            exception_id=body.exception_id,
            tech_id=tech_id,
            reason=body.reason.strip(),
            overridden_by=admin["id"],
            hub_id=t.get("hub_id", 1),
        )
    except ValueError as ve:
        msg = str(ve)
        if "not found" in msg.lower():
            raise HTTPException(404, msg)
        if "does not belong" in msg.lower():
            raise HTTPException(403, msg)
        raise HTTPException(400, msg)
    _audit_from(admin, "technician.5s_flag_override", request,
                target_type="technician", target_id=tech_id,
                target_label=t.get("name"),
                after={"exception_id": body.exception_id,
                       "override_id":  new_id})
    return {"ok": True, "override_id": new_id}


@app.get("/api/admin/technicians/{tech_id}/reviews", response_model=Dict[str, Any])
def admin_technician_reviews_list(request: Request, tech_id: int,
                                  status: Optional[str] = None,
                                  limit: int = 50):
    admin = _require_super_admin(request)
    t = get_tech_by_id(tech_id)
    if not t:
        raise HTTPException(404, "Technician not found")
    rows = list_technician_reviews(tech_id, status=status, limit=limit)
    _audit_from(admin, "technician.reviews_view", request,
                target_type="technician", target_id=tech_id,
                target_label=t.get("name"),
                after={"count": len(rows),
                       "field_names": list(_TECH_REVIEW_PII_FIELDS)})
    return rows


@app.post("/api/admin/technicians/{tech_id}/reviews")
def admin_technician_review_create(request: Request, tech_id: int,
                                   body: TechnicianReviewCreate):
    admin = _require_super_admin(request)
    t = get_tech_by_id(tech_id)
    if not t:
        raise HTTPException(404, "Technician not found")
    errs = []
    if body.review_type not in ("coaching", "written_warning",
                                "positive_feedback", "other"):
        errs.append({"field": "review_type", "message": "Invalid review type"})
    if not (body.summary or "").strip():
        errs.append({"field": "summary", "message": "Summary is required"})
    if body.summary and len(body.summary) > 1000:
        errs.append({"field": "summary", "message": "Summary must be ≤ 1000 chars"})
    if body.action_items and len(body.action_items) > 2000:
        errs.append({"field": "action_items",
                     "message": "Action items must be ≤ 2000 chars"})
    if body.status and body.status not in ("open", "resolved", "archived"):
        errs.append({"field": "status", "message": "Invalid status"})
    if body.followup_date and not re.fullmatch(r"\d{4}-\d{2}-\d{2}",
                                               body.followup_date):
        errs.append({"field": "followup_date",
                     "message": "Follow-up date must be ISO date (YYYY-MM-DD)"})
    if errs:
        raise HTTPException(400, errs)
    try:
        rid = create_technician_review(
            tech_id=tech_id,
            review_type=body.review_type,
            summary=body.summary.strip(),
            reviewer_id=admin["id"],
            status=body.status or "open",
            action_items=(body.action_items or None),
            followup_date=body.followup_date,
            hub_id=t.get("hub_id", 1),
        )
    except ValueError as ve:
        raise HTTPException(400, str(ve))
    _audit_from(admin, "technician.review_logged", request,
                target_type="technician", target_id=tech_id,
                target_label=t.get("name"),
                after={"review_id":     rid,
                       "review_type":   body.review_type,
                       "status":        body.status or "open",
                       "followup_date": body.followup_date,
                       "field_names":   list(_TECH_REVIEW_PII_FIELDS)})
    return {"ok": True, "review_id": rid}


@app.patch("/api/admin/technicians/{tech_id}/reviews/{review_id}")
def admin_technician_review_update(request: Request, tech_id: int,
                                   review_id: int,
                                   body: TechnicianReviewUpdate):
    admin = _require_super_admin(request)
    t = get_tech_by_id(tech_id)
    if not t:
        raise HTTPException(404, "Technician not found")
    # IDOR-safe: confirm review belongs to this tech.
    existing = list_technician_reviews(tech_id, status=None, limit=1000)
    if not any(r["id"] == review_id for r in existing):
        raise HTTPException(404, "Review not found for this technician")
    errs = []
    if body.summary is not None and not body.summary.strip():
        errs.append({"field": "summary", "message": "Summary cannot be blank"})
    if body.summary and len(body.summary) > 1000:
        errs.append({"field": "summary", "message": "Summary must be ≤ 1000 chars"})
    if body.action_items and len(body.action_items) > 2000:
        errs.append({"field": "action_items",
                     "message": "Action items must be ≤ 2000 chars"})
    if body.status and body.status not in ("open", "resolved", "archived"):
        errs.append({"field": "status", "message": "Invalid status"})
    if body.followup_date and not re.fullmatch(r"\d{4}-\d{2}-\d{2}",
                                               body.followup_date):
        errs.append({"field": "followup_date",
                     "message": "Follow-up date must be ISO date (YYYY-MM-DD)"})
    if errs:
        raise HTTPException(400, errs)
    try:
        update_technician_review(
            review_id,
            status=body.status,
            summary=body.summary,
            action_items=body.action_items,
            followup_date=body.followup_date,
        )
    except ValueError as ve:
        msg = str(ve)
        if "not editable" in msg:
            raise HTTPException(409, msg)
        if "not found" in msg:
            raise HTTPException(404, msg)
        raise HTTPException(400, msg)
    _audit_from(admin, "technician.review_updated", request,
                target_type="technician", target_id=tech_id,
                target_label=t.get("name"),
                after={"review_id":     review_id,
                       "status":        body.status,
                       "followup_date": body.followup_date,
                       "field_names":   list(_TECH_REVIEW_PII_FIELDS)})
    return {"ok": True}


@app.get("/api/admin/technicians/{tech_id}/certifications", response_model=Dict[str, Any])
def admin_technician_certifications(request: Request, tech_id: int):
    admin = _require_super_admin(request)
    t = get_tech_by_id(tech_id)
    if not t:
        raise HTTPException(404, "Technician not found")
    payload = get_technician_certifications(tech_id)
    _audit_from(admin, "technician.certifications_view", request,
                target_type="technician", target_id=tech_id,
                target_label=t.get("name"))
    return payload


@app.get("/api/admin/technicians/{tech_id}/payroll-summary", response_model=Dict[str, Any])
def admin_technician_payroll_summary(request: Request, tech_id: int,
                                     limit: int = 6):
    admin = _require_super_admin(request)
    t = get_tech_by_id(tech_id)
    if not t:
        raise HTTPException(404, "Technician not found")
    payload = get_technician_payroll_summary(tech_id, limit=limit)
    _audit_from(admin, "technician.payroll_summary_view", request,
                target_type="technician", target_id=tech_id,
                target_label=t.get("name"),
                after={"limit": limit})
    return payload


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


@app.put("/api/admin/visits/{visit_id}", response_model=Dict[str, Any])
def admin_update_visit(request: Request, visit_id: int, body: VisitUpdate):
    admin = _require_record_access(request, "visit", visit_id, write=True)
    before = get_visit_by_id(visit_id)
    update_visit(visit_id, body.model_dump())
    _audit_from(admin, "visit.update", request,
                target_type="visit", target_id=visit_id,
                target_label=f"{body.visit_type} #{visit_id}",
                before=before, after=body.model_dump())
    return {"ok": True}


@app.delete("/api/admin/visits/{visit_id}", response_model=OkResponse)
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
    admin = _require_record_access(request, "review", review_id, write=True)
    update_review_status(review_id, "approved")
    _audit_from(admin, "review.approve", request,
                target_type="review", target_id=review_id)
    return {"ok": True}


@app.put("/api/admin/reviews/{review_id}/reject")
def admin_reject_review(request: Request, review_id: int):
    admin = _require_record_access(request, "review", review_id, write=True)
    update_review_status(review_id, "rejected")
    _audit_from(admin, "review.reject", request,
                target_type="review", target_id=review_id)
    return {"ok": True}


@app.delete("/api/admin/reviews/{review_id}")
def admin_delete_review(request: Request, review_id: int):
    admin = _require_record_access(request, "review", review_id, write=True)
    # Look up before deleting so the audit row captures the snapshot
    existing = [r for r in get_all_reviews() if r["id"] == review_id]
    if not existing:
        _audit_deny(viewer_kind="admin", viewer_id=admin["id"],
                    action="review.delete",
                    resource_type="review", resource_id=review_id,
                    reason="resource_not_found_or_no_access", request=request)
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


@app.get("/api/admin/photos/{photo_id}/meta")
def admin_photo_meta(request: Request, photo_id: int):
    """Full chain-of-custody metadata for a single photo: server stamps
    + client claims (geo, device, camera). Gated by visit:view_photos
    so HR/inv_mgr can't pull tech geolocation history."""
    _require_perm(request, "visit:view_photos")
    p = get_photo_by_id(photo_id)
    if not p:
        raise HTTPException(404, "Photo not found")
    return p


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


# ── 5S workplace-discipline endpoints ─────────────────────────────────────────
# Tech-side endpoints
@app.get("/api/tech/5s/assets/mine")
def tech_fs_my_assets(request: Request):
    tech_id = _require_tech(request)
    return fs_list_assets(tech_id=tech_id, active_only=True)


@app.get("/api/tech/5s/checklist")
def tech_fs_checklist(request: Request, asset_id: int, phase: str):
    tech_id = _require_tech(request)
    asset = fs_get_asset_by_id(asset_id)
    if not asset:
        raise HTTPException(404, "Asset not found")
    if asset.get("assigned_tech_id") != tech_id:
        raise HTTPException(403, "Not your asset")
    items = fs_get_checklist_for_phase(asset_id, phase)
    if not items:
        raise HTTPException(400, "No checklist defined for this asset/phase")
    return {"asset_id": asset_id, "phase": phase, "items": items}


class TechFSAuditSubmit(BaseModel):
    asset_id: int
    phase: str
    items: List[dict]
    client_meta: Optional[dict] = None


@app.post("/api/tech/5s/audit")
def tech_fs_submit_audit(request: Request, body: TechFSAuditSubmit):
    tech_id = _require_tech(request)
    asset = fs_get_asset_by_id(body.asset_id)
    if not asset:
        raise HTTPException(404, "Asset not found")
    if asset.get("assigned_tech_id") != tech_id:
        raise HTTPException(403, "Not your asset")
    if body.phase not in ("start_shift", "end_shift"):
        raise HTTPException(400, "Tech may only submit start_shift or end_shift audits")
    # Attach server IP into client_meta (server-issued data only).
    meta = dict(body.client_meta or {})
    meta["server_ip"] = _client_ip(request)
    meta["server_ts"] = datetime.now(timezone.utc).isoformat()
    try:
        out = fs_submit_audit(
            asset_id=body.asset_id, auditor_id=tech_id, auditor_kind="tech",
            phase=body.phase, items=body.items, client_meta=meta,
        )
    except ValueError as e:
        raise HTTPException(400, str(e))
    tech = get_tech_by_id(tech_id)
    log_audit(
        actor_type="tech", actor_id=tech_id,
        actor_prid=tech.get("prid") if tech else None,
        actor_label=tech.get("name") if tech else None,
        action="fs.audit.submit",
        target_type="fs_audit", target_id=out["audit_id"],
        target_label=f"{asset['asset_code']}/{body.phase}",
        after_value={"overall_pass": out["overall_pass"],
                     "exception_count": len(out["exception_ids"])},
        ip_address=_client_ip(request),
    )
    return out


@app.get("/api/tech/5s/exceptions/mine")
def tech_fs_my_exceptions(request: Request):
    tech_id = _require_tech(request)
    rows = fs_list_exceptions(tech_id=tech_id, limit=200)
    # filter to open-ish
    return [r for r in rows if r["status"] in ("open", "escalated", "escalated_director")]


@app.get("/api/tech/5s/today")
def tech_fs_today(request: Request):
    tech_id = _require_tech(request)
    return fs_today_status_for_tech(tech_id)


# ── 5S exception photo upload (tech) ─────────────────────────────────────────
FS_EXCEPTION_PHOTOS_DIR = Path(os.environ.get("FS_EXCEPTION_PHOTOS_DIR",
                                              "uploads/5s"))
FS_EXCEPTION_PHOTOS_DIR.mkdir(parents=True, exist_ok=True)
MAX_FS_EXC_PHOTO_SIZE = 8 * 1024 * 1024  # 8 MB hard cap for 5S exception photo uploads
_FS_EXC_PHOTO_EXTS = {".jpg", ".jpeg", ".png"}
_FS_EXC_PHOTO_MAGIC = {
    ".jpg":  [b"\xff\xd8\xff"],
    ".jpeg": [b"\xff\xd8\xff"],
    ".png":  [b"\x89PNG\r\n\x1a\n"],
}
_FS_EXC_PHOTO_MIMES = {"image/jpeg", "image/jpg", "image/png"}


def _fs_exc_photo_ext_from_mime(mime: str) -> Optional[str]:
    m = (mime or "").lower().strip()
    if m in ("image/jpeg", "image/jpg"):
        return ".jpg"
    if m == "image/png":
        return ".png"
    return None


@app.post("/api/tech/5s/exceptions/{exception_id}/photo")
async def tech_fs_exception_upload_photo(
    request: Request,
    exception_id: int,
    file:        UploadFile = File(...),
    audit_id:    int        = Form(...),
    item_key:    str        = Form(...),
    client_meta: Optional[str] = Form(None),
):
    """Tech-side companion to tech.html's queued 5S exception photo capture.
    Auth + IDOR: caller must either own the asset (fs_assets.assigned_tech_id)
    OR be the auditor on the exception's audit. Anything else is 404."""
    tech_id = _require_tech(request)

    exc = fs_get_exception(exception_id)
    if not exc:
        raise HTTPException(404, "Exception not found")
    asset = fs_get_asset_by_id(exc["asset_id"])
    audit = fs_get_audit_with_items(exc["audit_id"]) if exc.get("audit_id") else None
    owner_ok   = bool(asset and asset.get("assigned_tech_id") == tech_id)
    auditor_ok = bool(audit
                       and audit.get("auditor_kind") == "tech"
                       and audit.get("auditor_id") == tech_id)
    if not (owner_ok or auditor_ok):
        # IDOR-safe: return 404 to avoid leaking existence.
        raise HTTPException(404, "Exception not found")

    # Audit_id / item_key sanity (these are echoed back to the client as
    # confirmation that the right exception was hit — also recorded in
    # client_meta for forensics).
    if audit_id and exc.get("audit_id") and audit_id != exc.get("audit_id"):
        raise HTTPException(400, "audit_id does not match exception")
    if exc.get("category") and item_key and item_key != exc.get("category"):
        # Non-fatal — the exception is keyed on category, the client passes
        # the failed checklist item_key. We log it via client_meta but don't
        # block the upload.
        pass

    # ── File validation ─────────────────────────────────────────────────
    body = await file.read()
    if not body:
        raise HTTPException(400, "Empty file")
    if len(body) > MAX_FS_EXC_PHOTO_SIZE:
        raise HTTPException(413, f"File too large (max {MAX_FS_EXC_PHOTO_SIZE // (1024*1024)} MB)")

    # Trust the magic bytes over the client-declared content_type.
    sniffed = _imghdr.what(None, h=body)
    if sniffed == "jpeg":
        ext, mime = ".jpg", "image/jpeg"
    elif sniffed == "png":
        ext, mime = ".png", "image/png"
    else:
        # Fall back to magic-byte prefix sniffing for headers imghdr doesn't
        # recognise. If neither matches, reject.
        ext, mime = None, None
        for e, prefixes in _FS_EXC_PHOTO_MAGIC.items():
            if any(body.startswith(p) for p in prefixes):
                ext = e
                mime = "image/jpeg" if e in (".jpg", ".jpeg") else "image/png"
                break
        if not ext:
            raise HTTPException(400, "Unsupported file type (only JPEG/PNG allowed)")

    # Cross-check with the declared content-type — when it disagrees we go
    # with the sniffed value but reject obviously-wrong types (e.g. text/html).
    declared = (file.content_type or "").lower()
    if declared and declared not in _FS_EXC_PHOTO_MIMES:
        # Some clients send application/octet-stream — that's fine; we trust
        # the sniff. Outright lies (HTML/scripts/etc.) get 400.
        if declared.startswith("text/") or "html" in declared or "script" in declared:
            raise HTTPException(400, "Content-Type rejected")

    # ── Persist to disk ─────────────────────────────────────────────────
    ts = int(time.time())
    rand6 = _secrets.token_hex(3)  # 6 hex chars
    fname = f"{exception_id}__{ts}__{rand6}{ext}"
    out_path = FS_EXCEPTION_PHOTOS_DIR / fname
    try:
        out_path.write_bytes(body)
    except OSError as e:
        raise HTTPException(500, f"Could not save photo: {type(e).__name__}")

    # ── Client meta (parsed, capped, encrypted at rest) ─────────────────
    cm = None
    if client_meta:
        try:
            parsed = _json.loads(client_meta)
            if isinstance(parsed, dict):
                cm = parsed
        except Exception:
            cm = None
    # Stamp server-authoritative breadcrumbs into the meta payload so the
    # forensic trail isn't 100% client-controlled.
    cm = dict(cm or {})
    cm["server_ip"] = _client_ip(request)
    cm["server_ts"] = datetime.now(timezone.utc).isoformat()
    cm["server_audit_id"] = audit_id
    cm["server_item_key"] = (item_key or "")[:64]

    original = (file.filename or "")[:255] or None

    try:
        out = create_exception_photo(
            exception_id=exception_id, filename=fname, mime=mime,
            size_bytes=len(body), uploaded_by_id=tech_id,
            uploaded_by_kind="tech", original_filename=original,
            client_meta=cm, hub_id=(asset or {}).get("hub_id") or 1,
        )
    except Exception as e:
        # Best-effort: drop the now-orphan file off disk on DB failure.
        try: out_path.unlink(missing_ok=True)
        except Exception: pass
        raise HTTPException(500, f"Could not record photo: {type(e).__name__}")

    tech = get_tech_by_id(tech_id)
    log_audit(
        actor_type="tech", actor_id=tech_id,
        actor_prid=tech.get("prid") if tech else None,
        actor_label=tech.get("name") if tech else None,
        action="fs.exception.photo_uploaded",
        target_type="fs_exception", target_id=exception_id,
        target_label=str(exception_id),
        after_value={"photo_id": out["id"], "filename": fname,
                     "size_bytes": len(body), "mime": mime},
        ip_address=_client_ip(request),
    )
    return {"id": out["id"], "exception_id": exception_id,
            "filename": fname, "uploaded_at": out["uploaded_at"]}


@app.get("/api/admin/5s/exceptions/{exception_id}/photos")
def admin_fs_exception_list_photos(request: Request, exception_id: int):
    """Admin view of the photos a tech attached to an exception. Super_admin
    OR supervisor_admin with fs:exception_resolve. Each row carries a signed
    URL the front-end can use to fetch the binary via the existing /photos/
    signed-download surface."""
    admin = _require_record_access(request, "fs_exception", exception_id, write=False)
    exc = fs_get_exception(exception_id)
    if not exc:
        _audit_deny(viewer_kind="admin", viewer_id=admin["id"],
                    action="fs.exception.photos_view",
                    resource_type="fs_exception", resource_id=exception_id,
                    reason="resource_not_found_or_no_access", request=request)
        raise HTTPException(404, "Exception not found")
    photos = list_exception_photos(exception_id)
    out = []
    for p in photos:
        p = dict(p)
        if p.get("filename"):
            # Reuse the existing signed-URL infra so this surface is
            # consistent with visit photos. The download endpoint reads
            # PHOTOS_DIR — exception photos live in FS_EXCEPTION_PHOTOS_DIR,
            # so callers must prefix /uploads/5s/ for the actual binary.
            p["url"] = f"/uploads/5s/{p['filename']}"
            p["signed_url"] = _sign_photo_url(p["filename"])
        out.append(p)
    _audit_from(admin, "fs.exception.photos_view", request,
                target_type="fs_exception", target_id=exception_id,
                target_label=str(exception_id),
                after={"count": len(out)})
    return out


# Admin-side endpoints
@app.get("/api/admin/5s/assets")
def admin_fs_list_assets(request: Request, hub_id: Optional[int] = None,
                         asset_type: Optional[str] = None,
                         tech_id: Optional[int] = None,
                         active_only: bool = True):
    _require_perm(request, "fs:report_view")
    return fs_list_assets(hub_id=hub_id, asset_type=asset_type,
                          tech_id=tech_id, active_only=active_only)


class AdminFSAssetCreate(BaseModel):
    asset_code: str
    asset_type: str
    label: str
    hub_id: int = 1
    assigned_tech_id: Optional[int] = None
    static_location: Optional[str] = None
    notes: Optional[str] = None


@app.post("/api/admin/5s/assets")
def admin_fs_create_asset(request: Request, body: AdminFSAssetCreate):
    admin = _require_perm(request, "fs:asset_manage")
    try:
        aid = fs_create_asset(
            asset_code=body.asset_code, asset_type=body.asset_type, label=body.label,
            hub_id=body.hub_id, assigned_tech_id=body.assigned_tech_id,
            static_location=body.static_location, notes=body.notes,
        )
    except ValueError as e:
        raise HTTPException(400, str(e))
    except Exception as e:
        raise HTTPException(400, f"Could not create asset: {e}")
    _audit_from(admin, "fs.asset.create", request,
                target_type="fs_asset", target_id=aid,
                target_label=body.asset_code,
                after={"asset_code": body.asset_code, "asset_type": body.asset_type})
    return {"id": aid}


class AdminFSAssetUpdate(BaseModel):
    label: Optional[str] = None
    assigned_tech_id: Optional[int] = None
    static_location: Optional[str] = None
    active: Optional[int] = None
    notes: Optional[str] = None


@app.patch("/api/admin/5s/assets/{asset_id}")
def admin_fs_update_asset(request: Request, asset_id: int, body: AdminFSAssetUpdate):
    admin = _require_perm(request, "fs:asset_manage")
    before = fs_get_asset_by_id(asset_id)
    if not before:
        raise HTTPException(404, "Asset not found")
    fields = {k: v for k, v in body.dict().items() if v is not None}
    if not fields:
        return {"ok": True, "noop": True}
    fs_update_asset(asset_id, **fields)
    _audit_from(admin, "fs.asset.update", request,
                target_type="fs_asset", target_id=asset_id,
                target_label=before["asset_code"],
                before=before, after=fields)
    return {"ok": True}


class AdminFSAssetItemCreate(BaseModel):
    item_type: str
    item_label: str
    sop_required: bool = True
    location_code: Optional[str] = None
    expiry_date: Optional[str] = None
    part_id: Optional[int] = None


@app.post("/api/admin/5s/assets/{asset_id}/items")
def admin_fs_add_asset_item(request: Request, asset_id: int,
                             body: AdminFSAssetItemCreate):
    admin = _require_perm(request, "fs:asset_manage")
    asset = fs_get_asset_by_id(asset_id)
    if not asset:
        raise HTTPException(404, "Asset not found")
    try:
        iid = fs_add_asset_item(
            asset_id=asset_id, item_type=body.item_type,
            item_label=body.item_label, sop_required=body.sop_required,
            location_code=body.location_code, expiry_date=body.expiry_date,
            part_id=body.part_id,
        )
    except ValueError as e:
        raise HTTPException(400, str(e))
    _audit_from(admin, "fs.asset_item.add", request,
                target_type="fs_asset_item", target_id=iid,
                target_label=body.item_label,
                after={"asset_id": asset_id, "item_type": body.item_type})
    return {"id": iid}


@app.get("/api/admin/5s/assets/{asset_id}/items")
def admin_fs_list_asset_items(request: Request, asset_id: int):
    _require_perm(request, "fs:report_view")
    return fs_list_asset_items(asset_id)


@app.delete("/api/admin/5s/assets/{asset_id}/items/{item_id}")
def admin_fs_remove_asset_item(request: Request, asset_id: int, item_id: int):
    admin = _require_perm(request, "fs:asset_manage")
    fs_remove_asset_item(item_id)
    _audit_from(admin, "fs.asset_item.remove", request,
                target_type="fs_asset_item", target_id=item_id)
    return {"ok": True}


class AdminFSAuditSubmit(BaseModel):
    asset_id: int
    phase: str = "weekly_manager"
    items: List[dict]
    client_meta: Optional[dict] = None


@app.post("/api/admin/5s/audit")
def admin_fs_submit_audit(request: Request, body: AdminFSAuditSubmit):
    admin = _require_perm(request, "fs:audit_any")
    asset = fs_get_asset_by_id(body.asset_id)
    if not asset:
        raise HTTPException(404, "Asset not found")
    meta = dict(body.client_meta or {})
    meta["server_ip"] = _client_ip(request)
    meta["server_ts"] = datetime.now(timezone.utc).isoformat()
    try:
        out = fs_submit_audit(
            asset_id=body.asset_id, auditor_id=admin["id"], auditor_kind="admin",
            phase=body.phase, items=body.items, client_meta=meta,
        )
    except ValueError as e:
        raise HTTPException(400, str(e))
    _audit_from(admin, "fs.audit.submit", request,
                target_type="fs_audit", target_id=out["audit_id"],
                target_label=f"{asset['asset_code']}/{body.phase}",
                after={"overall_pass": out["overall_pass"],
                       "exception_count": len(out["exception_ids"])})
    return out


@app.get("/api/admin/5s/audits")
def admin_fs_list_audits(request: Request,
                         hub_id: Optional[int] = None,
                         tech_id: Optional[int] = None,
                         asset_id: Optional[int] = None,
                         phase: Optional[str] = None,
                         date_from: Optional[str] = None,
                         date_to: Optional[str] = None,
                         limit: int = 200):
    _require_perm(request, "fs:report_view")
    return fs_list_audits(hub_id=hub_id, tech_id=tech_id, asset_id=asset_id,
                          phase=phase, date_from=date_from, date_to=date_to,
                          limit=limit)


@app.get("/api/admin/5s/audits/{audit_id}")
def admin_fs_get_audit(request: Request, audit_id: int):
    admin = _require_record_access(request, "fs_audit", audit_id, write=False)
    out = fs_get_audit_with_items(audit_id)
    if not out:
        _audit_deny(viewer_kind="admin", viewer_id=admin["id"],
                    action="fs.audit.view",
                    resource_type="fs_audit", resource_id=audit_id,
                    reason="resource_not_found_or_no_access", request=request)
        raise HTTPException(404, "Audit not found")
    return out


@app.get("/api/admin/5s/exceptions")
def admin_fs_list_exceptions(request: Request,
                              status: Optional[str] = "open",
                              hub_id: Optional[int] = None,
                              asset_id: Optional[int] = None,
                              severity: Optional[str] = None,
                              limit: int = 200):
    _require_perm(request, "fs:report_view")
    # Treat "all" as no filter.
    if status == "all":
        status = None
    return fs_list_exceptions(status=status, hub_id=hub_id, asset_id=asset_id,
                              severity=severity, limit=limit)


class AdminFSResolve(BaseModel):
    resolution_note: str = ""


@app.post("/api/admin/5s/exceptions/{exception_id}/resolve")
def admin_fs_resolve_exception(request: Request, exception_id: int,
                                body: AdminFSResolve):
    # Per-record gate: fs:exception_resolve is the role grant, but a
    # delegate on this specific exception (or fs_exception type) also wins.
    admin = _require_record_access(request, "fs_exception", exception_id, write=True)
    before = fs_get_exception(exception_id)
    if not before:
        _audit_deny(viewer_kind="admin", viewer_id=admin["id"],
                    action="fs.exception.resolve",
                    resource_type="fs_exception", resource_id=exception_id,
                    reason="resource_not_found_or_no_access", request=request)
        raise HTTPException(404, "Exception not found")
    try:
        fs_resolve_exception(exception_id, admin["id"], "admin",
                             resolution_note=body.resolution_note or "")
    except ValueError as e:
        raise HTTPException(400, str(e))
    _audit_from(admin, "fs.exception.resolve", request,
                target_type="fs_exception", target_id=exception_id,
                target_label=before["category"],
                before={"status": before["status"]},
                after={"status": "resolved"})
    return {"ok": True}


@app.post("/api/admin/5s/exceptions/{exception_id}/escalate")
def admin_fs_escalate_exception(request: Request, exception_id: int):
    admin = _require_record_access(request, "fs_exception", exception_id, write=True)
    before = fs_get_exception(exception_id)
    if not before:
        _audit_deny(viewer_kind="admin", viewer_id=admin["id"],
                    action="fs.exception.escalate",
                    resource_type="fs_exception", resource_id=exception_id,
                    reason="resource_not_found_or_no_access", request=request)
        raise HTTPException(404, "Exception not found")
    try:
        fs_escalate_exception(exception_id, escalated_to_id=admin["id"],
                              actor_id=admin["id"], actor_kind="admin",
                              target_status="escalated_director")
    except ValueError as e:
        raise HTTPException(400, str(e))
    _audit_from(admin, "fs.exception.escalate_director", request,
                target_type="fs_exception", target_id=exception_id,
                target_label=before["category"],
                before={"status": before["status"]},
                after={"status": "escalated_director"})
    return {"ok": True}


@app.get("/api/admin/5s/compliance")
def admin_fs_compliance_overview(request: Request,
                                  hub_id: Optional[int] = None,
                                  window_days: int = 30):
    _require_perm(request, "fs:report_view")
    return fs_list_compliance_overview(hub_id=hub_id, window_days=window_days)


@app.get("/api/admin/5s/compliance/{tech_id}")
def admin_fs_compliance_tech(request: Request, tech_id: int,
                              window_days: int = 30):
    _require_perm(request, "fs:report_view")
    return fs_compute_compliance_score(tech_id, window_days=window_days)


@app.get("/api/admin/5s/dashboard")
def admin_fs_dashboard(request: Request, hub_id: Optional[int] = None):
    _require_perm(request, "fs:report_view")
    overview = fs_list_compliance_overview(hub_id=hub_id, window_days=30)
    open_excs  = fs_list_exceptions(status="open", hub_id=hub_id, limit=500)
    esc_excs   = fs_list_exceptions(status="escalated", hub_id=hub_id, limit=500)
    director_excs = fs_list_exceptions(status="escalated_director", hub_id=hub_id, limit=500)
    safety_open = [e for e in (open_excs + esc_excs + director_excs)
                   if e.get("severity") == "safety_loto"]
    return {
        "compliance":            overview,
        "open_exceptions":       len(open_excs),
        "escalated_exceptions":  len(esc_excs),
        "director_exceptions":   len(director_excs),
        "safety_red_count":      len(safety_open),
        "safety_red":            safety_open[:25],
    }


# Phase 3: coaching log endpoints
class AdminFSCoachingOpen(BaseModel):
    tech_id: int
    plan_text: str = ""


@app.post("/api/admin/5s/coaching")
def admin_fs_open_coaching(request: Request, body: AdminFSCoachingOpen):
    admin = _require_perm(request, "fs:coaching_manage")
    score = fs_compute_compliance_score(body.tech_id, window_days=30)
    cid = fs_open_coaching(body.tech_id, opened_by_id=admin["id"],
                           band_at_open=score["band"], plan_text=body.plan_text)
    _audit_from(admin, "fs.coaching.open", request,
                target_type="fs_coaching", target_id=cid,
                target_label=f"tech:{body.tech_id}",
                after={"band_at_open": score["band"]})
    return {"id": cid}


class AdminFSCoachingClose(BaseModel):
    close_note: str = ""


@app.post("/api/admin/5s/coaching/{coaching_id}/close")
def admin_fs_close_coaching(request: Request, coaching_id: int,
                             body: AdminFSCoachingClose):
    admin = _require_perm(request, "fs:coaching_manage")
    fs_close_coaching(coaching_id, closed_by_id=admin["id"],
                      close_note=body.close_note or "")
    _audit_from(admin, "fs.coaching.close", request,
                target_type="fs_coaching", target_id=coaching_id)
    return {"ok": True}


@app.get("/api/admin/5s/coaching")
def admin_fs_list_coaching(request: Request,
                            tech_id: Optional[int] = None,
                            status: Optional[str] = None):
    _require_perm(request, "fs:report_view")
    return fs_list_coaching(tech_id=tech_id, status=status)


# Phase 4: KPI cross-correlation. Joint diagnostic — if the KPI module is not
# wired up yet, the database helper returns fs_band only with a placeholder
# diagnostic string. The admin Dashboard surfaces "systemic / performance /
# lucky / healthy" labels off this endpoint.
@app.get("/api/admin/5s/kpi-correlation/{tech_id}")
def admin_fs_kpi_correlation(request: Request, tech_id: int,
                              window_days: int = 30):
    _require_perm(request, "fs:report_view")
    return fs_correlate_5s_to_kpi(tech_id, window_days=window_days)


@app.get("/api/admin/5s/export")
def admin_fs_export(request: Request, format: str = "json"):
    admin = _require_perm(request, "fs:report_view")
    data = fs_export_all()
    _audit_from(admin, "fs.export", request, target_type="fs_export",
                after={"audits": len(data["audits"]), "format": format})
    if format == "csv":
        import csv as _csv, io as _io
        buf = _io.StringIO()
        # Audits sheet
        buf.write("# fs_audits\n")
        w = _csv.writer(buf)
        if data["audits"]:
            w.writerow(list(data["audits"][0].keys()))
            for r in data["audits"]:
                w.writerow(list(r.values()))
        buf.write("\n# fs_audit_items\n")
        if data["audit_items"]:
            w.writerow(list(data["audit_items"][0].keys()))
            for r in data["audit_items"]:
                w.writerow(list(r.values()))
        buf.write("\n# fs_exceptions\n")
        if data["exceptions"]:
            w.writerow(list(data["exceptions"][0].keys()))
            for r in data["exceptions"]:
                w.writerow(list(r.values()))
        buf.write("\n# fs_exception_events\n")
        if data["exception_events"]:
            w.writerow(list(data["exception_events"][0].keys()))
            for r in data["exception_events"]:
                w.writerow(list(r.values()))
        return Response(content=buf.getvalue(), media_type="text/csv",
                        headers={"Content-Disposition": 'attachment; filename="fs_export.csv"'})
    return data


# ── 5S background auto-escalation tick (Phase 2) ──────────────────────────────
# Every 15 min, move overdue exceptions up the ladder:
#   open > 24h  → escalated (to supervisor_admin)
#   escalated > 48h → escalated_director (to super_admin)
import asyncio as _asyncio


async def _fs_escalation_loop():
    while True:
        try:
            now_iso = datetime.now(timezone.utc).isoformat()
            overdue = fs_find_overdue_exceptions(now_iso)
            sup = None; director = None
            for a in get_all_admin_users():
                if a.get("role") == "supervisor_admin" and a.get("active"):
                    sup = a; break
            for a in get_all_admin_users():
                if a.get("role") == "super_admin" and a.get("active"):
                    director = a; break
            for eid in overdue.get("to_manager", []):
                try:
                    fs_escalate_exception(eid,
                                          escalated_to_id=(sup["id"] if sup else 0),
                                          actor_id=0, actor_kind="system",
                                          target_status="escalated")
                    _notify_manager(eid)
                except Exception:
                    pass
            for eid in overdue.get("to_director", []):
                try:
                    fs_escalate_exception(eid,
                                          escalated_to_id=(director["id"] if director else 0),
                                          actor_id=0, actor_kind="system",
                                          target_status="escalated_director")
                    _notify_director(eid)
                except Exception:
                    pass
        except Exception as _e:
            logger.error(f"5S escalation tick error: {_e}")
        await _asyncio.sleep(15 * 60)


def _build_fs_notify_payload(exception_id: int, recipient_role: str):
    """Decrypts the exception + asset + hub context for an escalation email.
    Returns (subject, html, plain_to_or_none). recipient_role is 'manager' or
    'director' — used for subject framing only. Returns None on missing exc."""
    try:
        exc = fs_get_exception(exception_id)
    except Exception:
        exc = None
    if not exc:
        return None
    try:
        asset = fs_get_asset_by_id(exc.get("asset_id")) or {}
    except Exception:
        asset = {}
    try:
        hub = get_hub_by_id(exc.get("hub_id") or 1) or {}
    except Exception:
        hub = {}
    # Age in hours since opened
    age_hours = None
    try:
        opened = datetime.fromisoformat(exc.get("opened_at",
                                                "").replace("Z", "+00:00"))
        age_hours = round((datetime.now(timezone.utc) -
                          opened).total_seconds() / 3600.0, 1)
    except Exception:
        pass
    severity = (exc.get("severity") or "normal").upper()
    asset_code = asset.get("asset_code") or f"asset:{exc.get('asset_id')}"
    asset_label = asset.get("label") or asset_code
    hub_name = hub.get("name") or f"hub:{exc.get('hub_id')}"
    role_label = "Manager" if recipient_role == "manager" else "Director"
    safety_tag = "🚨 SAFETY/LOTO" if severity == "SAFETY_LOTO" else "Escalation"
    subject = (f"[5S {safety_tag}] {asset_code} — exception #{exception_id} "
               f"({role_label} action required)")
    desc = (exc.get("description") or "").strip() or "(no description)"
    # HTML-escape user-controllable strings before interpolating
    def _esc(s: str) -> str:
        return (str(s).replace("&", "&amp;").replace("<", "&lt;")
                       .replace(">", "&gt;").replace('"', "&quot;"))
    html = f"""
    <div style="font-family:Arial,sans-serif;max-width:640px;margin:0 auto;">
      <div style="background:#0B2545;padding:20px;color:white;">
        <h2 style="margin:0;color:#22A08A;">5S {_esc(safety_tag)}</h2>
        <p style="margin:4px 0 0;color:#cbd5e0;font-size:13px;">
          {_esc(role_label)} action required · {_esc(hub_name)}
        </p>
      </div>
      <div style="padding:20px;border:1px solid #e8ecf0;">
        <table style="width:100%;border-collapse:collapse;font-size:14px;">
          <tr><td style="padding:6px 0;color:#5A6472;width:160px;">Exception ID</td>
              <td style="padding:6px 0;"><strong>#{exception_id}</strong></td></tr>
          <tr><td style="padding:6px 0;color:#5A6472;">Severity</td>
              <td style="padding:6px 0;"><strong style="color:{'#dc2626' if severity=='SAFETY_LOTO' else '#f59e0b'};">{_esc(severity)}</strong></td></tr>
          <tr><td style="padding:6px 0;color:#5A6472;">Category</td>
              <td style="padding:6px 0;">{_esc(exc.get('category') or '—')}</td></tr>
          <tr><td style="padding:6px 0;color:#5A6472;">Asset</td>
              <td style="padding:6px 0;">{_esc(asset_label)} ({_esc(asset_code)})</td></tr>
          <tr><td style="padding:6px 0;color:#5A6472;">Hub</td>
              <td style="padding:6px 0;">{_esc(hub_name)}</td></tr>
          <tr><td style="padding:6px 0;color:#5A6472;">Opened by</td>
              <td style="padding:6px 0;">{_esc(exc.get('opened_by_kind') or '—')}:{exc.get('opened_by_id') or '—'}</td></tr>
          <tr><td style="padding:6px 0;color:#5A6472;">Opened at</td>
              <td style="padding:6px 0;">{_esc(exc.get('opened_at') or '—')}</td></tr>
          <tr><td style="padding:6px 0;color:#5A6472;">Age</td>
              <td style="padding:6px 0;">{age_hours if age_hours is not None else '—'} hours</td></tr>
          <tr><td style="padding:6px 0;color:#5A6472;">Current status</td>
              <td style="padding:6px 0;">{_esc(exc.get('status') or '—')}</td></tr>
        </table>
        <div style="margin-top:16px;padding:14px;background:#f5f7f9;
                    border-left:3px solid #22A08A;">
          <p style="margin:0 0 6px;color:#5A6472;font-size:12px;
                    text-transform:uppercase;letter-spacing:1px;">Description</p>
          <p style="margin:0;font-size:14px;white-space:pre-wrap;">{_esc(desc)}</p>
        </div>
      </div>
      <div style="padding:14px 20px;background:#f5f7f9;font-size:12px;
                  color:#5A6472;">
        Automated 5S escalation — PrimeCool Services.
        Resolve, escalate, or override via the 5S dashboard.
      </div>
    </div>
    """
    return subject, html


def _send_fs_notification(exception_id: int, recipient_role: str):
    """Send a 5S escalation email via Resend if configured; otherwise write
    only the existing audit row. Failures never raise — they're recorded as
    `fs.notify.<role>_failed` audit rows so the escalation loop keeps moving.

    recipient_role: 'manager' | 'director'.
    """
    action_ok = f"fs.notify.{recipient_role}"
    action_skip = f"fs.notify.{recipient_role}_skipped"
    action_fail = f"fs.notify.{recipient_role}_failed"

    api_key = os.environ.get("RESEND_API_KEY")
    notify_email = os.environ.get("NOTIFY_EMAIL", "juggarr@gmail.com")

    if not api_key:
        # Email not configured — keep the legacy audit-log-only behavior so
        # nothing breaks in dev, but record that no email was sent.
        try:
            log_audit(actor_type="system", action=action_skip,
                      target_type="fs_exception", target_id=exception_id,
                      target_label="RESEND_API_KEY not set")
        except Exception:
            pass
        log_audit(actor_type="system", action=action_ok,
                  target_type="fs_exception", target_id=exception_id)
        return

    payload = _build_fs_notify_payload(exception_id, recipient_role)
    if not payload:
        try:
            log_audit(actor_type="system", action=action_fail,
                      target_type="fs_exception", target_id=exception_id,
                      target_label="exception_not_found")
        except Exception:
            pass
        return
    subject, html = payload

    try:
        resend_lib.api_key = api_key
        resend_lib.Emails.send({
            "from":    "PrimeCool Services <onboarding@resend.dev>",
            "to":      notify_email,
            "subject": subject,
            "html":    html,
        })
        log_audit(actor_type="system", action=action_ok,
                  target_type="fs_exception", target_id=exception_id,
                  target_label=notify_email)
    except Exception as e:
        # Never swallow silently — write a failure audit + a logger.warning
        # with the error class only (not the full traceback, which can leak).
        err_class = type(e).__name__
        logger.warning(f"5S notify ({recipient_role}) email send failed: "
                       f"{err_class} on exception {exception_id}")
        try:
            log_audit(actor_type="system", action=action_fail,
                      target_type="fs_exception", target_id=exception_id,
                      target_label=f"send_failed: {err_class}")
        except Exception:
            pass


def _notify_manager(exception_id: int):
    """Send a 5S escalation email to the manager. Falls back to audit-only
    when RESEND_API_KEY is unset. Errors are recorded as `fs.notify.manager_failed`."""
    _send_fs_notification(exception_id, "manager")


def _notify_director(exception_id: int):
    """Send a 5S escalation email to the director (48h cascade). Same
    fallback + audit-on-failure pattern as `_notify_manager`."""
    _send_fs_notification(exception_id, "director")


@app.on_event("startup")
async def _start_fs_escalation_loop():
    _asyncio.create_task(_fs_escalation_loop())


@app.get("/tech/home")
def tech_landing():
    # TP-2: new 2-tab landing (Sign In for Work / My Profile) + company
    # message board. The existing /tech remains the jobs/5S/payslips PWA.
    return FileResponse("tech_landing.html")


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


# ═══════════════════════════════════════════════════════════════════════════
# Delegation endpoints
# ═══════════════════════════════════════════════════════════════════════════
from database import (
    create_delegation as _create_delegation,
    revoke_delegation as _revoke_delegation,
    cascade_revoke_power as _cascade_revoke_power,
    list_delegations as _list_delegations,
    get_delegation as _get_delegation,
    list_active_delegations_for_recipient as _list_active_for_recipient,
    list_cascade_revoked_recent as _list_cascade_recent,
    create_regrant_request as _create_regrant_req,
    approve_regrant_request as _approve_regrant_req,
    deny_regrant_request as _deny_regrant_req,
    list_regrant_requests as _list_regrant_reqs,
    expire_delegations_sweep as _expire_delegations_sweep,
    get_admin_user_by_id as _get_admin_for_deleg,
)


_VALID_SCOPE_TYPES = {"customer", "visit", "invoice", "technician"}


class DelegationGrantRequest(BaseModel):
    recipient_id: int
    delegation_type: str          # 'record' | 'record_type' | 'power'
    scope_record_id: Optional[int] = None
    scope_record_type: Optional[str] = None
    permission_level: Optional[str] = None   # 'read' | 'read_write'
    valid_until: Optional[str] = None
    grantor_notes: Optional[str] = ""


class RegrantRequestBody(BaseModel):
    original_delegation_id: int
    notes: Optional[str] = ""


class ReviewNotesBody(BaseModel):
    review_notes: Optional[str] = ""


class RevokeBody(BaseModel):
    reason: Optional[str] = ""


def _can_grant_delegations(admin: dict) -> bool:
    """Super_admin always can. Otherwise admin must have has_delegation_power."""
    if admin.get("role") == "super_admin":
        return True
    return bool(admin.get("has_delegation_power"))


@app.post("/api/admin/delegations", response_model=Dict[str, Any])
def admin_delegation_grant(request: Request, body: DelegationGrantRequest):
    admin = _require_admin(request)
    if not _can_grant_delegations(admin):
        raise HTTPException(403, "Only super_admin or admins with delegation power can grant")
    # Locked rule 5 — power-grant only by super_admin.
    if body.delegation_type == "power" and admin.get("role") != "super_admin":
        raise HTTPException(403, "Only super_admin may grant delegation power")
    if body.delegation_type not in ("record", "record_type", "power"):
        raise HTTPException(422, "delegation_type must be record, record_type, or power")
    # Locked rule 4 — no self-grants (including super_admin → self).
    if int(body.recipient_id) == int(admin["id"]):
        raise HTTPException(422, "Self-grants are not allowed")
    # Locked rule 3 — tech recipients rejected. The recipient must exist as an admin.
    recipient = _get_admin_for_deleg(int(body.recipient_id))
    if not recipient:
        raise HTTPException(422, "Recipient must be an existing admin user (tech recipients are rejected in v1)")
    if recipient.get("role", "").startswith("tech"):
        raise HTTPException(422, "Tech recipients are not allowed in v1")
    # Scope validation per type
    if body.delegation_type in ("record", "record_type"):
        if not body.scope_record_type or body.scope_record_type not in _VALID_SCOPE_TYPES:
            raise HTTPException(422, f"scope_record_type required and must be one of {sorted(_VALID_SCOPE_TYPES)}")
        if body.delegation_type == "record" and not body.scope_record_id:
            raise HTTPException(422, "scope_record_id required for record-level delegations")
        if not body.permission_level or body.permission_level not in ("read", "read_write"):
            raise HTTPException(422, "permission_level must be 'read' or 'read_write'")
    perm_level = body.permission_level if body.delegation_type != "power" else None
    new_id = _create_delegation(
        grantor_id=admin["id"], grantor_role=admin.get("role", ""),
        recipient_id=body.recipient_id, recipient_kind="admin",
        delegation_type=body.delegation_type,
        scope_record_id=body.scope_record_id,
        scope_record_type=body.scope_record_type,
        permission_level=perm_level,
        valid_until=body.valid_until,
        grantor_notes=(body.grantor_notes or "")[:500],
    )
    try:
        _audit_from(admin, "delegation.granted", request,
                    target_type="delegations", target_id=new_id,
                    after={"recipient_id": body.recipient_id,
                           "delegation_type": body.delegation_type,
                           "scope_record_type": body.scope_record_type,
                           "scope_record_id": body.scope_record_id,
                           "permission_level": perm_level,
                           "valid_until": body.valid_until})
        if body.delegation_type == "power":
            _audit_from(admin, "delegation_power.granted", request,
                        target_type="admin_users", target_id=body.recipient_id)
    except Exception as _e:
        logger.warning(f"[delegation] audit-write failed: {_e}")
    return {"id": new_id, "ok": True}


@app.post("/api/admin/delegations/{delegation_id}/revoke", response_model=OkResponse)
def admin_delegation_revoke(request: Request, delegation_id: int, body: RevokeBody):
    admin = _require_admin(request)
    row = _get_delegation(delegation_id)
    if not row:
        _audit_deny(viewer_kind="admin", viewer_id=admin["id"],
                    action="delegation.revoke",
                    resource_type="delegation", resource_id=delegation_id,
                    reason="resource_not_found_or_no_access", request=request)
        raise HTTPException(404, "Delegation not found")
    if admin.get("role") != "super_admin" and int(row["grantor_id"]) != int(admin["id"]):
        _audit_deny(viewer_kind="admin", viewer_id=admin["id"],
                    action="delegation.revoke",
                    resource_type="delegation", resource_id=delegation_id,
                    reason="not_grantor_or_super_admin", request=request)
        raise HTTPException(403, "Only the grantor or super_admin may revoke")
    if row.get("revoked_at"):
        return {"ok": True, "already_revoked": True}
    # Power revoke → cascade
    if row["delegation_type"] == "power":
        cascaded = _cascade_revoke_power(int(row["recipient_id"]), revoked_by=admin["id"])
        # Also revoke the originating delegation row itself
        _revoke_delegation(delegation_id, admin["id"],
                           reason=(body.reason or "")[:500], revoke_kind="manual")
        try:
            _audit_from(admin, "delegation_power.revoked", request,
                        target_type="admin_users", target_id=row["recipient_id"],
                        after={"cascaded": cascaded})
            for cid in cascaded:
                _audit_from(admin, "delegation.cascade_revoked", request,
                            target_type="delegations", target_id=cid)
        except Exception as _e:
            logger.warning(f"[delegation] audit-write failed: {_e}")
        return {"ok": True, "cascaded": cascaded}
    # Non-power → single row
    _revoke_delegation(delegation_id, admin["id"],
                       reason=(body.reason or "")[:500], revoke_kind="manual")
    try:
        _audit_from(admin, "delegation.revoked", request,
                    target_type="delegations", target_id=delegation_id)
    except Exception as _e:
        logger.warning(f"[delegation] audit-write failed: {_e}")
    return {"ok": True}


@app.get("/api/admin/delegations", response_model=Dict[str, Any])
def admin_delegation_list(request: Request,
                          as_: Optional[str] = Query(None, alias="as"),
                          status: Optional[str] = None,
                          type: Optional[str] = None):
    admin = _require_admin(request)
    filters = {}
    if type:
        filters["delegation_type"] = type
    if status:
        filters["status"] = status
    # super_admin sees all; delegating_admin sees only own (as grantor or recipient)
    if admin.get("role") != "super_admin":
        if as_ == "recipient":
            filters["recipient_id"] = admin["id"]
        else:
            filters["grantor_id"] = admin["id"]
    return {"rows": _list_delegations(filters)}


@app.get("/api/admin/delegations/my-active", response_model=Dict[str, Any])
def admin_delegation_my_active(request: Request):
    admin = _require_admin(request)
    rows = _list_active_for_recipient(admin["id"])
    cascade_recent = _list_cascade_recent(admin["id"], days=30)
    return {"count": len(rows), "rows": rows,
            "cascade_revoked_recent": cascade_recent}


@app.get("/api/admin/delegations/regrant-requests", response_model=Dict[str, Any])
def admin_regrant_list(request: Request, status: Optional[str] = "open"):
    _require_super_admin(request)
    return {"rows": _list_regrant_reqs(status=status)}


@app.post("/api/admin/delegations/regrant-requests", response_model=Dict[str, Any])
def admin_regrant_create(request: Request, body: RegrantRequestBody):
    admin = _require_admin(request)
    orig = _get_delegation(int(body.original_delegation_id))
    if not orig:
        raise HTTPException(404, "Original delegation not found")
    if orig.get("revoke_kind") != "power_cascade":
        raise HTTPException(400, "Only cascade-revoked delegations can be re-granted via this flow")
    if int(orig["recipient_id"]) != int(admin["id"]):
        raise HTTPException(403, "Only the original recipient may request re-grant")
    rid = _create_regrant_req(admin["id"], int(body.original_delegation_id),
                              notes=(body.notes or "")[:500])
    try:
        _audit_from(admin, "delegation.regrant_requested", request,
                    target_type="delegation_regrant_requests", target_id=rid)
    except Exception as _e:
        logger.warning(f"[delegation] audit-write failed: {_e}")
    return {"id": rid, "ok": True}


@app.post("/api/admin/delegations/regrant-requests/{request_id}/approve", response_model=OkResponse)
def admin_regrant_approve(request: Request, request_id: int, body: ReviewNotesBody):
    admin = _require_super_admin(request)
    try:
        res = _approve_regrant_req(int(request_id), admin["id"],
                                   review_notes=(body.review_notes or "")[:500])
    except ValueError as e:
        raise HTTPException(404, str(e))
    try:
        _audit_from(admin, "delegation.regrant_approved", request,
                    target_type="delegation_regrant_requests", target_id=request_id,
                    after={"new_delegation_id": res["new_delegation_id"]})
    except Exception as _e:
        logger.warning(f"[delegation] audit-write failed: {_e}")
    return res


@app.post("/api/admin/delegations/regrant-requests/{request_id}/deny", response_model=OkResponse)
def admin_regrant_deny(request: Request, request_id: int, body: ReviewNotesBody):
    admin = _require_super_admin(request)
    ok = _deny_regrant_req(int(request_id), admin["id"],
                           review_notes=(body.review_notes or "")[:500])
    if not ok:
        raise HTTPException(404, "Request not found or not open")
    try:
        _audit_from(admin, "delegation.regrant_denied", request,
                    target_type="delegation_regrant_requests", target_id=request_id)
    except Exception as _e:
        logger.warning(f"[delegation] audit-write failed: {_e}")
    return {"ok": True}


@app.get("/api/admin/delegations/{delegation_id}", response_model=Dict[str, Any])
def admin_delegation_detail(request: Request, delegation_id: int):
    admin = _require_admin(request)
    row = _get_delegation(int(delegation_id))
    if not row:
        _audit_deny(viewer_kind="admin", viewer_id=admin["id"],
                    action="delegation.view",
                    resource_type="delegation", resource_id=delegation_id,
                    reason="resource_not_found_or_no_access", request=request)
        raise HTTPException(404, "Delegation not found")
    if admin.get("role") != "super_admin" \
       and int(row["grantor_id"]) != int(admin["id"]) \
       and int(row["recipient_id"]) != int(admin["id"]):
        _audit_deny(viewer_kind="admin", viewer_id=admin["id"],
                    action="delegation.view",
                    resource_type="delegation", resource_id=delegation_id,
                    reason="not_party_to_delegation", request=request)
        raise HTTPException(403, "Forbidden")
    return row


# ── Delegation expiry cron (every 6 hours) ─────────────────────────────────
async def _delegation_expiry_loop():
    # Sleep once on boot so init_db has time to settle.
    await _asyncio.sleep(30)
    while True:
        try:
            n = _expire_delegations_sweep()
            if n:
                try:
                    log_audit(actor_type="system", action="delegation.cron_sweep",
                              target_type="delegations",
                              after_value={"expired_count": n})
                except Exception as _e:
                    logger.warning(f"[delegation] audit-write failed: {_e}")
        except Exception as _e:
            logger.error(f"delegation expiry sweep error: {_e}")
        await _asyncio.sleep(6 * 60 * 60)


@app.on_event("startup")
async def _start_delegation_expiry_loop():
    _asyncio.create_task(_delegation_expiry_loop())


# ── TP-1b: per-tech EOD enforcement cron ─────────────────────────────────
TECH_EOD_GRACE_MIN = int(os.environ.get("TECH_EOD_GRACE_MIN", "120"))


def _tech_eod_pass():
    """Run one EOD enforcement pass."""
    from datetime import datetime as _dt, timezone as _tz, timedelta as _td
    from database import _con as _dbcon
    now = _dt.now(_tz.utc)
    today_iso = now.date().isoformat()
    techs = list_clocked_in_techs_today()
    for t in techs:
        tid = t["tech_id"]
        # On-call techs are explicitly allowed to be clocked in outside
        # normal hours — no overtime alert, no auto-sign-out cutoff. They
        # close out their shift manually (with the 5S end-shift audit).
        if is_tech_on_call_today(tid):
            continue
        sched_end = get_tech_scheduled_end_today(tid)
        if not sched_end:
            con = _dbcon()
            try:
                existing = con.execute(
                    "SELECT 1 FROM security_alerts WHERE kind = 'tech_no_schedule' "
                    "AND actor_id = ? AND substr(created_at, 1, 10) = ? LIMIT 1",
                    (tid, today_iso),
                ).fetchone()
            finally:
                con.close()
            if not existing:
                _tp1_raise_security_alert(
                    kind="tech_no_schedule", severity="low",
                    actor_type="tech", actor_id=tid,
                    summary=f"Tech #{tid} clocked in but has no schedule on file",
                    details={"work_date": today_iso},
                )
            continue
        if now.isoformat() <= sched_end:
            continue
        if is_overtime_approved(tid):
            continue
        con = _dbcon()
        try:
            existing_ot = con.execute(
                "SELECT 1 FROM security_alerts WHERE kind = 'tech_overtime_pending' "
                "AND actor_id = ? AND substr(created_at, 1, 10) = ? LIMIT 1",
                (tid, today_iso),
            ).fetchone()
        finally:
            con.close()
        if not existing_ot:
            _tp1_raise_security_alert(
                kind="tech_overtime_pending", severity="low",
                actor_type="tech", actor_id=tid,
                summary=f"Tech #{tid} is in overtime — pending admin approval",
                details={"scheduled_end": sched_end, "work_date": today_iso},
            )
        try:
            sched_end_dt = _dt.fromisoformat(sched_end)
        except Exception:
            continue
        if now < sched_end_dt + _td(minutes=TECH_EOD_GRACE_MIN):
            continue
        try:
            cid = record_auto_clock_out(tid, today=today_iso)
        except Exception as e:
            logger.warning(f"auto_clock_out failed for tech {tid}: {e}")
            continue
        # Synthesize an end_shift fail-all audit for the tech's assigned vehicle/asset.
        con = _dbcon()
        try:
            asset = con.execute(
                "SELECT id, asset_type FROM fs_assets WHERE assigned_tech_id = ? "
                "AND asset_type = 'vehicle' AND active = 1 LIMIT 1",
                (tid,),
            ).fetchone()
            if not asset:
                asset = con.execute(
                    "SELECT id, asset_type FROM fs_assets WHERE assigned_tech_id = ? "
                    "AND active = 1 LIMIT 1",
                    (tid,),
                ).fetchone()
        finally:
            con.close()
        if asset:
            try:
                from database import FS_DEFAULT_CHECKLIST
                checklist = FS_DEFAULT_CHECKLIST.get(
                    (asset["asset_type"], "end_shift"),
                    FS_DEFAULT_CHECKLIST.get(
                        (asset["asset_type"], "weekly_manager"), {})
                )
                items = []
                for section, keys in (checklist or {}).items():
                    for k in keys:
                        items.append({
                            "section": section, "item_key": k,
                            "status": "fail",
                            "note": ("Auto-recorded by EOD enforcement: tech "
                                     "did not sign out by end-of-shift + grace"),
                        })
                if items:
                    fs_submit_audit(asset_id=asset["id"], auditor_id=tid,
                                    auditor_kind="tech", phase="end_shift",
                                    items=items, client_meta=None)
            except Exception as e:
                logger.warning(f"synth end_shift fail-all failed for tech "
                               f"{tid}: {e}")
        try:
            log_audit(actor_type="system",
                      action="tech.auto_signout_5s_fail",
                      target_type="technician", target_id=tid,
                      target_label=f"work_date={today_iso}",
                      after_value={"clock_event_id": cid,
                                   "scheduled_end": sched_end,
                                   "grace_min": TECH_EOD_GRACE_MIN})
        except Exception:
            pass
        _tp1_raise_security_alert(
            kind="tech_auto_signout", severity="medium",
            actor_type="tech", actor_id=tid,
            summary=(f"Tech #{tid} auto-signed-out at EOD; "
                     f"all 5S items recorded as FAIL"),
            details={"work_date": today_iso, "scheduled_end": sched_end},
        )


async def _tech_eod_loop():
    while True:
        try:
            await _asyncio.sleep(5 * 60)
            _tech_eod_pass()
        except Exception as e:
            logger.warning(f"tech EOD loop tick error: {e}")


@app.on_event("startup")
async def _start_tech_eod_loop():
    _asyncio.create_task(_tech_eod_loop())


@app.get("/")
def index():
    return FileResponse("index.html")
