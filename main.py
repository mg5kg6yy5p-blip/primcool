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

from fastapi import FastAPI, HTTPException, Request, UploadFile, File, Form, Response, Query, Body
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, PlainTextResponse, RedirectResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
import jwt
import pyotp
import qrcode
import resend as resend_lib
import backup as _backup

from database import (
    init_db, save_submission, bootstrap_super_admin,
    get_user_settings, set_user_settings,
    get_customer_by_code, get_customer_by_id, get_all_customers,
    create_customer, delete_customer, verify_customer, set_customer_pin,
    validate_pin_policy, record_pin_failure, reset_pin_failures,
    is_customer_pin_locked,
    record_admin_login_failure, reset_admin_login_failures, is_admin_login_locked,
    record_tech_login_failure, reset_tech_login_failures, is_tech_login_locked,
    get_customer_by_code_and_email, create_customer_pin_reset, consume_customer_pin_reset,
    get_customer_equipment, get_customer_equipment_portal_safe,
    get_equipment_by_id, create_equipment, delete_equipment,
    get_customer_with_decryption, update_customer_fields,
    get_customer_equipment_with_visits, get_customer_visits_paginated,
    get_visit_full_detail, get_visit_photos_for_admin,
    update_invoice_payment_status,
    get_customer_visits, get_all_visits, create_visit, update_visit, delete_visit,
    create_pm_contract, get_pm_contract, list_pm_contracts, update_pm_contract,
    list_visits_for_contract, generate_due_pm_visits, pm_contract_schedule,
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
    verify_tech, get_tech_by_id, get_tech_by_code, get_all_techs, create_tech, update_tech,
    # W1+W2 unified staff helpers
    list_staff, get_staff_by_id, VALID_STAFF_TYPES, VALID_DEPARTMENTS,
    # Pass B warehouse movements
    record_part_movement, list_warehouse_movements, stock_by_location,
    VALID_MOVEMENT_REASONS, VALID_MOVEMENT_REFS,
    # Pass C receiving queue
    list_open_pos_for_receiving,
    # Pass D warehouse deliveries
    create_warehouse_delivery, list_warehouse_deliveries,
    mark_delivery_loaded, mark_delivery_delivered,
    cancel_warehouse_delivery, VALID_DELIVERY_KINDS,
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
    create_estimate, update_estimate, get_estimate_by_id, get_all_estimates,
    get_customer_estimates, transition_estimate_status, convert_estimate_to_invoice,
    delete_estimate, expire_stale_estimates, list_scheduled_visits_on,
    get_visit_parts, add_visit_part, remove_visit_part, get_visit_part_by_id,
    build_invoice_lines_from_visit,
    # Admin users + audit
    verify_admin_user, get_admin_user_by_id, get_admin_user_by_username, get_all_admin_users,
    create_admin_user, update_admin_user, set_admin_role, set_admin_active,
    set_admin_password, count_active_admins, get_admin_by_email,
    create_admin_password_reset, consume_admin_password_reset,
    set_admin_mfa_pending, activate_admin_mfa, disable_admin_mfa,
    replace_admin_backup_codes, consume_admin_backup_code,
    # Tech MFA mirror — May 2026, parity with admin + customer.
    set_tech_mfa_pending, activate_tech_mfa, disable_tech_mfa,
    replace_tech_backup_codes, consume_tech_backup_code,
    get_tech_backup_codes_status,
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
    count_open_security_alerts, resolve_security_alert,
    resolve_security_alerts_bulk, detect_anomalies_for_actor,
    create_session, get_session_by_jti, is_session_active,
    revoke_session, revoke_all_sessions_for, get_active_sessions_for,
    get_recent_sessions_for, revoke_other_sessions_for,
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
    get_invoice_metrics, get_gct_liability_report, list_invoices, export_invoices_csv,
    get_invoice_full, record_invoice_payment_v2,
    transition_invoice_status, create_invoice_with_lines,
    update_invoice_with_lines,
    # Online payment links (#1b)
    create_payment_link, get_payment_link_by_token, mark_payment_link_paid,
    cancel_payment_link, get_active_payment_link_for_invoice,
    # Idempotency keys (#4 offline replay)
    idempotency_lookup, idempotency_store, purge_stale_idempotency_keys,
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
        # Note: onboarding (tech:create / admin:create) is reserved for HR +
        # super_admin per the unified Onboarding flow. system_admin can view
        # and update existing staff but not create new hires.
        "tech:view", "tech:update", "tech:reset_pin",
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
        # Onboarding partner — HR owns onboarding for every employee type
        # (office admin, field tech, parts runner, warehouse staff). Mirrors
        # super_admin's onboarding scope without granting any other
        # super-admin powers.
        "admin:create", "admin:update", "admin:set_role", "admin:set_active",
        "admin:reset_password", "admin:view_all",
        "tech:view", "tech:create", "tech:update", "tech:reset_pin", "tech:delete",
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

# ── Warehouse module permissions (W2) ────────────────────────────────────────
# Operator directive: "inventory manager is material manager not a people
# manager and don't have the same powers." So inventory_manager keeps its
# stock/PO scope and gets warehouse:view_queue (so they can see what's
# moving on the floor) — but NOT warehouse:manage_staff (people management).
#
# super_admin + hr_admin are the only roles that can add/remove warehouse
# staff (mirrors the existing tech:create / tech:delete pattern; those
# perms are reused — staff_type='warehouse_floor' rows live in the same
# technicians table as a tech, so existing tech:create grants the right
# to create any staff_type).
#
# A future "warehouse_manager" admin role could be added if the operator
# wants in-warehouse line-manager autonomy without giving inventory_manager
# people-management powers. Filed for follow-up.
ADMIN_PERMS["super_admin"].update({
    "warehouse:view_queue", "warehouse:manage_assets",
})
ADMIN_PERMS["supervisor_admin"].update({
    "warehouse:view_queue", "warehouse:manage_assets",
})
ADMIN_PERMS["inventory_manager"].update({
    "warehouse:view_queue",  # material visibility only — NO manage_assets
    # Asset list needed to render the warehouse tab's selectors
    # (per-asset checklist editor + checksheet upload). They can READ
    # asset metadata; they cannot create/disable assets (no
    # fs:asset_manage).
    "fs:report_view",
})
ADMIN_PERMS["hr_admin"].update({
    "warehouse:view_queue",  # for staffing context — read-only
})

# ── R5: 30-staff scale — dedicated dispatcher + warehouse_supervisor ────────
# At 30 staff (18 techs + 4 warehouse + 3 dispatchers + 5 admins) the
# admin_supervisor role started doing too many jobs. Split into two
# tighter roles so the dispatcher seat doesn't need full supervisor
# powers and the warehouse manager seat doesn't need full HR powers.
#
# dispatcher — schedules and re-assigns visits, marks call-outs,
#              edits tech schedules + on-call. Cannot manage staff,
#              cannot touch invoices, cannot view payroll.
# warehouse_supervisor — runs the warehouse floor: onboards warehouse
#              staff, approves count variances, manages assets, but
#              has no field-tech or admin powers.
ADMIN_PERMS["dispatcher"] = {
    "tech:view",
    "customer:view",
    "visit:view", "visit:create", "visit:update",
    "schedule:view", "schedule:edit",
    "tech:manage_schedule", "tech:approve_overtime",
    "audit:view_self",
    "documents:view",
    "kpi:view_team", "kpi:flag_view",
    "company:read_messages",
}
ADMIN_PERMS["warehouse_supervisor"] = {
    "tech:view",                     # roster context only
    "warehouse:view_queue", "warehouse:manage_assets",
    "inventory:view", "inventory:create", "inventory:update", "inventory:adjust",
    "po:create", "po:send", "po:receive", "po:close_out",
    "count:create", "count:approve",
    "fs:asset_manage", "fs:report_view",
    "audit:view_self",
    "documents:view",
    "company:read_messages",
}

# ── R6: 50+ staff scale — future-proofing org roles ─────────────────────────
# Added ahead of need so the seats exist in the dropdown the moment the
# operator hires for them. Each role is dormant until someone is onboarded
# into it. Scoped tightly: no role here can delete admins, change roles, or
# approve payroll — those stay super_admin-only (with HR generating payroll).
#
# operations_manager — COO/GM tier. Broad operational oversight just below
#     the CEO: manages staff (not delete/role-change), full ops on visits,
#     inventory, invoices, POs; views payroll but cannot approve it.
ADMIN_PERMS["operations_manager"] = {
    "admin:view_all", "admin:update", "admin:set_active",
    "tech:view", "tech:create", "tech:update", "tech:reset_pin", "tech:export",
    "tech:approve_overtime", "tech:manage_schedule", "tech:manage_certifications",
    "tech:release_kpi_period",
    "customer:view", "customer:create", "customer:update", "customer:export",
    "visit:view", "visit:create", "visit:update", "visit:export",
    "visit:view_photos", "visit:flag",
    "review:view", "review:approve", "review:reject",
    "timesheet:view_all",
    "schedule:view", "schedule:edit",
    "inventory:view", "inventory:create", "inventory:update", "inventory:adjust",
    "inventory:export",
    "po:create", "po:send", "po:receive", "po:close_out", "po:approve_variance",
    "count:create", "count:approve",
    "invoice:view", "invoice:create", "invoice:update", "invoice:record_payment",
    "invoice:export",
    "payroll:view_all",              # view only — generate=HR, approve=CEO
    "security:view_alerts",
    "audit:view_all",
    "documents:upload", "documents:view", "documents:view_highly_sensitive",
    "fs:audit_any", "fs:exception_resolve", "fs:exception_escalate_director",
    "fs:asset_manage", "fs:report_view", "fs:coaching_manage",
    "kpi:view_team", "kpi:recompute", "kpi:view_definitions",
    "kpi:flag_view", "kpi:flag_resolve",
    "kpi:note_write_coaching", "kpi:note_write_recognition", "kpi:note_view",
    "kpi:goal_create", "kpi:goal_close", "kpi:goal_view",
    "company:post_message", "company:read_messages",
    "warehouse:view_queue", "warehouse:manage_assets",
}
# accountant — Finance / bookkeeping. Owns the invoice lifecycle and
#     generates payroll, but cannot approve/mark-paid payroll (separation of
#     duties — CEO approves). No staff management.
ADMIN_PERMS["accountant"] = {
    "customer:view",
    "visit:view",
    "invoice:view", "invoice:create", "invoice:update", "invoice:delete",
    "invoice:record_payment", "invoice:export",
    "inventory:view", "inventory:export",
    "payroll:generate", "payroll:view_all",
    "documents:upload", "documents:view", "documents:view_highly_sensitive",
    "audit:view_self",
    "company:read_messages",
}
# account_manager — Sales / commercial accounts. Owns the customer
#     relationship; read-only on money, no scheduling, no staff.
ADMIN_PERMS["account_manager"] = {
    "customer:view", "customer:create", "customer:update", "customer:export",
    "visit:view", "visit:export",
    "invoice:view",
    "documents:view",
    "audit:view_self",
    "company:read_messages",
}
# csr — Customer Service Rep / front desk. Books jobs and logs customers;
#     no tech-schedule editing, no OT approval, no money.
ADMIN_PERMS["csr"] = {
    "customer:view", "customer:create", "customer:update",
    "visit:view", "visit:create",
    "schedule:view",
    "documents:view",
    "audit:view_self",
    "company:read_messages",
}
# master_tech — Field supervisor (operator's name for the service-crew lead
#     who logs into the console). Reviews/flags work, approves OT, manages
#     tech schedules + certs, sees team KPI. No money, no inventory, no
#     onboarding.
ADMIN_PERMS["master_tech"] = {
    "tech:view", "tech:approve_overtime", "tech:manage_schedule",
    "tech:manage_certifications", "tech:release_kpi_period",
    "customer:view",
    "visit:view", "visit:create", "visit:update", "visit:view_photos", "visit:flag",
    "review:view",
    "schedule:view", "schedule:edit",
    "timesheet:view_all",
    "documents:view",
    "audit:view_self",
    "kpi:view_team", "kpi:flag_view",
    "kpi:note_write_coaching", "kpi:note_write_recognition", "kpi:note_view",
    "kpi:goal_view",
    "fs:audit_any", "fs:report_view",
    "company:read_messages",
}
# safety_officer — Safety & Compliance (EPA/OSHA, 5S program owner). Full 5S
#     authority + certification tracking + compliance docs. No money, no
#     hiring.
ADMIN_PERMS["safety_officer"] = {
    "tech:view", "tech:manage_certifications",
    "visit:view", "visit:view_photos", "visit:flag",
    "documents:upload", "documents:view", "documents:view_highly_sensitive",
    "fs:audit_any", "fs:exception_resolve", "fs:exception_escalate_director",
    "fs:asset_manage", "fs:report_view", "fs:audit_override", "fs:coaching_manage",
    "audit:view_self",
    "kpi:view_team", "kpi:flag_view",
    "company:read_messages", "company:post_message",
}
# quality_manager — QA over completed jobs. Owns the reviews queue and KPI
#     flags; no money, no staff, no scheduling.
ADMIN_PERMS["quality_manager"] = {
    "customer:view",
    "visit:view", "visit:view_photos", "visit:flag",
    "review:view", "review:approve", "review:reject", "review:delete",
    "kpi:view_team", "kpi:flag_view", "kpi:flag_resolve",
    "kpi:note_write_coaching", "kpi:note_view",
    "fs:report_view",
    "documents:view",
    "audit:view_self",
    "company:read_messages",
}
# marketing — Marketing / comms. Read-only ops visibility + can post to the
#     company message board.
ADMIN_PERMS["marketing"] = {
    "customer:view",
    "review:view",
    "documents:view",
    "company:post_message", "company:read_messages",
    "audit:view_self",
}


# ── Estimate / quote permissions (#3) ─────────────────────────────────────────
# Estimates are the pre-invoice step in the same sales → billing flow, so their
# permissions track the invoice permissions a role already holds. No role gains
# estimate powers it wouldn't reasonably have given its invoice scope:
#   invoice:view   → estimate:view
#   invoice:create → estimate:create, estimate:update, estimate:send, estimate:convert
#   invoice:delete → estimate:delete
for _erole, _eperms in ADMIN_PERMS.items():
    if "invoice:view" in _eperms:
        _eperms.add("estimate:view")
    if "invoice:create" in _eperms:
        _eperms.update({"estimate:create", "estimate:update",
                        "estimate:send", "estimate:convert"})
    if "invoice:delete" in _eperms:
        _eperms.add("estimate:delete")


def _admin_can(role: str, perm: str) -> bool:
    return perm in ADMIN_PERMS.get(role, set())

PHOTOS_DIR = Path(os.environ.get("PHOTOS_DIR", "uploads/photos"))
PHOTOS_DIR.mkdir(parents=True, exist_ok=True)
MAX_PHOTO_SIZE = 12 * 1024 * 1024  # 12 MB
ALLOWED_PHOTO_EXTS = {".jpg", ".jpeg", ".png", ".webp", ".heic"}
# Magic-byte prefixes for the simple image formats. webp/heic are container
# formats (RIFF/ISO-BMFF) sniffed separately below.
_PHOTO_MAGIC = {
    ".jpg":  [b"\xff\xd8\xff"],
    ".jpeg": [b"\xff\xd8\xff"],
    ".png":  [b"\x89PNG\r\n\x1a\n"],
}


def _photo_content_ok(ext: str, body: bytes) -> bool:
    """Returns True if `body` actually looks like the image type `ext` claims.
    Stops attackers from smuggling HTML/SVG/scripts behind a .jpg/.png name.
    webp = RIFF....WEBP; heic = ISO-BMFF 'ftyp' box with a heic-family brand."""
    if not body:
        return False
    if ext in _PHOTO_MAGIC:
        return any(body.startswith(p) for p in _PHOTO_MAGIC[ext])
    if ext == ".webp":
        return len(body) >= 12 and body[0:4] == b"RIFF" and body[8:12] == b"WEBP"
    if ext == ".heic":
        if len(body) < 12 or body[4:8] != b"ftyp":
            return False
        brand = body[8:12]
        return brand in (b"heic", b"heix", b"heim", b"heis", b"hevc",
                         b"hevx", b"mif1", b"msf1")
    return False


def _validate_photo_upload(filename: str, body: bytes) -> str:
    """Shared validation for visit/part/avatar photo uploads. Returns the
    lower-cased extension. Raises HTTPException on bad ext, size, or content
    that doesn't match the claimed image type."""
    ext = (Path(filename or "").suffix or "").lower()
    if ext not in ALLOWED_PHOTO_EXTS:
        raise HTTPException(400, f"Unsupported file type {ext or '(none)'}")
    if not body:
        raise HTTPException(400, "Empty file")
    if len(body) > MAX_PHOTO_SIZE:
        raise HTTPException(413, f"File too large (max {MAX_PHOTO_SIZE // (1024*1024)} MB)")
    if not _photo_content_ok(ext, body):
        raise HTTPException(400, f"File content does not match a {ext} image")
    return ext

# Profile-photo (avatar) settings — uploads are re-encoded via Pillow to a
# fixed-size JPEG. That gives us three things at once:
#   1) EXIF is stripped (privacy + any embedded location).
#   2) Any payload hidden in image metadata is destroyed by re-encode.
#   3) Output size is bounded, so signed URLs hit a small/cacheable file.
AVATAR_MAX_BYTES = 5 * 1024 * 1024  # 5 MB pre-resize
AVATAR_SIZE_PX   = 512
AVATAR_JPEG_QUALITY = 85

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


def _enforce_forgot_rate(request: Request, identity: str = ""):
    """Rate-limit the forgot-password / forgot-pin endpoints (IT-module #7).

    These endpoints send an email on every successful (code,email) match and
    are an enumeration + mail-bomb surface, so they were the most practical
    abuse path left open. Two layers, both per source IP:

      • per-identity  — 5 / hour, keyed on the supplied email/code, so one
                         victim can't be targeted with a flood of reset mails.
      • per-IP global — 20 / hour across all identities, so a single client
                         can't spray reset requests across many accounts to
                         enumerate which (code,email) pairs exist.

    The 200/ok response is unchanged (no enumeration leak); we just cap the
    rate. 429 is generic and identical regardless of whether the identity
    exists, preserving the no-enumeration contract."""
    msg = "Too many reset requests. Please wait a while and try again."
    _enforce_rate(request, bucket="forgot", identity=(identity or "").lower(),
                  max_attempts=5, window_seconds=3600, message=msg)
    _enforce_rate(request, bucket="forgot_ip", identity="",
                  max_attempts=20, window_seconds=3600, message=msg)


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
            # NIS is charged only on insurable earnings up to this annual
            # ceiling. Both employee (payslip) and employer (cost report) caps
            # read from this single value — verify with TAJ when it changes.
            "annual_insurable_ceiling": 1_500_000,
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


def _process_avatar(body: bytes) -> bytes:
    """Validate, center-crop-square, resize to AVATAR_SIZE_PX, re-encode as
    JPEG. Strips EXIF and any embedded payload via the re-encode. Raises
    HTTPException(400) on anything that doesn't decode as a real raster image.

    Pillow's verify() is called before we touch the pixels — it walks the
    container far enough to reject truncated / malformed files (including the
    classic 'PNG-looking gzip bomb' shape) without allocating the bitmap.
    Then we re-open (verify() leaves the file unusable for actual decoding)
    and do the cover-crop + resize."""
    from PIL import Image, UnidentifiedImageError  # local import: only loaded when an avatar is uploaded
    try:
        Image.open(io.BytesIO(body)).verify()
    except (UnidentifiedImageError, Exception):
        raise HTTPException(400, "Not a valid image file")
    try:
        img = Image.open(io.BytesIO(body))
        # Apply EXIF orientation BEFORE we discard EXIF, otherwise iPhone
        # portraits land sideways. ImageOps.exif_transpose is a no-op when
        # the file has no orientation tag.
        from PIL import ImageOps
        img = ImageOps.exif_transpose(img)
        # Cover-crop to a centred square so the avatar circle never shows
        # background fill.
        w, h = img.size
        side = min(w, h)
        left = (w - side) // 2
        top  = (h - side) // 2
        img = img.crop((left, top, left + side, top + side))
        img = img.resize((AVATAR_SIZE_PX, AVATAR_SIZE_PX), Image.LANCZOS)
        if img.mode in ("RGBA", "LA", "P"):
            # JPEG has no alpha — composite onto white so transparent PNGs
            # don't render as black blobs.
            bg = Image.new("RGB", img.size, (255, 255, 255))
            if img.mode == "P":
                img = img.convert("RGBA")
            bg.paste(img, mask=img.split()[-1] if img.mode in ("RGBA", "LA") else None)
            img = bg
        elif img.mode != "RGB":
            img = img.convert("RGB")
        buf = io.BytesIO()
        img.save(buf, format="JPEG", quality=AVATAR_JPEG_QUALITY, optimize=True)
        return buf.getvalue()
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(400, "Could not process image")


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


# ── Idempotency helpers (#4 offline replay) ─────────────────────────────────
# The field PWA attaches an `Idempotency-Key` header to every queued write so a
# reconnect-replay (or double-tap) can't create duplicates. Usage in an
# endpoint, AFTER the ownership/404 check but BEFORE state guards:
#     key, cached = _idem_begin(request, tech_id, "job.start")
#     if cached is not None:
#         return cached
#     ... do the mutation, build `result` ...
#     return _idem_finish(key, tech_id, "job.start", result)
def _idem_key_from(request: Request) -> Optional[str]:
    k = (request.headers.get("Idempotency-Key")
         or request.headers.get("X-Idempotency-Key") or "").strip()
    # Bound it and keep it to safe characters — it's a client UUID, not free text.
    if not k or len(k) > 200:
        return None
    return k


def _idem_begin(request: Request, subject_id: int, scope: str):
    """Returns (key_or_None, cached_response_or_None). A non-None cached value
    means this exact write already succeeded — return it unchanged."""
    key = _idem_key_from(request)
    if not key:
        return None, None
    hit = idempotency_lookup(key, subject_id)
    if hit is not None:
        return key, hit.get("response")
    return key, None


def _idem_finish(key: Optional[str], subject_id: int, scope: str, response):
    """Persist the response under the key (first writer wins). If another
    request stored first (race), return THEIR cached response so both callers
    agree. Keyless callers pass through unchanged."""
    if not key:
        return response
    stored = idempotency_store(key, subject_id, scope, response)
    if not stored:
        hit = idempotency_lookup(key, subject_id)
        if hit is not None and hit.get("response") is not None:
            return hit["response"]
    return response


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


# Background-loop starters register themselves into this list at module
# import time; lifespan() awaits each one after the synchronous startup
# work is done. Replaces the four @app.on_event("startup") decorators
# (deprecated by FastAPI in favor of lifespan) without forcing each
# loop's definition to move next to the lifespan handler. Audit L4,
# 2026-05-23.
_LIFESPAN_STARTERS: list = []


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
    # De-duped on a 24-hour window: every server restart re-runs this
    # sweep, but the fact "we have N dormant accounts" doesn't change
    # often enough to warrant a fresh alert per boot. Without this
    # guard, 50+ restarts/day during dev test runs filled the open
    # alert queue with 180+ duplicate "77 dormant accounts" rows.
    dormant_days = int(os.environ.get("DORMANT_DAYS", "90"))
    try:
        dormant = find_dormant_accounts(days=dormant_days)
        total = sum(len(v) for v in dormant.values())
        if total > 0:
            logger.warning(f"{total} dormant account(s) (>{dormant_days}d): "
                           f"{len(dormant['admin'])} admin, {len(dormant['tech'])} tech, "
                           f"{len(dormant['customer'])} customer")
            try:
                if not recent_alert_exists("dormant_accounts",
                                           actor_id=None,
                                           within_minutes=24 * 60):
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

    # Background loops — see _LIFESPAN_STARTERS doc above. Each starter
    # is fire-and-forget (it creates an asyncio.Task and returns); a
    # failure in one shouldn't stop the others.
    for _starter in _LIFESPAN_STARTERS:
        try:
            await _starter()
        except Exception as e:
            logger.warning(f"lifespan starter {_starter.__name__} failed: {e}")
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


def _require_viewer(request: Request) -> dict:
    """Resolve the current signed-in subject from ANY of the three session
    cookies (admin / tech / customer) and return {type, id}. Raises 401 when
    nobody is signed in. Used by surfaces that belong to every authenticated
    user regardless of kind — e.g. the notification centre — gated on identity
    only, never on a feature permission (per the 'features for all' rule)."""
    actor = _identify_actor_silent(request)
    if not actor:
        raise HTTPException(401, "Sign-in required")
    return {"type": actor["actor_type"], "id": actor["actor_id"]}


def _notify_pto_decision(req: dict, decision: str):
    """Best-effort in-app notification to the technician whose time-off
    request was just decided. Silent on any failure — the request row and
    audit entry remain the source of truth, so a notify error never blocks
    the decision."""
    try:
        if not req or not req.get("tech_id"):
            return
        approved = decision == "approved"
        kind_label = (req.get("kind") or "time-off").replace("_", " ")
        span = req.get("start_date") or ""
        if req.get("end_date") and req.get("end_date") != req.get("start_date"):
            span = f"{span} – {req.get('end_date')}"
        _notify(
            "tech", int(req["tech_id"]), "payroll",
            f"Time-off request {decision}",
            body=f"Your {kind_label} request"
                 + (f" for {span}" if span else "")
                 + f" was {decision} by your supervisor.",
            link="/tech", severity=("success" if approved else "warning"),
            dedupe_key=f"pto_decision:{req.get('id')}",
            dedupe_window_minutes=1440)
    except Exception as _e:
        logger.warning(f"[notif] pto decision notify failed: {_e}")


def _push_fanout(recipient_type: str, recipient_id: int, *, title: str,
                 body: str, link: str = None):
    """Best-effort web-push fan-out to every browser the recipient has
    subscribed. No-op when WEBPUSH_ENABLED is off (the in-app row already
    landed), so local dev never makes the external vendor-push POST. Dead
    endpoints (404/410) get a failure bump and are dropped after a few
    strikes. Never raises into the caller."""
    import webpush as _wp
    if not _wp.is_enabled():
        return
    from database import (list_push_subscriptions, mark_push_subscription_sent,
                          mark_push_subscription_failure)
    # Audience-correct icon (real PWA assets under /icons). No admin-specific
    # brand mark exists, so admin falls back to the generic customer icon.
    _icon = "/icons/tech-192.png" if recipient_type == "tech" else "/icons/customer-192.png"
    payload = _json.dumps({"title": title, "body": body or "", "link": link or "/",
                           "icon": _icon})
    for sub in list_push_subscriptions(recipient_type, int(recipient_id)):
        try:
            res = _wp.send(sub, payload)
            if res.get("sent"):
                mark_push_subscription_sent(sub["endpoint"])
            else:
                mark_push_subscription_failure(sub["endpoint"])
        except _wp.WebPushDisabled:
            return
        except Exception as _e:
            logger.warning(f"[push] send error for sub {sub.get('id')}: {_e}")


def _notify(recipient_type: str, recipient_id: int, kind: str, title: str, *,
            body: str = None, link: str = None, severity: str = "info",
            dedupe_key: str = None, dedupe_window_minutes: int = None):
    """Create the authoritative in-app notification row AND attempt a
    best-effort web-push to the recipient's browsers. The in-app feed is the
    source of truth; push is a convenience layer that is silently skipped
    when disabled or unsubscribed. Returns the notification id (or None)."""
    nid = None
    try:
        from database import create_notification
        nid = create_notification(recipient_type, int(recipient_id), kind, title,
                                  body=body, link=link, severity=severity,
                                  dedupe_key=dedupe_key,
                                  dedupe_window_minutes=dedupe_window_minutes)
    except Exception as _e:
        logger.warning(f"[notif] create failed: {_e}")
        return None
    try:
        _push_fanout(recipient_type, recipient_id, title=title,
                     body=body or "", link=link)
    except Exception as _e:
        logger.warning(f"[notif] push fanout failed: {_e}")
    return nid


# ── Low-stock alerting (#6) ──────────────────────────────────────────────────
# Inventory had a reorder_point and a passive dashboard counter but nothing
# proactively told anyone when stock crossed it. These helpers notify every
# admin who can see inventory, deduped per part for 24h, both in real time
# (right after a stock-decrementing write) and via a daily safety-net sweep.
def _admins_for_inventory_alerts() -> list:
    """Active admin ids whose role can view inventory — the audience for
    low-stock alerts. Best-effort; [] on any error."""
    try:
        from database import get_all_admin_users
        return [a["id"] for a in get_all_admin_users()
                if a.get("active") and _admin_can(a.get("role"), "inventory:view")]
    except Exception as _e:
        logger.warning(f"[lowstock] admin audience lookup failed: {_e}")
        return []


def _emit_low_stock_alert(part: dict, admin_ids: list):
    sku = part.get("sku") or f"#{part.get('id')}"
    qty = part.get("quantity")
    rp = part.get("reorder_point") or 0
    title = f"Low stock: {sku}"
    body = f"{part.get('name') or ''} is at {qty:g} (reorder point {rp:g}). Time to reorder."
    for aid in admin_ids:
        _notify("admin", aid, "inventory", title, body=body,
                link="/admin#inventory", severity="warning",
                dedupe_key=f"lowstock:{part.get('id')}", dedupe_window_minutes=1440)


def _check_low_stock(part_id: int):
    """If a part is at/below its reorder point, alert inventory admins. Never
    raises — a stock write must not fail because alerting hiccupped."""
    try:
        part = get_part_by_id(part_id)
        if not part or not part.get("active"):
            return
        rp = part.get("reorder_point") or 0
        qty = part.get("quantity")
        if rp <= 0 or qty is None or qty > rp:
            return
        _emit_low_stock_alert(part, _admins_for_inventory_alerts())
    except Exception as _e:
        logger.warning(f"[lowstock] check failed for part {part_id}: {_e}")


# ── Appointment reminders (#5) ───────────────────────────────────────────────
# Scheduled visits existed but customers got no heads-up before one. These
# helpers remind the billed customer (in-app + push + best-effort email) at
# fixed lead times before a still-scheduled visit, deduped per (visit, lead)
# so each wave fires at most once even though the sweep runs several times/day.
def _appt_when_label(visit: dict) -> str:
    date = (visit.get("scheduled_date") or "").strip()
    time = (visit.get("scheduled_time") or "").strip()
    return date + (f" at {time}" if time else "")


def _appt_lead_label(lead_days: int) -> str:
    if lead_days <= 0:
        return "today"
    if lead_days == 1:
        return "tomorrow"
    return f"in {lead_days} days"


def _send_appointment_reminder_email(customer: dict, visit: dict, lead_label: str) -> None:
    """Best-effort email reminder of an upcoming visit. No-op without
    RESEND_API_KEY (the local default) or a customer email. Never raises —
    the in-app notification is the source of truth."""
    api_key = os.environ.get("RESEND_API_KEY")
    to_addr = (customer or {}).get("email")
    if not (api_key and to_addr):
        return
    try:
        resend_lib.api_key = api_key
        vt = "maintenance" if (visit.get("visit_type") == "PM") else "service"
        when = _appt_when_label(visit)
        subject = f"Reminder: PrimeCool {vt} visit {lead_label}"
        tech_line = (f"<p style='margin:4px 0'><strong>Technician:</strong> "
                     f"{visit.get('technician')}</p>") if visit.get("technician") else ""
        html = (
            f"<h2 style='color:#0B2545'>Upcoming {vt} visit</h2>"
            f"<p>Hello {(customer or {}).get('name') or 'there'},</p>"
            f"<p>This is a friendly reminder that PrimeCool Services has a "
            f"<strong>{vt} visit</strong> scheduled for <strong>{when}</strong>.</p>"
            f"{tech_line}"
            f"<p>Need to reschedule? Reply to this email or call us and we'll "
            f"find a better time.</p>"
            f"<p style='color:#6b7280;font-size:12px'>PrimeCool Services</p>"
        )
        resend_lib.Emails.send({
            "from":    "PrimeCool Services <onboarding@resend.dev>",
            "to":      to_addr,
            "subject": subject,
            "html":    html,
        })
    except Exception as e:
        logger.warning(f"[apptreminder] email failed for visit {visit.get('id')}: {e}")


def _emit_appointment_reminder(visit: dict, lead_days: int) -> None:
    """In-app + push + best-effort email reminder for one upcoming visit,
    deduped per (visit, lead) so the same wave never double-fires."""
    cust_id = visit.get("customer_id")
    if not cust_id:
        return
    lead_label = _appt_lead_label(lead_days)
    vt = "maintenance" if (visit.get("visit_type") == "PM") else "service"
    title = f"Upcoming {vt} visit {lead_label}"
    body = f"Your PrimeCool {vt} visit is scheduled for {_appt_when_label(visit)}."
    _notify("customer", int(cust_id), "visit", title, body=body,
            link="/portal", severity="info",
            dedupe_key=f"apptreminder:{visit.get('id')}:{lead_days}d",
            dedupe_window_minutes=14 * 24 * 60)
    try:
        cust = get_customer_by_id(int(cust_id))
        _send_appointment_reminder_email(cust, visit, lead_label)
    except Exception as _e:
        logger.warning(f"[apptreminder] customer lookup failed for visit "
                       f"{visit.get('id')}: {_e}")


def _send_invoice_email(customer: dict, inv: dict) -> None:
    """Best-effort email delivery of a sent invoice. No-op without
    RESEND_API_KEY (the local default) or a customer email. Never raises —
    the status transition + in-app notification are the source of truth, so
    a mail hiccup must not fail the send."""
    api_key = os.environ.get("RESEND_API_KEY")
    to_addr = (customer or {}).get("email")
    if not (api_key and to_addr):
        return
    try:
        resend_lib.api_key = api_key
        cur = (inv.get("currency") or "USD").upper()
        try:
            total = float(inv.get("total") or 0)
            paid = float(inv.get("amount_paid") or 0)
        except (TypeError, ValueError):
            total, paid = 0.0, 0.0
        balance = total - paid
        due = inv.get("due_date") or ""
        due_line = (f"<p style='margin:4px 0'><strong>Due:</strong> {due}</p>"
                    if due else "")
        subject = f"Invoice {inv.get('invoice_number')} from PrimeCool Services"
        html = (
            f"<h2 style='color:#0B2545'>Invoice {inv.get('invoice_number')}</h2>"
            f"<p>Hello {(customer or {}).get('name') or 'there'},</p>"
            f"<p>A new invoice has been issued to your account.</p>"
            f"<p style='margin:4px 0'><strong>Total:</strong> {cur} {total:,.2f}</p>"
            f"<p style='margin:4px 0'><strong>Balance due:</strong> {cur} {balance:,.2f}</p>"
            f"{due_line}"
            f"<p>Sign in to your customer portal to review the full invoice"
            f" and payment options.</p>"
            f"<p style='color:#6b7280;font-size:12px'>PrimeCool Services</p>"
        )
        resend_lib.Emails.send({
            "from":    "PrimeCool Services <onboarding@resend.dev>",
            "to":      to_addr,
            "subject": subject,
            "html":    html,
        })
    except Exception as e:
        logger.warning(f"[invoice] email failed for invoice {inv.get('id')}: {e}")


def _send_estimate_email(customer: dict, est: dict) -> None:
    """Best-effort email delivery of a sent estimate. No-op without
    RESEND_API_KEY (local default) or a customer email. Never raises."""
    api_key = os.environ.get("RESEND_API_KEY")
    to_addr = (customer or {}).get("email")
    if not (api_key and to_addr) or not est:
        return
    try:
        resend_lib.api_key = api_key
        cur = (est.get("currency") or "USD").upper()
        try:
            total = float(est.get("total") or 0)
        except (TypeError, ValueError):
            total = 0.0
        valid = est.get("valid_until") or ""
        valid_line = (f"<p style='margin:4px 0'><strong>Valid until:</strong> {valid}</p>"
                      if valid else "")
        subject = f"Estimate {est.get('estimate_number')} from PrimeCool Services"
        html = (
            f"<h2 style='color:#0B2545'>Estimate {est.get('estimate_number')}</h2>"
            f"<p>Hello {(customer or {}).get('name') or 'there'},</p>"
            f"<p>We've prepared an estimate for your review.</p>"
            f"<p style='margin:4px 0'><strong>Estimated total:</strong> {cur} {total:,.2f}</p>"
            f"{valid_line}"
            f"<p>Sign in to your customer portal to review the line items and"
            f" <strong>approve or decline</strong> this estimate.</p>"
            f"<p style='color:#6b7280;font-size:12px'>PrimeCool Services</p>"
        )
        resend_lib.Emails.send({
            "from":    "PrimeCool Services <onboarding@resend.dev>",
            "to":      to_addr,
            "subject": subject,
            "html":    html,
        })
    except Exception as e:
        logger.warning(f"[estimate] email failed for estimate {est.get('id')}: {e}")


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
    """Cache policy for two response classes browsers must not stale-serve.

    1. /api/* — never cache. Without this, the back button can replay a
       previous user's data on a shared device after they sign out (Scenario 7).

    2. HTML documents (the SPA shells: admin.html, staff_home.html, portal_*,
       tech.html, …) — must revalidate on every load. These go out via
       FileResponse, which sets only ETag/Last-Modified and NO Cache-Control,
       so browsers apply *heuristic freshness* and serve a stale shell for a
       while without checking back. The inline JS lives inside these HTML files
       (only pc_shared.js carries a ?v= cache-buster), so a stale shell means a
       stale app — which is why edits used to need a hard reload. "no-cache"
       forces revalidation: the server returns a cheap 304 when unchanged and
       the fresh document the moment it changes, so a plain reload is enough.
       Static assets (JS/CSS/images — all ?v=-busted, none text/html) stay
       cacheable and are untouched here.
    """
    response = await call_next(request)
    if request.url.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
        response.headers["Pragma"] = "no-cache"
    elif response.headers.get("content-type", "").startswith("text/html"):
        response.headers["Cache-Control"] = "no-cache, must-revalidate, private"
        response.headers["Pragma"] = "no-cache"

    # ── Security headers (defense-in-depth) ──────────────────────────────
    # Applied to every response. These are cheap and don't change behaviour:
    #   • nosniff   — stop MIME-sniffing an upload/response into something
    #                 executable.
    #   • frame     — the app is never framed (no <iframe> usage), so deny
    #                 framing outright to kill clickjacking.
    #   • referrer  — never leak full URLs (which carry ids) to third parties.
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")

    # HSTS only over real HTTPS — never on local/LAN http dev, where it would
    # pin the browser to https for the dev host.
    if request.url.scheme == "https":
        response.headers.setdefault(
            "Strict-Transport-Security",
            "max-age=31536000; includeSubDomains")

    # Full CSP only on the HTML shells. Inline scripts + inline event handlers
    # are used throughout, so script/style must allow 'unsafe-inline'; there are
    # no external scripts and no eval, so we keep it as tight as the app allows.
    # frame-ancestors 'none' is the modern clickjacking guard (pairs with XFO).
    # Google Fonts (style+font), data:/blob: images, and same-origin everything
    # else cover the app's actual needs.
    if response.headers.get("content-type", "").startswith("text/html"):
        response.headers.setdefault("Content-Security-Policy", (
            "default-src 'self'; "
            "base-uri 'self'; "
            "object-src 'none'; "
            "frame-ancestors 'none'; "
            "form-action 'self'; "
            "img-src 'self' data: blob:; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com; "
            "connect-src 'self'"
        ))
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

# CORS — closes audit finding M4 (GAP-CORS).
#
# Dev (PROD_MODE=false): permissive — file://, localhost:*, dev
# tooling, fetch-from-anywhere is fine and developers expect it.
#
# Prod (PROD_MODE=true): the only origins that may exchange cookies
# or read responses are the ones explicitly listed in CORS_ALLOW_ORIGINS
# (comma-separated, e.g. "https://app.primecool.example.jm,
# https://portal.primecool.example.jm"). Falls back to ["null"] (no
# valid origin) if nothing is set, which fails closed.
#
# CSRF middleware (csrf_origin_check) is the second line of defense
# for mutating requests; this is the first line.
_cors_origins_env = os.environ.get("CORS_ALLOW_ORIGINS", "").strip()
if PROD_MODE:
    _cors_origins = [o.strip() for o in _cors_origins_env.split(",") if o.strip()] or ["null"]
    _cors_allow_credentials = True
else:
    _cors_origins = ["*"]
    _cors_allow_credentials = False  # CORS spec: cannot combine '*' with credentials
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=_cors_allow_credentials,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
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


class PortalSetInitialPin(BaseModel):
    """First-login forced PIN set (must_set_pin gate). Authenticated by the
    portal session cookie — no reset token, the customer is already signed in."""
    pin:         str
    confirm_pin: str


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


class AdminChangeOwnPassword(BaseModel):
    # Self-service password change from the My Profile panel.
    # Requires the current password so a hijacked session can't pivot
    # to permanent account takeover without it.
    current_password: str
    new_password:     str
    confirm_password: str


class TechChangeOwnPin(BaseModel):
    # Self-service PIN change from the tech portal. Mirrors
    # AdminChangeOwnPassword — requires the current PIN as re-auth so a
    # stolen session alone can't permanently take over the account.
    # Also the endpoint that clears must_change_credentials for a tech
    # flagged for a first-login forced reset (pre-launch checklist #2).
    current_pin: str
    new_pin:     str
    confirm_pin: str


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
    must_set_pin:  bool = False          # force the customer to choose their own PIN at first login


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


class EquipmentUpdate(BaseModel):
    """PATCH body — every field optional so the client can send only what
    changed. The DB helper update_equipment ignores any keys it doesn't
    recognise, and customer_id is intentionally NOT editable here (re-
    parenting equipment between customers is a separate, riskier action)."""
    name:          Optional[str] = None
    type:          Optional[str] = None
    model:         Optional[str] = None
    serial_number: Optional[str] = None
    location:      Optional[str] = None
    notes:         Optional[str] = None


class PMContractCreate(BaseModel):
    customer_id:    int
    equipment_id:   Optional[int] = None
    title:          str = ""
    start_date:     str
    end_date:       str
    frequency:      str
    contract_value: float = 0
    notes:          str = ""
    hub_id:         Optional[int] = None


class PMContractUpdate(BaseModel):
    """PATCH body — every field optional. customer_id is intentionally not
    editable (re-parenting a contract is a separate, riskier action)."""
    title:          Optional[str] = None
    start_date:     Optional[str] = None
    end_date:       Optional[str] = None
    frequency:      Optional[str] = None
    contract_value: Optional[float] = None
    status:         Optional[str] = None
    notes:          Optional[str] = None
    equipment_id:   Optional[int] = None


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
    # Multi-tech crew (extras beyond the lead in assigned_tech_id). Empty list
    # = no extras. The lead is filtered out of this list server-side if it
    # accidentally sneaks in.
    crew_tech_ids:    List[int] = []


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
    # None = "don't touch the crew"; [] = "replace crew with empty list".
    # This split lets the existing edit modal (which doesn't yet send a
    # crew array) keep working without wiping prior assignments.
    crew_tech_ids:    Optional[List[int]] = None


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
    # W1+W2: unified staff entity. staff_type controls per-role asset
    # provisioning (vehicle/truck/PPE locker) in create_tech.
    staff_type:  Optional[str] = "tech"   # see VALID_STAFF_TYPES
    department:  Optional[str] = None     # defaults per staff_type


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
    # Client-supplied UUID per "Record Payment" click. If two requests
    # arrive with the same (invoice_id, idempotency_key), the second
    # silently returns the first payment's id without inserting a
    # duplicate. Optional — omit for legacy / scripted callers.
    # Audit M3, 2026-05-23.
    idempotency_key: Optional[str] = None


# ── Estimate / quote models (#3) ──────────────────────────────────────────────
class EstimateLineItem(BaseModel):
    line_type:   str = "other"   # 'labor' | 'part' | 'other'
    part_id:     Optional[int] = None
    description: str
    quantity:    float = 1
    unit_price:  float = 0


class EstimateCreate(BaseModel):
    customer_id: int
    visit_id:    Optional[int] = None
    issue_date:  str
    valid_until: Optional[str] = None
    tax_rate:    float = INVOICE_TAX_RATE
    currency:    str = "JMD"
    notes:       str = ""
    line_items:  List[EstimateLineItem] = []


class EstimateUpdate(BaseModel):
    customer_id: int
    visit_id:    Optional[int] = None
    issue_date:  str
    valid_until: Optional[str] = None
    tax_rate:    float = INVOICE_TAX_RATE
    currency:    str = "JMD"
    notes:       str = ""
    line_items:  List[EstimateLineItem] = []


class EstimateDecline(BaseModel):
    reason: str = ""


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
@app.get("/api/health")
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

    # Operator policy (2026-05-25): MFA is OPTIONAL on the customer
    # portal. Previously every customer was force-marched into TOTP
    # enrolment at first sign-in (pre-launch security review). Operator
    # rolled that back because customers couldn't sign in and the
    # tightened PIN floor + lockout is sufficient defence-in-depth at
    # the customer tier. The staff portals (/staff) still hard-require
    # MFA; only the customer-facing /portal flow is relaxed here.
    #
    # If a customer has *already* enrolled MFA via the self-serve
    # security panel, we still demand the TOTP code on every sign-in —
    # so opting in is honoured even though it's not forced.
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
            "mfa_enabled":   bool(customer.get("mfa_enabled")),
            # First-login gate: when true the portal forces a set-your-own-PIN
            # step (so the seeded "1000 + id" PIN never sticks on a real
            # account). Only meaningful for PIN-auth customers.
            "must_set_pin":  bool(customer.get("must_set_pin"))
                             and customer.get("auth_mode", "pin") != "password"}


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
    return {"token": token, "name": cust["name"],
            "must_set_pin": bool(cust.get("must_set_pin"))
                            and cust.get("auth_mode", "pin") != "password"}


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
    _enforce_forgot_rate(request, body.email or body.code)
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
    customer_id = consume_customer_pin_reset(body.token)
    if not customer_id:
        raise HTTPException(400, "Reset link is invalid or has expired")
    # Token proved ownership; load the customer row for the phone-as-PIN
    # check. Same shape as the tech reset path.
    cust = get_customer_by_id(customer_id) or {}
    _validate_pin_or_400(
        body.pin, phone_on_file=cust.get("phone"),
        actor_type="customer", actor_id=customer_id,
        label=cust.get("customer_code") or f"customer#{customer_id}",
    )
    set_customer_pin(customer_id, body.pin)
    reset_pin_failures(customer_id)
    return {"ok": True}


@app.post("/api/portal/set-pin")
def portal_set_initial_pin(body: PortalSetInitialPin, request: Request):
    """First-login forced PIN set. Driven by the `must_set_pin` gate surfaced
    on the login response: the portal redirects the just-signed-in customer
    here to replace the seeded PIN with one of their own. Authenticated by the
    session cookie (the customer proved the seeded PIN to get here), so no
    reset token is needed. Also usable as a general logged-in PIN change."""
    customer_id = _require_customer(request)
    cust = get_customer_by_id(customer_id)
    if not cust:
        raise HTTPException(404, "Customer not found")
    if cust.get("auth_mode") == "password":
        # Password-auth accounts don't have a PIN to set; use /api/portal/password.
        raise HTTPException(400, "This account uses password sign-in")
    if body.pin != body.confirm_pin:
        raise HTTPException(400, "PINs do not match")
    _validate_pin_or_400(
        body.pin, phone_on_file=cust.get("phone"),
        actor_type="customer", actor_id=customer_id,
        label=cust.get("customer_code") or f"customer#{customer_id}",
    )
    set_customer_pin(customer_id, body.pin)   # also clears must_set_pin
    reset_pin_failures(customer_id)
    _audit_customer(cust, "portal.pin_set_initial", request)
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


# ── Unified staff portal — single entry for admin / tech / warehouse ─────────
# Customers keep their separate portal at /portal (customer = consumer of
# the service, not staff). "Welcome to PrimeCool — where you are everything"
# is the welcome line for staff. This façade is a stepping-stone toward the
# β migration to a single `staff` table; for now it tries admin first then
# tech, and returns enough info for the unified portal to route the user.

class StaffLoginRequest(BaseModel):
    identifier: str   # admin username OR tech_code
    secret:     str   # admin password OR tech PIN
    mfa_code:   Optional[str] = None  # currently unused at this layer;
                                       # MFA verify uses the kind-specific
                                       # /api/admin/mfa/verify or
                                       # /api/tech/login/mfa endpoints


def _staff_lock_guard(kind: str, row: dict, request: Request, identity: str):
    """IT-module #9 — per-account login lockout for staff (admin + tech),
    independent of source IP. Checked BEFORE password/PIN verification so a
    locked account can't be probed with valid credentials inside the window.
    Raises a generic 401 (no enumeration) if the account is currently locked."""
    if not row:
        return
    checker = is_admin_login_locked if kind == "admin" else is_tech_login_locked
    locked, locked_until = checker(row["id"])
    if locked:
        _audit_anon("auth.login_failed", request, attempted_identity=identity,
                    actor_type=kind, target_label=f"account locked until {locked_until}")
        raise HTTPException(401, "Invalid credentials")


def _staff_record_login_failure(kind: str, row: dict, request: Request, identity: str):
    """Record one failed staff login. At the threshold this flips the account
    into a 30-min lock and raises a high-severity security alert (bursts across
    accounts from rotating IPs are the credential-spray signature this catches
    where the per-IP rate limit alone can't)."""
    if not row:
        return
    recorder = record_admin_login_failure if kind == "admin" else record_tech_login_failure
    res = recorder(row["id"])
    if res.get("locked"):
        try:
            create_security_alert(
                kind="account_lockout", severity="high",
                summary=f"{kind.title()} {identity} locked after {res['failed']} failed sign-in attempts",
                actor_type=kind, actor_id=row["id"],
                details={"locked_until": res["locked_until"], "ip": _client_ip(request)},
            )
        except Exception:
            pass


@app.post("/api/staff/login")
def staff_login(req: StaffLoginRequest, request: Request, response: Response):
    """Unified staff login. Tries the admin identity space first, then
    the tech space. Returns one of:

      {"kind": "admin", "token": "...", "redirect_to": "/home",
       "name": "...", ...}                   — issued session

      {"kind": "admin", "requires_mfa": True,
       "mfa_token": "...", "redirect_to": "/home", ...}
       (caller submits TOTP to /api/admin/mfa/verify)

      {"kind": "admin", "requires_mfa_setup": True,
       "mfa_enrol_token": "...", "redirect_to": "/home", ...}
       (caller submits to /api/admin/mfa/setup + /activate)

      Same shapes for "tech" with redirect_to="/tech/home" and
      MFA endpoints /api/tech/mfa/* + /api/tech/login/mfa.

    On a credential miss in BOTH spaces, returns 401. The error
    message is intentionally generic so an attacker can't enumerate
    which identifier space exists.

    The actual session cookie / response shape mirrors the underlying
    kind-specific login endpoint so the existing admin / tech UIs
    can use whatever path the unified portal forwards them to."""
    identifier = (req.identifier or "").strip()
    secret     = req.secret or ""
    if not identifier or not secret:
        raise HTTPException(400, "identifier and secret are required")
    _enforce_login_rate(request, f"staff:{identifier}")

    # IT-module #9 — resolve the candidate rows up front so we can (a) refuse a
    # locked account before verifying, and (b) record a failure against the
    # right account on a credential miss. Lookups are generic; the response
    # stays identical whether or not the identifier exists (no enumeration).
    admin_row = get_admin_user_by_username(identifier)
    tech_row  = get_tech_by_code(identifier)
    _staff_lock_guard("admin", admin_row, request, identifier)
    _staff_lock_guard("tech", tech_row, request, identifier)

    # Identifier-collision detection: this login resolves the admin space
    # FIRST, so if the SAME identifier matches both an admin and a tech the
    # tech is silently shadowed (they can never reach the portal). The
    # creation-time guard (staff_identifier_conflict) prevents NEW
    # collisions; this surfaces any pre-existing one as a security alert so
    # ops can rename one of the accounts. Non-fatal — login still proceeds
    # (admin-first) so we don't lock out the admin half of the pair.
    if admin_row and tech_row:
        try:
            # De-dup: the alert is a standing "rename one of these" signal, not
            # a per-attempt event. Without this it would fire on every colliding
            # login. recent_alert_exists keys on (kind, actor_id) within 30 min.
            if not recent_alert_exists("staff_identifier_collision",
                                       admin_row["id"], within_minutes=30):
                create_security_alert(
                    kind="staff_identifier_collision", severity="medium",
                    summary=(f"Identifier '{identifier}' matches BOTH admin "
                             f"#{admin_row['id']} and tech #{tech_row['id']} — "
                             f"the tech is shadowed on /staff login. Rename one."),
                    actor_type="staff_unified", actor_id=admin_row["id"],
                    details={"identifier": identifier,
                             "admin_id": admin_row["id"],
                             "tech_id": tech_row["id"]},
                )
        except Exception as _e:
            logger.debug(f"collision alert write failed: {_e}")

    # Try admin first — admins use username + password, generally
    # alphanumeric. verify_admin_user is constant-time on miss.
    admin = verify_admin_user(identifier, secret)
    if admin and admin.get("active"):
        reset_admin_login_failures(admin["id"])
        # Mirror admin_login's response shape; same gates.
        if not admin.get("mfa_enabled"):
            enrol_token = _make_token(
                {"sub": str(admin["id"]), "type": "admin_mfa_enrol"},
                MFA_TOKEN_TTL,
            )
            _audit_from(admin, "admin.login.password_ok_mfa_enrol_required",
                        request)
            return {"kind": "admin", "name": admin["name"],
                    "redirect_to": "/home",
                    "requires_mfa_setup": True,
                    "mfa_enrol_token": enrol_token}
        # Already enrolled — pre-MFA verify step.
        mfa_token = _make_token(
            {"sub": str(admin["id"]), "type": "admin_pre_mfa"},
            MFA_TOKEN_TTL,
        )
        _audit_from(admin, "admin.login.password_ok", request)
        return {"kind": "admin", "name": admin["name"],
                "redirect_to": "/home",
                "requires_mfa": True,
                "mfa_token": mfa_token}

    # Admin identifier matched but password was wrong — count it against the
    # admin account (may trip the lockout).
    if admin_row and admin is None:
        _staff_record_login_failure("admin", admin_row, request, identifier)

    # Try tech — uses tech_code (case-folded) + numeric PIN.
    tech = verify_tech(identifier, secret)
    if tech and tech.get("active"):
        reset_tech_login_failures(tech["id"])
        if not tech.get("mfa_enabled"):
            enrol_token = _make_token(
                {"sub": str(tech["id"]), "type": "tech_mfa_enrol"},
                MFA_TOKEN_TTL,
            )
            return {"kind": "tech", "name": tech["name"],
                    "tech_code": tech["tech_code"],
                    "redirect_to": "/home",
                    "requires_mfa_setup": True,
                    "mfa_enrol_token": enrol_token}
        mfa_token = _make_token(
            {"sub": str(tech["id"]), "type": "tech_pre_mfa"},
            MFA_TOKEN_TTL,
        )
        return {"kind": "tech", "name": tech["name"],
                "tech_code": tech["tech_code"],
                "redirect_to": "/home",
                "requires_mfa": True,
                "mfa_token": mfa_token}

    # Tech identifier matched but PIN was wrong — count it against the tech.
    if tech_row and tech is None:
        _staff_record_login_failure("tech", tech_row, request, identifier)

    # Neither space matched — generic error.
    _audit_anon("auth.login_failed", request,
                attempted_identity=identifier,
                actor_type="staff_unified",
                target_label="invalid identifier or secret")
    raise HTTPException(401, "Invalid credentials")


@app.get("/staff")
def staff_portal_page():
    """Serves the unified PrimeCool staff portal."""
    return FileResponse("staff_portal.html")


# ── Tech routes ───────────────────────────────────────────────────────────────

@app.post("/api/tech/login")
def tech_login(req: TechLogin, request: Request, response: Response):
    """Tech portal login.

    Three response shapes:

    1. Forced MFA enrolment (must_enrol_mfa=1, mfa_enabled=0):
       {requires_mfa_setup: true, mfa_enrol_token: "<jwt>", name}
       No session cookie. Client takes the enrol_token to
       /api/tech/mfa/setup → /api/tech/mfa/activate. activate_tech_mfa
       clears must_enrol_mfa so the next login proceeds.

    2. MFA verification (mfa_enabled=1, no mfa_code in body):
       {requires_mfa: true, mfa_token: "<jwt>", name}
       No session. Client POSTs the mfa_token + the user's TOTP code
       to /api/tech/login/mfa to complete the login.

    3. Issued session: original shape with the 7d session token,
       must_change_credentials flag (forced PIN reset, item #2)."""
    _enforce_login_rate(request, req.tech_code)
    # IT-module #9 — per-account lockout (independent of IP).
    tech_row = get_tech_by_code(req.tech_code)
    _staff_lock_guard("tech", tech_row, request, req.tech_code)
    tech = verify_tech(req.tech_code, req.pin)
    if not tech:
        _staff_record_login_failure("tech", tech_row, request, req.tech_code)
        _audit_anon("auth.login_failed", request,
                    attempted_identity=req.tech_code,
                    actor_type="tech",
                    target_label="invalid PRID or PIN")
        raise HTTPException(401, "Invalid tech code or PIN")
    reset_tech_login_failures(tech["id"])

    # Gate 1 — MFA enrolment HARD-REQUIRED (May 2026 operator
    # directive: everyone who logs in needs MFA). must_enrol_mfa is
    # kept as ops-tracking signal but no longer gates the check.
    if not tech.get("mfa_enabled"):
        enrol_token = _make_token(
            {"sub": str(tech["id"]), "type": "tech_mfa_enrol"},
            MFA_TOKEN_TTL,
        )
        return {"requires_mfa_setup": True,
                "mfa_enrol_token": enrol_token,
                "name": tech["name"]}

    # Gate 2 — already enrolled, need TOTP step.
    if tech.get("mfa_enabled"):
        mfa_token = _make_token(
            {"sub": str(tech["id"]), "type": "tech_pre_mfa"},
            MFA_TOKEN_TTL,
        )
        return {"requires_mfa": True,
                "mfa_token": mfa_token,
                "name": tech["name"]}

    # No MFA required — issue session as before.
    token, _ = _issue_session("tech", tech["id"], timedelta(days=7), request)
    _set_session_cookie(response, COOKIE_TECH, token, 7 * 24 * 3600)
    bump_last_login("tech", tech["id"])
    return {
        "token":     token,
        "name":      tech["name"],
        "tech_code": tech["tech_code"],
        "must_change_credentials": bool(tech.get("must_change_credentials")),
    }


@app.post("/api/tech/login/mfa")
def tech_login_mfa(body: dict, request: Request, response: Response):
    """Step 2 of two-step tech login. Verifies the TOTP (or backup
    code) and issues the session cookie. Body: {mfa_token, code}."""
    mfa_token = (body or {}).get("mfa_token") or ""
    code      = ((body or {}).get("code") or "").strip()
    if not mfa_token or not code:
        raise HTTPException(400, "mfa_token and code required")
    try:
        data = jwt.decode(mfa_token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(401, "MFA window expired — please sign in again")
    except jwt.InvalidTokenError:
        raise HTTPException(401, "Invalid MFA token")
    if data.get("type") != "tech_pre_mfa":
        raise HTTPException(403, "Forbidden")
    _enforce_login_rate(request, f"techmfa:{data.get('sub','')}")
    tech_id = int(data["sub"])
    tech = get_tech_by_id(tech_id)
    if not tech or not tech.get("active") or not tech.get("mfa_enabled"):
        raise HTTPException(401, "MFA not configured")
    if not _verify_tech_totp_or_backup(tech, code):
        _audit_anon("auth.mfa_failed", request,
                    attempted_identity=tech.get("tech_code", str(tech_id)),
                    actor_type="tech")
        raise HTTPException(401, "Incorrect code")
    token, _ = _issue_session("tech", tech["id"], timedelta(days=7), request)
    _set_session_cookie(response, COOKIE_TECH, token, 7 * 24 * 3600)
    bump_last_login("tech", tech["id"])
    return {
        "token":     token,
        "name":      tech["name"],
        "tech_code": tech["tech_code"],
        "must_change_credentials": bool(tech.get("must_change_credentials")),
    }


def _verify_tech_totp_or_backup(tech: dict, code: str) -> bool:
    """True if `code` is a valid current TOTP for the tech's secret OR
    matches an unused backup code (which is then marked used).
    Mirrors _verify_admin_totp_or_backup."""
    if not tech.get("mfa_secret"):
        return False
    code = (code or "").strip()
    if pyotp.TOTP(tech["mfa_secret"]).verify(code, valid_window=1):
        return True
    if consume_tech_backup_code(tech["id"], code):
        return True
    return False


def _resolve_tech_enrolment_actor(request: Request) -> dict:
    """The MFA enrol endpoints accept either a full tech session token
    OR the short-lived tech_mfa_enrol token from tech_login(). Returns
    the technician row. Raises HTTPException on bad/expired token.

    BUG FIX (2026-05-25): the Bearer header is checked FIRST, the
    pc_tech_session cookie second. Previously the cookie won
    unconditionally — so a stale cookie from a deleted-then-recreated
    tech would override the fresh mfa_enrol_token in the Authorization
    header and surface as 'Account inactive' (because the deleted
    tech id no longer existed in the technicians table). The enrol
    flow's contract is "Bearer the short-lived enrol token"; this
    matches that contract and falls back to the cookie only when no
    Bearer is supplied (a tech who's already signed in calling /setup
    via the My Profile UI). Stale cookie that points at a deleted
    tech now triggers a clearer 401 message + tells the client to
    clear stored credentials."""
    h = request.headers.get("authorization", "")
    raw = ""
    if h.lower().startswith("bearer "):
        raw = h.split(" ", 1)[1].strip()
    if not raw:
        raw = _read_token(request, COOKIE_TECH) or ""
    if not raw:
        raise HTTPException(401, "Authentication required")
    try:
        data = jwt.decode(raw, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(401, "Enrolment token expired — sign in again")
    except jwt.InvalidTokenError:
        raise HTTPException(401, "Invalid token")
    if data.get("type") not in ("tech", "tech_mfa_enrol"):
        raise HTTPException(403, "Forbidden")
    tech_id = int(data.get("sub", 0))
    tech = get_tech_by_id(tech_id) if tech_id else None
    if not tech:
        # Either a stale cookie from a deleted tech, or a forged sub.
        # Distinct error message so the client knows to clear stored
        # creds + sign in again instead of getting the wrong "inactive"
        # diagnostic.
        raise HTTPException(401, "Stale session — clear cookies / use a private window and sign in again")
    if not tech.get("active"):
        raise HTTPException(403, "Account inactive")
    return tech


@app.get("/api/tech/mfa/status")
def tech_mfa_status(request: Request):
    """Read-only MFA state for the signed-in tech."""
    tech = _resolve_tech_enrolment_actor(request)
    return {
        "enabled":      bool(tech.get("mfa_enabled")),
        "must_enrol":   bool(tech.get("must_enrol_mfa")),
        "backup_codes": get_tech_backup_codes_status(tech["id"]),
    }


@app.post("/api/tech/mfa/setup")
def tech_mfa_setup(request: Request):
    """Generate a candidate TOTP secret + provisioning URI for the tech
    to scan in their authenticator app. Doesn't enable MFA until the
    matching /activate call confirms a working code."""
    tech = _resolve_tech_enrolment_actor(request)
    if tech.get("mfa_enabled"):
        raise HTTPException(400, "MFA already enabled. Disable it first to re-enrol.")
    secret = pyotp.random_base32()
    set_tech_mfa_pending(tech["id"], secret)
    totp = pyotp.TOTP(secret)
    label_email = tech.get("email") or tech.get("tech_code") or f"tech#{tech['id']}"
    uri = totp.provisioning_uri(name=label_email, issuer_name=MFA_ISSUER)
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    qr_data_uri = f"data:image/png;base64,{base64.b64encode(buf.getvalue()).decode()}"
    return {
        "secret":           secret,
        "provisioning_uri": uri,
        "qr_data_uri":      qr_data_uri,
        "issuer":           MFA_ISSUER,
        "account":          label_email,
    }


@app.post("/api/tech/mfa/activate")
def tech_mfa_activate(request: Request, body: MfaActivate):
    """Confirm a code from the candidate secret, flip mfa_enabled=1,
    issue one-time backup codes, clear must_enrol_mfa."""
    tech = _resolve_tech_enrolment_actor(request)
    if tech.get("mfa_enabled"):
        raise HTTPException(400, "MFA is already enabled")
    if not tech.get("mfa_secret"):
        raise HTTPException(400, "No setup in progress — call /mfa/setup first")
    totp = pyotp.TOTP(tech["mfa_secret"])
    if not totp.verify((body.code or "").strip(), valid_window=1):
        raise HTTPException(401, "Incorrect code — check your authenticator and try again")
    plain, hashed = _generate_backup_codes(10)
    activate_tech_mfa(tech["id"], hashed)
    _tp1_tech_audit(tech["id"], "tech.mfa.activated", request,
                    target_type="technician", target_id=tech["id"])
    return {"ok": True, "backup_codes": plain}


@app.post("/api/tech/mfa/regenerate-backup-codes")
def tech_mfa_regenerate(request: Request, body: MfaVerify):
    """Issue a fresh set of 10 backup codes. Requires a current TOTP
    or an unused backup code so an unattended terminal can't silently
    rotate them."""
    tech = _resolve_tech_enrolment_actor(request)
    if not tech.get("mfa_enabled"):
        raise HTTPException(400, "MFA is not enabled")
    if not _verify_tech_totp_or_backup(tech, body.code):
        raise HTTPException(401, "Incorrect code")
    plain, hashed = _generate_backup_codes(10)
    replace_tech_backup_codes(tech["id"], hashed)
    _tp1_tech_audit(tech["id"], "tech.mfa.backup_regenerated", request,
                    target_type="technician", target_id=tech["id"])
    return {"ok": True, "backup_codes": plain}


class TechMfaDisable(BaseModel):
    pin: str
    code: str


@app.post("/api/tech/mfa/disable")
def tech_mfa_disable(request: Request, body: TechMfaDisable):
    """Requires both the current PIN AND a current TOTP/backup code.
    Use case: tech lost their authenticator and an admin reset
    isn't available — they verify with PIN + a stored backup code."""
    tech = _resolve_tech_enrolment_actor(request)
    if not tech.get("mfa_enabled"):
        raise HTTPException(400, "MFA is not enabled")
    if not verify_tech(tech["tech_code"], body.pin):
        raise HTTPException(401, "Incorrect PIN")
    if not _verify_tech_totp_or_backup(tech, body.code):
        raise HTTPException(401, "Incorrect code")
    disable_tech_mfa(tech["id"])
    _tp1_tech_audit(tech["id"], "tech.mfa.disabled", request,
                    target_type="technician", target_id=tech["id"])
    return {"ok": True}


@app.post("/api/admin/technicians/{tech_id}/mfa/reset")
def admin_reset_tech_mfa(request: Request, tech_id: int):
    """Admin path to disable a tech's MFA (lost authenticator, no
    backup codes left). Flips must_enrol_mfa back on so the next
    login forces re-enrolment."""
    admin = _require_perm(request, "tech:reset_pin")
    tech = get_tech_by_id(tech_id)
    if not tech:
        raise HTTPException(404, "Technician not found")
    disable_tech_mfa(tech_id)
    # Also flip must_enrol_mfa on so they're forced to re-enrol next
    # login. Done via direct UPDATE since disable_tech_mfa intentionally
    # leaves the flag untouched (so an admin can choose to "MFA off
    # for now" if a tech is offline temporarily).
    from database import _con as _dbcon
    con = _dbcon()
    try:
        con.execute(
            "UPDATE technicians SET must_enrol_mfa = 1 WHERE id = ?",
            (tech_id,),
        )
        con.commit()
    finally:
        con.close()
    _audit_from(admin, "tech.mfa.reset_by_admin", request,
                target_type="technician", target_id=tech_id,
                target_label=tech.get("tech_code"))
    return {"ok": True}


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
    _enforce_forgot_rate(request, body.email or body.tech_code)
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
    if body.pin != body.confirm_pin:
        raise HTTPException(400, "PINs do not match")
    tech_id = consume_pin_reset_token(body.token)
    if not tech_id:
        raise HTTPException(400, "Reset link is invalid or has expired")
    # Phone-on-file check requires the tech row; load it now (the
    # token already proved ownership). 422 on weak PIN; security
    # alert on phone-as-PIN attempt.
    tech = get_tech_by_id(tech_id) or {}
    _validate_pin_or_400(
        body.pin, phone_on_file=tech.get("phone"),
        actor_type="tech", actor_id=tech_id,
        label=tech.get("tech_code") or f"tech#{tech_id}",
    )
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
    # Accept the lead OR any crew member. all_tech_ids is attached by
    # get_visit_by_id and merges assigned_tech_id with the visit_techs
    # crew. A 404 here means the tech is neither on the job — we surface
    # it as not-found rather than 403 so we don't leak existence.
    if not visit or tech_id not in (visit.get("all_tech_ids") or []):
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
    # Lead OR crew: all_tech_ids is the merged set computed by get_visit_by_id.
    if not visit or tech_id not in (visit.get("all_tech_ids") or []):
        raise HTTPException(404, "Job not found")
    key, cached = _idem_begin(request, tech_id, "job.part_add")
    if cached is not None:
        return cached
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
    # A tech consuming parts on a job can drop stock below reorder — alert.
    _check_low_stock(body.part_id)
    return _idem_finish(key, tech_id, "job.part_add", {"id": vp_id})


@app.delete("/api/tech/jobs/{visit_id}/parts/{vp_id}")
def tech_remove_part(request: Request, visit_id: int, vp_id: int):
    tech_id = _require_tech(request)
    visit = get_visit_by_id(visit_id)
    # Lead OR crew: all_tech_ids is the merged set computed by get_visit_by_id.
    if not visit or tech_id not in (visit.get("all_tech_ids") or []):
        raise HTTPException(404, "Job not found")
    key, cached = _idem_begin(request, tech_id, "job.part_remove")
    if cached is not None:
        return cached
    vp = get_visit_part_by_id(vp_id)
    if not vp or vp["visit_id"] != visit_id:
        # On a replay the part may already be gone — treat as idempotent success
        # if this key was the one that removed it. (No key → genuine 404.)
        if key:
            return _idem_finish(key, tech_id, "job.part_remove", {"ok": True})
        raise HTTPException(404, "Visit part not found")
    tech = get_tech_by_id(tech_id)
    remove_visit_part(
        vp_id,
        removed_by_tech_id=tech_id,
        tech_prid=tech.get("prid") if tech else None,
        tech_label=tech.get("name") if tech else None,
    )
    return _idem_finish(key, tech_id, "job.part_remove", {"ok": True})


@app.put("/api/tech/jobs/{visit_id}/start")
def tech_start_job(request: Request, visit_id: int):
    tech_id = _require_tech(request)
    visit   = get_visit_by_id(visit_id)
    # Lead OR crew: all_tech_ids is the merged set computed by get_visit_by_id.
    if not visit or tech_id not in (visit.get("all_tech_ids") or []):
        raise HTTPException(404, "Job not found")
    key, cached = _idem_begin(request, tech_id, "job.start")
    if cached is not None:
        return cached
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
    return _idem_finish(key, tech_id, "job.start", {"ok": True, "start_time": now_iso})


@app.put("/api/tech/jobs/{visit_id}/complete")
def tech_complete_job(request: Request, visit_id: int, body: TechCompleteVisit):
    tech_id = _require_tech(request)
    visit   = get_visit_by_id(visit_id)
    # Lead OR crew: all_tech_ids is the merged set computed by get_visit_by_id.
    if not visit or tech_id not in (visit.get("all_tech_ids") or []):
        raise HTTPException(404, "Job not found")
    key, cached = _idem_begin(request, tech_id, "job.complete")
    if cached is not None:
        return cached
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
    return _idem_finish(key, tech_id, "job.complete",
                        {"ok": True, "end_time": end_iso, "submitted_at": end_iso})


@app.post("/api/tech/jobs/{visit_id}/readings")
def tech_add_reading(request: Request, visit_id: int, body: TechReadingCreate):
    tech_id = _require_tech(request)
    visit = get_visit_by_id(visit_id)
    # Lead OR crew: all_tech_ids is the merged set computed by get_visit_by_id.
    if not visit or tech_id not in (visit.get("all_tech_ids") or []):
        raise HTTPException(404, "Job not found")
    key, cached = _idem_begin(request, tech_id, "job.reading")
    if cached is not None:
        return cached
    if visit.get("submitted_at"):
        raise HTTPException(409, "Job locked — cannot add readings after submission")
    rid = add_visit_reading(visit_id, tech_id, body.model_dump())
    return _idem_finish(key, tech_id, "job.reading", {"id": rid})


@app.post("/api/tech/jobs/{visit_id}/signature")
def tech_capture_signature(request: Request, visit_id: int, body: TechSignatureCreate):
    tech_id = _require_tech(request)
    visit = get_visit_by_id(visit_id)
    # Lead OR crew: all_tech_ids is the merged set computed by get_visit_by_id.
    if not visit or tech_id not in (visit.get("all_tech_ids") or []):
        raise HTTPException(404, "Job not found")
    key, cached = _idem_begin(request, tech_id, "job.signature")
    if cached is not None:
        return cached
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
    return _idem_finish(key, tech_id, "job.signature", {"id": sid})


@app.post("/api/tech/jobs/{visit_id}/checklist")
def tech_set_checklist(request: Request, visit_id: int, body: TechChecklistSet):
    tech_id = _require_tech(request)
    visit = get_visit_by_id(visit_id)
    # Lead OR crew: all_tech_ids is the merged set computed by get_visit_by_id.
    if not visit or tech_id not in (visit.get("all_tech_ids") or []):
        raise HTTPException(404, "Job not found")
    key, cached = _idem_begin(request, tech_id, "job.checklist")
    if cached is not None:
        return cached
    if visit.get("submitted_at"):
        raise HTTPException(409, "Job locked")
    set_visit_checklist(visit_id, body.items, tech_id)
    return _idem_finish(key, tech_id, "job.checklist", {"ok": True})


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
    # Lead OR crew: all_tech_ids is the merged set computed by get_visit_by_id.
    if not visit or tech_id not in (visit.get("all_tech_ids") or []):
        raise HTTPException(404, "Job not found")
    key, cached = _idem_begin(request, tech_id, "job.photo")
    if cached is not None:
        return cached

    if category not in ("before", "after"):
        raise HTTPException(400, "Invalid category — must be 'before' or 'after'")

    body = await file.read()
    ext  = _validate_photo_upload(file.filename, body)

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
    return _idem_finish(key, tech_id, "job.photo",
                        {"id": photo_id, "filename": fname,
                         "url": _sign_photo_url(fname), "category": category})


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


def _validate_pin_or_400(pin: str, phone_on_file: str,
                         actor_type: str, actor_id: int,
                         label: str = ""):
    """Wrapper around database.validate_pin_policy that:
      * Raises HTTPException(422) with the policy message on weak PINs.
      * Specifically raises a security_alert with kind
        'phone_as_pin_attempt' when the PIN matches the phone on
        file — that's the most-likely-malicious pattern (a tech or
        customer trying to use a phone number an attacker may have
        from a contact card).
    Callers MUST pass actor_type ('tech' | 'customer' | 'admin') and
    actor_id so the alert can be attributed; label is a human-readable
    hint for the alert summary."""
    try:
        validate_pin_policy(pin, phone_on_file=phone_on_file)
    except ValueError as e:
        msg = str(e)
        if "phone number" in msg.lower():
            _tp1_raise_security_alert(
                kind="phone_as_pin_attempt",
                severity="medium",
                summary=(f"{actor_type.capitalize()} #{actor_id}"
                        f"{(' (' + label + ')') if label else ''} "
                        f"attempted to set a PIN matching their phone "
                        f"number on file"),
                actor_type=actor_type, actor_id=actor_id,
                details={"label": label or None},
            )
        raise HTTPException(422, msg)


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
    # ── Day-off determination — MUST mirror the sign-in gate exactly ──────
    # tp1_tech_sign_in() refuses a sign-in with 409 dayoff_reason_required
    # when the tech is neither scheduled today nor on call. The landing card
    # reads is_day_off to decide whether to surface the reason field, so it
    # has to be derived from the *same* inputs — otherwise the two drift and
    # the tech who is technically "off" (no weekday schedule row) but has
    # jobs assigned gets an un-actionable raw-JSON error toast on sign-in,
    # which is exactly what happened in the field. "Scheduled today" == there
    # is an active schedule row with an end-time for today == sched_end set.
    scheduled_today = sched_end is not None
    is_day_off = (not scheduled_today) and (not on_call)

    # Jamaica observes EST (UTC-5) year-round (no DST since 1983), so a fixed
    # offset is correct here. Local labels are cosmetic — the client falls
    # back gracefully if they're null.
    def _hhmm_12h(hhmm):
        try:
            hh, mm = str(hhmm).split(":")[:2]
            h = int(hh); suffix = "AM" if h < 12 else "PM"
            return f"{h % 12 or 12}:{mm} {suffix}"
        except Exception:
            return hhmm or None

    def _jm_time_label(iso):
        if not iso:
            return None
        try:
            d = _dt.fromisoformat(iso)
            if d.tzinfo is None:
                d = d.replace(tzinfo=_tz.utc)
            return _hhmm_12h(d.astimezone(_tz(_td(hours=-5))).strftime("%H:%M"))
        except Exception:
            return None

    today_schedule_label = None
    if scheduled_today and today_sched:
        _st = _hhmm_12h(today_sched.get("start_time"))
        _en = _hhmm_12h(today_sched.get("end_time"))
        today_schedule_label = f"Scheduled {_st}–{_en}" if (_st and _en) else None
    elif on_call:
        today_schedule_label = "On call today"

    # Off-hours: scheduled today but the current Jamaica-local time falls
    # outside the shift window (before start or after end). On-call techs are
    # exempt — they're expected outside operational hours. The landing prompts
    # for a justification in this case too, mirroring the day-off prompt; the
    # reason is recorded on the clock-in. "HH:MM" strings compare correctly
    # lexicographically because they're zero-padded.
    is_off_hours = False
    if scheduled_today and not on_call and today_sched:
        try:
            now_jm = _dt.now(_tz(_td(hours=-5))).strftime("%H:%M")
            _s = str(today_sched.get("start_time") or "")[:5]
            _e = str(today_sched.get("end_time") or "")[:5]
            if _s and _e:
                is_off_hours = (now_jm < _s) or (now_jm > _e)
        except Exception:
            is_off_hours = False
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
        # Aliases the landing card (staff_home.html) reads. Kept alongside the
        # canonical *_count keys so existing consumers don't break.
        "pm_today": pm, "cm_today": cm,
        "schedule_today": ({
            "start": (today_sched or {}).get("start_time"),
            "end":   (today_sched or {}).get("end_time"),
            "active": bool((today_sched or {}).get("active")),
            "on_call": bool((today_sched or {}).get("on_call")),
        } if today_sched else None),
        "today_schedule_label": today_schedule_label,
        "on_call_today": on_call,
        "is_day_off": is_day_off,
        "is_off_hours": is_off_hours,
        "sign_in_status": sign_in_status,
        "signed_in_at": (open_in or {}).get("event_at"),
        "signed_in_at_local": _jm_time_label((open_in or {}).get("event_at")),
        "in_overtime": in_overtime,
        "overtime_approved": ot_approved,
        "auto_signout_at": auto_signout_at,
    }


def _all_audits_done_for_today(tech_id: int, phase: str,
                               today_iso: str) -> bool:
    """Per the field spec the tech must complete the start- or end-shift
    audit for EVERY assigned auditable asset (vehicle + toolkit) FOR
    THE CURRENT CYCLE — i.e. submitted after the most recent clock
    event today. See database.audit_cycle_threshold for the semantics.

    Storage isn't audited per-shift, so it's excluded — same filter
    the 5S home page uses to render the asset list."""
    from database import _con as _dbcon, audit_cycle_threshold
    threshold = audit_cycle_threshold(tech_id, today_iso)
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
            "AND auditor_kind = 'tech' AND phase = ? AND audit_ts > ? "
            "LIMIT 1",
            (a["id"], tech_id, phase, threshold),
        ).fetchone()
        if not done:
            con.close()
            return False
    con.close()
    return True


@app.post("/api/tech/me/sign-in")
def tp1_tech_sign_in(request: Request, body: TechSignInBody):
    from datetime import datetime as _dt, timezone as _tz
    from database import _biweekly_period_for, get_or_create_timesheet
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
    # Auto-create the current biweekly timesheet if one doesn't already
    # exist. Idempotent — re-signing in within the same period just returns
    # the existing draft. Fail-soft because timesheet creation must never
    # block the actual clock-in.
    try:
        period_start, period_end = _biweekly_period_for(today_iso)
        get_or_create_timesheet(tech_id, period_start, period_end)
    except Exception as _e:
        logger.warning("timesheet auto-create failed for tech %s: %s", tech_id, _e)
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
    # email_hash is an HMAC-blind-index used internally for
    # password-reset lookups; not reversible but it's still a
    # structured identifier that shouldn't leave the server.
    # Audit M2, 2026-05-23.
    return {k: v for k, v in dict(t).items() if k not in
            ("pin_hash", "mfa_secret", "backup_codes", "email_hash")}


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
    # IT-module #9 — per-account lockout (independent of IP).
    admin_row = get_admin_user_by_username(req.username)
    _staff_lock_guard("admin", admin_row, request, req.username)
    admin = verify_admin_user(req.username, req.password)
    if not admin:
        _staff_record_login_failure("admin", admin_row, request, req.username)
        _audit_anon("auth.login_failed", request,
                    attempted_identity=req.username,
                    actor_type="admin",
                    target_label="invalid credentials")
        raise HTTPException(401, "Invalid username or password")
    reset_admin_login_failures(admin["id"])
    if not admin.get("active"):
        _audit_anon("auth.login_failed", request,
                    attempted_identity=req.username,
                    actor_type="admin",
                    target_label="account deactivated")
        raise HTTPException(403, "Account is deactivated")

    # MFA-enrolment gate (HARD-REQUIRED, May 2026 operator directive):
    # EVERY admin without MFA is intercepted on login. The
    # must_enrol_mfa column is retained as explicit ops tracking
    # ("the bootstrap pass flagged this account") but the runtime
    # check no longer consults it — if mfa_enabled is False the
    # admin is funnelled into enrolment, full stop.
    if not admin.get("mfa_enabled"):
        enrol_token = _make_token(
            {"sub": str(admin["id"]), "type": "admin_mfa_enrol"},
            MFA_TOKEN_TTL,
        )
        _audit_from(admin, "admin.login.password_ok_mfa_enrol_required", request)
        return {"requires_mfa_setup": True,
                "mfa_enrol_token": enrol_token,
                "name": admin["name"]}

    # MFA verification gate (already enrolled — verify code next)
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
    # Pre-launch checklist item #2 — forced password reset on first
    # prod login. The bootstrap super_admin is seeded with
    # must_change_credentials=1 in database.bootstrap_super_admin;
    # set_admin_password clears it on a successful change. The UI
    # reads must_change_credentials and routes into the change-
    # password flow before letting the admin reach any other surface.
    return {
        "token":    token,
        "name":     admin["name"],
        "username": admin["username"],
        "role":     admin["role"],
        "prid":     admin.get("prid"),
        "requires_mfa": False,
        "must_change_credentials": bool(admin.get("must_change_credentials")),
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
        # Mirror the admin_login response so the UI sees the flag
        # regardless of whether the user has MFA enabled. (Item #2)
        "must_change_credentials": bool(admin.get("must_change_credentials")),
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


def _resolve_admin_enrolment_actor(request: Request) -> dict:
    """The admin-side MFA enrol endpoints accept EITHER a full admin
    session token OR the short-lived `admin_mfa_enrol` token returned
    by /api/admin/login or /api/staff/login when the admin needs to
    enrol. Mirrors _resolve_tech_enrolment_actor on the tech side.

    Without this, the unified /staff portal couldn't drive admin
    enrolment — the enrol token is what the user has at that point,
    but _require_admin rejects everything except type='admin'.

    BUG FIX (2026-05-25): Bearer header now wins over the cookie so
    a stale pc_admin_session cookie from a deleted-then-recreated
    admin doesn't sabotage the fresh enrol_token. Same symptom as
    the tech side — see _resolve_tech_enrolment_actor for full
    write-up."""
    h = request.headers.get("authorization", "")
    raw = ""
    if h.lower().startswith("bearer "):
        raw = h.split(" ", 1)[1].strip()
    if not raw:
        raw = _read_token(request, COOKIE_ADMIN) or ""
    if not raw:
        raise HTTPException(401, "Authentication required")
    try:
        data = jwt.decode(raw, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(401, "Enrolment token expired — sign in again")
    except jwt.InvalidTokenError:
        raise HTTPException(401, "Invalid token")
    if data.get("type") not in ("admin", "admin_mfa_enrol"):
        raise HTTPException(403, "Forbidden")
    admin_id = int(data.get("sub", 0))
    admin = get_admin_user_by_id(admin_id) if admin_id else None
    if not admin:
        raise HTTPException(401, "Stale session — clear cookies / use a private window and sign in again")
    if not admin.get("active"):
        raise HTTPException(403, "Account inactive")
    return admin


@app.get("/api/admin/mfa/status")
def admin_mfa_status(request: Request):
    admin = _require_admin(request)
    return {
        "enabled": bool(admin.get("mfa_enabled")),
        "backup_codes": get_admin_backup_codes_status(admin["id"]),
    }


@app.post("/api/admin/mfa/setup")
def admin_mfa_setup(request: Request):
    """Generates a candidate secret + QR code. Does NOT enable MFA until /activate.
    Accepts the enrolment token from /api/staff/login so a forced-MFA
    admin (no full session yet) can complete enrolment."""
    admin = _resolve_admin_enrolment_actor(request)
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
    then enables MFA and returns one-time backup codes.
    Accepts the enrolment token (see admin_mfa_setup)."""
    admin = _resolve_admin_enrolment_actor(request)
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


@app.post("/api/admin/me/password")
def admin_change_own_password(request: Request, body: AdminChangeOwnPassword):
    """Self-service password change from My Profile.

    Requires the *current* password (re-auth) so a stolen session
    token alone can't permanently take over the account. Validates
    against the same strength rules as new-account creation, blocks
    no-op changes, then issues a fresh password hash and logs the
    event. The current session stays valid — the user explicitly
    chose to keep working — but every other live session is revoked
    so a previously-stolen cookie can't outlive the password.
    """
    admin = _require_admin(request)
    from database import _verify_password, revoke_admin_sessions_except
    if not _verify_password(body.current_password, admin["password_hash"]):
        _audit_from(admin, "admin.password.change_failed", request,
                    target_type="admin", target_id=admin["id"],
                    target_label=admin["username"], details={"reason": "bad_current"})
        raise HTTPException(401, "Current password is incorrect")
    if body.new_password != body.confirm_password:
        raise HTTPException(400, "New passwords do not match")
    if body.new_password == body.current_password:
        raise HTTPException(400, "New password must be different from current password")
    _validate_password_strength(body.new_password)
    set_admin_password(admin["id"], body.new_password)
    # Revoke other sessions but keep the current one alive — the
    # user is actively in the UI and shouldn't be bounced for
    # changing their own password.
    current_jti = None
    try:
        token = _read_token(request, COOKIE_ADMIN)
        if token:
            data = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM],
                              options={"verify_exp": False})
            current_jti = data.get("jti")
    except Exception:
        pass
    try:
        revoke_admin_sessions_except(admin["id"], current_jti)
    except Exception:
        # Helper may not exist on older DBs; non-fatal.
        pass
    _audit_from(admin, "admin.password.changed", request,
                target_type="admin", target_id=admin["id"],
                target_label=admin["username"])
    return {"ok": True}


@app.post("/api/tech/me/pin")
def tech_change_own_pin(request: Request, body: TechChangeOwnPin):
    """Self-service PIN change from the tech portal.

    Tech-side mirror of admin_change_own_password. Requires the
    *current* PIN (re-auth) so a stolen session token alone can't
    permanently take over the account, validates the new PIN against
    the same policy as account creation, blocks no-op changes, then
    sets the new PIN (set_tech_pin also clears must_change_credentials,
    satisfying pre-launch checklist #2's forced first-login reset).
    Every other live tech session is revoked so a previously-stolen
    cookie can't outlive the PIN; the current session stays alive."""
    from database import _verify_pin, get_tech_by_id
    tech_id = _require_tech(request)
    tech = get_tech_by_id(tech_id)
    if not tech:
        raise HTTPException(404, "Tech not found")
    if not _verify_pin(body.current_pin, tech.get("pin_hash") or ""):
        _tp1_tech_audit(tech_id, "tech.pin.change_failed", request,
                        target_type="tech", target_id=tech_id,
                        target_label=tech.get("tech_code"),
                        after={"reason": "bad_current"})
        raise HTTPException(401, "Current PIN is incorrect")
    if body.new_pin != body.confirm_pin:
        raise HTTPException(400, "New PINs do not match")
    if body.new_pin == body.current_pin:
        raise HTTPException(400, "New PIN must be different from current PIN")
    _validate_pin_or_400(body.new_pin, phone_on_file=tech.get("phone"),
                         actor_type="tech", actor_id=tech_id,
                         label=tech.get("tech_code") or f"tech#{tech_id}")
    set_tech_pin(tech_id, body.new_pin)
    # Revoke other sessions but keep the current one alive.
    current_jti = None
    try:
        token = _read_token(request, COOKIE_TECH)
        if token:
            data = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM],
                              options={"verify_exp": False})
            current_jti = data.get("jti")
    except Exception:
        pass
    try:
        from database import revoke_tech_sessions_except
        revoke_tech_sessions_except(tech_id, current_jti)
    except Exception:
        # Helper may not exist on older DBs; non-fatal.
        pass
    _tp1_tech_audit(tech_id, "tech.pin.changed", request,
                    target_type="tech", target_id=tech_id,
                    target_label=tech.get("tech_code"))
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
    _enforce_forgot_rate(request, body.email)
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
    # IT-module #8: the admin reset rule was weaker than the portal
    # (≥8 chars, no complexity). Match the portal floor exactly —
    # ≥12 chars, letters+digits, common-password deny-list.
    if body.password != body.confirm_password:
        raise HTTPException(400, "Passwords do not match")
    _validate_password_strength(body.password)
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
    # IT-module #8: admin credentials use the same strength floor as the
    # portal (≥12 chars + letters/digits + deny-list), not the old ≥8.
    _validate_password_strength(body.password)
    # PRID is generated server-side and used as the username.
    data = body.model_dump()
    try:
        new_id, prid = create_admin_user(data, created_by=admin["id"])
    except ValueError as ve:
        # Reciprocal-uniqueness guard tripped (custom username collides
        # with a technician code/PRID).
        raise HTTPException(409, str(ve))
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


class PromoteTechBody(BaseModel):
    role: str
    password: str
    username: str = ""


@app.post("/api/admin/techs/{tech_id}/promote")
def admin_promote_tech(request: Request, tech_id: int, body: PromoteTechBody):
    """Promote-from-within: lift a field tech into an office/admin role.

    The two identity systems don't share a table — field staff live in
    `technicians`, office/admin staff in `admin_users` — so a promotion is a
    *hop*, not an in-place edit: we mint a brand-new admin account in the target
    role (carrying over name / contact / hire date), then terminate the old tech
    record. PRID is unique across BOTH tables, so the new admin gets a freshly
    generated PRID — the old one can't be reused. Job history stays attached to
    the archived tech record; the audit entry stitches old→new together so the
    lineage is traceable.

    Gated on admin:create (super_admin / hr_admin) — same bar as onboarding a
    fresh admin, which is exactly what this is."""
    admin = _require_perm(request, "admin:create")
    target = get_tech_by_id(tech_id)
    if not target:
        raise HTTPException(404, "Tech not found")
    if target.get("staff_type") not in (None, "tech"):
        raise HTTPException(400, "Only field technicians can be promoted to an office role")
    if not target.get("active"):
        raise HTTPException(400, "Cannot promote an inactive or terminated tech")
    if body.role not in ADMIN_PERMS:
        raise HTTPException(400, "Unknown role")
    if body.role == "super_admin" and not _admin_can(admin["role"], "admin:set_role"):
        raise HTTPException(403, "You cannot promote directly into super_admin")
    # IT-module #8: match the portal strength floor for admin credentials.
    _validate_password_strength(body.password or "")

    data = {
        "name":      target.get("name") or "",
        "email":     target.get("email") or "",
        "phone":     target.get("phone") or "",
        "role":      body.role,
        "password":  body.password,
        "username":  (body.username or "").strip(),
        "hire_date": target.get("hire_date") or "",
    }
    try:
        new_admin_id, new_prid = create_admin_user(data, created_by=admin["id"])
    except ValueError as ve:
        # Reciprocal-uniqueness guard: the chosen username collides with a
        # technician code/PRID. (Leaving username blank uses the
        # auto-generated, globally-unique PRID and avoids this.)
        raise HTTPException(409, str(ve))
    # Archive the field record last — if admin creation failed above we never
    # get here, so we never strand a tech with no destination account.
    term = terminate_account("tech", tech_id)
    _audit_from(admin, "account.promoted", request,
                target_type="tech", target_id=tech_id,
                target_label=target.get("name") or target.get("prid"),
                after={"from_role": target.get("role"),
                       "to_role": body.role,
                       "new_admin_id": new_admin_id,
                       "new_prid": new_prid,
                       "old_tech_terminated_at": term.get("terminated_at"),
                       "sessions_revoked": term.get("sessions_revoked")})
    return {"ok": True, "admin_id": new_admin_id, "prid": new_prid,
            "username": (data["username"] or new_prid).lower()}


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
    # IT-module #8: match the portal strength floor for admin credentials.
    _validate_password_strength(body.password)
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


# ── Biweekly timesheet workflow ──────────────────────────────────────────────
#
# Auto-created on first sign-in of a pay period, edited by the tech (and
# optionally by the supervisor), submitted for a 2-stage approval that
# ends with super_admin_approved. Routes both for techs (under
# /api/tech/me/timesheets/*) and admins (under /api/admin/timesheets/*).
# State transitions live in database.transition_timesheet which enforces
# nothing — the caller is responsible for verifying the move is legal.

class TimesheetDayOverride(BaseModel):
    work_date:            str
    manual_start_time:    Optional[str] = None
    manual_end_time:      Optional[str] = None
    manual_break_minutes: Optional[int] = None
    note:                 Optional[str] = None

class TimesheetNotes(BaseModel):
    tech_notes: str = ""

class TimesheetReject(BaseModel):
    reason: str

class TimesheetForceApprove(BaseModel):
    reason: str


def _ts_or_404(timesheet_id):
    from database import aggregate_timesheet
    agg = aggregate_timesheet(timesheet_id)
    if not agg:
        raise HTTPException(404, "Timesheet not found")
    return agg


def _admin_is_super(admin):
    return (admin.get("role") or "").lower() == "super_admin"


def _admin_supervises_tech(admin, tech_id):
    """True if `admin` is the supervisor of `tech_id` per technicians.supervisor_id.
    Falls back to True for any supervisor_admin when the tech has no
    supervisor set (so submissions don't get stranded)."""
    from database import get_tech_by_id
    t = get_tech_by_id(int(tech_id))
    if not t:
        return False
    if t.get("supervisor_id") == admin["id"]:
        return True
    if t.get("supervisor_id") is None and (admin.get("role") or "").lower() == "supervisor_admin":
        return True
    return False


# ── Tech-facing endpoints ────────────────────────────────────────────────────

@app.get("/api/tech/me/timesheets")
def tech_list_timesheets(request: Request):
    from database import list_timesheets_for_tech
    tech_id = _require_tech(request)
    return list_timesheets_for_tech(tech_id, limit=12)


@app.get("/api/tech/me/timesheets/current")
def tech_current_timesheet(request: Request):
    """Returns the tech's current-period timesheet with daily aggregation.
    Auto-creates a draft if none exists yet — even if the tech hasn't
    signed in for the period (so they can record retroactive overrides).
    Also lazily accrues vacation hours up through the most recent completed
    pay period, so the balance shown beside the timesheet is always live."""
    from database import (_biweekly_period_for, get_or_create_timesheet,
                          aggregate_timesheet, get_or_init_pto)
    tech_id = _require_tech(request)
    today_iso = datetime.now(timezone.utc).date().isoformat()
    period_start, period_end = _biweekly_period_for(today_iso)
    ts = get_or_create_timesheet(tech_id, period_start, period_end)
    agg = aggregate_timesheet(ts["id"])
    # Self-healing accrual: credit any biweekly periods that ended on/
    # before today and haven't been credited yet for this year.
    try:
        year = int(today_iso[:4])
        bal = get_or_init_pto(tech_id, year, accrue_through_period_end=today_iso)
        agg["pto_balance"] = bal
    except Exception as _e:
        agg["pto_balance"] = None
    return agg


@app.get("/api/tech/me/pto-balance")
def tech_pto_balance(request: Request, year: int = None):
    """Stand-alone PTO balance — used by the My Pay hub to show
    Floating Holidays and Vacation tallies. Now also reports the
    carryover line so the user can see how the year's seed was built."""
    from database import (get_or_init_pto, _vacation_carryover_from,
                          VACATION_STARTING_HOURS)
    tech_id = _require_tech(request)
    today_iso = datetime.now(timezone.utc).date().isoformat()
    y = int(year) if year else int(today_iso[:4])
    bal = get_or_init_pto(tech_id, y, accrue_through_period_end=today_iso)
    # Compute carryover from the prior year (if any) for the breakdown
    # line shown in the UI. This is purely informational — the carryover
    # was already baked into bal.vacation_balance at seed time.
    carryover = 0.0; carry_cap = 0.0; eoy_remaining = 0.0
    if bal:
        try:
            carryover, carry_cap, eoy_remaining = _vacation_carryover_from(y - 1, tech_id)
        except Exception:
            pass
    return {
        "year": y,
        "balance": bal,
        "carryover_from_prior_year": {
            "applied":     round(carryover, 2),
            "cap_nov_dec": round(carry_cap, 2),
            "eoy_balance": round(eoy_remaining, 2),
        },
        "starting_seed": VACATION_STARTING_HOURS,
    }


class PtoRequestBody(BaseModel):
    kind: str            # 'vacation' | 'floating' | 'sick'
    start_date: str      # YYYY-MM-DD
    end_date: str        # YYYY-MM-DD
    hours: float
    reason: Optional[str] = ""


class PtoDecisionBody(BaseModel):
    note: Optional[str] = ""


@app.get("/api/tech/me/pto-projection")
def tech_pto_projection(request: Request, month: str = None):
    """Return per-day projected vacation balance for a calendar month, so
    the request-time-off calendar can show "you'd still have X hours on
    this date" beneath each selectable cell.

    Projection algorithm:
      • For each date D in the requested month:
          base = current vacation balance (today)
          + accrual: count biweekly periods whose period_end is > today
            AND <= D, multiply by VACATION_PER_PERIOD (3.6h)
          − approved PTO with start_date in (today, D]
      • Past dates (D < today) report the current balance unchanged
        (purely informational; the UI disables selection on past days).

    Returns a list with one entry per day in the month, plus metadata."""
    from database import (get_or_init_pto, jamaican_holidays, _biweekly_period_for,
                          VACATION_PER_PERIOD, VACATION_STARTING_HOURS,
                          list_pto_requests, _vacation_carryover_from)
    from datetime import date as _date, timedelta as _td
    tech_id = _require_tech(request)
    today_iso = datetime.now(timezone.utc).date().isoformat()
    today_d   = _date.fromisoformat(today_iso)
    today_yr  = today_d.year
    # Default to current month if none supplied
    if month and len(month) >= 7:
        view_yr = int(month[:4]); view_mo = int(month[5:7])
    else:
        view_yr = today_yr; view_mo = today_d.month
    # Always grab THIS year's balance for the status strip.
    bal_now = get_or_init_pto(tech_id, today_yr, accrue_through_period_end=today_iso) or {}
    current_balance = float(bal_now.get("vacation_balance") or 0)
    floating_avail  = float(bal_now.get("floating_total") or 0) - float(bal_now.get("floating_used") or 0)
    sick_avail      = float(bal_now.get("sick_total") or 0)    - float(bal_now.get("sick_used") or 0)
    # All approved future PTO (we'll filter per-date below).
    upcoming = [r for r in list_pto_requests(tech_id=tech_id, status="approved")
                if r["start_date"] > today_iso]

    # ── Helper: collect every biweekly period_end in a [start, end] range
    def _period_ends_in(d_from, d_to):
        out = []
        if d_from > d_to: return out
        probe = d_from
        while probe <= d_to:
            ps, pe = _biweekly_period_for(probe.isoformat())
            pe_d = _date.fromisoformat(pe)
            if d_from <= pe_d <= d_to and (not out or pe_d > out[-1]):
                out.append(pe_d)
            probe = pe_d + _td(days=1)
        return out

    # ── Helper: project balance for a specific date D, year-aware.
    # Approved PTO between two ISO strings (start, end) inclusive of end.
    def _approved_used(s_iso, e_iso):
        return sum(float(r["hours"]) for r in upcoming
                   if s_iso < r["start_date"] <= e_iso)

    # Pre-compute, for any year y in {today_yr .. view_yr+1}, the cached
    # "year start balance" so we don't reseed it for every date.
    year_seeds = {}
    def _year_start_balance(y):
        """Effective vacation balance on Jan 1 of year `y` (carryover
        already applied for years after current; for current year it's
        whatever vacation_balance was at year-start — but we don't need
        that, only future years use this)."""
        if y in year_seeds: return year_seeds[y]
        if y <= today_yr:
            year_seeds[y] = current_balance
            return current_balance
        # For future years, simulate the rollover from y-1 → y:
        #   eoy_remaining = projection on Dec 31 of (y-1)
        #   carryover     = min(eoy_remaining, Nov+Dec accruals in (y-1))
        #   seed          = 40 + carryover (Oct 31 hire rule already
        #                   inherent in get_or_init_pto — but for future
        #                   years past the hire year, every tech gets 40)
        prev = _year_start_balance(y - 1)
        # Accruals across all of (y-1) — for y-1 == today_yr we count
        # only the part AFTER today (because `prev` already incorporates
        # everything up to today). For earlier years, count the full year.
        if (y - 1) == today_yr:
            from_d = today_d + _td(days=1)
        else:
            from_d = _date(y - 1, 1, 1)
        to_d = _date(y - 1, 12, 31)
        accrued_count = len(_period_ends_in(from_d, to_d))
        accrued_hours = round(accrued_count * VACATION_PER_PERIOD, 2)
        # Approved PTO in (y-1) on or before Dec 31 of (y-1) but after
        # the "from" anchor — same window as accruals.
        used = sum(float(r["hours"]) for r in upcoming
                   if from_d.isoformat() <= r["start_date"] <= to_d.isoformat())
        eoy_remaining = max(0.0, prev + accrued_hours - used)
        # Carryover cap = Nov+Dec accruals only.
        nov_dec_start = _date(y - 1, 11, 1)
        nd_count = len(_period_ends_in(nov_dec_start, to_d))
        carryover = min(eoy_remaining, round(nd_count * VACATION_PER_PERIOD, 2))
        seed = round(VACATION_STARTING_HOURS + carryover, 2)
        year_seeds[y] = seed
        return seed

    holidays = jamaican_holidays(view_yr)
    # First / last day of the requested month.
    first = _date(view_yr, view_mo, 1)
    next_m_first = _date(view_yr + (1 if view_mo == 12 else 0),
                         1 if view_mo == 12 else view_mo + 1, 1)
    last = next_m_first - _td(days=1)

    days = []
    cur = first
    while cur <= last:
        ds = cur.isoformat()
        if cur < today_d:
            projected = current_balance  # past, informational
        elif cur.year == today_yr:
            # Same year: today's balance + accruals (today, D] − approved PTO in same window
            accrued_count = len(_period_ends_in(today_d + _td(days=1), cur))
            accrual = round(accrued_count * VACATION_PER_PERIOD, 2)
            used = _approved_used(today_iso, ds)
            projected = round(current_balance + accrual - used, 2)
        else:
            # Future year: start from THAT year's seed (which already
            # includes carryover from the prior year), then add accruals
            # that occurred in (Jan 1, D] of that year.
            seed = _year_start_balance(cur.year)
            jan1 = _date(cur.year, 1, 1)
            accrued_count = len(_period_ends_in(jan1, cur))
            accrual = round(accrued_count * VACATION_PER_PERIOD, 2)
            used = sum(float(r["hours"]) for r in upcoming
                       if jan1.isoformat() <= r["start_date"] <= ds)
            projected = round(seed + accrual - used, 2)
        days.append({
            "date":              ds,
            "weekday":           cur.strftime("%a"),
            "is_today":          (cur == today_d),
            "is_past":           (cur <  today_d),
            "is_weekend":        (cur.weekday() >= 5),
            "is_holiday":        ds in holidays,
            "holiday_name":      holidays.get(ds),
            "projected_balance": projected,
        })
        cur += _td(days=1)
    return {
        "month":               f"{view_yr:04d}-{view_mo:02d}",
        "today":               today_iso,
        "current_balance":     current_balance,
        "floating_available":  floating_avail,
        "sick_available":      sick_avail,
        "sick_cap":            float(bal_now.get("sick_total") or 0),
        "per_period_accrual":  VACATION_PER_PERIOD,
        "year_seed_after_carryover": year_seeds.get(view_yr) if view_yr > today_yr else None,
        "days":                days,
    }


@app.post("/api/tech/me/pto-requests")
def tech_create_pto_request(request: Request, body: PtoRequestBody):
    """Tech submits a time-off request for supervisor approval. We do a
    balance preview here so the tech sees an immediate warning if they
    don't have enough — but the request is still accepted (supervisor
    decides). Approval-time deduction is enforced in decide_pto_request."""
    from database import create_pto_request, get_or_init_pto
    tech_id = _require_tech(request)
    if body.kind not in ("vacation", "floating", "sick"):
        raise HTTPException(422, "kind must be 'vacation', 'floating', or 'sick'")
    if body.hours <= 0:
        raise HTTPException(422, "hours must be positive")
    if body.end_date < body.start_date:
        raise HTTPException(422, "end_date must be on or after start_date")
    year = int(body.start_date[:4])
    bal = get_or_init_pto(tech_id, year,
                          accrue_through_period_end=datetime.now(timezone.utc).date().isoformat())
    warn = None
    if body.kind == "vacation" and body.hours > (bal["vacation_balance"] or 0) + 1e-6:
        warn = (f"Heads-up: you only have {bal['vacation_balance']:.2f}h vacation "
                f"available; supervisor may decline.")
    if body.kind == "floating":
        days_avail = (bal["floating_total"] or 0) - (bal["floating_used"] or 0)
        if (body.hours / 8.0) > days_avail + 1e-6:
            warn = (f"Heads-up: you only have {days_avail:.2f} floating-holiday "
                    f"day(s); supervisor may decline.")
    if body.kind == "sick":
        sick_avail = (bal.get("sick_total") or 0) - (bal.get("sick_used") or 0)
        if body.hours > sick_avail + 1e-6:
            warn = (f"Heads-up: you only have {sick_avail:.2f}h sick/family time "
                    f"available (40h annual cap). Doctor's note required to exceed.")
    rid = create_pto_request(tech_id, body.kind, body.start_date, body.end_date,
                             float(body.hours), body.reason)
    _audit_from({"id": tech_id, "kind": "tech"}, "pto.request_created", request,
                target_type="pto_request", target_id=rid,
                after={"kind": body.kind, "start": body.start_date,
                       "end": body.end_date, "hours": body.hours})
    return {"id": rid, "ok": True, "balance_warning": warn}


@app.get("/api/tech/me/pto-requests")
def tech_list_pto_requests(request: Request):
    """Tech's own request history (most recent first)."""
    from database import list_pto_requests
    tech_id = _require_tech(request)
    return {"requests": list_pto_requests(tech_id=tech_id)}


@app.post("/api/tech/me/pto-requests/{request_id}/cancel")
def tech_cancel_pto_request(request: Request, request_id: int):
    """Tech withdraws a still-pending request. Refuses if already decided."""
    from database import get_pto_request, decide_pto_request
    tech_id = _require_tech(request)
    req = get_pto_request(request_id)
    if not req or req["tech_id"] != tech_id:
        raise HTTPException(404, "Request not found")
    try:
        decide_pto_request(request_id, "cancelled", actor_kind="tech",
                           actor_id=tech_id, note="Cancelled by employee")
    except ValueError as e:
        raise HTTPException(409, str(e))
    _audit_from({"id": tech_id, "kind": "tech"}, "pto.request_cancelled", request,
                target_type="pto_request", target_id=request_id)
    return {"ok": True}


@app.get("/api/admin/pto-requests")
def admin_list_pto_requests(request: Request, status: str = "pending"):
    """Supervisor / admin review queue. Defaults to pending; pass
    ?status=approved|denied|cancelled|all to filter otherwise."""
    admin = _require_admin(request)
    from database import list_pto_requests
    s = None if status == "all" else status
    return {"requests": list_pto_requests(status=s)}


@app.post("/api/admin/pto-requests/{request_id}/approve")
def admin_approve_pto_request(request: Request, request_id: int, body: PtoDecisionBody):
    admin = _require_admin(request)
    from database import decide_pto_request
    try:
        out = decide_pto_request(request_id, "approved",
                                 actor_kind="admin", actor_id=admin["id"],
                                 note=body.note)
    except ValueError as e:
        # Balance-insufficient errors land here.
        raise HTTPException(422, str(e))
    _audit_from(admin, "pto.request_approved", request,
                target_type="pto_request", target_id=request_id,
                after={"note": body.note})
    _notify_pto_decision(out, "approved")
    return {"ok": True, "request": out}


@app.post("/api/admin/pto-requests/{request_id}/deny")
def admin_deny_pto_request(request: Request, request_id: int, body: PtoDecisionBody):
    admin = _require_admin(request)
    from database import decide_pto_request
    try:
        out = decide_pto_request(request_id, "denied",
                                 actor_kind="admin", actor_id=admin["id"],
                                 note=body.note)
    except ValueError as e:
        raise HTTPException(409, str(e))
    _audit_from(admin, "pto.request_denied", request,
                target_type="pto_request", target_id=request_id,
                after={"note": body.note})
    _notify_pto_decision(out, "denied")
    return {"ok": True, "request": out}


@app.get("/api/tech/me/timesheets/{timesheet_id}")
def tech_get_timesheet(request: Request, timesheet_id: int):
    tech_id = _require_tech(request)
    agg = _ts_or_404(timesheet_id)
    if agg["timesheet"]["tech_id"] != tech_id:
        raise HTTPException(404, "Timesheet not found")
    return agg


@app.patch("/api/tech/me/timesheets/{timesheet_id}/notes")
def tech_update_timesheet_notes(request: Request, timesheet_id: int, body: TimesheetNotes):
    from database import update_timesheet_notes
    tech_id = _require_tech(request)
    agg = _ts_or_404(timesheet_id)
    ts  = agg["timesheet"]
    if ts["tech_id"] != tech_id:
        raise HTTPException(404, "Timesheet not found")
    if ts["status"] != "draft":
        raise HTTPException(409, "Only draft timesheets can be edited by the tech")
    update_timesheet_notes(timesheet_id, body.tech_notes)
    log_audit(actor_type="tech", actor_id=tech_id,
              actor_label=None, action="timesheet.notes_update",
              target_type="timesheet", target_id=timesheet_id,
              after_value={"tech_notes": body.tech_notes},
              ip_address=request.client.host if request.client else None)
    return {"ok": True}


@app.put("/api/tech/me/timesheets/{timesheet_id}/day")
def tech_upsert_timesheet_day(request: Request, timesheet_id: int, body: TimesheetDayOverride):
    """Set or replace the per-day override (correct a missed clock-in/out,
    record a manual break). Only allowed while the timesheet is a draft."""
    from database import upsert_timesheet_override
    tech_id = _require_tech(request)
    agg = _ts_or_404(timesheet_id)
    ts  = agg["timesheet"]
    if ts["tech_id"] != tech_id:
        raise HTTPException(404, "Timesheet not found")
    # Tech can self-correct only while the supervisor hasn't approved yet.
    # 'submitted' rewinds to draft so the supervisor re-reviews the updated
    # numbers. Once supervisor_approved or super_admin_approved, the sheet
    # is locked — only a supervisor reopen unlocks it. Defense-in-depth for
    # the payroll-integrity gap flagged in the May 2026 security audit.
    if body.work_date < ts["period_start"] or body.work_date > ts["period_end"]:
        raise HTTPException(400, "work_date is outside this timesheet's period")
    if ts["status"] not in ("draft", "submitted"):
        raise HTTPException(409,
            f"Timesheet is {ts['status']} — ask your supervisor to reopen it before editing.")
    if ts["status"] == "submitted":
        try:
            from database import _con as _dbcon
            con = _dbcon()
            con.execute(
                "UPDATE tech_timesheets SET status='draft', "
                "submitted_at=NULL, submitted_by_kind=NULL, submitted_by_id=NULL, "
                "week1_submitted_at=NULL, week1_submitted_by_kind=NULL, week1_submitted_by_id=NULL, "
                "week2_submitted_at=NULL, week2_submitted_by_kind=NULL, week2_submitted_by_id=NULL "
                "WHERE id = ?", (timesheet_id,))
            con.commit(); con.close()
        except Exception:
            pass
        log_audit(actor_type="tech", actor_id=tech_id, actor_label=None,
                  action="timesheet.reopened_by_tech_edit",
                  target_type="timesheet", target_id=timesheet_id,
                  target_label=body.work_date,
                  after_value={"prior_status": "submitted", "new_status": "draft"},
                  ip_address=request.client.host if request.client else None)
    upsert_timesheet_override(
        timesheet_id, body.work_date,
        manual_start_time=body.manual_start_time,
        manual_end_time=body.manual_end_time,
        manual_break_minutes=body.manual_break_minutes,
        note=body.note,
        edited_by_kind="tech", edited_by_id=tech_id,
    )
    log_audit(actor_type="tech", actor_id=tech_id,
              actor_label=None, action="timesheet.day_override",
              target_type="timesheet", target_id=timesheet_id,
              target_label=body.work_date,
              after_value=body.model_dump(),
              ip_address=request.client.host if request.client else None)
    return {"ok": True}


@app.delete("/api/tech/me/timesheets/{timesheet_id}/day")
def tech_delete_timesheet_day(request: Request, timesheet_id: int, work_date: str):
    """Tech removes their manual override for a given day. Underlying
    clock events (if any) remain; the day falls back to whatever the raw
    sign-in / sign-out events show. Same rewind-to-draft policy as PUT:
    deleting on an approved sheet kicks it back into the review queue."""
    from database import delete_timesheet_override
    tech_id = _require_tech(request)
    agg = _ts_or_404(timesheet_id)
    ts  = agg["timesheet"]
    if ts["tech_id"] != tech_id:
        raise HTTPException(404, "Timesheet not found")
    if work_date < ts["period_start"] or work_date > ts["period_end"]:
        raise HTTPException(400, "work_date is outside this timesheet's period")
    # Same lock policy as the PUT: no tech mutations once supervisor approved.
    if ts["status"] not in ("draft", "submitted"):
        raise HTTPException(409,
            f"Timesheet is {ts['status']} — ask your supervisor to reopen it before editing.")
    if ts["status"] == "submitted":
        try:
            from database import _con as _dbcon
            con = _dbcon()
            con.execute(
                "UPDATE tech_timesheets SET status='draft', "
                "submitted_at=NULL, submitted_by_kind=NULL, submitted_by_id=NULL, "
                "week1_submitted_at=NULL, week1_submitted_by_kind=NULL, week1_submitted_by_id=NULL, "
                "week2_submitted_at=NULL, week2_submitted_by_kind=NULL, week2_submitted_by_id=NULL "
                "WHERE id = ?", (timesheet_id,))
            con.commit(); con.close()
        except Exception:
            pass
        log_audit(actor_type="tech", actor_id=tech_id, actor_label=None,
                  action="timesheet.reopened_by_tech_edit",
                  target_type="timesheet", target_id=timesheet_id,
                  target_label=work_date,
                  after_value={"prior_status": "submitted", "new_status": "draft",
                               "via": "day_delete"},
                  ip_address=request.client.host if request.client else None)
    delete_timesheet_override(timesheet_id, work_date)
    log_audit(actor_type="tech", actor_id=tech_id,
              actor_label=None, action="timesheet.day_override_cleared",
              target_type="timesheet", target_id=timesheet_id,
              target_label=work_date,
              ip_address=request.client.host if request.client else None)
    return {"ok": True}


@app.post("/api/tech/me/timesheets/{timesheet_id}/submit")
def tech_submit_timesheet(request: Request, timesheet_id: int, week: int = None):
    """Submit a timesheet for supervisor review. Supports per-week
    submission via the optional `?week=1` or `?week=2` query param —
    techs can submit Week 1 mid-period without waiting for Week 2 to
    finish. When both weeks are submitted, overall status flips from
    'draft' to 'submitted' so the supervisor queue picks it up.
    Omit `week` to submit the full biweekly timesheet at once (legacy)."""
    from database import transition_timesheet, submit_timesheet_week
    tech_id = _require_tech(request)
    agg = _ts_or_404(timesheet_id)
    ts  = agg["timesheet"]
    if ts["tech_id"] != tech_id:
        raise HTTPException(404, "Timesheet not found")
    if ts["status"] != "draft":
        raise HTTPException(409, f"Cannot submit from status='{ts['status']}'")
    if week in (1, 2):
        try:
            outcome = submit_timesheet_week(timesheet_id, int(week),
                                            submitted_by_kind="tech",
                                            submitted_by_id=tech_id)
        except ValueError as e:
            raise HTTPException(409, str(e))
        log_audit(actor_type="tech", actor_id=tech_id, actor_label=None,
                  action=f"timesheet.submit_week_{week}",
                  target_type="timesheet", target_id=timesheet_id,
                  after_value={"outcome": outcome},
                  ip_address=request.client.host if request.client else None)
        return {"ok": True, "week": week, "outcome": outcome}
    # Legacy: submit both weeks at once.
    transition_timesheet(timesheet_id, "submitted",
                         submitted_by_kind="tech", submitted_by_id=tech_id)
    # Backfill the per-week flags so the UI shows both as submitted.
    from datetime import datetime as _dt
    now = _dt.now(timezone.utc).isoformat()
    from database import _con
    con = _con()
    con.execute(
        "UPDATE tech_timesheets SET "
        "week1_submitted_at = COALESCE(week1_submitted_at, ?), "
        "week1_submitted_by_kind = COALESCE(week1_submitted_by_kind, 'tech'), "
        "week1_submitted_by_id   = COALESCE(week1_submitted_by_id, ?), "
        "week2_submitted_at = COALESCE(week2_submitted_at, ?), "
        "week2_submitted_by_kind = COALESCE(week2_submitted_by_kind, 'tech'), "
        "week2_submitted_by_id   = COALESCE(week2_submitted_by_id, ?) "
        "WHERE id = ?",
        (now, tech_id, now, tech_id, int(timesheet_id)),
    )
    con.commit(); con.close()
    log_audit(actor_type="tech", actor_id=tech_id,
              actor_label=None, action="timesheet.submit",
              target_type="timesheet", target_id=timesheet_id,
              ip_address=request.client.host if request.client else None)
    return {"ok": True, "outcome": "submitted"}


# ── Admin-facing endpoints (supervisor + super_admin) ────────────────────────

@app.get("/api/admin/timesheets/pending")
def admin_pending_timesheets(request: Request):
    """Role-scoped queue. supervisor_admin: their own techs' submissions.
    super_admin: everything currently waiting for the final pass + any
    stranded submissions from techs with no supervisor."""
    from database import (
        list_pending_timesheets_for_supervisor,
        list_pending_timesheets_for_super_admin,
    )
    admin = _require_perm(request, "timesheet:view_all")
    if _admin_is_super(admin):
        return list_pending_timesheets_for_super_admin()
    return list_pending_timesheets_for_supervisor(admin["id"])


@app.get("/api/admin/timesheets/{timesheet_id}")
def admin_get_timesheet(request: Request, timesheet_id: int):
    """Full detail. Supervisor can read their assigned techs' timesheets;
    super_admin can read any."""
    admin = _require_perm(request, "timesheet:view_all")
    agg = _ts_or_404(timesheet_id)
    if not _admin_is_super(admin) and not _admin_supervises_tech(admin, agg["timesheet"]["tech_id"]):
        raise HTTPException(403, "Not the supervisor for this tech")
    return agg


@app.patch("/api/admin/timesheets/{timesheet_id}/notes")
def admin_update_timesheet_notes(request: Request, timesheet_id: int, body: TimesheetNotes):
    from database import update_timesheet_notes
    admin = _require_perm(request, "timesheet:view_all")
    agg = _ts_or_404(timesheet_id)
    ts  = agg["timesheet"]
    if not _admin_is_super(admin) and not _admin_supervises_tech(admin, ts["tech_id"]):
        raise HTTPException(403, "Not the supervisor for this tech")
    if ts["status"] == "super_admin_approved":
        raise HTTPException(409, "Cannot edit a fully-approved timesheet")
    update_timesheet_notes(timesheet_id, body.tech_notes)
    _audit_from(admin, "timesheet.notes_update", request,
                target_type="timesheet", target_id=timesheet_id,
                after={"tech_notes": body.tech_notes})
    return {"ok": True}


@app.put("/api/admin/timesheets/{timesheet_id}/day")
def admin_upsert_timesheet_day(request: Request, timesheet_id: int, body: TimesheetDayOverride):
    from database import upsert_timesheet_override
    admin = _require_perm(request, "timesheet:view_all")
    agg = _ts_or_404(timesheet_id)
    ts  = agg["timesheet"]
    if not _admin_is_super(admin) and not _admin_supervises_tech(admin, ts["tech_id"]):
        raise HTTPException(403, "Not the supervisor for this tech")
    if ts["status"] == "super_admin_approved":
        raise HTTPException(409, "Cannot edit a fully-approved timesheet")
    if body.work_date < ts["period_start"] or body.work_date > ts["period_end"]:
        raise HTTPException(400, "work_date is outside this timesheet's period")
    upsert_timesheet_override(
        timesheet_id, body.work_date,
        manual_start_time=body.manual_start_time,
        manual_end_time=body.manual_end_time,
        manual_break_minutes=body.manual_break_minutes,
        note=body.note,
        edited_by_kind="admin", edited_by_id=admin["id"],
    )
    _audit_from(admin, "timesheet.day_override", request,
                target_type="timesheet", target_id=timesheet_id,
                target_label=body.work_date,
                after=body.model_dump())
    return {"ok": True}


@app.post("/api/admin/timesheets/{timesheet_id}/submit-as-tech")
def admin_submit_timesheet_as_tech(request: Request, timesheet_id: int):
    """Supervisor submits on the tech's behalf (tech is in the field /
    forgot)."""
    from database import transition_timesheet
    admin = _require_perm(request, "timesheet:view_all")
    agg = _ts_or_404(timesheet_id)
    ts  = agg["timesheet"]
    if not _admin_is_super(admin) and not _admin_supervises_tech(admin, ts["tech_id"]):
        raise HTTPException(403, "Not the supervisor for this tech")
    if ts["status"] != "draft":
        raise HTTPException(409, f"Cannot submit from status='{ts['status']}'")
    transition_timesheet(timesheet_id, "submitted",
                         submitted_by_kind="admin", submitted_by_id=admin["id"])
    _audit_from(admin, "timesheet.submit_as_tech", request,
                target_type="timesheet", target_id=timesheet_id,
                target_label=f"tech_id={ts['tech_id']}")
    return {"ok": True}


@app.post("/api/admin/timesheets/{timesheet_id}/approve")
def admin_approve_timesheet(request: Request, timesheet_id: int):
    """Role-driven approval. supervisor: submitted → supervisor_approved.
    super_admin: supervisor_approved → super_admin_approved (final, locks
    the timesheet for payroll consumption)."""
    from database import transition_timesheet
    admin = _require_perm(request, "timesheet:view_all")
    agg = _ts_or_404(timesheet_id)
    ts  = agg["timesheet"]
    if _admin_is_super(admin):
        if ts["status"] != "supervisor_approved":
            raise HTTPException(409, "Super admin can only approve a supervisor-approved timesheet (use force-approve to bypass)")
        transition_timesheet(timesheet_id, "super_admin_approved",
                             super_admin_id=admin["id"])
        _audit_from(admin, "timesheet.super_admin_approve", request,
                    target_type="timesheet", target_id=timesheet_id,
                    target_label=f"tech_id={ts['tech_id']}")
        return {"ok": True, "status": "super_admin_approved"}
    if not _admin_supervises_tech(admin, ts["tech_id"]):
        raise HTTPException(403, "Not the supervisor for this tech")
    if ts["status"] != "submitted":
        raise HTTPException(409, f"Cannot supervisor-approve from status='{ts['status']}'")
    transition_timesheet(timesheet_id, "supervisor_approved",
                         supervisor_id=admin["id"])
    _audit_from(admin, "timesheet.supervisor_approve", request,
                target_type="timesheet", target_id=timesheet_id,
                target_label=f"tech_id={ts['tech_id']}")
    return {"ok": True, "status": "supervisor_approved"}


@app.post("/api/admin/timesheets/{timesheet_id}/reject")
def admin_reject_timesheet(request: Request, timesheet_id: int, body: TimesheetReject):
    """Sends the timesheet all the way back to draft with a required reason.
    Tech sees the reason and revises before resubmitting."""
    from database import transition_timesheet
    admin = _require_perm(request, "timesheet:view_all")
    if not (body.reason or "").strip():
        raise HTTPException(400, "Rejection reason is required")
    agg = _ts_or_404(timesheet_id)
    ts  = agg["timesheet"]
    if ts["status"] not in ("submitted", "supervisor_approved"):
        raise HTTPException(409, f"Cannot reject from status='{ts['status']}'")
    if not _admin_is_super(admin) and not _admin_supervises_tech(admin, ts["tech_id"]):
        raise HTTPException(403, "Not the supervisor for this tech")
    transition_timesheet(timesheet_id, "draft", reject_reason=body.reason.strip())
    _audit_from(admin, "timesheet.reject", request,
                target_type="timesheet", target_id=timesheet_id,
                target_label=f"tech_id={ts['tech_id']}",
                after={"reason": body.reason.strip()})
    return {"ok": True}


@app.post("/api/admin/timesheets/{timesheet_id}/force-approve")
def admin_force_approve_timesheet(request: Request, timesheet_id: int, body: TimesheetForceApprove):
    """super_admin escape hatch — jump straight to super_admin_approved with
    a required reason audit-logged loudly. Use when the supervisor is
    unavailable and payroll cannot wait."""
    from database import transition_timesheet
    admin = _require_perm(request, "timesheet:view_all")
    if not _admin_is_super(admin):
        raise HTTPException(403, "Only super_admin can force-approve")
    if not (body.reason or "").strip():
        raise HTTPException(400, "Force-approve reason is required")
    agg = _ts_or_404(timesheet_id)
    ts  = agg["timesheet"]
    if ts["status"] == "super_admin_approved":
        raise HTTPException(409, "Already fully approved")
    transition_timesheet(timesheet_id, "super_admin_approved",
                         super_admin_id=admin["id"],
                         force_reason=body.reason.strip())
    _audit_from(admin, "timesheet.force_approve", request,
                target_type="timesheet", target_id=timesheet_id,
                target_label=f"tech_id={ts['tech_id']}",
                after={"reason": body.reason.strip(), "prior_status": ts["status"]})
    return {"ok": True, "status": "super_admin_approved", "force_approved": True}


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
    # Defense-in-depth separation of duties: whoever HR'd this batch can't
    # also approve it. Super-admins bypass — they sit above the org chart
    # and own both functions in single-operator deployments, and the audit
    # log still captures the self-approval for traceability.
    is_super = (admin.get("role") or "").lower() == "super_admin"
    if pp.get("created_by") == admin["id"] and not is_super:
        raise HTTPException(403, "You cannot approve a pay period you yourself created.")
    try:
        result = approve_pay_period(period_id, admin["id"],
                                    allow_self_approval=is_super)
    except ValueError as e:
        raise HTTPException(400, str(e))
    _audit_from(admin, "payroll.period_approve", request,
                target_type="pay_period", target_id=period_id,
                target_label=pp["label"], after=result)
    return result


@app.delete("/api/admin/payroll/periods/{period_id}")
def admin_delete_pay_period(request: Request, period_id: int):
    """Delete a pay period. Super-admin only. Allowed while the period is
    still in draft; deleting an approved or paid period requires explicit
    ?force=1 because it permanently removes the period row and cascades to
    its payslips. Captured in the audit log."""
    from database import _con as _dbcon
    admin = _require_perm(request, "payroll:approve")
    if (admin.get("role") or "").lower() != "super_admin":
        raise HTTPException(403, "Only super-admin can delete a pay period.")
    pp = get_pay_period(period_id)
    if not pp:
        raise HTTPException(404, "Pay period not found")
    force = (request.query_params.get("force") or "").lower() in ("1","true","yes")
    if pp["status"] != "draft" and not force:
        raise HTTPException(409,
            f"Period is {pp['status']}. Pass ?force=1 to delete a non-draft period.")
    con = _dbcon()
    try:
        con.execute("DELETE FROM payslips WHERE pay_period_id = ?", (period_id,))
        con.execute("DELETE FROM pay_periods WHERE id = ?", (period_id,))
        con.commit()
    finally:
        con.close()
    _audit_from(admin, "payroll.period_delete", request,
                target_type="pay_period", target_id=period_id,
                target_label=pp.get("label"),
                before={"status": pp.get("status"),
                        "created_by": pp.get("created_by"),
                        "period_start": pp.get("period_start"),
                        "period_end": pp.get("period_end")})
    return {"ok": True, "deleted": period_id}


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


# ── Printable-payslip enrichment (Jamaica-compliant) ────────────────────────
# When the popup/print view opens, we enrich the raw payslip with:
#   1. YTD totals scoped to the JM tax year (Apr 1 → Mar 31)
#   2. Employer-side statutory contributions (NIS-ER, NHT-ER, Ed Tax-ER,
#      HEART Trust) — computed at render time from gross_pay
#   3. Bank / TRN / NIS# placeholders (real fields land later — see TODO)
#   4. Company info block (TRN + NIS Employer # are placeholders for now)
#
# Rates below reflect JM statutory rates current at time of writing.
# When the Ministry of Finance updates them, change the constants here.
_JM_NIS_EE_RATE   = 0.03      # Employee NIS  3 %
_JM_NIS_ER_RATE   = 0.03      # Employer NIS  3 %
_JM_NIS_CEILING_MO = JAMAICA_TAX_REFERENCE["payroll"]["nis"]["annual_insurable_ceiling"] / 12  # Insurable ceiling → monthly (single source: JAMAICA_TAX_REFERENCE)
_JM_NHT_EE_RATE   = 0.02      # Employee NHT  2 %
_JM_NHT_ER_RATE   = 0.03      # Employer NHT  3 %
_JM_EDTAX_EE_RATE = 0.0225    # Employee Ed-Tax  2.25 %
_JM_EDTAX_ER_RATE = 0.035     # Employer Ed-Tax  3.5 %
_JM_HEART_RATE    = 0.03      # HEART Trust  3 %  (employer)
_JM_HEART_THRESHOLD_MO = 173_328  # only if monthly wage bill ≥ this
# Company-level statutory identifiers for the printable payslip (IT-module
# #10). These are now CONFIG, read from the environment, instead of the old
# hardcoded "TODO-COMPANY-TRN" / "TODO-NIS-EMPLOYER-#" strings that would have
# printed fake employer tax IDs on a real payroll run.
#
# Set these in .dev.env (local) / the deploy env (prod):
#   PC_COMPANY_NAME, PC_COMPANY_ADDRESS, PC_COMPANY_PHONE,
#   PC_COMPANY_TRN, PC_COMPANY_NIS_ER
#
# When a statutory ID is unset we render the sentinel "— not set —" (see
# _PC_TAXID_UNSET) rather than a fabricated number, so an un-configured
# payslip is obviously incomplete instead of silently wrong. A real Tax
# Administration Jamaica TRN is 9 digits; values are validated lightly at
# load (digits/length warning only — we never block startup on it).
_PC_TAXID_UNSET = "— not set —"


def _env_or_unset(key: str) -> str:
    v = (os.environ.get(key) or "").strip()
    return v or _PC_TAXID_UNSET


_PC_COMPANY = {
    "name":     (os.environ.get("PC_COMPANY_NAME") or "PrimeCool Services Limited").strip(),
    "address":  (os.environ.get("PC_COMPANY_ADDRESS") or "Kingston, Jamaica").strip(),
    "phone":    (os.environ.get("PC_COMPANY_PHONE") or "").strip(),
    "trn":      _env_or_unset("PC_COMPANY_TRN"),
    "nis_er":   _env_or_unset("PC_COMPANY_NIS_ER"),
}
# Loud, non-fatal warning so anyone running a real payroll without the IDs
# configured sees it in the logs (and the payslip shows "— not set —").
if _PC_COMPANY["trn"] == _PC_TAXID_UNSET or _PC_COMPANY["nis_er"] == _PC_TAXID_UNSET:
    logger.warning(
        "Payroll: employer TRN / NIS Employer # not configured "
        "(PC_COMPANY_TRN / PC_COMPANY_NIS_ER). Payslips will print "
        "'%s' for the missing field(s) until these env vars are set.",
        _PC_TAXID_UNSET,
    )


def _jm_tax_year_bounds(period_end_iso: str):
    """Return (start_iso, end_iso) of the JM tax year that contains
    period_end. JM tax year runs Apr 1 → Mar 31."""
    from datetime import date as _date
    d = _date.fromisoformat(period_end_iso[:10])
    if d.month >= 4:
        start = _date(d.year, 4, 1)
        end   = _date(d.year + 1, 3, 31)
    else:
        start = _date(d.year - 1, 4, 1)
        end   = _date(d.year, 3, 31)
    return start.isoformat(), end.isoformat(), f"{start.year}/{str(end.year)[-2:]}"


def _payslip_ytd(subject_type: str, subject_id: int,
                  tax_year_start: str, period_end: str) -> dict:
    """Sum all payslips for this employee in the current tax year up to
    and including the current period_end. Hidden draft periods are
    excluded so YTD never leaks figures the employee hasn't seen."""
    from database import _con as _db_con
    con = _db_con()
    row = con.execute(
        """SELECT COALESCE(SUM(p.hours_regular),0)  AS hours_regular,
                  COALESCE(SUM(p.hours_overtime),0) AS hours_overtime,
                  COALESCE(SUM(p.fixed_salary),0)   AS fixed_salary,
                  COALESCE(SUM(p.bonus),0)          AS bonus,
                  COALESCE(SUM(p.gross_pay),0)      AS gross_pay,
                  COALESCE(SUM(p.paye_tax),0)       AS paye_tax,
                  COALESCE(SUM(p.nis),0)            AS nis,
                  COALESCE(SUM(p.nht),0)            AS nht,
                  COALESCE(SUM(p.education_tax),0)  AS education_tax,
                  COALESCE(SUM(p.other_deductions),0) AS other_deductions,
                  COALESCE(SUM(p.total_deductions),0) AS total_deductions,
                  COALESCE(SUM(p.net_pay),0)        AS net_pay
             FROM payslips p
             JOIN pay_periods pp ON p.pay_period_id = pp.id
            WHERE p.subject_type = ? AND p.subject_id = ?
              AND pp.status IN ('approved','paid')
              AND pp.period_end >= ?
              AND pp.period_end <= ?""",
        (subject_type, int(subject_id), tax_year_start, period_end),
    ).fetchone()
    con.close()
    return dict(row) if row else {}


def _payslip_employer_contribs(gross: float) -> dict:
    """Employer-side JM statutory contributions, derived from gross_pay.
    These aren't stored on the payslip (they're employer cost, not
    employee net) so we recompute on demand for the printable view."""
    g = float(gross or 0)
    nis_base = min(g, _JM_NIS_CEILING_MO)
    return {
        "nis_er":    round(nis_base * _JM_NIS_ER_RATE, 2),
        "nht_er":    round(g * _JM_NHT_ER_RATE, 2),
        "edtax_er":  round(g * _JM_EDTAX_ER_RATE, 2),
        "heart":     round(g * _JM_HEART_RATE, 2) if g >= _JM_HEART_THRESHOLD_MO else 0.0,
        "_rates": {
            "nis_er":   _JM_NIS_ER_RATE,
            "nht_er":   _JM_NHT_ER_RATE,
            "edtax_er": _JM_EDTAX_ER_RATE,
            "heart":    _JM_HEART_RATE,
            "heart_threshold_mo": _JM_HEART_THRESHOLD_MO,
            "nis_ceiling_mo":     _JM_NIS_CEILING_MO,
        },
    }


def _enrich_payslip_for_print(ps: dict) -> dict:
    """Adds .ytd, .employer_contribs, .company, .bank, .tax_year to
    a payslip dict. Non-destructive: existing keys are preserved.

    Bank + TRN + NIS# per-employee fields aren't stored yet — see the
    payslip schema in database.py. Until those columns exist, the
    print view shows 'On file' rather than fail. The operator confirmed
    in Q2/Q3 that these will be added later."""
    out = dict(ps)
    ty_start, ty_end, ty_label = _jm_tax_year_bounds(ps.get("period_end") or "")
    out["tax_year"] = {"start": ty_start, "end": ty_end, "label": ty_label}
    out["ytd"] = _payslip_ytd(ps["subject_type"], ps["subject_id"],
                                ty_start, ps.get("period_end") or "")
    out["employer_contribs"] = _payslip_employer_contribs(ps.get("gross_pay") or 0)
    out["company"] = dict(_PC_COMPANY)
    # Bank / TRN / NIS# placeholders. Mask last-4 once we have a real
    # account number to mask (per Q3 — mask all but last 4 with *).
    out["bank"] = {
        "bank_name":      "On file",
        "account_name":   ps.get("subject_name") or "",
        "account_masked": "****",
    }
    out["employee_ids"] = {
        "trn":   "On file",
        "nis":   "On file",
    }
    out["_jm_compliance_note"] = (
        "Calculated per Jamaica statutory rates "
        "(PAYE / NIS / NHT / Education Tax / HEART Trust)."
    )
    return out


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
    return _enrich_payslip_for_print(ps)


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
    return _enrich_payslip_for_print(ps)


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
    _check_low_stock(part_id)
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
    # Pass C: destination location for the warehouse stock grid.
    # Optional for backward compat with legacy receive callers; when
    # provided the receipt shows up in stock_by_location() and joins
    # the warehouse audit chain.
    to_location_id:    Optional[int] = None


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
                                    admin["id"], body.notes,
                                    to_location_id=body.to_location_id)
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
    ext  = _validate_photo_upload(file.filename, body)
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
    _require_admin_or_power(request)
    return get_invoice_metrics()


@app.get("/api/admin/invoices/gct-report")
def admin_invoice_gct_report(request: Request,
                             from_: Optional[str] = Query(None, alias="from"),
                             to: Optional[str] = None):
    """Accrual-basis output-GCT liability report (per month, per currency).
    Collection/global financial view → super_admin or a blanket power
    delegation, matching the invoices-metrics gate."""
    admin = _require_admin_or_power(request)
    report = get_gct_liability_report(from_date=from_, to_date=to)
    _audit_from(admin, "invoice.gct_report", request, target_type="invoice",
                after={"from": report["from"], "to": report["to"],
                       "currencies": list(report["totals_by_currency"].keys())})
    return report


@app.get("/api/admin/invoices/list")
def admin_invoice_list_v2_pre(request: Request,
                                status: Optional[str] = None,
                                from_: Optional[str] = Query(None, alias="from"),
                                to: Optional[str] = None,
                                page: int = 1,
                                limit: int = 20):
    _require_admin_or_power(request)
    return list_invoices(
        {"status": status, "from": from_, "to": to},
        page=page, limit=limit,
    )


@app.get("/api/admin/invoices/export.csv")
def admin_invoice_export_csv_pre(request: Request,
                                   status: Optional[str] = None,
                                   from_: Optional[str] = Query(None, alias="from"),
                                   to: Optional[str] = None):
    admin = _require_admin_or_power(request)
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
    _require_admin_or_power(request)
    return search_parts_catalog(q, limit=limit)


@app.get("/api/admin/fx-rates")
def admin_fx_rate_get_pre(request: Request,
                            currency: str,
                            effective_date: Optional[str] = None):
    _require_admin_or_power(request)
    cu = (currency or "").upper()
    if cu not in ("USD", "GBP"):
        raise HTTPException(400, "Invalid currency")
    rate = get_active_fx_rate(cu, effective_date)
    return rate or {}


@app.post("/api/admin/fx-rates")
async def admin_fx_rate_set_pre(request: Request):
    admin = _require_admin_or_power(request)
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
    _require_admin_or_power(request)
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

# ── Online payment provider (#1b) ────────────────────────────────────────────
# Provider-agnostic. The active provider is chosen by env so a real gateway
# (Stripe/Fygaro/WiPay/etc.) can be swapped in WITHOUT code changes — the agent
# cannot create gateway accounts, accept ToS, or make external calls, so the
# default 'stub' provider keeps the WHOLE loop functional locally: it issues a
# self-hosted checkout page and settles through the same chain-hashed payment
# path a real webhook would use. Real keys/secret live in env only.
PAYMENT_PROVIDER       = (os.environ.get("PAYMENT_PROVIDER", "stub") or "stub").lower()
PAYMENT_LINK_TTL_HOURS = int(os.environ.get("PAYMENT_LINK_TTL_HOURS", "72"))
# Shared secret a REAL provider signs its webhook with. Unset locally → the
# webhook endpoint refuses (503) rather than accepting unauthenticated settle
# requests. The stub never uses the webhook; it settles via the confirm route
# which is gated by the unguessable per-link token instead.
PAYMENT_WEBHOOK_SECRET = os.environ.get("PAYMENT_WEBHOOK_SECRET", "")


def _payment_link_outstanding(inv: dict) -> float:
    """JMD outstanding on an invoice (total − amount_paid), rounded to cents."""
    return round(float(inv["total"]) - float(inv.get("amount_paid") or 0), 2)


def _settle_payment_link(link: dict, *, provider_ref: str = None,
                         actor_label: str = "online") -> dict:
    """Settle a pending payment link: record the money against its invoice via
    the append-only, chain-hashed record_invoice_payment_v2 path (method='card',
    reusing the link's idempotency_key so a webhook retry / double-confirm can
    never double-credit), then flip the link to 'paid'. Idempotent end-to-end.

    Returns {already_paid|settled, payment_id, invoice_status, ...}. Raises
    HTTPException on a link that's not payable."""
    if link["status"] == "paid":
        return {"already_paid": True, "payment_id": link.get("payment_id"),
                "link_status": "paid"}
    if link["status"] != "pending":
        raise HTTPException(409, f"Payment link is '{link['status']}', not payable.")
    inv = get_invoice_by_id(link["invoice_id"], with_lines=False)
    if not inv:
        raise HTTPException(404, "Invoice not found")
    outstanding = _payment_link_outstanding(inv)
    # Cap the recorded amount at the live outstanding so a stale link (invoice
    # partly paid by other means after the link was issued) can't overpay.
    amount = min(float(link["amount"]), outstanding) if outstanding > 0 else 0.0
    if amount <= 0.005:
        # Nothing left to pay — treat as already settled and close the link.
        mark_payment_link_paid(link["id"], payment_id=0, provider_ref=provider_ref)
        return {"already_paid": True, "payment_id": None, "link_status": "paid",
                "invoice_status": inv["status"]}
    payload = {
        "amount_jmd":      amount,
        "payment_method":  "card",
        "payment_date":    datetime.now(timezone.utc).date().isoformat(),
        "notes":           f"Online payment ({link['provider']}) · link {link['token'][:8]}…",
        "idempotency_key": link["idempotency_key"],
    }
    result = record_invoice_payment_v2(
        link["invoice_id"], payload,
        recorded_by=None, recorded_by_label=actor_label, recorded_by_prid=None,
    )
    mark_payment_link_paid(link["id"], payment_id=result["id"],
                           provider_ref=provider_ref)
    after = get_invoice_by_id(link["invoice_id"], with_lines=False)
    return {
        "settled":        not result.get("duplicate", False),
        "duplicate":      result.get("duplicate", False),
        "payment_id":     result["id"],
        "amount":         amount,
        "invoice_status": after["status"],
        "link_status":    "paid",
    }


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
    admin = _require_admin_or_power(request)
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
    # The API/UI express tax_rate as a PERCENT (0–100), but the storage layer
    # (`_recompute_invoice_totals` does subtotal * tax_rate) and the v1 path
    # both treat tax_rate as a FRACTION. Convert at the boundary so the column
    # stays a fraction; otherwise tax_amount would be inflated 100×.
    body["tax_rate"]   = tax_rate / 100.0
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
    admin = _require_record_access(request, "invoice", invoice_id, write=True)
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
        # Percent (API/UI) → fraction (storage). See admin_invoice_create_v2.
        body["tax_rate"] = tr / 100.0
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
    admin = _require_record_access(request, "invoice", invoice_id, write=True)
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
    # Best-effort in-app notification to the billed customer (A5). Never
    # blocks the send: the status transition + audit are the source of truth.
    try:
        cust_id = inv.get("customer_id")
        if cust_id:
            _notify(
                "customer", int(cust_id), "invoice",
                f"Invoice {inv['invoice_number']} is ready",
                body="A new invoice has been issued to your account. "
                     "Open your portal to review it.",
                link="/portal", severity="info",
                dedupe_key=f"invoice_sent:{invoice_id}",
                dedupe_window_minutes=1440)
    except Exception as _e:
        logger.warning(f"[notif] invoice.sent customer notify failed: {_e}")
    # Best-effort email delivery (no-op locally without RESEND_API_KEY). Uses
    # get_customer_by_id for the DECRYPTED email — the invoice join carries
    # the ciphertext, not the plaintext address.
    try:
        cust_id = inv.get("customer_id")
        if cust_id:
            _send_invoice_email(get_customer_by_id(int(cust_id)), inv)
    except Exception as _e:
        logger.warning(f"[invoice] email dispatch failed for {invoice_id}: {_e}")
    return {"ok": True, "status": "sent"}


@app.post("/api/admin/invoices/{invoice_id}/cancel", response_model=OkResponse)
async def admin_invoice_cancel(request: Request, invoice_id: int):
    """Cancel an invoice. Reason is required and encrypted at rest."""
    admin = _require_record_access(request, "invoice", invoice_id, write=True)
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
    admin = _require_record_access(request, "invoice", invoice_id, write=True)
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
        # Client-supplied UUID per "Record Payment" click — reused on
        # retry so a double-tap / network-retry can't double-credit the
        # invoice. Optional; keyless callers fall back to the 30s window.
        "idempotency_key":      (str(body.get("idempotency_key")).strip()
                                 if body.get("idempotency_key") else None),
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
    _require_record_access(request, "invoice", invoice_id, write=False)
    inv = get_invoice_full(invoice_id)
    if not inv:
        raise HTTPException(404, "Invoice not found")
    return inv.get("payments", [])


# ── Estimates / quotes — admin endpoints (#3) ────────────────────────────────
def _emit_estimate_customer_notify(estimate_id: int, kind_title: str, body: str,
                                   dedupe_suffix: str):
    """Best-effort in-app + push to the estimate's customer."""
    try:
        est = get_estimate_by_id(estimate_id, with_lines=False)
        if est and est.get("customer_id"):
            _notify("customer", int(est["customer_id"]), "estimate", kind_title,
                    body=body, link="/portal", severity="info",
                    dedupe_key=f"estimate_{dedupe_suffix}:{estimate_id}",
                    dedupe_window_minutes=1440)
    except Exception as _e:
        logger.warning(f"[estimate] customer notify failed for {estimate_id}: {_e}")


def _admins_for_estimate_alerts() -> list:
    """Active admin ids whose role can view estimates."""
    try:
        from database import get_all_admin_users
        return [a["id"] for a in get_all_admin_users()
                if a.get("active") and _admin_can(a.get("role"), "estimate:view")]
    except Exception as _e:
        logger.warning(f"[estimate] admin audience lookup failed: {_e}")
        return []


def _notify_admins_estimate_decision(est: dict, decision: str, reason: str = None):
    """Tell the estimate's creator (or, failing that, estimate-viewing admins)
    that the customer approved/declined. Best-effort — never raises."""
    try:
        est_no = est.get("estimate_number") or f"#{est.get('id')}"
        sev = "success" if decision == "approved" else "warning"
        title = f"Estimate {est_no} {decision}"
        body = f"The customer has {decision} estimate {est_no}."
        if decision == "declined" and reason:
            body += f" Reason: {reason[:160]}"
        elif decision == "approved":
            body += " You can now convert it into an invoice."
        creator = est.get("created_by")
        recipients = [int(creator)] if creator else _admins_for_estimate_alerts()
        for aid in recipients:
            _notify("admin", aid, "estimate", title, body=body,
                    link="/admin#estimates", severity=sev,
                    dedupe_key=f"estimate_decision:{est.get('id')}",
                    dedupe_window_minutes=1440)
    except Exception as _e:
        logger.warning(f"[estimate] decision notify failed: {_e}")


@app.get("/api/admin/estimates")
def admin_list_estimates(request: Request, status: Optional[str] = None):
    _require_perm(request, "estimate:view")
    return get_all_estimates(status=status)


@app.get("/api/admin/estimates/{estimate_id}", response_model=Dict[str, Any])
def admin_get_estimate(request: Request, estimate_id: int):
    _require_perm(request, "estimate:view")
    est = get_estimate_by_id(estimate_id)
    if not est:
        raise HTTPException(404, "Estimate not found")
    return est


@app.post("/api/admin/estimates")
def admin_create_estimate(request: Request, body: EstimateCreate):
    admin = _require_perm(request, "estimate:create")
    data = body.model_dump()
    data["line_items"] = [li if isinstance(li, dict) else li.model_dump()
                          for li in data.get("line_items", [])]
    estimate_id = create_estimate(data, created_by=admin["id"])
    est = get_estimate_by_id(estimate_id, with_lines=False)
    _audit_from(admin, "estimate.create", request,
                target_type="estimate", target_id=estimate_id,
                target_label=est["estimate_number"],
                after={"customer_id": body.customer_id, "total": est["total"]})
    return {"id": estimate_id, "estimate_number": est["estimate_number"]}


@app.put("/api/admin/estimates/{estimate_id}", response_model=Dict[str, Any])
def admin_update_estimate(request: Request, estimate_id: int, body: EstimateUpdate):
    admin = _require_perm(request, "estimate:update")
    before = get_estimate_by_id(estimate_id, with_lines=False)
    if not before:
        raise HTTPException(404, "Estimate not found")
    if before["status"] != "draft":
        raise HTTPException(400, f"Cannot edit a {before['status']} estimate")
    data = body.model_dump()
    data["line_items"] = [li if isinstance(li, dict) else li.model_dump()
                          for li in data.get("line_items", [])]
    update_estimate(estimate_id, data)
    after = get_estimate_by_id(estimate_id, with_lines=False)
    _audit_from(admin, "estimate.update", request,
                target_type="estimate", target_id=estimate_id,
                target_label=before["estimate_number"],
                before={"total": before["total"]}, after={"total": after["total"]})
    return {"ok": True}


@app.post("/api/admin/estimates/{estimate_id}/send", response_model=Dict[str, Any])
def admin_estimate_send(request: Request, estimate_id: int):
    """draft → sent. Notifies the customer (in-app + push + best-effort email)."""
    admin = _require_perm(request, "estimate:send")
    est = get_estimate_by_id(estimate_id, with_lines=False)
    if not est:
        raise HTTPException(404, "Estimate not found")
    try:
        transition_estimate_status(estimate_id, "sent", actor_id=admin["id"])
    except ValueError as e:
        raise HTTPException(400, str(e))
    _audit_from(admin, "estimate.sent", request,
                target_type="estimate", target_id=estimate_id,
                target_label=est["estimate_number"],
                before={"status": est["status"]}, after={"status": "sent"})
    _emit_estimate_customer_notify(
        estimate_id, f"Estimate {est['estimate_number']} for your review",
        "A new estimate is waiting in your portal. Review it to approve or decline.",
        "sent")
    try:
        cust = get_customer_by_id(int(est["customer_id"]))
        _send_estimate_email(cust, get_estimate_by_id(estimate_id, with_lines=False))
    except Exception as _e:
        logger.warning(f"[estimate] email dispatch failed for {estimate_id}: {_e}")
    return {"ok": True, "status": "sent"}


@app.post("/api/admin/estimates/{estimate_id}/cancel", response_model=Dict[str, Any])
def admin_estimate_cancel(request: Request, estimate_id: int):
    admin = _require_perm(request, "estimate:update")
    est = get_estimate_by_id(estimate_id, with_lines=False)
    if not est:
        raise HTTPException(404, "Estimate not found")
    try:
        transition_estimate_status(estimate_id, "canceled", actor_id=admin["id"])
    except ValueError as e:
        raise HTTPException(400, str(e))
    _audit_from(admin, "estimate.canceled", request,
                target_type="estimate", target_id=estimate_id,
                target_label=est["estimate_number"],
                before={"status": est["status"]}, after={"status": "canceled"})
    return {"ok": True, "status": "canceled"}


@app.post("/api/admin/estimates/{estimate_id}/convert", response_model=Dict[str, Any])
def admin_estimate_convert(request: Request, estimate_id: int):
    """Convert an APPROVED estimate into a draft invoice."""
    admin = _require_perm(request, "estimate:convert")
    est = get_estimate_by_id(estimate_id, with_lines=False)
    if not est:
        raise HTTPException(404, "Estimate not found")
    try:
        invoice_id = convert_estimate_to_invoice(estimate_id, created_by=admin["id"])
    except ValueError as e:
        raise HTTPException(400, str(e))
    inv = get_invoice_by_id(invoice_id, with_lines=False)
    _audit_from(admin, "estimate.converted", request,
                target_type="estimate", target_id=estimate_id,
                target_label=est["estimate_number"],
                after={"invoice_id": invoice_id,
                       "invoice_number": inv["invoice_number"] if inv else None})
    return {"ok": True, "invoice_id": invoice_id,
            "invoice_number": inv["invoice_number"] if inv else None}


@app.delete("/api/admin/estimates/{estimate_id}", response_model=OkResponse)
def admin_delete_estimate(request: Request, estimate_id: int):
    admin = _require_perm(request, "estimate:delete")
    est = get_estimate_by_id(estimate_id, with_lines=False)
    if not est:
        raise HTTPException(404, "Estimate not found")
    if est["status"] not in ("draft", "canceled"):
        raise HTTPException(400, "Only draft or canceled estimates can be deleted")
    delete_estimate(estimate_id)
    _audit_from(admin, "estimate.delete", request,
                target_type="estimate", target_id=estimate_id,
                target_label=est["estimate_number"], before=est)
    return {"ok": True}


# Customer-side invoice access
@app.get("/api/portal/invoices")
def portal_invoices(request: Request):
    customer_id = _require_customer(request)
    return get_customer_invoices(customer_id)


@app.get("/api/portal/pm-contracts")
def portal_pm_contracts(request: Request):
    """The logged-in customer's own PM contracts (read-only, curated shape).
    Internal-only fields (notes, created_by, generation bookkeeping) are
    omitted; upcoming scheduled PM-visit dates are surfaced so the client can
    see what's coming."""
    customer_id = _require_customer(request)
    today = datetime.now(timezone.utc).date().isoformat()
    out = []
    for c in list_pm_contracts({"customer_id": customer_id}):
        upcoming = [v["scheduled_date"] for v in list_visits_for_contract(c["id"])
                    if v["status"] == "scheduled" and (v["scheduled_date"] or "") >= today]
        out.append({
            "contract_code": c["contract_code"],
            "title": c.get("title") or "",
            "start_date": c["start_date"],
            "end_date": c["end_date"],
            "frequency": c["frequency"],
            "contract_value": c["contract_value"],
            "status": c["status"],
            "upcoming_visits": sorted(upcoming),
        })
    return {"contracts": out, "count": len(out)}


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


@app.post("/api/portal/invoices/{invoice_id}/pay", response_model=Dict[str, Any])
def portal_invoice_pay(request: Request, invoice_id: int):
    """Customer kicks off an online payment for one of their OWN outstanding
    invoices. Creates (or reuses) a pending payment link and returns a
    tokenised checkout URL.

    With the local 'stub' provider the checkout_url is a self-hosted page that
    simulates a gateway; swapping PAYMENT_PROVIDER + keys to a real gateway
    would instead create a remote checkout session and return ITS url here —
    no other code changes. IDOR-safe: a foreign/unknown invoice 404s."""
    customer_id = _require_customer(request)
    _enforce_rate(request, "invpay", str(customer_id),
                  max_attempts=20, window_seconds=3600,
                  message="Too many payment attempts in the last hour. Please try later.")
    inv = get_invoice_by_id(invoice_id, with_lines=False)
    if not inv or inv["customer_id"] != customer_id or inv["status"] == "draft":
        raise HTTPException(404, "Invoice not found")
    if inv["status"] in ("paid", "cancelled"):
        raise HTTPException(400, f"This invoice is '{inv['status']}' — nothing to pay.")
    outstanding = _payment_link_outstanding(inv)
    if outstanding <= 0.005:
        raise HTTPException(400, "This invoice has no outstanding balance.")

    # Reuse a still-live link rather than minting a fresh token on every click.
    link = get_active_payment_link_for_invoice(invoice_id)
    if not link:
        token = _secrets.token_urlsafe(32)
        idem  = "pl_" + _secrets.token_hex(16)
        expires = (datetime.now(timezone.utc)
                   + timedelta(hours=PAYMENT_LINK_TTL_HOURS)).isoformat()
        link = create_payment_link(
            invoice_id, amount=outstanding,
            currency=(inv.get("currency") or "JMD"),
            provider=PAYMENT_PROVIDER, token=token, idempotency_key=idem,
            expires_at=expires, created_by_customer=customer_id,
        )
    cust = get_customer_by_id(customer_id)
    _audit_customer(cust, "portal.payment_initiated", request,
                    target_type="invoice", target_id=invoice_id,
                    target_label=inv.get("invoice_number"),
                    after={"amount": outstanding, "provider": PAYMENT_PROVIDER,
                           "link_id": link["id"]})
    return {
        "ok": True,
        "provider": link["provider"],
        "amount": link["amount"],
        "currency": link["currency"],
        "invoice_number": inv.get("invoice_number"),
        # For the stub provider this is our own checkout page. A real provider
        # would put its hosted-checkout URL here instead.
        "checkout_url": f"/pay/{link['token']}",
    }


# ── Stub checkout page + settlement (local provider only) ────────────────────
@app.get("/pay/{token}", response_class=HTMLResponse)
def stub_checkout_page(token: str):
    """Self-hosted checkout page for the LOCAL STUB provider. Stands in for a
    real gateway's hosted-checkout screen so the whole pay loop works offline.
    The unguessable token is the bearer of authority (same model as a real
    gateway checkout link). With a real provider configured this route is moot —
    the customer is sent to the provider's own page instead."""
    link = get_payment_link_by_token(token)
    if not link:
        return HTMLResponse("<h1>Payment link not found</h1>", status_code=404)
    inv = get_invoice_by_id(link["invoice_id"], with_lines=False)
    inv_no = (inv or {}).get("invoice_number", "—")
    cur = link["currency"]
    amt = f"{float(link['amount']):,.2f}"
    if link["status"] == "paid":
        body = ('<div class="state ok"><h1>✓ Already paid</h1>'
                f'<p>Invoice {inv_no} has been settled. You can close this window.</p></div>')
    elif link["status"] != "pending":
        body = (f'<div class="state"><h1>Link {link["status"]}</h1>'
                '<p>This payment link is no longer active.</p></div>')
    else:
        body = f'''
        <div class="card">
          <div class="badge">TEST / STUB PROVIDER</div>
          <h1>Pay invoice {inv_no}</h1>
          <div class="amt">{cur}&nbsp;${amt}</div>
          <p class="sub">This is a local simulation of an online card payment.
             No real card is charged. Clicking “Pay now” settles the invoice
             through the same recorded-payment path a real gateway webhook uses.</p>
          <button id="payBtn" onclick="pay()">Pay now</button>
          <div id="msg" class="msg"></div>
        </div>
        <script>
          async function pay() {{
            var b = document.getElementById('payBtn'),
                m = document.getElementById('msg');
            b.disabled = true; b.textContent = 'Processing…';
            try {{
              var r = await fetch('/api/pay/{token}/confirm', {{ method:'POST' }});
              var d = await r.json();
              if (r.ok) {{
                document.querySelector('.card').innerHTML =
                  '<div class="state ok"><h1>✓ Payment complete</h1>'
                  + '<p>Thank you! Invoice {inv_no} is now '
                  + (d.invoice_status === 'paid' ? 'fully paid' : 'updated')
                  + '. You can close this window and return to your portal.</p></div>';
              }} else {{
                m.textContent = (d.detail || 'Payment failed. Please try again.');
                b.disabled = false; b.textContent = 'Pay now';
              }}
            }} catch (e) {{
              m.textContent = 'Network error — please try again.';
              b.disabled = false; b.textContent = 'Pay now';
            }}
          }}
        </script>'''
    html = f'''<!doctype html><html lang="en"><head><meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>PrimeCool — Secure Payment</title>
    <style>
      :root {{ --navy:#0B2545; --steel:#1B4F82; --teal:#22A08A; --teal-deep:#1A7A6A; }}
      * {{ box-sizing:border-box; }}
      body {{ margin:0; font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
              background:linear-gradient(135deg,var(--navy),var(--steel));
              min-height:100vh; display:flex; align-items:center; justify-content:center; padding:20px; }}
      .card,.state {{ background:#fff; border-radius:16px; padding:36px 32px; max-width:420px; width:100%;
               box-shadow:0 20px 60px rgba(0,0,0,.3); text-align:center; }}
      .badge {{ display:inline-block; background:#fff4e5; color:#9a5b00; font-size:11px; font-weight:800;
               letter-spacing:.6px; padding:5px 10px; border-radius:6px; margin-bottom:14px; }}
      h1 {{ font-size:20px; color:var(--navy); margin:0 0 8px; }}
      .amt {{ font-size:38px; font-weight:800; color:var(--teal-deep); margin:10px 0 14px; }}
      .sub {{ font-size:13px; color:#5b6b7b; line-height:1.55; margin:0 0 22px; }}
      button {{ background:var(--teal); color:#fff; border:0; border-radius:10px; font-size:16px;
               font-weight:700; padding:14px 22px; width:100%; cursor:pointer; }}
      button:hover {{ background:var(--teal-deep); }}
      button:disabled {{ opacity:.6; cursor:default; }}
      .msg {{ color:#b00020; font-size:13px; margin-top:14px; min-height:18px; }}
      .state.ok h1 {{ color:var(--teal-deep); }}
      .state p {{ color:#5b6b7b; font-size:14px; line-height:1.6; }}
    </style></head><body>{body}</body></html>'''
    return HTMLResponse(html)


@app.post("/api/pay/{token}/confirm", response_model=Dict[str, Any])
def stub_payment_confirm(token: str, request: Request):
    """STUB-provider settlement. Stands in for the gateway callback: the
    unguessable token authorises the settle. Only valid while the active
    provider is 'stub' — a real deployment settles via /api/payments/webhook
    instead, and this route refuses so a stub confirm can't be replayed against
    a real-provider link."""
    link = get_payment_link_by_token(token)
    if not link:
        raise HTTPException(404, "Payment link not found")
    if link["provider"] != "stub" or PAYMENT_PROVIDER != "stub":
        raise HTTPException(409, "This link is settled by the payment provider, "
                                 "not by the stub confirm route.")
    # Expiry check — a stale pending link can't be settled.
    if link["status"] == "pending" and link.get("expires_at") \
            and link["expires_at"] < datetime.now(timezone.utc).isoformat():
        cancel_payment_link(link["id"])
        raise HTTPException(410, "This payment link has expired. Please start a new payment.")
    out = _settle_payment_link(link, provider_ref=f"stub_{_secrets.token_hex(6)}",
                               actor_label="online (stub)")
    inv = get_invoice_by_id(link["invoice_id"], with_lines=False)
    # Audit under the owning customer so it threads into their portal history.
    cust = get_customer_by_id(link["created_by_customer"]) if link.get("created_by_customer") else None
    if cust and not out.get("already_paid"):
        _audit_customer(cust, "portal.payment_settled", request,
                        target_type="invoice", target_id=link["invoice_id"],
                        target_label=(inv or {}).get("invoice_number"),
                        after={"amount": out.get("amount"), "provider": "stub",
                               "payment_id": out.get("payment_id"),
                               "invoice_status": out.get("invoice_status")})
    return {"ok": True, **out,
            "invoice_status": out.get("invoice_status") or (inv or {}).get("status")}


@app.post("/api/payments/webhook", response_model=Dict[str, Any])
async def payments_webhook(request: Request):
    """Real-provider settlement entry point. Provider-agnostic shell:
      • Requires PAYMENT_WEBHOOK_SECRET to be configured (else 503) — we never
        accept an unauthenticated settle.
      • Verifies an HMAC-SHA256 signature over the raw body, sent in the
        `X-PrimeCool-Signature` header. (A specific gateway's header/scheme is
        adapted here when its keys are wired in.)
      • Looks up the link by the `token` (or `provider_ref`) in the payload and
        settles it through the same idempotent path as the stub.
    Locally — with no secret set — this returns 503, which is correct: there is
    no real provider to receive callbacks from."""
    if not PAYMENT_WEBHOOK_SECRET:
        raise HTTPException(503, "No payment provider webhook configured.")
    raw = await request.body()
    sig = request.headers.get("X-PrimeCool-Signature", "")
    expected = hmac.new(PAYMENT_WEBHOOK_SECRET.encode(), raw, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expected):
        raise HTTPException(401, "Invalid webhook signature")
    try:
        payload = _json.loads(raw.decode("utf-8") or "{}")
    except Exception:
        raise HTTPException(400, "Malformed webhook body")
    token = payload.get("token") or payload.get("client_reference_id") or ""
    if not token:
        raise HTTPException(400, "Webhook missing payment token")
    link = get_payment_link_by_token(token)
    if not link:
        raise HTTPException(404, "Unknown payment link")
    # Only settle on a success-type event. Unknown event types ack with 200 so
    # the provider doesn't retry, but take no action.
    event = (payload.get("event") or payload.get("type") or "").lower()
    if event and "succ" not in event and "paid" not in event and "complete" not in event:
        return {"ok": True, "ignored": event}
    out = _settle_payment_link(link, provider_ref=payload.get("provider_ref"),
                               actor_label=f"online ({link['provider']})")
    return {"ok": True, **out}


# ── Estimates / quotes — customer portal endpoints (#3) ──────────────────────
@app.get("/api/portal/estimates")
def portal_estimates(request: Request):
    """The logged-in customer's own estimates (drafts/canceled excluded)."""
    customer_id = _require_customer(request)
    return get_customer_estimates(customer_id)


def _portal_estimate_or_404(request: Request, estimate_id: int):
    """Fetch an estimate that belongs to the caller and is visible to them
    (not a draft / canceled). IDOR-safe indistinguishable 404. Returns
    (customer_id, estimate)."""
    customer_id = _require_customer(request)
    est = get_estimate_by_id(estimate_id)
    if (not est or est["customer_id"] != customer_id
            or est["status"] in ("draft", "canceled")):
        raise HTTPException(404, "Estimate not found")
    return customer_id, est


@app.get("/api/portal/estimates/{estimate_id}", response_model=Dict[str, Any])
def portal_estimate_detail(request: Request, estimate_id: int):
    customer_id, est = _portal_estimate_or_404(request, estimate_id)
    cust = get_customer_by_id(customer_id)
    _audit_customer(cust, "portal.viewed_estimate", request,
                    target_type="estimate", target_id=estimate_id,
                    target_label=est.get("estimate_number"))
    # Drop the internal decline_reason from the customer-facing payload — it's
    # their own input but we don't echo it back as part of the quote view.
    est.pop("decline_reason", None)
    return est


@app.post("/api/portal/estimates/{estimate_id}/approve", response_model=Dict[str, Any])
def portal_estimate_approve(request: Request, estimate_id: int):
    """Customer approves a sent estimate (sent → approved)."""
    customer_id, est = _portal_estimate_or_404(request, estimate_id)
    if est["status"] != "sent":
        raise HTTPException(400, f"This estimate cannot be approved (it is '{est['status']}').")
    try:
        transition_estimate_status(estimate_id, "approved")
    except ValueError as e:
        raise HTTPException(400, str(e))
    cust = get_customer_by_id(customer_id)
    _audit_customer(cust, "portal.approved_estimate", request,
                    target_type="estimate", target_id=estimate_id,
                    target_label=est.get("estimate_number"))
    _notify_admins_estimate_decision(est, "approved", reason=None)
    return {"ok": True, "status": "approved"}


@app.post("/api/portal/estimates/{estimate_id}/decline", response_model=Dict[str, Any])
def portal_estimate_decline(request: Request, estimate_id: int, body: EstimateDecline):
    """Customer declines a sent estimate (sent → declined). Reason optional,
    encrypted at rest."""
    customer_id, est = _portal_estimate_or_404(request, estimate_id)
    if est["status"] != "sent":
        raise HTTPException(400, f"This estimate cannot be declined (it is '{est['status']}').")
    reason = (body.reason or "").strip()[:1000]
    try:
        transition_estimate_status(estimate_id, "declined", decline_reason=reason)
    except ValueError as e:
        raise HTTPException(400, str(e))
    cust = get_customer_by_id(customer_id)
    _audit_customer(cust, "portal.declined_estimate", request,
                    target_type="estimate", target_id=estimate_id,
                    target_label=est.get("estimate_number"))
    _notify_admins_estimate_decision(est, "declined", reason=reason)
    return {"ok": True, "status": "declined"}


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


# ── Database backups (super_admin only) ─────────────────────────────────────
# A backup artifact is an encrypted, gzipped, point-in-time snapshot of the
# ENTIRE database (invoices, payroll, the chained audit trail). It therefore
# carries every secret the app holds, so the surface is locked to super_admin
# and every create/download/verify is audit-logged. Restore is deliberately
# NOT an HTTP action — overwriting the live DB is a console operation
# (`python3 backup.py restore <name> <dest>`); the API only proves a backup is
# restorable via verify.
@app.get("/api/admin/backups")
def admin_backups_list(request: Request):
    admin = _require_super_admin(request)
    _audit_from(admin, "backup.list", request, target_type="backup", target_id=None)
    return {"backups": _backup.list_backups(), "config": _backup.config_summary()}


@app.post("/api/admin/backups")
def admin_backups_create(request: Request):
    admin = _require_super_admin(request)
    try:
        meta = _backup.create_backup(reason="manual",
                                     actor=f"admin:{admin['id']}")
    except Exception as e:
        logger.error(f"[backup] manual create failed: {e}")
        raise HTTPException(500, f"backup failed: {e}")
    _audit_from(admin, "backup.create", request,
                target_type="backup", target_id=None, target_label=meta["name"],
                after={"encrypted": meta["encrypted"],
                       "artifact_bytes": meta["artifact_bytes"],
                       "sha256": meta["artifact_sha256"]})
    return meta


@app.get("/api/admin/backups/{name}/download")
def admin_backups_download(request: Request, name: str):
    admin = _require_super_admin(request)
    # Step-up: downloading the whole DB demands a fresh MFA proof, same bar as
    # a Highly Sensitive document.
    _require_recent_mfa(request, admin)
    try:
        path = _backup._safe_path(name)
    except (ValueError, FileNotFoundError):
        raise HTTPException(404, "backup not found")
    _audit_from(admin, "backup.download", request,
                target_type="backup", target_id=None, target_label=name)
    return FileResponse(path, media_type="application/octet-stream", filename=name)


@app.post("/api/admin/backups/{name}/verify")
def admin_backups_verify(request: Request, name: str):
    admin = _require_super_admin(request)
    try:
        result = _backup.verify_backup(name)
    except (ValueError, FileNotFoundError):
        raise HTTPException(404, "backup not found")
    except Exception as e:
        logger.error(f"[backup] verify failed for {name}: {e}")
        raise HTTPException(500, f"verify failed: {e}")
    _audit_from(admin, "backup.verify", request,
                target_type="backup", target_id=None, target_label=name,
                after={"ok": result["ok"], "integrity": result["integrity"]})
    return result


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


class AlertBulkResolveBody(BaseModel):
    ids: List[int]
    note: Optional[str] = None
    status: Optional[str] = "resolved"  # 'resolved' | 'dismissed'


@app.post("/api/admin/security/alerts/bulk-resolve")
def admin_bulk_resolve_alerts(request: Request, body: AlertBulkResolveBody):
    """Resolve / dismiss multiple open alerts in a single round-trip.

    Per-row endpoint stays the unit primitive; this is a wrapper so the
    admin UI can clear a burst of low-severity alerts (overtime
    pending, day-off sign-in, etc.) without a per-row prompt loop.
    Already-closed alerts are skipped silently — the response reports
    the count so the UI can show "Resolved 7 of 9 (2 were already
    closed)" when selections go stale between fetch and submit."""
    admin = _require_perm(request, "security:resolve_alerts")
    if body.status not in ("resolved", "dismissed"):
        raise HTTPException(400, "status must be 'resolved' or 'dismissed'")
    if not body.ids:
        raise HTTPException(400, "ids must be a non-empty list")
    if len(body.ids) > 500:
        # Hard ceiling to prevent runaway requests.
        raise HTTPException(400, "too many alerts in one batch (max 500)")
    result = resolve_security_alerts_bulk(
        body.ids, admin["id"], note=body.note or "", status=body.status,
    )
    _audit_from(admin, f"security.alert_{body.status}_bulk", request,
                target_type="security_alert",
                target_label=f"{result['updated']} of {result['requested']}",
                after={"ids_updated": result["ids_updated"],
                       "requested": result["requested"],
                       "skipped_already_closed":
                           result["skipped_already_closed"],
                       "note": body.note or ""})
    return {"ok": True, **result}


# ---------------------------------------------------------------------------
# In-app notification centre (A5).
#
# These belong to EVERY authenticated subject — admin, technician, or
# customer — so they gate on identity via `_require_viewer`, never on a
# feature permission. A viewer only ever sees rows addressed to their own
# (recipient_type, recipient_id) pair; the helpers enforce that scoping in
# SQL, so there is no cross-subject leak even though the route is shared.
# ---------------------------------------------------------------------------
@app.get("/api/notifications")
def list_my_notifications(request: Request, unread: int = 0, limit: int = 50):
    from database import list_notifications, count_unread_notifications
    v = _require_viewer(request)
    limit = max(1, min(int(limit or 50), 200))
    items = list_notifications(v["type"], v["id"],
                               only_unread=bool(unread), limit=limit)
    return {"items": items,
            "unread": count_unread_notifications(v["type"], v["id"])}


@app.get("/api/notifications/unread-count")
def my_unread_notification_count(request: Request):
    """Tiny polling endpoint for the bell badge — returns just the integer
    so the shared widget can poll cheaply from all six pages."""
    from database import count_unread_notifications
    v = _require_viewer(request)
    return {"unread": count_unread_notifications(v["type"], v["id"])}


@app.post("/api/notifications/{notif_id}/read")
def mark_my_notification_read(request: Request, notif_id: int):
    from database import mark_notification_read, count_unread_notifications
    v = _require_viewer(request)
    ok = mark_notification_read(notif_id, v["type"], v["id"])
    if not ok:
        # Either it does not exist or it is not addressed to this viewer.
        raise HTTPException(404, "Notification not found")
    return {"ok": True,
            "unread": count_unread_notifications(v["type"], v["id"])}


@app.post("/api/notifications/read-all")
def mark_all_my_notifications_read(request: Request):
    from database import mark_all_notifications_read
    v = _require_viewer(request)
    n = mark_all_notifications_read(v["type"], v["id"])
    return {"ok": True, "marked": n, "unread": 0}


# ---------------------------------------------------------------------------
# Web Push (A5) — VAPID + RFC 8291. The browser needs the VAPID public key to
# subscribe; the subscription (endpoint + keys) is stored per signed-in
# subject. Actual delivery is gated by WEBPUSH_ENABLED (off in local dev), so
# these endpoints only ever store/remove subscriptions locally — no external
# call. `configured` tells the client whether push is even available.
# ---------------------------------------------------------------------------
@app.get("/api/push/vapid-public-key")
def push_vapid_public_key():
    import webpush as _wp
    key = _wp.get_public_key()
    return {"key": key, "configured": bool(key), "enabled": _wp.is_enabled()}


# Recognised Web Push service host suffixes. A subscription endpoint is just a
# URL the server later POSTs to, so we constrain it to known push providers to
# avoid storing an attacker-chosen URL (mild SSRF / abuse vector).
_PUSH_HOST_SUFFIXES = (
    ".googleapis.com",              # FCM (Chrome, Edge, Android)
    ".push.services.mozilla.com",  # Firefox
    ".notify.windows.com",         # WNS (legacy Edge)
    ".push.apple.com",             # Safari / Apple
)


def _is_valid_push_endpoint(endpoint: str) -> bool:
    from urllib.parse import urlparse
    try:
        u = urlparse(endpoint)
    except Exception:
        return False
    if u.scheme != "https" or not u.hostname:
        return False
    host = u.hostname.lower()
    return any(host == s.lstrip(".") or host.endswith(s)
               for s in _PUSH_HOST_SUFFIXES)


@app.post("/api/push/subscribe")
async def push_subscribe(request: Request):
    """Store a browser push subscription for the current signed-in subject.
    Identity-gated only (any admin/tech/customer may subscribe their own
    browser) — never a feature permission. Auth is checked BEFORE the body is
    parsed so an unauthenticated caller gets 401 (not a 422 schema probe)."""
    v = _require_viewer(request)
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(400, "invalid JSON body")
    if not isinstance(body, dict):
        raise HTTPException(400, "invalid body")
    keys = body.get("keys") or {}
    endpoint = body.get("endpoint")
    p256dh = keys.get("p256dh") if isinstance(keys, dict) else None
    auth = keys.get("auth") if isinstance(keys, dict) else None
    if not (endpoint and p256dh and auth):
        raise HTTPException(400, "endpoint, keys.p256dh and keys.auth are required")
    if not _is_valid_push_endpoint(endpoint):
        raise HTTPException(400, "endpoint is not a recognised push service URL")
    from database import upsert_push_subscription
    ua = (request.headers.get("user-agent", "") or "")[:255]
    sid = upsert_push_subscription(v["type"], v["id"], endpoint=endpoint,
                                   p256dh=p256dh, auth=auth, user_agent=ua)
    return {"ok": True, "id": sid}


@app.post("/api/push/unsubscribe")
async def push_unsubscribe(request: Request):
    """Remove a push subscription. Requires a signed-in subject; the delete is
    owner-scoped so a subject can only remove its own subscriptions. Auth is
    checked before the body is parsed (401, not a 422 schema probe)."""
    v = _require_viewer(request)
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(400, "invalid JSON body")
    endpoint = body.get("endpoint") if isinstance(body, dict) else None
    if not endpoint:
        raise HTTPException(400, "endpoint is required")
    from database import delete_push_subscription
    delete_push_subscription(endpoint, recipient_type=v["type"], recipient_id=v["id"])
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
        # New customer — phone-on-file is the value the admin just
        # entered in this request. If they're trying to set the PIN
        # to that phone, refuse + alert.
        _validate_pin_or_400(
            body.pin, phone_on_file=getattr(body, "phone", None),
            actor_type="admin", actor_id=admin["id"],
            label=f"new customer '{body.name}'",
        )
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
    cust = get_customer_by_id(customer_id)
    if not cust:
        raise HTTPException(404, "Customer not found")
    _validate_pin_or_400(
        body.pin, phone_on_file=cust.get("phone"),
        actor_type="customer", actor_id=customer_id,
        label=cust.get("customer_code") or f"customer#{customer_id}",
    )
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
# Delegation retrofit (2026-06-06): every record-scoped admin endpoint whose
# path names a delegatable record (customer/visit/invoice/technician) now flows
# through this guard, and collection/global endpoints flow through
# `_require_admin_or_power`. Only meta-governance surfaces stay hard
# super_admin: the access-denied audit reader and the delegation
# regrant-request approve/deny queue (a power-delegate must not self-approve
# delegation governance). See docs/FIXMES.md "Resolved".
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


# ── Collection-scope access guard (super_admin OR a blanket "power" grant) ──
# `_require_record_access` covers endpoints that name a single delegatable
# record (customer/visit/invoice/technician). Collection / global endpoints
# (invoice list, fx-rates, parts search, …) have no record_id to scope a
# record/record_type delegation against, so the only delegation that can stand
# in for the super_admin role here is a blanket `power` grant. Non-delegated
# non-super admins are denied exactly as `_require_super_admin` would deny them
# — this widens access ONLY for active power-delegation holders.
def _require_admin_or_power(request: Request, action: str = "super_admin_only"):
    from database import lookup_record_delegation as _lookup_deleg
    admin = _require_admin(request)
    if admin.get("role") == "super_admin":
        try:
            _audit_from(admin, "access.role_allow", request,
                        target_type=None, target_id=None)
        except Exception as _e:
            logger.warning(f"[delegation] audit-write failed: {_e}")
        return admin
    # A power grant matches any record_type unconditionally (priority 3 in
    # lookup_record_delegation), so a sentinel record_type/id surfaces it while
    # never matching a record/record_type-scoped grant.
    deleg = None
    try:
        deleg = _lookup_deleg(admin["id"], "__collection__", 0)
    except Exception as _e:
        logger.warning(f"[delegation] power lookup failed: {_e}")
    if deleg and deleg.get("delegation_type") == "power":
        verbose = os.environ.get("DELEGATION_VERBOSE_AUDIT", "1") != "0"
        if verbose:
            try:
                _audit_from(admin, "delegation.accessed", request,
                            target_type=None, target_id=None,
                            after={"delegation_id": deleg["id"],
                                   "delegation_type": "power",
                                   "scope": "collection"})
            except Exception as _e:
                logger.warning(f"[delegation] audit-write failed: {_e}")
        return admin
    _deny_response(reason="not_super_admin",
                   viewer_kind="admin", viewer_id=admin["id"],
                   action=action,
                   resource_type=None, resource_id=None,
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
        # MFA is hard-required for ALL customers (residential + commercial)
        # at portal_login since the pre-launch security review (Track B,
        # commit 2e8ead0). No per-customer flag is needed — the login
        # handler intercepts every account without mfa_enabled and routes
        # them through enrolment before issuing a session.

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


@app.get("/api/admin/customers/{customer_id}/equipment",
         response_model=List[Dict[str, Any]])
def admin_list_equipment(request: Request, customer_id: int):
    """super_admin sees the enriched view (PM/CM dates + decrypted serial/
    location/notes) and an audit row is written. Other roles fall back to
    the legacy basic equipment list — needed because the existing Customers
    tab "View" button is wired to this endpoint for all admin roles.

    response_model was Dict[str, Any] but both backing helpers
    (get_customer_equipment_with_visits, get_customer_equipment) return
    a LIST of equipment rows. FastAPI tried to coerce list → dict and
    500'd with ResponseValidationError on every call — fully broke the
    Equipment Register on customer detail pages. Field-reported by
    super_admin May 2026."""
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
    """Delegation-aware: paginated reverse-chronological service history."""
    admin = _require_record_access(request, "customer", customer_id, write=False)
    cust = get_customer_by_id(customer_id)
    if not cust:
        raise HTTPException(404, "Customer not found")
    _audit_from(admin, "customer.visits_view", request,
                target_type="customer", target_id=customer_id,
                target_label=cust.get("customer_code"),
                after={"page": page, "limit": limit})
    return get_customer_visits_paginated(customer_id, page=page, limit=limit)


# ── Preventive-maintenance (PM) contracts ───────────────────────────────────
# A contract is a customer-scoped record, so per-contract endpoints flow
# through the delegation-aware `_require_record_access(... "customer" ...)`
# guard (a customer-delegate can manage that customer's contracts). The
# cross-customer list + the manual generation trigger are collection/global
# operations, so they flow through `_require_admin_or_power` (super_admin or a
# blanket power delegation). The nightly generator runs unattended (cron).
_PM_FREQUENCIES = ("monthly", "quarterly", "semiannual", "annual")
_PM_STATUSES    = ("active", "paused", "expired", "cancelled")


def _validate_pm_contract(*, start_date=None, end_date=None, frequency=None,
                          contract_value=None, status=None,
                          require_all=True) -> list:
    """Returns a list of {field, message} dicts. Empty = OK. When
    require_all is False (PATCH), only validates the fields that are present."""
    errs = []
    def _is_ymd(s):
        return bool(s) and bool(re.fullmatch(r"\d{4}-\d{2}-\d{2}", str(s)))
    if frequency is not None or require_all:
        if (frequency or "").lower() not in _PM_FREQUENCIES:
            errs.append({"field": "frequency",
                         "message": "Must be one of: monthly, quarterly, semiannual, annual"})
    if start_date is not None or require_all:
        if not _is_ymd(start_date):
            errs.append({"field": "start_date", "message": "Start date must be ISO date (YYYY-MM-DD)"})
    if end_date is not None or require_all:
        if not _is_ymd(end_date):
            errs.append({"field": "end_date", "message": "End date must be ISO date (YYYY-MM-DD)"})
    # Range check only when both ends are valid ISO dates.
    if _is_ymd(start_date) and _is_ymd(end_date) and str(end_date) < str(start_date):
        errs.append({"field": "end_date", "message": "End date must be on or after the start date"})
    if contract_value is not None:
        try:
            if float(contract_value) < 0:
                errs.append({"field": "contract_value", "message": "Contract value cannot be negative"})
        except (TypeError, ValueError):
            errs.append({"field": "contract_value", "message": "Contract value must be a number"})
    if status is not None and status not in _PM_STATUSES:
        errs.append({"field": "status",
                     "message": "Must be one of: active, paused, expired, cancelled"})
    return errs


def _pm_contract_with_visits(contract: dict) -> dict:
    """Decorate a contract dict with its materialised visits + the full
    computed due-date schedule for the term."""
    out = dict(contract)
    out["visits"] = list_visits_for_contract(contract["id"])
    out["schedule"] = pm_contract_schedule(
        contract.get("start_date"), contract.get("end_date"), contract.get("frequency"))
    return out


@app.get("/api/admin/pm-contracts", response_model=Dict[str, Any])
def admin_pm_contracts_list(request: Request,
                            customer_id: Optional[int] = None,
                            status: Optional[str] = None,
                            hub_id: Optional[int] = None):
    """List PM contracts. Cross-customer view is a collection op (power-or-super).
    When scoped to a single customer_id, honour a customer-record delegation so
    a customer-delegate can see that customer's contracts."""
    if customer_id is not None:
        admin = _require_record_access(request, "customer", customer_id, write=False)
    else:
        admin = _require_admin_or_power(request)
    filters = {}
    if customer_id is not None:
        filters["customer_id"] = customer_id
    if status:
        filters["status"] = status
    if hub_id is not None:
        filters["hub_id"] = hub_id
    rows = list_pm_contracts(filters)
    _audit_from(admin, "pm_contract.list", request,
                target_type="customer", target_id=customer_id,
                after={"count": len(rows), "status": status})
    return {"contracts": rows, "count": len(rows)}


@app.post("/api/admin/pm-contracts", response_model=Dict[str, Any])
def admin_pm_contract_create(request: Request, body: PMContractCreate):
    # Customer-scoped write — a customer-record (read_write) delegate may create.
    admin = _require_record_access(request, "customer", body.customer_id, write=True)
    cust = get_customer_by_id(body.customer_id)
    if not cust:
        raise HTTPException(404, "Customer not found")
    errs = _validate_pm_contract(start_date=body.start_date, end_date=body.end_date,
                                 frequency=body.frequency,
                                 contract_value=body.contract_value)
    if errs:
        raise HTTPException(422, detail={"errors": errs})
    if body.equipment_id is not None:
        eq = get_equipment_by_id(body.equipment_id)
        if not eq or int(eq.get("customer_id") or 0) != int(body.customer_id):
            raise HTTPException(422, detail={"errors": [
                {"field": "equipment_id", "message": "Equipment not found for this customer"}]})
    data = body.model_dump()
    if data.get("hub_id") is None:
        data["hub_id"] = cust.get("hub_id", 1)
    cid = create_pm_contract(data, by_kind="admin", by_id=admin["id"])
    contract = get_pm_contract(cid)
    _audit_from(admin, "pm_contract.created", request,
                target_type="customer", target_id=body.customer_id,
                target_label=cust.get("customer_code"),
                after={"contract_id": cid, "contract_code": contract["contract_code"],
                       "frequency": contract["frequency"],
                       "start_date": contract["start_date"],
                       "end_date": contract["end_date"]})
    return {"ok": True, "contract": contract}


@app.post("/api/admin/pm-contracts/generate", response_model=Dict[str, Any])
def admin_pm_contracts_generate(request: Request,
                                lookahead_days: int = 30,
                                contract_id: Optional[int] = None):
    """Manually run the PM-visit generator (the same routine the nightly cron
    runs). Collection/global op → super_admin or a blanket power delegation."""
    admin = _require_admin_or_power(request)
    lookahead_days = max(0, min(int(lookahead_days), 365))
    result = generate_due_pm_visits(lookahead_days=lookahead_days,
                                    only_contract_id=contract_id)
    _audit_from(admin, "pm_contract.generate_run", request,
                target_type="pm_contracts", target_id=contract_id,
                after={"created": len(result["created"]),
                       "expired": len(result["expired"]),
                       "processed": result["processed"],
                       "lookahead_days": lookahead_days})
    return {"ok": True, **result}


@app.get("/api/admin/pm-contracts/{contract_id}", response_model=Dict[str, Any])
def admin_pm_contract_detail(request: Request, contract_id: int):
    contract = get_pm_contract(contract_id)
    if not contract:
        # Authenticate before leaking existence; treat as not-found for any admin.
        _require_admin(request)
        raise HTTPException(404, "Contract not found")
    admin = _require_record_access(request, "customer", contract["customer_id"], write=False)
    _audit_from(admin, "pm_contract.view", request,
                target_type="customer", target_id=contract["customer_id"],
                after={"contract_id": contract_id})
    return {"contract": _pm_contract_with_visits(contract)}


@app.patch("/api/admin/pm-contracts/{contract_id}", response_model=Dict[str, Any])
def admin_pm_contract_update(request: Request, contract_id: int, body: PMContractUpdate):
    contract = get_pm_contract(contract_id)
    if not contract:
        _require_admin(request)
        raise HTTPException(404, "Contract not found")
    admin = _require_record_access(request, "customer", contract["customer_id"], write=True)
    updates = {k: v for k, v in body.model_dump().items() if v is not None}
    if not updates:
        raise HTTPException(422, detail={"errors": [
            {"field": "_", "message": "No fields to update"}]})
    # Validate using the post-merge view so a partial PATCH still keeps a sane range.
    merged_start = updates.get("start_date", contract["start_date"])
    merged_end   = updates.get("end_date", contract["end_date"])
    errs = _validate_pm_contract(
        start_date=merged_start, end_date=merged_end,
        frequency=updates.get("frequency"), contract_value=updates.get("contract_value"),
        status=updates.get("status"), require_all=False)
    if errs:
        raise HTTPException(422, detail={"errors": errs})
    if "equipment_id" in updates and updates["equipment_id"] is not None:
        eq = get_equipment_by_id(updates["equipment_id"])
        if not eq or int(eq.get("customer_id") or 0) != int(contract["customer_id"]):
            raise HTTPException(422, detail={"errors": [
                {"field": "equipment_id", "message": "Equipment not found for this customer"}]})
    update_pm_contract(contract_id, updates, by_kind="admin", by_id=admin["id"])
    after = get_pm_contract(contract_id)
    _audit_from(admin, "pm_contract.updated", request,
                target_type="customer", target_id=contract["customer_id"],
                before={k: contract.get(k) for k in updates},
                after={k: after.get(k) for k in updates} | {"contract_id": contract_id})
    return {"ok": True, "contract": _pm_contract_with_visits(after)}


@app.post("/api/admin/pm-contracts/{contract_id}/cancel", response_model=Dict[str, Any])
def admin_pm_contract_cancel(request: Request, contract_id: int):
    contract = get_pm_contract(contract_id)
    if not contract:
        _require_admin(request)
        raise HTTPException(404, "Contract not found")
    admin = _require_record_access(request, "customer", contract["customer_id"], write=True)
    if contract["status"] == "cancelled":
        return {"ok": True, "already_cancelled": True}
    update_pm_contract(contract_id, {"status": "cancelled"}, by_kind="admin", by_id=admin["id"])
    _audit_from(admin, "pm_contract.cancelled", request,
                target_type="customer", target_id=contract["customer_id"],
                before={"status": contract["status"]},
                after={"status": "cancelled", "contract_id": contract_id})
    return {"ok": True, "contract": get_pm_contract(contract_id)}


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
    admin = _require_record_access(request, "visit", visit_id, write=False)
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
    admin = _require_record_access(request, "visit", visit_id, write=True)

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

# DECISION: the tech ladder is stored as stable internal enum values and
# rendered through display labels in the UI — we intentionally do NOT rename
# the stored strings. Rationale:
#   * Nothing gates on these values: a field grade grants zero permissions,
#     it only drives a display label (_ROLE_LABEL) and an org-rank sort key
#     (_ORG_RANK). So the stored string is a key, not behaviour.
#   * Renaming the enum would churn the verify_tech / get_all_techs surface
#     and ~20 references for no functional gain.
#   * The old spec's level_1/level_2/level_3/lead scheme has been superseded
#     by the richer ladder below (Apprentice / Technician / Senior / Journeyman
#     / Installation / Commercial), so migrating TO it would be backwards.
# If HR ever wants different *labels*, change _ROLE_LABEL + the dropdowns; the
# stored enum stays put. (Supersedes the former level_1/2/3/lead rename FIXME.)
_TECH_ROLE_VALUES         = ("tech", "lead_tech", "apprentice",
                             "senior_tech", "install_tech", "commercial_tech")
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
    """Delegation-aware: paginated reverse-chronological job history."""
    admin = _require_record_access(request, "technician", tech_id, write=False)
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
    admin = _require_record_access(request, "technician", tech_id, write=False)
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
    admin = _require_record_access(request, "technician", tech_id, write=True)
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
    # Use database._con() (was: bare sqlite3.connect("submissions.db"))
    # so the connection inherits journal_mode=WAL, synchronous=FULL,
    # and foreign_keys=ON; and honors DB_PATH env overrides instead of
    # hard-coding the file. Audit M1, 2026-05-23.
    try:
        from database import _con as _dbcon
        con = _dbcon()
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
    # Encrypt then update via database._con() so the connection
    # inherits the WAL / synchronous=FULL / foreign_keys=ON pragmas
    # and honors DB_PATH env overrides. Audit M1, 2026-05-23.
    from database import _enc_dict as _enc_d, _con as _dbcon
    enc = _enc_d("kpi_goals", updates)
    sets = ", ".join(f"{k}=?" for k in enc.keys())
    args = list(enc.values()) + [goal_id]
    con = _dbcon()
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


async def _start_kpi_weekly_recompute_loop():
    _kpi_asyncio.create_task(_kpi_weekly_recompute_loop())
_LIFESPAN_STARTERS.append(_start_kpi_weekly_recompute_loop)


@app.post("/api/admin/technicians/{tech_id}/5s-override")
def admin_technician_5s_override(request: Request, tech_id: int,
                                 body: Technician5SOverride):
    """super_admin-only: persist a forensic override row for a 5S exception.
    Does NOT mutate the original fs_exceptions row — that row stays for the
    audit trail. The override is a parallel forensic record."""
    admin = _require_record_access(request, "technician", tech_id, write=True)
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
    admin = _require_record_access(request, "technician", tech_id, write=False)
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
    admin = _require_record_access(request, "technician", tech_id, write=True)
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
    admin = _require_record_access(request, "technician", tech_id, write=True)
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
    admin = _require_record_access(request, "technician", tech_id, write=False)
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
    admin = _require_record_access(request, "technician", tech_id, write=False)
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


@app.patch("/api/admin/equipment/{equipment_id}")
def admin_update_equipment(request: Request, equipment_id: int, body: EquipmentUpdate):
    """Edit an equipment row's editable fields (name/type/model + encrypted
    serial/location/notes). customer_id is intentionally not changeable
    here. before/after diffs are written to the audit log so reviewers can
    see what was changed."""
    from database import update_equipment
    admin = _require_perm(request, "customer:update")
    before = get_equipment_by_id(equipment_id)
    if not before:
        raise HTTPException(404, "Equipment not found")
    updates = {k: v for k, v in body.model_dump(exclude_unset=True).items() if v is not None}
    if not updates:
        return {"ok": True, "id": equipment_id, "no_changes": True}
    update_equipment(equipment_id, updates,
                     updated_by_kind="admin", updated_by_id=admin["id"])
    after = get_equipment_by_id(equipment_id)
    _audit_from(admin, "equipment.update", request,
                target_type="equipment", target_id=equipment_id,
                target_label=after.get("name") if after else before.get("name"),
                before=before, after=after)
    return {"ok": True, "id": equipment_id, "equipment": after}


@app.post("/api/admin/equipment/{equipment_id}/deactivate")
def admin_deactivate_equipment(request: Request, equipment_id: int):
    """Soft-delete: hides the equipment from the everyday list (techs can no
    longer pick it for new visits) while preserving the visit_id →
    equipment_id history. Hard delete remains a separate, more dangerous
    endpoint."""
    from database import deactivate_equipment
    admin = _require_perm(request, "customer:update")
    eq = get_equipment_by_id(equipment_id)
    if not eq:
        raise HTTPException(404, "Equipment not found")
    deactivate_equipment(equipment_id,
                         updated_by_kind="admin", updated_by_id=admin["id"])
    _audit_from(admin, "equipment.deactivate", request,
                target_type="equipment", target_id=equipment_id,
                target_label=eq.get("name"))
    return {"ok": True}


# ── Tech-side equipment endpoints ────────────────────────────────────────────
#
# Techs can read, create, and update equipment for ANY customer — the field
# reality is that the tech is standing in front of a unit and needs to be
# able to record it without bouncing back to the office. The audit log
# captures who did what; abuse is enforced after-the-fact rather than via
# heavy per-customer ACLs.

def _audit_tech(tech, action, request, target_type=None, target_id=None,
                target_label=None, before=None, after=None):
    """Tech-side wrapper around log_audit. tech is the dict returned by
    get_tech_by_id (so we have name + tech_code for the audit row)."""
    log_audit(
        actor_type="tech",
        actor_id=tech["id"],
        actor_prid=tech.get("prid") or tech.get("tech_code"),
        actor_label=tech.get("name"),
        actor_role=tech.get("role"),
        action=action,
        target_type=target_type,
        target_id=target_id,
        target_label=target_label,
        before_value=before,
        after_value=after,
        ip_address=request.client.host if request.client else None,
    )


def _tech_or_404(request):
    """Returns the tech's full row (not just the id) so we can pass it to
    _audit_tech and reuse name/tech_code in responses."""
    tech_id = _require_tech(request)
    from database import get_tech_by_id
    tech = get_tech_by_id(tech_id)
    if not tech:
        raise HTTPException(404, "Tech profile not found")
    return tech


@app.get("/api/tech/customers/search")
def tech_search_customers(request: Request, q: str = "", limit: int = 25):
    """Lightweight customer search for the tech's standalone Equipment
    screen. Returns enough to build a chip row + tap-through (id, name,
    customer_code, address, phone). Filters on name / customer_code /
    company / phone, case-insensitive, active customers only."""
    _require_tech(request)
    needle = (q or "").strip().lower()
    rows = get_all_customers() or []
    if needle:
        def hit(c):
            for k in ("name", "company", "customer_code", "phone", "email"):
                v = (c.get(k) or "").lower()
                if needle in v:
                    return True
            return False
        rows = [c for c in rows if hit(c)]
    # Active customers only — terminated accounts aren't relevant for new
    # field work.
    rows = [c for c in rows if (c.get("active") in (1, True, None))]
    out = []
    for c in rows[: max(1, min(int(limit), 100))]:
        out.append({
            "id":            c["id"],
            "name":          c.get("name"),
            "company":       c.get("company"),
            "customer_code": c.get("customer_code"),
            "address":       c.get("address"),
            "phone":         c.get("phone"),
        })
    return out


@app.get("/api/tech/customers/{customer_id}")
def tech_get_customer(request: Request, customer_id: int):
    """Minimal customer header for the tech equipment screen. Strips out
    anything the tech doesn't need on this surface (billing terms, etc.)."""
    _require_tech(request)
    c = get_customer_by_id(customer_id)
    if not c:
        raise HTTPException(404, "Customer not found")
    return {
        "id":            c["id"],
        "name":          c.get("name"),
        "company":       c.get("company"),
        "customer_code": c.get("customer_code"),
        "address":       c.get("address"),
        "phone":         c.get("phone"),
        "email":         c.get("email"),
        "customer_type": c.get("customer_type"),
    }


@app.get("/api/tech/customers/{customer_id}/equipment")
def tech_list_customer_equipment(request: Request, customer_id: int):
    """List the customer's active equipment for the tech UI. Hides
    deactivated rows by default — those are admin-only via the
    `/api/admin/customers/{id}/equipment` view."""
    _require_tech(request)
    if not get_customer_by_id(customer_id):
        raise HTTPException(404, "Customer not found")
    return get_customer_equipment(customer_id)


@app.post("/api/tech/equipment")
def tech_create_equipment(request: Request, body: EquipmentCreate):
    """Tech adds a new piece of equipment in the field. Same shape as the
    admin endpoint; the audit row carries actor_type=tech."""
    tech = _tech_or_404(request)
    if not get_customer_by_id(body.customer_id):
        raise HTTPException(404, "Customer not found")
    equipment_id = create_equipment(body.model_dump())
    # Stamp updated_by_* on creation too, so we always know who touched it
    # last (avoids a NULL period until the first edit).
    from database import update_equipment as _upd
    _upd(equipment_id, {}, updated_by_kind="tech", updated_by_id=tech["id"])
    _audit_tech(tech, "equipment.create", request,
                target_type="equipment", target_id=equipment_id,
                target_label=body.name, after=body.model_dump())
    return {"id": equipment_id, "equipment": get_equipment_by_id(equipment_id)}


@app.patch("/api/tech/equipment/{equipment_id}")
def tech_update_equipment(request: Request, equipment_id: int, body: EquipmentUpdate):
    """Tech edits an existing equipment row. Same constraints as the admin
    endpoint (customer_id not editable, encryption applied to PII columns)."""
    from database import update_equipment
    tech = _tech_or_404(request)
    before = get_equipment_by_id(equipment_id)
    if not before:
        raise HTTPException(404, "Equipment not found")
    if not before.get("active", 1):
        raise HTTPException(409, "Equipment is deactivated and cannot be edited")
    updates = {k: v for k, v in body.model_dump(exclude_unset=True).items() if v is not None}
    if not updates:
        return {"ok": True, "id": equipment_id, "no_changes": True}
    update_equipment(equipment_id, updates,
                     updated_by_kind="tech", updated_by_id=tech["id"])
    after = get_equipment_by_id(equipment_id)
    _audit_tech(tech, "equipment.update", request,
                target_type="equipment", target_id=equipment_id,
                target_label=after.get("name") if after else before.get("name"),
                before=before, after=after)
    return {"ok": True, "id": equipment_id, "equipment": after}


@app.get("/api/admin/visits")
def admin_list_visits(request: Request):
    _require_perm(request, "visit:view")
    return get_all_visits()


@app.post("/api/admin/visits")
def admin_create_visit(request: Request, body: VisitCreate):
    admin = _require_perm(request, "visit:create")
    from database import set_visit_crew
    payload = body.model_dump()
    # crew_tech_ids isn't a column on maintenance_visits — it's handled
    # separately via the visit_techs table after the visit row is inserted.
    crew_ids = payload.pop("crew_tech_ids", []) or []
    visit_id = create_visit(payload)
    if crew_ids:
        set_visit_crew(visit_id, crew_ids,
                       by_kind="admin", by_id=admin["id"])
    _audit_from(admin, "visit.create", request,
                target_type="visit", target_id=visit_id,
                target_label=f"{body.visit_type} for cust {body.customer_id}",
                after=body.model_dump())
    return {"id": visit_id}


@app.put("/api/admin/visits/{visit_id}", response_model=Dict[str, Any])
def admin_update_visit(request: Request, visit_id: int, body: VisitUpdate):
    admin = _require_record_access(request, "visit", visit_id, write=True)
    from database import set_visit_crew
    before = get_visit_by_id(visit_id)
    payload = body.model_dump()
    # `crew_tech_ids` is None when the caller doesn't want to touch the
    # crew (legacy edit modals); only update when it's an actual list.
    crew_ids = payload.pop("crew_tech_ids", None)
    update_visit(visit_id, payload)
    if crew_ids is not None:
        set_visit_crew(visit_id, crew_ids,
                       by_kind="admin", by_id=admin["id"])
    _audit_from(admin, "visit.update", request,
                target_type="visit", target_id=visit_id,
                target_label=f"{body.visit_type} #{visit_id}",
                before=before, after=body.model_dump())
    return {"ok": True}


@app.get("/api/admin/visits/{visit_id}/crew")
def admin_get_visit_crew(request: Request, visit_id: int):
    """Lightweight crew query for the Visit edit modal — returns the lead
    AND the extras as one list with a `lead` flag so the picker can show
    them all with the lead marked."""
    from database import get_visit_crew
    _require_perm(request, "visit:view")
    v = get_visit_by_id(visit_id)
    if not v:
        raise HTTPException(404, "Visit not found")
    out = []
    if v.get("assigned_tech_id"):
        out.append({"id": v["assigned_tech_id"], "name": v.get("tech_name"), "lead": True})
    for c in get_visit_crew(visit_id):
        out.append({"id": c["id"], "name": c["name"], "lead": False})
    return out


@app.post("/api/admin/visits/{visit_id}/crew/{tech_id}")
def admin_add_visit_crew(request: Request, visit_id: int, tech_id: int):
    """Incrementally add ONE extra crew member without touching the rest of
    the crew. Used by the chip-picker's '+ add' control."""
    from database import add_visit_crew
    admin = _require_record_access(request, "visit", visit_id, write=True)
    if not get_visit_by_id(visit_id):
        raise HTTPException(404, "Visit not found")
    added = add_visit_crew(visit_id, tech_id, by_kind="admin", by_id=admin["id"])
    _audit_from(admin, "visit.crew_add", request,
                target_type="visit", target_id=visit_id,
                target_label=f"tech_id={tech_id}",
                after={"added": added})
    return {"ok": True, "added": added}


@app.delete("/api/admin/visits/{visit_id}/crew/{tech_id}")
def admin_remove_visit_crew(request: Request, visit_id: int, tech_id: int):
    """Incrementally remove ONE extra crew member. Cannot remove the lead
    via this path — change `assigned_tech_id` through the PUT endpoint."""
    from database import remove_visit_crew
    admin = _require_record_access(request, "visit", visit_id, write=True)
    if not get_visit_by_id(visit_id):
        raise HTTPException(404, "Visit not found")
    removed = remove_visit_crew(visit_id, tech_id)
    _audit_from(admin, "visit.crew_remove", request,
                target_type="visit", target_id=visit_id,
                target_label=f"tech_id={tech_id}",
                after={"removed": removed})
    return {"ok": True, "removed": removed}


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
    # Unified onboarding policy: only super_admin and hr_admin can onboard
    # any employee (field tech, parts runner, warehouse staff). Defense-in-
    # depth — the client-side Onboarding panel is gated the same way, but
    # this catches anyone hitting the endpoint directly.
    if (admin.get("role") or "").lower() not in ("super_admin", "hr_admin"):
        raise HTTPException(
            403, "Onboarding is restricted to super_admin and hr_admin.")
    # New tech, so phone-on-file is whatever the admin entered in this
    # same request. Phone-as-PIN check still applies — refuse to even
    # create the row if the admin tries to set the new tech's PIN to
    # their own phone number. (PIN min raised to 10 digits May 2026.)
    _validate_pin_or_400(
        body.pin, phone_on_file=body.phone,
        actor_type="admin", actor_id=admin["id"],
        label=f"new tech '{body.name}'",
    )
    # Role validation depends on staff_type. Field techs use the
    # traditional level enum; warehouse staff use 'tech' as a
    # placeholder (a separate role taxonomy for warehouse could be
    # added later if needed).
    staff_type = (body.staff_type or "tech").strip()
    if staff_type == "tech":
        if body.role not in _TECH_ROLE_VALUES:
            raise HTTPException(400, "Invalid tech role")
    elif staff_type in ("warehouse_floor", "parts_runner",
                        "warehouse_manager", "driver"):
        # Operator policy: warehouse onboarding & position assignment is
        # restricted to super_admin + hr_admin even if a role otherwise
        # has tech:create (e.g. supervisor_admin can create field techs
        # but must not create warehouse staff). UI hides the button;
        # this is the defence-in-depth server gate.
        if admin.get("role") not in ("super_admin", "hr_admin"):
            _audit_from(admin, "warehouse.staff.create_denied", request,
                        target_label=body.name,
                        details={"reason": "role_not_authorized",
                                 "staff_type": staff_type,
                                 "actor_role": admin.get("role")})
            raise HTTPException(
                403,
                "Warehouse staff onboarding is restricted to super_admin and hr_admin.",
            )
    else:
        raise HTTPException(400, f"Invalid staff_type: {staff_type}")
    try:
        tech_id, prid = create_tech(body.model_dump())
    except ValueError as ve:
        raise HTTPException(400, str(ve))
    except Exception as e:
        if "UNIQUE" in str(e):
            raise HTTPException(409, "PRID conflict — try again")
        raise
    _audit_from(admin, "tech.create", request,
                target_type="tech", target_id=tech_id, target_label=prid,
                after={"name": body.name, "tech_code": prid,
                       "role": body.role, "email": body.email,
                       "staff_type": staff_type})
    return {"id": tech_id, "prid": prid, "tech_code": prid}


@app.put("/api/admin/techs/{tech_id}")
def admin_update_tech(request: Request, tech_id: int, body: TechUpdate):
    admin = _require_perm(request, "tech:update")
    if body.role not in _TECH_ROLE_VALUES:
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
    tech = get_tech_by_id(tech_id)
    _validate_pin_or_400(
        body.pin, phone_on_file=(tech or {}).get("phone"),
        actor_type="tech", actor_id=tech_id,
        label=(tech or {}).get("tech_code") or f"tech#{tech_id}",
    )
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


# ── Unified staff listing (W2) ──────────────────────────────────────
# Reads against the same `technicians` table via list_staff(), filtered
# by staff_type / department. /api/admin/techs already exists and now
# filters to staff_type='tech' only (see database.get_all_techs). This
# new endpoint is the warehouse-aware equivalent for any admin who
# needs to see across all staff categories.

@app.get("/api/admin/staff")
def admin_list_staff(request: Request,
                     staff_type: Optional[str] = None,
                     department: Optional[str] = None,
                     active: bool = True):
    """List staff with optional staff_type / department filters.
    Reuses the tech:view permission (the entity is the same row in the
    same table). Filters validated against VALID_STAFF_TYPES /
    VALID_DEPARTMENTS to prevent typos returning empty lists silently."""
    _require_perm(request, "tech:view")
    if staff_type and staff_type not in VALID_STAFF_TYPES:
        raise HTTPException(400,
            f"staff_type must be one of {sorted(VALID_STAFF_TYPES)}")
    if department and department not in VALID_DEPARTMENTS:
        raise HTTPException(400,
            f"department must be one of {sorted(VALID_DEPARTMENTS)}")
    return list_staff(staff_type=staff_type, department=department,
                      active_only=bool(active))


@app.get("/api/admin/warehouse/staff")
def admin_list_warehouse_staff(request: Request):
    """Shortcut: every warehouse-department staff row, active by
    default. Used by the warehouse admin tab to render the floor +
    parts-runner roster in one place. Available to anyone with
    warehouse:view_queue (inventory_manager included)."""
    _require_perm(request, "warehouse:view_queue")
    return list_staff(department="warehouse", active_only=True)


# ── Warehouse inventory movements (Pass B) ──────────────────────────
# Append-only, chain-hashed history of every part movement (receipt /
# pick / transfer / adjustment / return / shipped). The parts.quantity
# global total stays in sync via record_part_movement's transactional
# UPDATE; per-location on-hand is computed from movements at read
# time via stock_by_location().

class WarehouseMovementBody(BaseModel):
    part_id:          int
    quantity_delta:   float     # signed: + inbound, - outbound
    reason:           str       # see VALID_MOVEMENT_REASONS
    from_location_id: Optional[int] = None
    to_location_id:   Optional[int] = None
    reference_kind:   Optional[str] = None
    reference_id:     Optional[int] = None
    notes:            Optional[str] = None


@app.post("/api/admin/warehouse/movements")
def admin_warehouse_record_movement(request: Request,
                                    body: WarehouseMovementBody):
    """Record a single inventory movement. Quantity sign convention:
       + for inbound (receipt / return), - for outbound (pick /
       shipped). Transfers can be a single row with both
       from_/to_location_id set; the quantity_delta is then 0 at the
       parts.quantity global total (the part didn't enter or leave
       the warehouse, just moved within it) — but on-hand at each
       location updates correctly via the per-location aggregation."""
    admin = _require_perm(request, "warehouse:manage_assets")
    try:
        mid = record_part_movement(
            part_id=body.part_id,
            quantity_delta=float(body.quantity_delta),
            reason=body.reason,
            from_location_id=body.from_location_id,
            to_location_id=body.to_location_id,
            performed_by_type="admin",
            performed_by_id=admin["id"],
            performed_by_label=admin.get("name"),
            performed_by_prid=admin.get("prid"),
            reference_kind=body.reference_kind,
            reference_id=body.reference_id,
            notes=body.notes,
        )
    except ValueError as ve:
        raise HTTPException(400, str(ve))
    _audit_from(admin, "warehouse.movement.recorded", request,
                target_type="part_movement", target_id=mid,
                after={"part_id": body.part_id,
                       "quantity_delta": body.quantity_delta,
                       "reason": body.reason,
                       "from_location_id": body.from_location_id,
                       "to_location_id":   body.to_location_id,
                       "reference_kind":   body.reference_kind,
                       "reference_id":     body.reference_id})
    _check_low_stock(body.part_id)
    return {"ok": True, "id": mid}


@app.get("/api/admin/warehouse/movements")
def admin_warehouse_list_movements(request: Request,
                                   part_id: Optional[int] = None,
                                   location_id: Optional[int] = None,
                                   reason: Optional[str] = None,
                                   reference_kind: Optional[str] = None,
                                   reference_id: Optional[int] = None,
                                   since: Optional[str] = None,
                                   limit: int = 200):
    """Filtered movement history. Read-only — gated by view_queue so
    inventory_manager + supervisors can audit without write perms."""
    _require_perm(request, "warehouse:view_queue")
    if reason and reason not in VALID_MOVEMENT_REASONS:
        raise HTTPException(400,
            f"reason must be one of {sorted(VALID_MOVEMENT_REASONS)}")
    if reference_kind and reference_kind not in VALID_MOVEMENT_REFS:
        raise HTTPException(400,
            f"reference_kind must be one of {sorted(VALID_MOVEMENT_REFS)}")
    return list_warehouse_movements(
        part_id=part_id, location_id=location_id, reason=reason,
        reference_kind=reference_kind, reference_id=reference_id,
        since=since, limit=max(1, min(int(limit), 1000)),
    )


@app.get("/api/admin/warehouse/stock-by-location")
def admin_warehouse_stock_by_location(request: Request,
                                      location_id: Optional[int] = None):
    """Per-location on-hand grid, computed from movements. Optional
    location_id filter narrows to one bin / van / truck."""
    _require_perm(request, "warehouse:view_queue")
    return stock_by_location(location_id=location_id)


@app.get("/api/admin/warehouse/receiving/queue")
def admin_warehouse_receiving_queue(request: Request):
    """Open POs awaiting delivery — every PO in status 'sent' or
    'draft' with at least one line still pending receipt, with each
    line's remaining qty. Drives the receiving sub-tab UI.

    Gated by po:receive so only roles that can actually mark items
    received see the queue."""
    _require_perm(request, "po:receive")
    return list_open_pos_for_receiving()


# ── Warehouse deliveries / shipping queue (Pass D) ──────────────────

class WarehouseDeliveryCreate(BaseModel):
    source_location_id: int
    part_id:            int
    quantity:           float
    destination_kind:   str        # see VALID_DELIVERY_KINDS
    destination_id:     Optional[int]  = None
    destination_label:  Optional[str]  = None
    runner_staff_id:    Optional[int]  = None
    notes:              Optional[str]  = None


@app.post("/api/admin/warehouse/deliveries")
def admin_warehouse_create_delivery(request: Request,
                                    body: WarehouseDeliveryCreate):
    """Create a pending delivery. Doesn't move inventory until
    /mark-loaded is called (runner has the parts physically loaded).
    Gated by warehouse:manage_assets (write-side)."""
    admin = _require_perm(request, "warehouse:manage_assets")
    try:
        did = create_warehouse_delivery(
            source_location_id=body.source_location_id,
            part_id=body.part_id,
            quantity=float(body.quantity),
            destination_kind=body.destination_kind,
            created_by_admin_id=admin["id"],
            destination_id=body.destination_id,
            destination_label=body.destination_label,
            runner_staff_id=body.runner_staff_id,
            notes=body.notes,
        )
    except ValueError as ve:
        raise HTTPException(400, str(ve))
    _audit_from(admin, "warehouse.delivery.created", request,
                target_type="warehouse_delivery", target_id=did,
                after={"part_id": body.part_id,
                       "quantity": body.quantity,
                       "destination_kind": body.destination_kind,
                       "destination_id": body.destination_id,
                       "runner_staff_id": body.runner_staff_id})
    return {"ok": True, "id": did}


@app.get("/api/admin/warehouse/deliveries")
def admin_warehouse_list_deliveries(request: Request,
                                    status: Optional[str] = None,
                                    runner_staff_id: Optional[int] = None,
                                    limit: int = 200):
    """Filtered delivery list. Gated by warehouse:view_queue (read)."""
    _require_perm(request, "warehouse:view_queue")
    if status and status not in (
        "pending", "loaded", "delivered", "cancelled"
    ):
        raise HTTPException(400, "invalid status filter")
    return list_warehouse_deliveries(
        status=status, runner_staff_id=runner_staff_id,
        limit=max(1, min(int(limit), 1000)),
    )


@app.post("/api/admin/warehouse/deliveries/{delivery_id}/mark-loaded")
def admin_warehouse_mark_loaded(request: Request, delivery_id: int):
    """Runner has loaded the parts. Posts the outbound part_movement
    (qty_delta<0, from_location set, chain-hashed) and flips the
    delivery to 'loaded'. Idempotent."""
    admin = _require_perm(request, "warehouse:manage_assets")
    try:
        result = mark_delivery_loaded(
            delivery_id,
            performed_by_admin_id=admin["id"],
            performed_by_label=admin.get("name"),
            performed_by_prid=admin.get("prid"),
        )
    except ValueError as ve:
        raise HTTPException(404, str(ve))
    _audit_from(admin, "warehouse.delivery.loaded", request,
                target_type="warehouse_delivery", target_id=delivery_id,
                after={"movement_id": result.get("movement_id"),
                       "already_loaded": result.get("already_loaded", False)})
    return result


@app.post("/api/admin/warehouse/deliveries/{delivery_id}/mark-delivered")
def admin_warehouse_mark_delivered(request: Request, delivery_id: int):
    """Final transition — just timestamps. Returns 409 if the delivery
    isn't in 'loaded' state (can't deliver something that wasn't
    physically loaded onto the truck)."""
    admin = _require_perm(request, "warehouse:manage_assets")
    if not mark_delivery_delivered(delivery_id):
        raise HTTPException(409, "Delivery must be in 'loaded' status to mark delivered")
    _audit_from(admin, "warehouse.delivery.delivered", request,
                target_type="warehouse_delivery", target_id=delivery_id)
    return {"ok": True}


class CancelBody(BaseModel):
    reason: Optional[str] = None


@app.post("/api/admin/warehouse/deliveries/{delivery_id}/cancel")
def admin_warehouse_cancel_delivery(request: Request, delivery_id: int,
                                    body: CancelBody):
    """Cancel a pending delivery before it's loaded. Refuses to
    cancel a loaded/delivered delivery (use a 'return' movement
    instead — the parts have already left the warehouse)."""
    admin = _require_perm(request, "warehouse:manage_assets")
    if not cancel_warehouse_delivery(delivery_id, reason=body.reason):
        raise HTTPException(409,
            "Only pending deliveries can be cancelled. If already loaded,"
            " record a 'return' movement to bring parts back into stock.")
    _audit_from(admin, "warehouse.delivery.cancelled", request,
                target_type="warehouse_delivery", target_id=delivery_id,
                after={"reason": body.reason})
    return {"ok": True}


@app.get("/warehouse")
def warehouse_admin_page():
    """Serves the warehouse admin landing (W2). Just returns admin.html
    today since the warehouse tab lives inside the existing admin
    panel surface; a dedicated /warehouse SPA can replace this later
    if the surface grows."""
    return FileResponse("admin.html")


# ── W3.a — per-asset 5S checklist override (warehouse manager edits) ─

class AssetChecklistOverride(BaseModel):
    # Mirrors FS_DEFAULT_CHECKLIST shape: each section is a list of
    # item_key strings. Unknown sections are dropped server-side.
    items_by_section: Dict[str, List[str]]


@app.get("/api/admin/fs/assets/{asset_id}/checklist/{phase}")
def admin_get_asset_checklist(request: Request, asset_id: int, phase: str):
    """Returns the EFFECTIVE checklist (override if present, else the
    asset_type default). Used by the warehouse manager UI to edit.
    Gated by warehouse:manage_assets so the inventory_manager can SEE
    the live checklist via the 5S panel but cannot EDIT it."""
    _require_perm(request, "warehouse:manage_assets")
    from database import (get_checklist_for_phase as _gcfp,
                          FS_SAFETY_ITEM_KEYS, fs_item_catalog)
    items = _gcfp(asset_id, phase)
    if not items:
        raise HTTPException(404,
            "No checklist exists for this asset / phase combination")
    # Flag the safety-critical items so the editor can badge them, and hand
    # back the full known-keys catalog so the UI can offer a validated
    # picker instead of blind free-text (a typo'd safety key would otherwise
    # silently downgrade audit severity — see fs_safety_near_miss).
    for it in items:
        it["safety_critical"] = it["item_key"] in FS_SAFETY_ITEM_KEYS
    return {"asset_id": asset_id, "phase": phase, "items": items,
            "catalog": fs_item_catalog()}


@app.post("/api/admin/fs/assets/{asset_id}/checklist/{phase}")
def admin_set_asset_checklist(request: Request, asset_id: int, phase: str,
                              body: AssetChecklistOverride):
    """UPSERT a per-asset checklist override. Items are passed as
    {section: [item_key, ...]} matching FS_DEFAULT_CHECKLIST shape.
    Pass an empty dict to delete the override (resolver falls back
    to the asset_type default)."""
    admin = _require_perm(request, "warehouse:manage_assets")
    from database import (set_asset_checklist_override,
                          clear_asset_checklist_override)
    if not any(body.items_by_section.values()):
        clear_asset_checklist_override(asset_id, phase)
        action = "fs.asset_checklist_cleared"
    else:
        try:
            set_asset_checklist_override(
                asset_id, phase, body.items_by_section,
                edited_by_admin_id=admin["id"],
            )
        except ValueError as ve:
            raise HTTPException(400, str(ve))
        action = "fs.asset_checklist_override_set"
    _audit_from(admin, action, request,
                target_type="fs_asset", target_id=asset_id,
                target_label=f"phase={phase}",
                after={"sections": {k: len(v) for k, v
                                    in body.items_by_section.items()}})
    return {"ok": True}


# ── W3.b — month-end equipment checksheet archive ─────────────────

CHECKSHEET_DIR = Path(os.environ.get(
    "CHECKSHEET_DIR", "uploads/checksheets"))
CHECKSHEET_DIR.mkdir(parents=True, exist_ok=True)
MAX_CHECKSHEET_SIZE = int(os.environ.get(
    "MAX_CHECKSHEET_SIZE_BYTES", str(10 * 1024 * 1024)))  # 10 MB
ALLOWED_CHECKSHEET_EXTS = {".pdf", ".jpg", ".jpeg", ".png", ".heic"}
# Server-derived media types for download. Never echo the client-supplied
# content_type back as the response media_type — a stored "text/html" would
# let a browser render an uploaded file inline. Derive from the (whitelisted)
# stored extension instead.
_CHECKSHEET_MEDIA = {
    ".pdf":  "application/pdf",
    ".jpg":  "image/jpeg", ".jpeg": "image/jpeg",
    ".png":  "image/png",  ".heic": "image/heic",
}


@app.post("/api/admin/warehouse/checksheets")
async def admin_upload_checksheet(
    request: Request,
    asset_id: int = Form(...),
    period_yyyymm: str = Form(...),
    notes: str = Form(""),
    file: UploadFile = File(...),
):
    """Month-end equipment checksheet upload. Operator workflow per
    spec: staff complete per-use paper checksheets during the month;
    the warehouse manager scans/photographs them and uploads at month
    end for compliance archive. The system stores the file +
    metadata; it does NOT enforce per-use completion in real time
    (that's the role of the daily 5S login/logout audit chain).

    Body (multipart):
      asset_id (int)        — the fs_asset whose checksheet this is
      period_yyyymm (str)   — 'YYYY-MM' the sheet covers
      notes (str, optional) — free-text context
      file                  — the scan/photo (PDF/JPG/PNG/HEIC ≤ 10 MB)

    Gated by warehouse:manage_assets so the upload is restricted to
    operators authorized to assert "these are the official records
    for this period"."""
    admin = _require_perm(request, "warehouse:manage_assets")
    # Validate period
    import re as _re
    if not _re.match(r"^\d{4}-\d{2}$", (period_yyyymm or "").strip()):
        raise HTTPException(400, "period_yyyymm must be YYYY-MM")
    # Validate file
    raw = await file.read()
    if len(raw) > MAX_CHECKSHEET_SIZE:
        raise HTTPException(413,
            f"File exceeds {MAX_CHECKSHEET_SIZE // (1024*1024)} MB limit")
    ext = Path(file.filename or "").suffix.lower()
    if ext not in ALLOWED_CHECKSHEET_EXTS:
        raise HTTPException(415,
            f"Unsupported file type — allow {sorted(ALLOWED_CHECKSHEET_EXTS)}")
    # Confirm asset exists
    from database import get_asset_by_id as _gabi
    asset = _gabi(asset_id)
    if not asset:
        raise HTTPException(404, "Asset not found")
    # Persist file
    safe_stem = _re.sub(r"[^A-Za-z0-9_-]+", "_",
                        Path(file.filename or "sheet").stem)[:80]
    fname = (f"{asset['asset_code']}-{period_yyyymm}-"
             f"{_secrets.token_urlsafe(6)}-{safe_stem}{ext}")
    dest = CHECKSHEET_DIR / fname
    dest.write_bytes(raw)
    # Record metadata
    from database import _con as _dbcon
    now_iso = datetime.now(timezone.utc).isoformat()
    con = _dbcon()
    try:
        cur = con.execute(
            "INSERT INTO warehouse_checksheet_uploads "
            "(asset_id, period_yyyymm, filename, content_type, "
            "size_bytes, uploaded_by_admin_id, uploaded_at, notes) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (asset_id, period_yyyymm, fname, file.content_type or "",
             len(raw), admin["id"], now_iso, (notes or "").strip() or None),
        )
        upload_id = cur.lastrowid
        con.commit()
    finally:
        con.close()
    _audit_from(admin, "warehouse.checksheet_uploaded", request,
                target_type="fs_asset", target_id=asset_id,
                target_label=f"{asset['asset_code']} {period_yyyymm}",
                after={"upload_id": upload_id,
                       "size_bytes": len(raw),
                       "filename": fname})
    return {"ok": True, "upload_id": upload_id, "filename": fname}


@app.get("/api/admin/warehouse/checksheets")
def admin_list_checksheets(request: Request,
                           asset_id: Optional[int] = None,
                           period_yyyymm: Optional[str] = None):
    """List checksheet uploads, optionally filtered by asset_id and/or
    period. Read access via warehouse:view_queue."""
    _require_perm(request, "warehouse:view_queue")
    where, args = [], []
    if asset_id is not None:
        where.append("asset_id = ?"); args.append(int(asset_id))
    if period_yyyymm:
        where.append("period_yyyymm = ?"); args.append(period_yyyymm)
    sql = "SELECT * FROM warehouse_checksheet_uploads"
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY uploaded_at DESC LIMIT 500"
    from database import _con as _dbcon
    con = _dbcon()
    try:
        rows = [dict(r) for r in con.execute(sql, args).fetchall()]
    finally:
        con.close()
    return rows


@app.get("/api/admin/warehouse/checksheets/{upload_id}/download")
def admin_download_checksheet(request: Request, upload_id: int):
    """Download a checksheet file. Direct file-download is gated by
    warehouse:view_queue (same as the listing) — the file IS the
    archived artifact, and warehouse:manage_assets is reserved for
    write actions."""
    _require_perm(request, "warehouse:view_queue")
    from database import _con as _dbcon
    con = _dbcon()
    try:
        row = con.execute(
            "SELECT * FROM warehouse_checksheet_uploads WHERE id = ?",
            (upload_id,),
        ).fetchone()
    finally:
        con.close()
    if not row:
        raise HTTPException(404, "Upload not found")
    path = CHECKSHEET_DIR / row["filename"]
    if not path.exists():
        raise HTTPException(404, "File missing from disk")
    media = _CHECKSHEET_MEDIA.get(Path(row["filename"]).suffix.lower(),
                                  "application/octet-stream")
    return FileResponse(str(path),
                        media_type=media,
                        filename=row["filename"])


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


# ── Unified staff home (/home) ────────────────────────────────────────────
# One landing page for ALL staff (admin + tech + warehouse). Looks like
# the tech landing but adapts its quick-jump tiles to the viewer's role.
# Sits in front of /admin and /tech as a "you are now signed in" shell.

@app.get("/home")
def staff_home_page():
    return FileResponse("staff_home.html")


def _resolve_any_staff(request: Request):
    """Return (kind, record) for either signed-in admin or tech.
    kind ∈ {'admin','tech'}. 401 if neither cookie validates."""
    # Try admin first.
    try:
        admin = _require_admin(request)
        return "admin", admin
    except HTTPException:
        pass
    try:
        tech_id = _require_tech(request)
        from database import get_tech_by_id as _gt
        tech = _gt(tech_id)
        if tech:
            return "tech", tech
    except HTTPException:
        pass
    raise HTTPException(401, "Sign-in required")


# ── Position-based ranking used by the org-chart endpoint ──────────────
# Lower rank = higher in the org. Drives sorting and Above/Peers/Below
# bucketing when a direct supervisor_id link isn't enough on its own.
_ORG_RANK = {
    "super_admin":          0,
    "operations_manager":   1,
    "ceo_assistant":        1,
    "supervisor_admin":     2,
    "hr_admin":             2,
    "system_admin":         2,
    "inventory_manager":    2,
    "accountant":           2,
    "account_manager":      2,
    "safety_officer":       2,
    "quality_manager":      2,
    "warehouse_supervisor": 3,
    "dispatcher":           3,
    "master_tech":          3,
    "csr":                  3,
    "marketing":            3,
    "warehouse_manager":    4,
    "lead_tech":            5,
    "senior_tech":          5,
    "tech":                 6,
    "install_tech":         6,
    "commercial_tech":      6,
    "warehouse_floor":      6,
    "parts_runner":         6,
    "driver":               6,
    "apprentice":           7,
}
_ROLE_LABEL = {
    "super_admin":          "Super Admin",
    "operations_manager":   "Operations Manager",
    "ceo_assistant":        "CEO Assistant",
    "supervisor_admin":     "Supervisor",
    "hr_admin":             "HR Admin",
    "system_admin":         "System Admin",
    "inventory_manager":    "Inventory Manager",
    "accountant":           "Accountant",
    "account_manager":      "Account Manager",
    "safety_officer":       "Safety Officer",
    "quality_manager":      "Quality Manager",
    "warehouse_supervisor": "Warehouse Supervisor",
    "dispatcher":           "Dispatcher",
    "master_tech":          "Master Tech",
    "csr":                  "Customer Service Rep",
    "marketing":            "Marketing",
    "warehouse_manager":    "Warehouse Manager",
    "lead_tech":            "Journeyman",
    "senior_tech":          "Senior Technician",
    "tech":                 "Technician",
    "install_tech":         "Installation Technician",
    "commercial_tech":      "Commercial Technician",
    "warehouse_floor":      "Warehouse Floor",
    "parts_runner":         "Parts Runner",
    "driver":               "Delivery Driver",
    "apprentice":           "Apprentice",
}


class OrgAssignBody(BaseModel):
    supervisor_id: Optional[int] = None   # null = remove supervisor
    reason: Optional[str] = ""


def _supervisor_chain_admin_ids(con, start_admin_id: int) -> set:
    """Walk UP the admin reporting chain starting from start_admin_id and
    return the set of admin_ids in the chain. Used to prevent cycles
    when reassigning supervisors."""
    seen = set()
    cur = int(start_admin_id)
    while cur and cur not in seen:
        seen.add(cur)
        row = con.execute(
            "SELECT supervisor_id FROM admin_users WHERE id = ?", (cur,)
        ).fetchone()
        if not row or not row["supervisor_id"]: break
        cur = int(row["supervisor_id"])
    return seen


@app.get("/api/admin/org/eligible-supervisors")
def admin_org_eligible_supervisors(request: Request):
    """Returns the full list of active admins that can be assigned as a
    supervisor. Gated on admin:view_all so HR + super_admin can populate
    the picker; the actual ASSIGN action is gated separately on admin:update."""
    admin = _require_perm(request, "admin:view_all")
    from database import _con
    con = _con(); con.row_factory = __import__('sqlite3').Row
    rows = con.execute(
        "SELECT id, name, prid, role FROM admin_users "
        "WHERE active = 1 ORDER BY name"
    ).fetchall()
    con.close()
    return {
        "admins": [
            {"id": r["id"], "name": r["name"], "prid": r["prid"],
             "role": r["role"],
             "role_label": _ROLE_LABEL.get(r["role"], (r["role"] or '').replace('_',' ').title())}
            for r in rows
        ]
    }


@app.post("/api/admin/org/people/{kind}/{person_id}/supervisor")
def admin_org_set_supervisor(request: Request, kind: str, person_id: int,
                              body: OrgAssignBody):
    """Assign (or clear) the supervisor for ANY person in the org. Caller
    needs admin:update (super_admin + hr_admin in the default matrix).
    Cycle-safe: refuses to assign someone to a supervisor whose own chain
    passes through this person. Full audit trail with PRID + before/after."""
    admin = _require_perm(request, "admin:update")
    if kind not in ("admin", "tech"):
        raise HTTPException(422, "kind must be 'admin' or 'tech'")
    from database import _con, set_admin_supervisor, set_tech_supervisor
    con = _con(); con.row_factory = __import__('sqlite3').Row
    tbl = "admin_users" if kind == "admin" else "technicians"
    person = con.execute(
        f"SELECT id, name, role, supervisor_id, active FROM {tbl} WHERE id = ?",
        (int(person_id),),
    ).fetchone()
    if not person:
        con.close(); raise HTTPException(404, "Person not found")
    if not person["active"]:
        con.close(); raise HTTPException(409, "Cannot reassign an inactive employee")
    new_sup_id = body.supervisor_id
    if new_sup_id is not None:
        try:
            new_sup_id = int(new_sup_id)
        except (TypeError, ValueError):
            con.close(); raise HTTPException(422, "supervisor_id must be an integer or null")
        sup = con.execute(
            "SELECT id, name, role FROM admin_users WHERE id = ? AND active = 1",
            (new_sup_id,)
        ).fetchone()
        if not sup:
            con.close(); raise HTTPException(404, "Supervisor not found or inactive")
        if kind == "admin" and new_sup_id == person_id:
            con.close(); raise HTTPException(422, "Cannot assign someone as their own supervisor")
        if kind == "admin":
            chain = _supervisor_chain_admin_ids(con, new_sup_id)
            if person_id in chain:
                con.close()
                raise HTTPException(
                    409,
                    "Cycle detected — that supervisor already reports to this person.",
                )
    before = {"supervisor_id": person["supervisor_id"]}
    con.close()
    if kind == "admin":
        set_admin_supervisor(person_id, new_sup_id)
    else:
        set_tech_supervisor(person_id, new_sup_id)
    _audit_from(admin, "org.supervisor_assigned", request,
                target_type=("admin_user" if kind == "admin" else "technician"),
                target_id=person_id, target_label=person["name"],
                before=before,
                after={"supervisor_id": new_sup_id,
                       "reason": (body.reason or "")[:300]})
    return {"ok": True, "person": {"id": person_id, "kind": kind,
                                    "name": person["name"]},
            "supervisor_id": new_sup_id}


@app.get("/api/me/org-chart")
def me_org_chart(request: Request, as_kind: str = None, as_id: int = None):
    """Returns the org context for the signed-in user: who they report to,
    who reports to them, and their peers. Works for both admins and techs.

    Any signed-in staff member may pass ?as_kind={admin|tech}&as_id=<id> to
    re-root the chart on another person — this powers the org-chart drill-down
    that lives on the Profile panel of EVERY staff surface (admin + tech). The
    payload is purely structural (name / role / PRID / department / avatar);
    it carries no contact info, salary, or other PII, and only ACTIVE people
    are ever resolved."""
    from database import _con
    kind, me = _resolve_any_staff(request)
    # Optional "view as someone else". Restricted to active staff so the
    # drill-down can't be used to resolve terminated/deactivated employees.
    if as_kind and as_id:
        if as_kind not in ('admin', 'tech'):
            raise HTTPException(422, "as_kind must be 'admin' or 'tech'")
        c = _con(); c.row_factory = __import__('sqlite3').Row
        tbl = 'admin_users' if as_kind == 'admin' else 'technicians'
        row = c.execute(f"SELECT * FROM {tbl} WHERE id = ? AND active = 1",
                        (int(as_id),)).fetchone()
        c.close()
        if not row:
            raise HTTPException(404, "Person not found")
        kind = as_kind
        me = dict(row)
    me_id   = me.get("id")
    me_role = (me.get("role") or "").lower()
    me_sup_id = me.get("supervisor_id")
    rank_me = _ORG_RANK.get(me_role, 99)

    def _norm(row, k):
        """Normalize an admin_users or technicians row into the chart-card shape."""
        if not row: return None
        role = (row.get("role") or "").lower()
        return {
            "id":          row.get("id"),
            "kind":        k,                       # 'admin' | 'tech'
            "name":        row.get("name") or "",
            "prid":        row.get("prid") or row.get("tech_code") or "",
            "role":        role,
            "role_label":  _ROLE_LABEL.get(role, role.replace('_',' ').title()),
            "department":  row.get("department") or "",
            "avatar_url":  _sign_photo_url(row.get("avatar_filename")) if row.get("avatar_filename") else None,
            "rank":        _ORG_RANK.get(role, 99),
        }

    con = _con()
    con.row_factory = __import__('sqlite3').Row

    # Manager — supervisor is always an admin_users row in this schema.
    manager = None
    if me_sup_id:
        r = con.execute(
            "SELECT id, name, prid, role, avatar_filename, supervisor_id "
            "FROM admin_users WHERE id = ? AND active = 1", (me_sup_id,)
        ).fetchone()
        if r: manager = _norm(dict(r), "admin")

    # If no explicit supervisor, treat the lowest-ranked active super_admin
    # as the implicit top-of-chain (so org chart never feels orphaned).
    if not manager and rank_me > 0:
        r = con.execute(
            "SELECT id, name, prid, role, avatar_filename, supervisor_id "
            "FROM admin_users WHERE role='super_admin' AND active=1 ORDER BY id LIMIT 1"
        ).fetchone()
        if r and r["id"] != me_id:
            manager = _norm(dict(r), "admin")
            manager["implicit"] = True

    # Direct reports — admins + techs whose supervisor_id == me.id.
    # (Only admins can be a supervisor in this schema.)
    reports = []
    if kind == "admin":
        for r in con.execute(
            "SELECT id, name, prid, role, avatar_filename, supervisor_id "
            "FROM admin_users WHERE supervisor_id = ? AND active = 1 ORDER BY name",
            (me_id,)
        ):
            reports.append(_norm(dict(r), "admin"))
        for r in con.execute(
            "SELECT id, name, prid, tech_code, role, department, avatar_filename, supervisor_id "
            "FROM technicians WHERE supervisor_id = ? AND active = 1 ORDER BY name",
            (me_id,)
        ):
            reports.append(_norm(dict(r), "tech"))

    # Peers — same supervisor as me (sibling under same manager). If I have
    # no supervisor, my peers are anyone at the same rank in either table.
    peers = []
    seen = {(me_id, kind)}
    if me_sup_id:
        for r in con.execute(
            "SELECT id, name, prid, role, avatar_filename, supervisor_id "
            "FROM admin_users WHERE supervisor_id = ? AND active = 1 ORDER BY name",
            (me_sup_id,)
        ):
            key = (r["id"], "admin")
            if key in seen: continue
            seen.add(key); peers.append(_norm(dict(r), "admin"))
        for r in con.execute(
            "SELECT id, name, prid, tech_code, role, department, avatar_filename, supervisor_id "
            "FROM technicians WHERE supervisor_id = ? AND active = 1 ORDER BY name",
            (me_sup_id,)
        ):
            key = (r["id"], "tech")
            if key in seen: continue
            seen.add(key); peers.append(_norm(dict(r), "tech"))
    else:
        # No supervisor recorded — fall back to same-rank peers org-wide.
        same_rank_roles = [k for k, v in _ORG_RANK.items() if v == rank_me]
        if same_rank_roles:
            placeholders = ",".join(["?"] * len(same_rank_roles))
            for r in con.execute(
                f"SELECT id, name, prid, role, avatar_filename, supervisor_id "
                f"FROM admin_users WHERE role IN ({placeholders}) AND active=1 AND id != ? ORDER BY name",
                (*same_rank_roles, me_id if kind == 'admin' else -1)
            ):
                key = (r["id"], "admin")
                if key in seen: continue
                seen.add(key); peers.append(_norm(dict(r), "admin"))
            for r in con.execute(
                f"SELECT id, name, prid, tech_code, role, department, avatar_filename, supervisor_id "
                f"FROM technicians WHERE role IN ({placeholders}) AND active=1 AND id != ? ORDER BY name",
                (*same_rank_roles, me_id if kind == 'tech' else -1)
            ):
                key = (r["id"], "tech")
                if key in seen: continue
                seen.add(key); peers.append(_norm(dict(r), "tech"))
    con.close()

    return {
        "me":      _norm({**me, "id": me_id, "role": me_role,
                          "supervisor_id": me_sup_id,
                          "avatar_filename": me.get("avatar_filename")}, kind),
        "manager": manager,
        "peers":   peers,
        "reports": reports,
    }


@app.get("/api/staff/me")
def api_staff_me(request: Request):
    """Lightweight identity payload for the unified home page. Returns
    enough for the shell to render a hero + role-aware nav tiles
    without any further round-trips."""
    kind, who = _resolve_any_staff(request)
    avatar_fn = who.get("avatar_filename")
    avatar_url = _sign_photo_url(avatar_fn) if avatar_fn else None
    if kind == "admin":
        return {
            "kind": "admin",
            "id": who["id"],
            "name": who["name"],
            "role": who.get("role"),
            "role_label": (who.get("role") or "").replace("_", " ").title(),
            "prid": who.get("prid"),
            "email": who.get("email"),
            "phone": who.get("phone"),
            "department": who.get("department") or "Administration",
            "avatar_url": avatar_url,
            # Effective permission set for this admin's role. The unified /home
            # Menu uses this to decide which Admin-Console destinations to show,
            # so we never duplicate the ADMIN_PERMS map on the client (it would
            # drift). Mirrors admin.html applyRoleVisibility() gating exactly.
            "perms": sorted(ADMIN_PERMS.get(who.get("role") or "", set())),
            # Delegations nav is gated on role==super_admin OR delegation power,
            # not a single perm — surface the flag so the Menu can match.
            "has_delegation_power": 1 if who.get("has_delegation_power") in (1, True) else 0,
        }
    # tech (includes warehouse_floor / warehouse_manager / parts_runner
    # — they live in the technicians table with a staff_type)
    staff_type = who.get("staff_type") or "tech"
    role_label_map = {
        "tech": "Technician",
        "warehouse_floor":   "Warehouse Floor",
        "warehouse_manager": "Warehouse Manager",
        "parts_runner":      "Parts Runner",
        "driver":            "Delivery Driver",
    }
    return {
        "kind": "tech",
        "id": who["id"],
        "name": who["name"],
        "tech_code": who.get("tech_code"),
        "role": who.get("role"),
        "staff_type": staff_type,
        "role_label": role_label_map.get(staff_type, "Technician"),
        "email": who.get("email"),
        "phone": who.get("phone"),
        "department": who.get("department") or (
            "Warehouse" if staff_type.startswith(("warehouse_", "parts_")) else "Field Services"),
        "avatar_url": avatar_url,
    }


@app.post("/api/staff/me/avatar")
async def api_staff_me_avatar_upload(request: Request, file: UploadFile = File(...)):
    """Upload or replace the signed-in staff member's profile photo. Works
    for both admins and techs — the subject's kind comes from the cookie,
    not the request body, so a user can only ever update their own avatar.

    The upload is re-encoded via Pillow (see _process_avatar): EXIF is
    stripped, the output is a 512x512 JPEG, anything that isn't a real
    image is rejected. Stored under uploads/photos/ with a deterministic
    filename, so re-uploading overwrites the previous file."""
    from database import set_subject_avatar
    kind, who = _resolve_any_staff(request)
    body = await file.read()
    if not body:
        raise HTTPException(400, "empty upload")
    if len(body) > AVATAR_MAX_BYTES:
        raise HTTPException(413, f"file too large (max {AVATAR_MAX_BYTES // (1024*1024)} MB)")
    out = _process_avatar(body)
    filename = f"avatar-{kind}-{int(who['id'])}.jpg"
    (PHOTOS_DIR / filename).write_bytes(out)
    set_subject_avatar(kind, who["id"], filename)
    return {"ok": True, "avatar_url": _sign_photo_url(filename)}


@app.delete("/api/staff/me/avatar")
def api_staff_me_avatar_delete(request: Request):
    """Remove the signed-in staff member's profile photo (DB row cleared
    + file unlinked). UI then falls back to coloured initials."""
    from database import set_subject_avatar, get_subject_avatar
    kind, who = _resolve_any_staff(request)
    fn = get_subject_avatar(kind, who["id"])
    if fn:
        try:
            (PHOTOS_DIR / fn).unlink(missing_ok=True)
        except Exception:
            pass
        set_subject_avatar(kind, who["id"], None)
    return {"ok": True}


@app.get("/api/staff/me/home")
def api_staff_me_home(request: Request):
    """Aggregated home-page payload. Tries each summary in a try-block
    so a single dead datasource doesn't break the whole shell."""
    kind, who = _resolve_any_staff(request)
    out = {
        "profile": api_staff_me(request),
        "today": datetime.now(timezone.utc).strftime("%A, %B %d, %Y"),
        "messages": [],
        "recent_pay": [],
        "tasks_summary": {},
    }
    # Recent company messages (universal — all staff see them).
    try:
        out["messages"] = (list_active_company_messages(limit=5) or [])
    except Exception:
        pass
    # Recent payslips (last 3) — every staff member has a self-view.
    try:
        if kind == "admin":
            rows = list_payslips_for_subject("admin", who["id"], limit=3)
        else:
            rows = list_payslips_for_subject("tech", who["id"], limit=3)
        out["recent_pay"] = [
            {"id": r["id"],
             "period_label": r.get("period_label"),
             "period_end":   r.get("period_end"),
             "net_pay":      r.get("net_pay"),
             "currency":     r.get("currency") or "JMD"}
            for r in (rows or [])
        ]
    except Exception:
        pass
    # Tasks-summary — role-aware counts so the home page can show
    # "you have 3 pending approvals" etc. Each block fails open.
    tasks = {}
    if kind == "admin":
        role = (who.get("role") or "").lower()
        try:
            if _admin_can(role, "fs:report_view"):
                tasks["open_5s_exceptions"] = len(fs_list_exceptions(status="open", limit=500) or [])
        except Exception:
            pass
        try:
            from database import count_open_security_alerts as _cosa
            if _admin_can(role, "security:view_alerts"):
                tasks["open_security_alerts"] = _cosa()
        except Exception:
            pass
    else:
        # Tech: open jobs + my open 5S exceptions.
        try:
            from database import get_tech_jobs as _gtj
            jobs = _gtj(who["id"]) or []
            tasks["open_jobs"] = sum(1 for j in jobs if (j.get("status") or "") in ("scheduled", "in_progress"))
        except Exception:
            pass
        try:
            mine = fs_list_exceptions(tech_id=who["id"], status="open", limit=100) or []
            tasks["my_open_5s"] = len(mine)
        except Exception:
            pass
    out["tasks_summary"] = tasks
    return out


# ─────────────────────────────────────────────────────────────────────────
# In-app user settings (per-user preferences) — shared by staff + customers
# ─────────────────────────────────────────────────────────────────────────
# One small whitelisted JSON object per user, persisted server-side so a
# user's preferences follow them across devices. The DB layer
# (get_user_settings / set_user_settings in database.py) is a dumb key/value
# store; ALL defaults and validation live here so there is a single source of
# truth. Every key below maps to a real, wired-up effect on the client — no
# decorative toggles.
_SETTINGS_DEFAULTS = {
    "time_format":         "24h",          # PC.fmtTime + clocks (12h/24h)
    "date_format":         "dmy",          # PC.fmtDate (dmy=04/Jun/2026, iso=2026-06-04, mdy=Jun/04/2026)
    "density":             "comfortable",  # body[data-pc-density] (comfortable/compact)
    "theme":               "light",        # html[data-pc-theme] (light/dark) — dark mode
    "font_scale":          "normal",       # body[data-pc-fontscale] (normal/large)
    "reduce_motion":       False,          # body[data-pc-motion="reduce"] — disables animations/transitions
    "default_landing":     "auto",         # which panel/tab opens on load
    "language":            "en",           # only English shipped today
    "start_of_week":       "monday",       # staff schedule/timesheet week anchor (monday/sunday)
    "announcement_alerts": True,           # staff: company-message bell dot/awaiting card
}
_SETTINGS_ENUMS = {
    "time_format":   {"12h", "24h"},
    "date_format":   {"dmy", "iso", "mdy"},
    "density":       {"comfortable", "compact"},
    "theme":         {"light", "dark"},
    "font_scale":    {"normal", "large"},
    "start_of_week": {"monday", "sunday"},
    "language":      {"en"},
}
# Keys coerced to a plain bool (no enum).
_SETTINGS_BOOLS = {"reduce_motion", "announcement_alerts"}
# Valid default-landing targets per identity. "auto" = the app's normal
# default (Home for staff, Overview for customers).
_LANDING_BY_SUBJECT = {
    "admin":    {"auto", "dashboard", "jobs", "schedule", "pay", "messages"},
    "tech":     {"auto", "dashboard", "jobs", "schedule", "pay", "messages"},
    "customer": {"auto", "overview", "account"},
}


def _settings_keys_for(subject_type: str):
    """Which setting keys apply to a given identity. announcement_alerts and
    start_of_week are staff-only (customers have no company bell or schedule)."""
    keys = ["time_format", "date_format", "density", "theme", "font_scale",
            "reduce_motion", "default_landing", "language"]
    if subject_type in ("admin", "tech"):
        keys.extend(["start_of_week", "announcement_alerts"])
    return keys


def _sanitize_settings(subject_type: str, incoming: dict) -> dict:
    """Return only valid, applicable keys from `incoming`, coerced to safe
    values. Unknown keys and invalid values are dropped silently."""
    out = {}
    if not isinstance(incoming, dict):
        return out
    allowed = _settings_keys_for(subject_type)
    for key in allowed:
        if key not in incoming:
            continue
        val = incoming[key]
        if key in _SETTINGS_ENUMS:
            if isinstance(val, str) and val in _SETTINGS_ENUMS[key]:
                out[key] = val
        elif key == "default_landing":
            if isinstance(val, str) and val in _LANDING_BY_SUBJECT.get(subject_type, {"auto"}):
                out[key] = val
        elif key in _SETTINGS_BOOLS:
            out[key] = bool(val)
    return out


def _effective_settings(subject_type: str, subject_id: int) -> dict:
    """Defaults (filtered to applicable keys) overlaid with the user's saved,
    re-sanitized preferences."""
    base = {k: _SETTINGS_DEFAULTS[k] for k in _settings_keys_for(subject_type)}
    stored = _sanitize_settings(subject_type, get_user_settings(subject_type, subject_id))
    base.update(stored)
    return base


@app.get("/api/staff/me/settings")
def api_staff_settings_get(request: Request):
    kind, who = _resolve_any_staff(request)
    return {"settings": _effective_settings(kind, int(who["id"]))}


@app.put("/api/staff/me/settings")
def api_staff_settings_put(request: Request, body: dict = Body(default={})):
    kind, who = _resolve_any_staff(request)
    current = _sanitize_settings(kind, get_user_settings(kind, int(who["id"])))
    current.update(_sanitize_settings(kind, body))
    set_user_settings(kind, int(who["id"]), current)
    return {"settings": _effective_settings(kind, int(who["id"]))}


@app.get("/api/portal/me/settings")
def api_portal_settings_get(request: Request):
    customer_id = _require_customer(request)
    return {"settings": _effective_settings("customer", customer_id)}


@app.put("/api/portal/me/settings")
def api_portal_settings_put(request: Request, body: dict = Body(default={})):
    customer_id = _require_customer(request)
    current = _sanitize_settings("customer", get_user_settings("customer", customer_id))
    current.update(_sanitize_settings("customer", body))
    set_user_settings("customer", customer_id, current)
    return {"settings": _effective_settings("customer", customer_id)}


# ── Sessions / sign-in history (Settings → Security) ──────────────────────
# Read-only "recent sign-ins" plus "sign out of all other devices". Sourced
# from the sessions table (each row is one login); login is a POST so it never
# reaches access_log. Every device row maps to a real revocable session — no
# decorative entries.
_COOKIE_BY_KIND = {
    "admin":    COOKIE_ADMIN,
    "tech":     COOKIE_TECH,
    "customer": COOKIE_CUSTOMER,
}


def _serialize_sessions(rows, current_jti):
    """Shape session rows for the client: drop the raw jti, flag the current
    device and whether each session is still live."""
    now_iso = datetime.now(timezone.utc).isoformat()
    out = []
    for r in rows:
        active = (not r.get("revoked_at")) and (r.get("expires_at") or "") > now_iso
        out.append({
            "created_at":   r.get("created_at"),
            "last_seen_at": r.get("last_seen_at"),
            "expires_at":   r.get("expires_at"),
            "ip_address":   r.get("ip_address"),
            "user_agent":   r.get("user_agent"),
            "active":       bool(active),
            "revoked":      bool(r.get("revoked_at")),
            "current":      bool(current_jti and r.get("jti") == current_jti),
        })
    return out


def _sessions_payload(kind: str, subject_id: int, request: Request):
    cookie = _COOKIE_BY_KIND.get(kind)
    current_jti = _current_session_jti(request, cookie) if cookie else None
    rows = get_recent_sessions_for(kind, int(subject_id), limit=20)
    active = get_active_sessions_for(kind, int(subject_id))
    return {
        "sessions": _serialize_sessions(rows, current_jti),
        "active_count": len(active),
    }


@app.get("/api/staff/me/sessions")
def api_staff_sessions_get(request: Request):
    kind, who = _resolve_any_staff(request)
    return _sessions_payload(kind, int(who["id"]), request)


@app.post("/api/staff/me/sessions/revoke-others")
def api_staff_sessions_revoke_others(request: Request):
    kind, who = _resolve_any_staff(request)
    current_jti = _current_session_jti(request, _COOKIE_BY_KIND.get(kind))
    n = revoke_other_sessions_for(kind, int(who["id"]), current_jti)
    return {"revoked": n, **_sessions_payload(kind, int(who["id"]), request)}


@app.get("/api/portal/me/sessions")
def api_portal_sessions_get(request: Request):
    customer_id = _require_customer(request)
    return _sessions_payload("customer", customer_id, request)


@app.post("/api/portal/me/sessions/revoke-others")
def api_portal_sessions_revoke_others(request: Request):
    customer_id = _require_customer(request)
    current_jti = _current_session_jti(request, COOKIE_CUSTOMER)
    n = revoke_other_sessions_for("customer", customer_id, current_jti)
    return {"revoked": n, **_sessions_payload("customer", customer_id, request)}


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
    item_summary = []
    for it in (body.items or []):
        if not isinstance(it, dict): continue
        item_summary.append({
            "item_id":  it.get("item_id") or it.get("id"),
            "label":    (it.get("item_label") or it.get("label") or '')[:80],
            "category": it.get("category"),
            "pass":     bool(it.get("pass")) if "pass" in it else None,
            "score":    it.get("score"),
            "note":     (it.get("note") or '')[:120] if it.get("note") else None,
        })
    log_audit(
        actor_type="tech", actor_id=tech_id,
        actor_prid=tech.get("prid") if tech else None,
        actor_label=tech.get("name") if tech else None,
        actor_role=tech.get("role") if tech else None,
        action="fs.audit.submit",
        target_type="fs_audit", target_id=out["audit_id"],
        target_label=f"{asset['asset_code']}/{body.phase}",
        after_value={
            "asset_id":         body.asset_id,
            "asset_code":       asset.get("asset_code"),
            "phase":            body.phase,
            "auditor_kind":     "tech",
            "overall_pass":     out.get("overall_pass"),
            "exception_count":  len(out.get("exception_ids", [])),
            "exception_ids":    out.get("exception_ids", [])[:20],
            "item_count":       len(item_summary),
            "items":            item_summary[:40],
        },
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
                after={
                    "asset_code":       body.asset_code,
                    "asset_type":       body.asset_type,
                    "label":            body.label,
                    "hub_id":           body.hub_id,
                    "assigned_tech_id": body.assigned_tech_id,
                    "static_location":  body.static_location,
                    "notes":            (body.notes or "")[:200],
                })
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
    # Scope `before` to only the fields that actually changed so the diff
    # is readable in the audit log (full asset record can be 20+ fields).
    before_scoped = {k: before.get(k) for k in fields.keys()}
    _audit_from(admin, "fs.asset.update", request,
                target_type="fs_asset", target_id=asset_id,
                target_label=before["asset_code"],
                before=before_scoped, after=fields)
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
                after={
                    "asset_id":      asset_id,
                    "asset_code":    asset.get("asset_code"),
                    "item_type":     body.item_type,
                    "item_label":    body.item_label,
                    "sop_required":  body.sop_required,
                    "location_code": body.location_code,
                    "expiry_date":   body.expiry_date,
                    "part_id":       body.part_id,
                })
    return {"id": iid}


@app.get("/api/admin/5s/assets/{asset_id}/items")
def admin_fs_list_asset_items(request: Request, asset_id: int):
    _require_perm(request, "fs:report_view")
    return fs_list_asset_items(asset_id)


@app.delete("/api/admin/5s/assets/{asset_id}/items/{item_id}")
def admin_fs_remove_asset_item(request: Request, asset_id: int, item_id: int):
    admin = _require_perm(request, "fs:asset_manage")
    # Snapshot the item BEFORE deletion so the audit log records exactly
    # what was removed (label, type, expiry, etc.) — otherwise after the
    # delete there's no way to reconstruct what disappeared.
    before_items = fs_list_asset_items(asset_id) or []
    before_item = next((i for i in before_items if (i.get("id") == item_id)), None) or {}
    fs_remove_asset_item(item_id)
    _audit_from(admin, "fs.asset_item.remove", request,
                target_type="fs_asset_item", target_id=item_id,
                target_label=before_item.get("item_label"),
                before={
                    "asset_id":      asset_id,
                    "item_type":     before_item.get("item_type"),
                    "item_label":    before_item.get("item_label"),
                    "sop_required":  before_item.get("sop_required"),
                    "location_code": before_item.get("location_code"),
                    "expiry_date":   before_item.get("expiry_date"),
                    "part_id":       before_item.get("part_id"),
                },
                after=None)
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
    # Compact per-item summary so the audit log records WHAT failed (not
    # just "n exceptions"). Each item entry: {label, pass, score?, note?}.
    item_summary = []
    for it in (body.items or []):
        if not isinstance(it, dict): continue
        item_summary.append({
            "item_id":    it.get("item_id") or it.get("id"),
            "label":      (it.get("item_label") or it.get("label") or '')[:80],
            "category":   it.get("category"),
            "pass":       bool(it.get("pass")) if "pass" in it else None,
            "score":      it.get("score"),
            "note":       (it.get("note") or '')[:120] if it.get("note") else None,
        })
    _audit_from(admin, "fs.audit.submit", request,
                target_type="fs_audit", target_id=out["audit_id"],
                target_label=f"{asset['asset_code']}/{body.phase}",
                after={
                    "asset_id":         body.asset_id,
                    "asset_code":       asset.get("asset_code"),
                    "phase":            body.phase,
                    "auditor_role":     admin.get("role"),
                    "overall_pass":     out.get("overall_pass"),
                    "exception_count":  len(out.get("exception_ids", [])),
                    "exception_ids":    out.get("exception_ids", [])[:20],
                    "item_count":       len(item_summary),
                    "items":            item_summary[:40],
                })
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
    # Pull the post-state so the audit row shows what the resolution
    # note actually committed as + when. before/after are full snapshots
    # so the forensic trail is complete (who, when, what changed, from-to).
    after_row = fs_get_exception(exception_id) or {}
    _audit_from(admin, "fs.exception.resolve", request,
                target_type="fs_exception", target_id=exception_id,
                target_label=f"{before.get('category','')} · {before.get('asset_code') or before.get('asset_id') or ''}",
                before={
                    "status":           before.get("status"),
                    "severity":         before.get("severity"),
                    "category":         before.get("category"),
                    "description":      (before.get("description") or "")[:200],
                    "asset_id":         before.get("asset_id"),
                    "asset_code":       before.get("asset_code"),
                    "tech_id":          before.get("tech_id"),
                    "opened_at":        before.get("opened_at"),
                    "audit_id":         before.get("audit_id"),
                },
                after={
                    "status":           "resolved",
                    "resolution_note":  (body.resolution_note or "")[:500],
                    "resolved_at":      after_row.get("resolved_at"),
                    "resolved_by_id":   admin.get("id"),
                    "resolved_by_prid": admin.get("prid"),
                    "resolved_by_role": admin.get("role"),
                })
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
    after_row = fs_get_exception(exception_id) or {}
    _audit_from(admin, "fs.exception.escalate_director", request,
                target_type="fs_exception", target_id=exception_id,
                target_label=f"{before.get('category','')} · {before.get('asset_code') or before.get('asset_id') or ''}",
                before={
                    "status":           before.get("status"),
                    "severity":         before.get("severity"),
                    "category":         before.get("category"),
                    "description":      (before.get("description") or "")[:200],
                    "asset_id":         before.get("asset_id"),
                    "asset_code":       before.get("asset_code"),
                    "tech_id":          before.get("tech_id"),
                    "opened_at":        before.get("opened_at"),
                    "audit_id":         before.get("audit_id"),
                    "escalated_to_id":  before.get("escalated_to_id"),
                },
                after={
                    "status":             "escalated_director",
                    "escalated_to_id":    admin.get("id"),
                    "escalated_to_prid":  admin.get("prid"),
                    "escalated_to_role":  admin.get("role"),
                    "escalated_at":       after_row.get("escalated_at"),
                })
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
    """5S dashboard counters. `open_exceptions` previously counted ONLY
    status='open' — once an exception got escalated it dropped out of
    the tile, even though it's still un-resolved. The 5S banner uses
    the union of open+escalated+escalated_director for safety_red,
    which made the OPEN tile (0) disagree with the banner (8 safety/
    LOTO open). Reconciled: OPEN tile now counts the UNION too, with
    a sub-breakdown by status so the operator can see the escalation
    flow. safety_red_count stays a strict subset of open_exceptions.
    Field-reported May 2026."""
    _require_perm(request, "fs:report_view")
    overview = fs_list_compliance_overview(hub_id=hub_id, window_days=30)
    open_excs     = fs_list_exceptions(status="open", hub_id=hub_id, limit=500)
    esc_excs      = fs_list_exceptions(status="escalated", hub_id=hub_id, limit=500)
    director_excs = fs_list_exceptions(status="escalated_director", hub_id=hub_id, limit=500)
    all_unresolved = open_excs + esc_excs + director_excs
    safety_open    = [e for e in all_unresolved
                      if e.get("severity") == "safety_loto"]
    return {
        "compliance":            overview,
        # Union of unresolved — matches the banner's denominator.
        "open_exceptions":       len(all_unresolved),
        # Per-status breakdown for any UI that wants to drill in.
        "status_open":           len(open_excs),
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


async def _start_fs_escalation_loop():
    _asyncio.create_task(_fs_escalation_loop())
_LIFESPAN_STARTERS.append(_start_fs_escalation_loop)


# /me + /tech/home — RETIRED (operator removed the page entirely
# 2026-05-25). Both URLs now 302 to /home. The clock-in card on /home
# replaces "Sign In for Work"; per-staff identity + recent pay live on
# /home's hero + Recent pay card; payroll detail is in admin#myprofile
# for admins (techs view their pay history on /home's Recent pay card).
@app.get("/me")
def my_profile_redirect():
    return RedirectResponse(url="/home", status_code=302)


@app.get("/tech/home")
def tech_home_redirect():
    return RedirectResponse(url="/home", status_code=302)


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
    recipient_kind: Optional[str] = "admin"  # 'admin' | 'tech' (techs allowed in v2)
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
    # Locked rule 4 — no self-grants. Now namespace-aware: an admin and a
    # tech may legitimately share a numeric id (different identity spaces),
    # so the self-check has to consider recipient_kind. We do it inside the
    # per-kind block below.
    # v2: any active employee (admin OR tech) can be a recipient. The
    # `recipient_kind` field disambiguates which identity space to look in.
    # Power delegations are still admin-only (techs don't have admin
    # delegation authority to wield even if granted).
    rkind = (body.recipient_kind or "admin").lower()
    if rkind not in ("admin", "tech"):
        raise HTTPException(422, "recipient_kind must be 'admin' or 'tech'")
    if rkind == "admin":
        recipient = _get_admin_for_deleg(int(body.recipient_id))
        if not recipient:
            raise HTTPException(422, "Recipient admin not found")
    else:
        from database import get_tech_by_id as _get_tech_for_deleg
        recipient = _get_tech_for_deleg(int(body.recipient_id))
        if not recipient or not recipient.get("active"):
            raise HTTPException(422, "Recipient employee not found or inactive")
        if body.delegation_type == "power":
            raise HTTPException(422, "Power delegations are admin-only")
    # Self-grant guard still applies — but only within the same identity space.
    if rkind == "admin" and int(body.recipient_id) == int(admin["id"]):
        raise HTTPException(422, "Self-grants are not allowed")
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
        recipient_id=body.recipient_id, recipient_kind=rkind,
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
    # Best-effort: ping the super-admins who own the regrant approval queue
    # (approve/deny are super_admin-only). Never blocks the request.
    try:
        from database import get_all_admin_users
        requester = admin.get("name") or admin.get("prid") or f"admin #{admin['id']}"
        for au in get_all_admin_users():
            if au.get("active") and au.get("role") == "super_admin":
                _notify(
                    "admin", int(au["id"]), "delegation",
                    "Re-grant request awaiting review",
                    body=f"{requester} requested re-grant of a cascade-revoked "
                         f"delegation. Open the delegations queue to approve or deny.",
                    link="/admin", severity="info",
                    dedupe_key=f"regrant_req:{rid}",
                    dedupe_window_minutes=1440)
    except Exception as _e:
        logger.warning(f"[notif] regrant request notify failed: {_e}")
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


async def _start_delegation_expiry_loop():
    _asyncio.create_task(_delegation_expiry_loop())
_LIFESPAN_STARTERS.append(_start_delegation_expiry_loop)


# ── PM-contract visit generation cron (daily) ──────────────────────────────
# Materialises upcoming PM visits from active contracts and expires contracts
# whose term has ended. Idempotent (see generate_due_pm_visits), so a missed
# run or a manual `/pm-contracts/generate` trigger never double-books a visit.
PM_GEN_LOOKAHEAD_DAYS = int(os.environ.get("PM_GEN_LOOKAHEAD_DAYS", "30"))


async def _pm_contract_gen_loop():
    await _asyncio.sleep(60)  # let init_db settle on boot
    while True:
        try:
            res = generate_due_pm_visits(lookahead_days=PM_GEN_LOOKAHEAD_DAYS)
            if res["created"] or res["expired"]:
                try:
                    log_audit(actor_type="system", action="pm_contract.cron_generate",
                              target_type="pm_contracts",
                              after_value={"created": len(res["created"]),
                                           "expired": len(res["expired"]),
                                           "processed": res["processed"]})
                except Exception as _e:
                    logger.warning(f"[pm] audit-write failed: {_e}")
                logger.info(f"pm generate cron: {len(res['created'])} visit(s) created, "
                            f"{len(res['expired'])} contract(s) expired")
        except Exception as _e:
            logger.error(f"pm generate cron error: {_e}")
        await _asyncio.sleep(24 * 60 * 60)


async def _start_pm_contract_gen_loop():
    _asyncio.create_task(_pm_contract_gen_loop())
_LIFESPAN_STARTERS.append(_start_pm_contract_gen_loop)


# ── Encrypted DB backup cron (default: daily) ──────────────────────────────
# Disaster recovery: everything the business needs lives in one SQLite file.
# This loop takes an online-backup snapshot, gzips + encrypts it, prunes old
# artifacts, and (when BACKUP_OFFSITE_CMD is set) pushes it off-box. It runs
# in-process like every other cron here — no external scheduler required.
async def _backup_loop():
    await _asyncio.sleep(90)  # let init_db settle, stagger after PM gen
    interval = max(1, _backup.INTERVAL_HOURS) * 60 * 60
    while True:
        try:
            meta = _backup.create_backup(reason="cron")
            try:
                log_audit(actor_type="system", action="backup.cron_create",
                          target_type="backup",
                          after_value={"name": meta["name"],
                                       "encrypted": meta["encrypted"],
                                       "artifact_bytes": meta["artifact_bytes"],
                                       "pruned": len(meta.get("pruned") or [])})
            except Exception as _e:
                logger.warning(f"[backup] audit-write failed: {_e}")
            logger.info(f"backup cron: wrote {meta['name']} "
                        f"({meta['artifact_bytes']} bytes, encrypted={meta['encrypted']})")
        except Exception as _e:
            logger.error(f"backup cron error: {_e}")
        await _asyncio.sleep(interval)


async def _start_backup_loop():
    _asyncio.create_task(_backup_loop())
_LIFESPAN_STARTERS.append(_start_backup_loop)


# ── Low-stock sweep cron (daily safety net) ────────────────────────────────
# Real-time hooks fire on stock-decrementing writes; this sweep catches parts
# that were already low, or that crossed the line because a reorder_point was
# raised. Deduped per part (24h) so it never floods the bell.
async def _low_stock_sweep_loop():
    await _asyncio.sleep(120)  # let init_db settle, stagger after backup
    while True:
        try:
            from database import list_low_stock_parts
            low = list_low_stock_parts()
            if low:
                admins = _admins_for_inventory_alerts()
                for p in low:
                    _emit_low_stock_alert(p, admins)
                logger.info(f"low-stock sweep: {len(low)} part(s) at/below reorder")
        except Exception as _e:
            logger.error(f"low-stock sweep error: {_e}")
        await _asyncio.sleep(24 * 60 * 60)


async def _start_low_stock_loop():
    _asyncio.create_task(_low_stock_sweep_loop())
_LIFESPAN_STARTERS.append(_start_low_stock_loop)


# ── Appointment reminder cron (#5) ─────────────────────────────────────────
# Remind customers of upcoming scheduled visits at fixed lead times. Deduped
# per (visit, lead) so each wave fires once even though the loop runs 4x/day
# (which keeps reminders timely without depending on a single fragile run).
def _appt_reminder_leads() -> list:
    """Lead-day offsets to remind at, from APPT_REMINDER_LEAD_DAYS (default
    '3,1' → three days out and the day before). Non-negative ints only."""
    raw = os.environ.get("APPT_REMINDER_LEAD_DAYS", "3,1")
    leads = []
    for tok in raw.replace(" ", "").split(","):
        try:
            d = int(tok)
        except ValueError:
            continue
        if d >= 0 and d not in leads:
            leads.append(d)
    return leads or [1]


async def _appointment_reminder_loop():
    await _asyncio.sleep(150)  # let init_db settle, stagger after low-stock
    from datetime import datetime as _dt, timezone as _tz, timedelta as _td
    from database import list_scheduled_visits_on
    while True:
        try:
            today = _dt.now(_tz.utc).date()
            leads = _appt_reminder_leads()
            total = 0
            for lead in leads:
                target = (today + _td(days=lead)).isoformat()
                for v in list_scheduled_visits_on(target):
                    _emit_appointment_reminder(v, lead)
                    total += 1
            if total:
                logger.info(f"appointment reminders: {total} visit-reminder(s) "
                            f"across leads {leads}")
        except Exception as _e:
            logger.error(f"appointment reminder cron error: {_e}")
        await _asyncio.sleep(6 * 60 * 60)  # 4x/day; dedupe prevents repeats


async def _start_appointment_reminders():
    _asyncio.create_task(_appointment_reminder_loop())
_LIFESPAN_STARTERS.append(_start_appointment_reminders)


# ── Estimate expiry cron (#3) ──────────────────────────────────────────────
# Sent/approved estimates past their valid_until are flipped to 'expired' so
# stale quotes can't be approved or converted. Idempotent daily sweep.
async def _estimate_expiry_loop():
    await _asyncio.sleep(180)  # let init_db settle, stagger after appt reminders
    from database import expire_stale_estimates
    while True:
        try:
            ids = expire_stale_estimates()
            if ids:
                logger.info(f"estimate expiry: marked {len(ids)} estimate(s) expired")
        except Exception as _e:
            logger.error(f"estimate expiry cron error: {_e}")
        await _asyncio.sleep(24 * 60 * 60)


async def _start_estimate_expiry():
    _asyncio.create_task(_estimate_expiry_loop())
_LIFESPAN_STARTERS.append(_start_estimate_expiry)


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


async def _start_tech_eod_loop():
    _asyncio.create_task(_tech_eod_loop())
_LIFESPAN_STARTERS.append(_start_tech_eod_loop)


@app.get("/")
def index():
    return FileResponse("index.html")
