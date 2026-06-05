# PrimeCool Services — System Operations Runbook

**Version:** v1.0
**Date:** 2026-05-31
**Status:** Development-only (not yet in production)
**Classification:** Confidential — Internal use only

> This runbook is written so that a competent full-stack developer who has
> never seen this system can understand, run, maintain, and operate it if the
> original builder is unavailable. Commands and file paths are exact. Where the
> code and the prior documentation disagree, the **code** is treated as
> authoritative and the discrepancy is flagged.

---

## Table of Contents

1. [System Overview](#1-system-overview)
2. [Core Data Model](#2-core-data-model)
3. [System Components — Deep Dive](#3-system-components--deep-dive)
4. [Security & Authentication](#4-security--authentication)
5. [Operational Runbook](#5-operational-runbook)
6. [Codebase Organization](#6-codebase-organization)
7. [Database Administration](#7-database-administration)
8. [Maintenance & Updates](#8-maintenance--updates)
9. [Known Limitations & Tech Debt](#9-known-limitations--tech-debt)
10. [Appendices](#10-appendices)

---

# 1. System Overview

## 1.1 Purpose and scope

PrimeCool is an **internal HVAC field-service ERP** for a Jamaica-based
preventive-maintenance / corrective-maintenance (PM/CM) operation. It manages
the full operational lifecycle of a field-service business:

- **Customers & equipment** — residential and commercial accounts, the HVAC
  units installed at each site, and their service history.
- **Maintenance visits (jobs)** — scheduling, technician dispatch, on-site
  data capture (readings, parts used, photos, hazards, customer signature),
  and completion.
- **Invoicing & payments** — invoice generation from visits/line items,
  multi-currency (JMD base with FX handling), payment recording, AR aging.
- **Inventory & procurement** — parts catalog, stock movements, purchase
  orders, goods receiving, physical counts, warehouse deliveries.
- **Payroll & time** — pay periods, payslips (with Jamaican statutory
  deductions: PAYE, NIS, NHT, education tax), technician timesheets, clock
  events, PTO/vacation/sick balances.
- **Performance management (KPI)** — per-technician KPI scoring, composite
  bands, coaching flags, development goals and PIPs.
- **5S workplace discipline** — vehicle/toolkit/storage asset audits,
  exceptions, escalations, coaching logs.
- **Self-service portals** — a technician PWA and a customer portal.
- **Governance** — role-based access control, delegation of authority,
  tamper-evident audit logging, and field-level PII encryption.

The system is built around **three principal classes** — administrators
(8 roles), technicians, and customers — each authenticating through a separate
session cookie.

## 1.2 Complete technology inventory

Everything below was identified directly from the codebase. No frameworks were
assumed.

### Languages
| Language | Where | Notes |
|---|---|---|
| **Python 3.9** (`target-version = "py39"`) | `main.py`, `database.py`, `crypto.py`, `scripts/*.py`, `tests/*.py` | Runtime confirmed `3.9.6`. |
| **HTML / CSS / vanilla JavaScript** | `*.html`, `static/pc_shared.js` | No JS build step; SPAs are hand-written single files. No React/Vue/framework. |
| **SQL (SQLite dialect)** | embedded in `database.py` | Raw SQL via the stdlib `sqlite3` driver — no ORM. |
| **Bash** | `scripts/backup.sh`, `scripts/restore.sh`, `scripts/backup_restore_drill.sh` | Backup/restore tooling. |

### Backend framework & runtime
| Component | Version (from `requirements.txt`) | Role |
|---|---|---|
| **FastAPI** | `>=0.110.0` | HTTP framework, ~392 routes. |
| **Uvicorn** (`uvicorn[standard]`) | `>=0.27.0` | ASGI server. |
| **python-multipart** | `>=0.0.9` | Multipart form / file upload parsing. |

### Database
| Component | Notes |
|---|---|
| **SQLite** (stdlib `sqlite3`) | Single-file DB at `submissions.db`. **WAL** journal mode, `synchronous=FULL`, `foreign_keys=ON`, `busy_timeout=5000ms`. No external DB server. |

### Authentication / cryptography libraries
| Component | Version | Role |
|---|---|---|
| **PyJWT** | `>=2.8.0` | Session tokens (HS256 JWT in HttpOnly cookies). |
| **argon2-cffi** | `>=23.1.0` | Argon2id hashing of passwords, PINs, MFA backup codes. |
| **pyotp** | `>=2.9.0` | TOTP multi-factor authentication. |
| **qrcode** | `>=7.4.2` | MFA enrolment QR PNG generation. |
| **Pillow** | `>=10.0.0` | Image handling (QR rendering / photo processing). |
| **cryptography** | `>=42.0.0` | Field-level encryption: AES-256-GCM (randomized) + AES-256-SIV (deterministic), HKDF key derivation. |

### Third-party services
| Service | Library | Purpose | Required? |
|---|---|---|---|
| **Resend** | `resend>=0.7.0` | Outbound transactional email (lead notifications, password/PIN reset links, security alerts, KPI flash reports, 5S escalations). | **Optional** — every send site no-ops gracefully if `RESEND_API_KEY` is unset. |

There is **no SMS provider, no payment gateway, no external file storage, and
no other outbound HTTP integration.** Files are stored on the local filesystem.

### Deployment tooling
- **Railway** (`railway.toml`, Nixpacks builder) is the intended production
  host. Start command: `uvicorn main:app --host 0.0.0.0 --port $PORT --proxy-headers --forwarded-allow-ips=*`.
- Linting/formatting: **ruff** + **black** (line length 110), config in
  `pyproject.toml`. Testing: **pytest**.

## 1.3 Architecture (text diagram)

```
   ┌─────────────┐   ┌─────────────┐   ┌──────────────────┐
   │  Admin SPA  │   │  Tech PWA   │   │ Customer Portal  │   Browsers / PWAs
   │ admin.html  │   │  tech.html  │   │ portal*.html     │   (vanilla JS SPAs)
   └──────┬──────┘   └──────┬──────┘   └────────┬─────────┘
          │  pc_admin_session │ pc_tech_session  │ pc_customer_session
          │  (HttpOnly JWT)   │ (HttpOnly JWT)    │ (HttpOnly JWT)
          └──────────────────┴───────────────────┘
                               │  HTTPS (prod) / HTTP (dev)
                               ▼
        ┌──────────────────────────────────────────────────────┐
        │                  FastAPI app (main.py)                 │
        │  • Preflight boot gate (4 checks) → boot_manifests/    │
        │  • Middleware: access-log, no-store, CSRF-origin, CORS │
        │  • ~392 routes: /api/admin /api/tech /api/portal       │
        │                 /api/staff  + page/file routes         │
        │  • RBAC (ADMIN_PERMS) + delegation engine              │
        │  • Async background loops (KPI recompute, 5S escalate, │
        │    delegation expiry, EOD timesheet enforce)           │
        └───────┬───────────────────────────┬──────────────────┘
                │                            │
                ▼                            ▼
   ┌────────────────────────┐    ┌──────────────────────────────┐
   │   crypto.py            │    │   database.py (data layer)     │
   │   AES-GCM / AES-SIV    │◄──►│   raw SQL over sqlite3         │
   │   HKDF sub-keys        │    │   audit hash-chains            │
   │   email blind-index    │    │   delegation lookups           │
   └────────────────────────┘    └───────────────┬───────────────┘
                                                  ▼
                                  ┌──────────────────────────────┐
                                  │  SQLite: submissions.db (WAL) │
                                  │  uploads/ (photos, documents) │
                                  └──────────────────────────────┘
                                                  │
                                                  ▼ (optional, async)
                                  ┌──────────────────────────────┐
                                  │  Resend API (outbound email)  │
                                  └──────────────────────────────┘
```

**Data flow (typical visit):** Admin schedules a visit (`POST /api/admin/visits`)
→ technician opens it in the PWA, starts the job, records readings/parts/photos/
signature, completes it (`PUT /api/tech/jobs/{id}/complete`) → admin generates an
invoice from the visit → records payment (`POST /api/admin/invoices/{id}/payments/v2`)
→ customer views the invoice in the portal. Every state change writes a
PII-redacted, hash-chained row to `audit_log`.

## 1.4 Deployment status

**Development-only.** The system is pre-launch (the public site is a holding
page, `index.html`). The intended production target is Railway, but the current
working dataset is seeded test data. All testing per project policy runs locally
on `127.0.0.1` / LAN — **not** against Railway or any external URL.

---

# 2. Core Data Model

The data layer is a single SQLite database, `submissions.db`, defined entirely
in `database.py`. There is no ORM — tables are created with
`CREATE TABLE IF NOT EXISTS` inside `init_db()` (database.py:260), and schema
evolution is done with idempotent `ALTER TABLE ADD COLUMN` loops guarded by
`PRAGMA table_info` checks. **Important SQLite caveat:** SQLite cannot `ALTER` a
table to add FOREIGN KEY or CHECK constraints, so columns added after a table's
initial creation have their constraints enforced only at the application layer,
not by the database.

There are **~70 tables**. Most columns are `TEXT`; timestamps are stored as
ISO-8601 strings. Many tables carry `hub_id INTEGER NOT NULL DEFAULT 1` for
future multi-location support (only Kingston, id=1, is seeded today).

## 2.1 Entity relationship overview (ASCII)

```
                         ┌──────────────┐
                         │    hubs      │ (id=1 Kingston seeded)
                         └──────┬───────┘
                                │ hub_id (soft ref on most tables)
   ┌──────────────┐      ┌──────┴───────┐      ┌─────────────────┐
   │ admin_users  │      │  customers   │1────*│   equipment     │
   │ (8 roles)    │      └──────┬───────┘      └────────┬────────┘
   └──────┬───────┘             │1                       │
          │ created_by/         │                        │ equipment_id
          │ supervisor_id       │ customer_id            │
          ▼ (self-ref)          ▼                        ▼
   ┌──────────────┐      ┌────────────────────────────────────┐
   │ delegations  │      │        maintenance_visits          │*
   │ delegation_* │      │  (jobs: scheduled→completed)       │
   └──────────────┘      └───┬────────┬─────────┬────────┬────┘
                             │        │         │        │
              visit_techs ◄──┤   visit_readings │   visit_photos
              (crew M:N)     │   visit_parts ◄──┤   visit_signatures
                             │                  │   visit_checklists
   ┌──────────────┐          │ visit_id         │
   │ technicians  │*─────────┘ assigned_tech_id │
   │ (techs +     │                             ▼
   │  staff_type) │                      ┌──────────────┐
   └──────┬───────┘                      │   invoices   │1──*┌─────────────────┐
          │ tech_id                      └──────┬───────┘    │invoice_line_items│
          ▼                                     │1           └─────────────────┘
   ┌──────────────────────────┐                 ▼
   │ tech_timesheets          │          ┌──────────────────┐
   │ tech_clock_events        │          │ invoice_payments │ (chain-hashed)
   │ tech_pto_* (bal/ledger/  │          └──────────────────┘
   │   requests)              │                 │ source_payment_id
   │ tech_schedules           │                 ▼
   │ tech_certifications      │          ┌──────────────────────────┐
   │ tech_cv_entries          │          │ customer_credit_movements │ (chain-hashed)
   │ kpi_* (scores/flags/     │          └──────────────────────────┘
   │   goals/notes)           │
   │ fs_* (5S audits/excpt)   │          ┌──────────────┐   ┌─────────────────┐
   └──────────────────────────┘          │ pay_periods  │1─*│    payslips     │
                                          └──────────────┘   └─────────────────┘
   parts 1──* part_movements (chain-hashed)
   parts ──* purchase_order_lines ──* goods_received   purchase_orders
   parts ──* physical_counts                           warehouse_deliveries

   GOVERNANCE / FORENSIC (append-only):
   audit_log (chain) · access_log · security_alerts · sessions · documents · fx_rates (chain)
```

## 2.2 Tables by domain

Below, every column is `TEXT` unless a type is given. `PK` = INTEGER PRIMARY KEY
AUTOINCREMENT. `(enc-r)` = randomized AES-GCM encrypted at rest; `(enc-d)` =
deterministic AES-SIV encrypted (searchable, paired with a `*_hash` blind
index); `(chain)` next to a table name = tamper-evident hash chain.

### Auth / identity / sessions

**admin_users** (database.py:554) — back-office staff.
`id PK`, `username NOT NULL UNIQUE`, `password_hash NOT NULL` (Argon2id),
`name NOT NULL`, `email NOT NULL UNIQUE` (enc-d), `phone` (enc-r),
`role NOT NULL`, `prid UNIQUE` (PrimeCool staff ID), `hire_date`,
`mfa_secret` (enc-r), `mfa_enabled INT DEFAULT 0`, `backup_codes` (JSON of
hashed codes), `active INT DEFAULT 1`, `created_by`/`supervisor_id`
(self-ref → admin_users.id), `terminated_at`, `last_login_at`, `email_hash`
(blind index), `must_change_credentials INT`, `must_enrol_mfa INT`,
`avatar_filename`, `has_delegation_power INT DEFAULT 0`, `created_at NOT NULL`.

**technicians** (database.py:434) — field staff (and other non-admin staff via
`staff_type`/`department`).
`id PK`, `tech_code NOT NULL UNIQUE`, `pin_hash NOT NULL` (Argon2id),
`name NOT NULL`, `phone` (enc-r), `email` (enc-d), `role DEFAULT 'tech'`,
`prid UNIQUE`, `hire_date`, `hourly_rate REAL`, `active INT DEFAULT 1`,
`employment_status CHECK IN ('active','on_leave','terminated')`,
`supervisor_id`, `mfa_secret` (enc-r), `mfa_enabled INT`, `mfa_backup_codes`,
`must_enrol_mfa INT`, `must_change_credentials INT`, `staff_type DEFAULT 'tech'`,
`department DEFAULT 'field'`, `avatar_filename`, `email_hash`, `hub_id`.

**customers** (database.py:276).
`id PK`, `customer_code NOT NULL UNIQUE`, `name NOT NULL`, `company`,
`email` (enc-d), `phone`/`address`/`notes` (enc-r), `pin_hash`,
`password_hash`, `auth_mode DEFAULT 'pin'` (`'pin'` or `'password'`),
`customer_type DEFAULT 'residential'`, `mfa_secret` (enc-r),
`mfa_enabled INT`, `backup_codes`, `active INT DEFAULT 1`,
`pin_failed_count INT`, `pin_locked_until`, `email_hash`, `last_login_at`,
`deletion_requested_at`, `terminated_at`, `hub_id`,
`credit_balance REAL DEFAULT 0` (running balance — see credit ledger),
`created_at NOT NULL`.

**sessions** (database.py:895) — server-side session registry for JWT
revocation. `id PK`, `jti NOT NULL UNIQUE`, `subject_type NOT NULL`
('admin'|'tech'|'customer'), `subject_id NOT NULL`, `ip_address`, `user_agent`,
`created_at NOT NULL`, `expires_at NOT NULL`, `revoked_at`, `last_seen_at`,
`mfa_verified_at`.

**Reset-token tables:** `customer_pin_resets` (393), `admin_password_resets`
(606), `tech_pin_resets` (998) — each: `token UNIQUE`, `expires_at`, `used_at`,
FK to its principal.

**hubs** (database.py:377) — `id PK`, `name UNIQUE`, `code UNIQUE`, `address`,
`active INT`. Seeded with id=1 Kingston.

### Customers / equipment / credit

**equipment** (403) — `customer_id NOT NULL → customers`, `name NOT NULL`,
`type`, `model`, `serial_number`/`location`/`notes` (enc-r), `active INT`,
polymorphic `updated_by_kind`/`updated_by_id`.

**customer_credit_movements** (355) — *(chain)* append-only credit ledger.
`customer_id`, `amount REAL`, `kind CHECK IN ('overpayment','refund_owed',
'refund_issued','applied_to_invoice','manual_adjustment')`, `source_invoice_id`,
`source_payment_id`, `note` (enc-r), `created_by`, `prior_chain_hash`,
`chain_hash NOT NULL`. The authoritative source for a customer's balance;
`customers.credit_balance` is the cached running sum, mutated only via
`record_customer_credit()`.

### Visits / jobs / field capture

**maintenance_visits** (1071) — the central job record.
`customer_id → customers`, `equipment_id → equipment`, `visit_type NOT NULL`,
`status DEFAULT 'scheduled'`, `scheduled_date`/`scheduled_time`,
`completed_date`, `assigned_tech_id → technicians`, `start_time`/`end_time`,
`work_done`/`parts_replaced`/`notes`/`hazards`/`access_codes`/
`contact_person_phone` (enc-r), `scope_of_work`, `estimated_duration_min INT`,
`next_pm_due`, `flagged_for_review INT`, `review_note`, `work_done_summary`,
`callback_of_visit_id`, `hub_id`.

Supporting visit tables:
- **visit_techs** (1147) — crew M:N junction, `PRIMARY KEY (visit_id, tech_id)`,
  `ON DELETE CASCADE`.
- **visit_parts** (452) — parts consumed on a visit (`part_id → parts`, qty,
  unit_price).
- **visit_readings** (1162) — HVAC gauge readings (pressures, temps, delta_t,
  superheat, subcool, approach_temp).
- **visit_signatures** (1183) — **write-once** (`visit_id UNIQUE`), stores
  `signature_b64` (enc-r) + `signature_sha256`.
- **visit_photos** (1008) — before/after photos with rich client metadata (geo,
  device, camera, network; `server_ua`/`client_meta_json` enc-r).
- **visit_checklists** (1368) — JSON checklist, one per visit.

**service_requests** (1262) — customer-initiated requests that admins triage
into visits. `reviews** (1055) — customer reviews of visits (rating, text,
status pending→approved).

### Invoicing / payments / FX

**invoices** (715) — `invoice_number NOT NULL UNIQUE`, `customer_id`,
`visit_id`, `issue_date`/`due_date NOT NULL`, `status DEFAULT 'draft'`
(draft→sent→paid; also cancelled), `subtotal`/`tax_rate`/`tax_amount`/`total`/
`amount_paid REAL`, `currency DEFAULT 'TTD'` (note: line default is TTD though
operations use JMD; `display_currency DEFAULT 'JMD'`), FX fields
(`fx_fee_pct REAL DEFAULT 2.0`, `fx_rate_used`, `fx_rate_source`),
`gct_amount REAL` (Jamaican GCT), `created_by → admin_users`, `sent_at`,
`paid_at`, `canceled_at`/`canceled_by`/`canceled_reason` (enc-r).

> **Behavioral note:** `create_invoice` always persists `status='draft'`
> regardless of the input. Promotion to `'sent'` is a separate action
> (`POST /api/admin/invoices/{id}/send`). This is intended lifecycle behavior.

**invoice_line_items** (738) — `invoice_id → invoices ON DELETE CASCADE`,
`line_type`, `description NOT NULL`, `quantity`/`unit_price`/`line_total REAL`,
`part_id`/`part_sku`, `tech_id`, `hours`/`hourly_rate REAL`, `sort_order INT`.

**invoice_payments** (751) — *(chain)* append-only payment ledger.
`invoice_id → invoices`, `payment_date NOT NULL`, `amount REAL NOT NULL` (JMD),
`method`, `reference`, `notes` (enc-r), `recorded_by`/`recorded_by_label`/
`recorded_by_prid`, foreign-currency fields, `hub_id NOT NULL`,
`prior_chain_hash`, `chain_hash`, `voided_at`, `idempotency_key` (partial-unique
index, 30s dedupe window). Written exclusively via `record_invoice_payment_v2()`
(database.py:10582), which recomputes invoice totals and auto-flips the invoice
to `'paid'` when fully covered.

**fx_rates** (836) — *(chain)* exchange rates, `from_currency`/`to_currency`,
`buy_rate REAL`, `source CHECK IN ('manual','api')`, `effective_date`,
`active INT`.

### Payroll

**pay_periods** (1201) — `period_start`/`period_end NOT NULL` (UNIQUE pair),
`label`, `status DEFAULT 'draft'`, `currency DEFAULT 'JMD'`, approval fields.

**payslips** (1223) — one per (period, subject). Earnings (`hours_regular`,
`hours_overtime`, `hourly_rate`, `overtime_rate`, `fixed_salary`, `bonus`,
`gross_pay`) and Jamaican statutory deductions (`paye_tax`, `nis`, `nht`,
`education_tax`, `other_deductions`, `total_deductions`, `net_pay`), all
`REAL DEFAULT 0`; `notes` (enc-r); `viewed_by_employee_at`. UNIQUE on
`(pay_period_id, subject_type, subject_id)`.

### Time & attendance / PTO

`tech_schedules` (2121, weekly pattern + on_call), `tech_on_call_overrides`
(2141), `tech_clock_events` (2155, *(chain)* immutable clock in/out),
`tech_overtime_approvals` (2171), `tech_timesheets` (2189, status draft→
submitted→supervisor_approved→super_admin_approved, biweekly with per-week
submit), `tech_timesheet_overrides` (2239, admin time edits),
`tech_pto_balances` (2264, floating/vacation/sick), `tech_pto_ledger` (2291,
append-only PTO entries), `tech_pto_requests` (2352, vacation/floating/sick).

### Inventory / parts / procurement / warehouse

`parts` (617, catalog with `sku UNIQUE`, `quantity REAL`, `reorder_point`),
`part_movements` (634, *(chain)* every stock delta with location refs),
`warehouse_deliveries` (687, parts-runner dispatch), `purchase_orders` (1303),
`purchase_order_lines` (1322), `goods_received` (1334), `physical_counts` (1350,
cycle counts with variance + approval).

### 5S workplace-discipline module (`fs_*`)

`fs_assets` (1380, vehicle/toolkit/storage), `fs_asset_items` (1399),
`fs_audits` (1416, *(chain)* start_shift/end_shift/weekly_manager),
`fs_audit_items` (1436, sort/set/shine/standardize/sustain pass/fail/na),
`fs_asset_checklists` (1513), `warehouse_checksheet_uploads` (1531),
`fs_exceptions` (1551, *(chain)* open→resolved/escalated, safety_loto severity),
`fs_exception_events` (1579, append-only trail), `fs_exception_photos` (1597,
*(chain)*), `fs_coaching_log` (1617, *(chain)*).

### KPI / performance module (`kpi_*`)

`kpi_definitions` (1861, 8 KPIs seeded), `kpi_thresholds` (1876, per-tier
green/amber/red), `kpi_periods` (1892), `kpi_scores` (1904, *(chain)*),
`kpi_composite_scores` (1922, *(chain)*), `kpi_flags` (1938, *(chain)*,
coaching→escalation), `kpi_recompute_log` (1963), `kpi_notes` (2032, *(chain)*),
`kpi_goals` (2060, *(chain)*, development goals + PIPs),
`kpi_goal_checkins` (2089, *(chain)*), `kpi_periods_released_to_tech` (2461).

### Technician detail / delegation

`technician_reviews` (1640, *(chain)*), `technician_kpi_overrides` (1660,
*(chain)*), `technician_5s_overrides` (1680, *(chain)*), `tech_certifications`
(2414), `tech_cv_entries` (2427, lockable work history), `tech_cv_edit_requests`
(2445), `delegations` (1705, *(chain)*, grant record/record_type/power access),
`delegation_power` (1803, *(chain)*), `delegation_regrant_requests` (1816,
*(chain)*), `company_messages` (2471, message board; `body` enc-r).

### Governance / audit / documents

**audit_log** (918) — *(chain)* the central tamper-evident audit trail.
`actor_type`/`actor_id`/`actor_prid`/`actor_label`/`actor_role`,
`action NOT NULL`, `target_type`/`target_id`/`target_label`,
`before_value`/`after_value` (PII-redacted JSON), `ip_address`,
`retention_class DEFAULT 'operational'`, `chain_hash`, `created_at NOT NULL`.

**access_log** (956) — append-only read trail (method, path, query, status, IP,
UA) for "who-viewed-what". Not hash-chained.

**security_alerts** (978) — anomaly/lockout/probe alerts (kind, severity,
status open→resolved).

**documents** (861) — uploaded files with `sensitivity` tier
(public/confidential/highly_sensitive), `document_type`, polymorphic
`linked_to_*`, `uploaded_by_*`, `expiry_date`, `deleted_at`.

## 2.3 Indexes

~90 indexes are created in `init_db()` (full list in database.py, e.g. lines
765–768 for invoices, 1284–1294 for the visit/customer/tech hot paths,
946–950 for the audit log). Notable: a **partial unique index** on
`invoice_payments(invoice_id, idempotency_key) WHERE idempotency_key IS NOT NULL`
(database.py:827) enforces payment idempotency.

## 2.4 Encryption / hashing strategy for sensitive fields

Implemented in `crypto.py`, applied per-column by `database.py` helpers
(`_enc_dict` on write at database.py:194, `_dec_row` on read at 210). Activated
only when `FIELD_ENCRYPTION_KEY` is set.

**Three cryptographic modes (all keyed from one master key via HKDF):**

1. **Randomized — AES-256-GCM** (`encrypt`/`decrypt`). Fresh 12-byte nonce per
   value; same plaintext → different ciphertext. Envelope:
   `v1:r:<base64(nonce‖ciphertext‖tag)>`. Used for non-searchable PII:
   phones, addresses, notes, MFA secrets, signatures, work-done text, hazards,
   access codes, and the `note`/`body`/`reason`/`description` columns across
   credit, FX, KPI, 5S, delegation, and message tables. The full per-table
   registry is `_PII_RAND` (database.py:136–185).

2. **Deterministic — AES-256-SIV (RFC 5297)** (`det_encrypt`/`det_decrypt`).
   Same plaintext + key → same ciphertext (reveals only equality). Envelope:
   `v1:d:<base64(siv_tag‖ciphertext)>`. Used **only** for the `email` column on
   `customers`, `technicians`, `admin_users` (`_PII_DET`, database.py:187–191)
   so equality lookups remain possible.

3. **Blind index — HMAC-SHA256** (`email_hash`). A 64-char hex fingerprint of
   the normalized (lowercased/trimmed) email, stored in the `email_hash` column
   alongside each deterministic email, for fast indexed equality seeks in
   forgot-password / login flows.

**Key derivation:** one `FIELD_ENCRYPTION_KEY` env var (≥32 chars) seeds three
independent sub-keys via HKDF-SHA256 with distinct salts/info
(`pc-aead-v1`, `pc-det-v1`, `pc-hmac-v1`). **Rotating this key makes all existing
ciphertext unreadable** — there is no key-versioning migration today (the `v1:`
prefix reserves room for one).

**What is *not* encrypted:** names and financial totals are intentionally left
plaintext (needed for sorting and `SUM()`); disk-level encryption is the at-rest
mitigation for those.

**Password / PIN hashing:** **Argon2id** via `argon2.PasswordHasher()` with
library-default parameters (`_hash_pin`/`_hash_password`, database.py:36/4548).
A legacy PBKDF2-HMAC-SHA256 path exists only as a fallback if argon2 is
unavailable, and `_needs_rehash` transparently upgrades old hashes on next
successful login. Hash columns: `admin_users.password_hash`,
`technicians.pin_hash`, `customers.pin_hash`/`password_hash`. MFA backup codes
are also Argon2-hashed (JSON list of `{hash, used_at}`).

**Tamper-evidence (hash chains):** ~23 tables carry a per-row `chain_hash`
computed as `SHA-256(prior_hash + canonical_json(row_fields))`, making them
append-only forensic ledgers. The audit and 5S chains use
`(prev or "GENESIS") + "\n" + canonical`; the payment/credit/part-movement
chains use `(prior or "") + json(...)`. **These formats are not byte-identical
across tables** — any verification tool must use the matching helper per table.
The audit chain is verifiable end-to-end via `verify_audit_chain()`
(database.py:5179) and surfaced at `POST /api/admin/audit/verify`.

---

# 3. System Components — Deep Dive

The HTTP surface is ~392 routes. They divide into page/file routes and four API
namespaces: `/api/admin/*` (269), `/api/tech/*` (73), `/api/portal/*` (17),
`/api/staff/*` (5), plus `/health` and a few public misc endpoints.

## 3.1 Admin Portal (`admin.html`, `/api/admin/*`)

**Frontend:** `admin.html` is a single ~810 KB vanilla-JS SPA served at `/admin`.
It renders ~19 panels via a `showPanel()` switch: Visits, Technicians, Invoices,
Documents, Inventory/Warehouse, Schedule, Timesheets, Payroll, My Pay, Admin
Users, Onboarding, Audit Log, Customer Reviews, 5S, Delegations, PTO/Time-Off,
Performance KPI, Company Messages, My Profile. It loads shared helpers from
`pc_shared.js` and gates UI elements client-side using the effective-permission
bundle (`/api/admin/me/access-bundle`).

**Authentication:** username + password → mandatory TOTP MFA (see §4.2). Session
cookie `pc_admin_session`, 12-hour hard expiry, 30-minute idle timeout.

**Available actions per role:** governed by `ADMIN_PERMS` (full matrix in §4.1).
Highlights of the API surface:

- **People:** `/api/admin/users/*` (10 routes — CRUD, role, active,
  terminate/reinstate, password, supervisor), `/api/admin/techs/*` (10),
  `/api/admin/customers/{id}/*` (12).
- **Field ops:** `/api/admin/visits/*` (17 — CRUD, crew add/remove, flag,
  invoice-prefill, CM-margin, photos, work-summary).
- **Money:** `/api/admin/invoices/*` (19 — CRUD + `v2`, send, cancel, aging,
  metrics, CSV export, payments + `payments/v2`), `/api/admin/payroll/*` (7),
  `/api/admin/fx-rates`.
- **Inventory:** `/api/admin/parts/*` (9), `/api/admin/purchase-orders/*` (6),
  `/api/admin/warehouse/*` (13), `/api/admin/physical-counts`.
- **Performance:** `/api/admin/kpi/*` (34 — definitions, thresholds, periods,
  recompute, scoreboard, flags, notes, goals/PIPs, flash-report email).
- **5S:** ~21 routes — assets, audits, exceptions, escalation, compliance,
  dashboard, coaching, export.
- **Governance:** `/api/admin/audit` (+ `/verify`), `/api/admin/access`,
  `/api/admin/security/*` (4), `/api/admin/sessions` (list / revoke-by-jti),
  `/api/admin/delegations/*` (9), `/api/admin/documents/*` (5).

## 3.2 Technician Portal (`tech.html`, `/api/tech/*`)

**Frontend:** `tech.html` (~157 KB) is a PWA (`manifest-tech.json`, scope
`/tech`) — the field visit-execution surface. Sections: Job Brief, Job Time
(clock), On-site Contact, Site Hazards, Work Performed, Field Readings, Parts
Used, Photos (before/after), Client Signature, Equipment, Next PM Due, 5S Audit,
My Performance (KPI), Payslip.

**Authentication:** `tech_code` + numeric PIN → mandatory TOTP MFA. Session
cookie `pc_tech_session`, 7-day expiry, **idle timeout disabled** (techs stay
logged in on shared/field devices).

**Job workflow (the core loop):**
1. `GET /api/tech/jobs/{id}` — load job brief.
2. `PUT /api/tech/jobs/{id}/start` — clock onto the job.
3. Capture data: `POST .../parts`, `.../readings`, `.../photos` (multipart,
   ≤12 MB, jpg/png/webp/heic), `.../signature` (write-once), `.../checklist`.
4. `PUT /api/tech/jobs/{id}/complete` — finalize.
5. Self-service: `/api/tech/me/sign-in` / `sign-out` (shift clock),
   `/me/today-overview`, `/me/timesheets`, `/me/pto-requests`, `/me/payslips`,
   `/me/kpi`, `/me/cv`. Plus 5S: `/api/tech/5s/audit`, `/5s/exceptions/*`.

Technicians can search/view only customers and equipment relevant to their
assigned work (self-scope enforced in the access layer).

## 3.3 Customer Portal (`portal.html` + `portal_dashboard.html`, `/api/portal/*`)

**Frontend:** `portal.html` is the login (PWA, scope `/portal`);
`portal_dashboard.html` (~94 KB) is the My-Account dashboard: service-visit
history, invoices, request service, leave a review, account security (2FA
self-enrolment), and privacy controls.

**Authentication:** `customer_code` + PIN *or* password (per `auth_mode`). MFA is
**optional** for customers (operator decision, 2026-05-25). Session cookie
`pc_customer_session`, 24-hour expiry, 20-minute idle timeout. Per-account PIN
lockout: 5 failures → 30-minute lock.

**Self-service functions:** `GET /me`, `GET /invoices` + `/{id}`,
`POST /requests` (service request) + `GET /requests`, `POST /reviews`,
`POST /password`, MFA setup/confirm, and GDPR-style **`GET /me/export`** (data
export) + **`POST /me/deletion-request`** (right-to-erasure request).

## 3.4 Unified staff login (`staff_portal.html`, `/api/staff/*`)

`staff_portal.html` is a single sign-in page that accepts either an admin
username or a tech code. `POST /api/staff/login` tries the admin identity space
first, then the tech space, and routes the caller into the appropriate MFA step
(it never issues a session itself). After auth, all staff land on the unified
`/home` dashboard (`staff_home.html`, ~220 KB) — a workday view with tiles for
"Awaiting Your Action", My Jobs, My Schedule, Recent Pay, Company Messages, time
submission, and the org chart. `staff_home.html` deep-links into role-specific
panels and into `/tech?view=...` for field functions.

## 3.5 Backend API / logic layer (`main.py`)

- **Entry point:** `app = FastAPI(lifespan=lifespan)` (main.py:1444), run by
  uvicorn.
- **Boot gate:** `_preflight_run()` runs at *module import* (before `app`
  exists) and refuses to start on any failed check (§5.1).
- **Request/response convention:** JSON in, JSON out for `/api/*`; HTML
  `FileResponse` for page routes; signed-URL file serving for photos/documents.
- **Business logic** lives in `main.py` route handlers calling `database.py`
  functions. There is no separate service layer — handlers do permission checks,
  validation, the DB call, and audit logging inline.

## 3.6 Database layer (`database.py`)

Raw `sqlite3` over a single connection helper `_con()` (database.py:230) that
sets WAL + `synchronous=FULL` + `foreign_keys=ON` + `busy_timeout=5000` and
`row_factory = sqlite3.Row`. CRUD functions, delegation lookups, audit-chain
helpers, and encryption wrappers all live here. Schema migrations are the
idempotent `ALTER`/table-rebuild pattern inside `init_db()` (§7.4).

## 3.7 Background jobs / async processes

Four `asyncio` loops are registered via `_LIFESPAN_STARTERS` and started at
lifespan startup (no external scheduler, no Celery, no cron):

| Loop | Cadence | Does |
|---|---|---|
| KPI weekly recompute | weekly | `recompute_all_open_periods(triggered_by="cron")` |
| 5S / FS escalation | periodic | auto-escalates overdue 5S exceptions, emails managers |
| Delegation expiry sweep | every 6 hours | expires lapsed delegations, audits `delegation.cron_sweep` |
| Per-tech EOD enforcement | daily | end-of-day timesheet/clock enforcement |

FastAPI `BackgroundTasks` is not used; the only threading primitive is a `Lock`
guarding the audit-chain write path.

## 3.8 Third-party integrations

**Resend** (email) is the sole external integration. Send sites: security-alert
emails, the public `/api/consult` lead form, the three forgot-password/PIN flows,
the KPI flash report, and 5S manager escalations. All gated on `RESEND_API_KEY`;
when unset, sends are skipped (and 5S escalation writes a
`fs.notify.manager_failed` audit row instead). Sender:
`PrimeCool Services <onboarding@resend.dev>`.

## 3.9 File handling

Uploads live on the local filesystem under `uploads/`:
- `uploads/photos/` — visit photos + avatars (≤12 MB).
- `uploads/documents/{public,confidential,highly_sensitive}/` — documents
  (≤25 MB), tiered by sensitivity.
- `uploads/5s/` — 5S exception photos.
- `uploads/checksheets/` — warehouse checksheet uploads.

**Access control:** photos (`GET /photos/{filename}`) and documents
(`GET /documents/{tier}/{filename}`) are **not** public static mounts — they
require an HMAC-SHA256-signed, time-limited URL minted by an authenticated API
endpoint. `highly_sensitive` document downloads additionally require the
`documents:view_highly_sensitive` permission **and** fresh MFA (re-auth within
15 minutes). `/images`, `/icons`, `/static` are public static mounts.

> ⚠️ **Gap:** `uploads/5s/` photos appear to be served as a plain static path
> (`/uploads/5s/{filename}`) without the signed-URL gate used for the other two
> photo/document paths. See §9.

---

# 4. Security & Authentication

## 4.1 Role-based access control (RBAC) matrix

Permissions are defined in the **`ADMIN_PERMS`** dict in `main.py` (assembled
across main.py:210–448 in layered `.update()` blocks). There are **8 admin
roles**. Enforcement: `_admin_can(role, perm)` returns `perm in
ADMIN_PERMS.get(role, set())` — **there is no super_admin wildcard**; super_admin
simply has every permission string explicitly listed. Routes gate with
`admin = _require_perm(request, "<perm>")` (main.py:1237), which writes an
`access.denied` audit row and returns 403 on a miss.

> **Doc discrepancy:** `README.md` and `docs/SECURITY.md` state "7 admin roles."
> The code defines **8**: `dispatcher` and `warehouse_supervisor` were added
> after those docs were written. Treat the code as authoritative.

**Role summary (full permission lists are in `ADMIN_PERMS`):**

| Role | Intent | Key powers | Notable exclusions |
|---|---|---|---|
| **super_admin** | Root of trust | Everything: user/role mgmt, payroll approve+pay, `kpi:flag_override`, `kpi:edit_thresholds`, `kpi:close_period`, `security:resolve_alerts`, all docs incl. highly-sensitive delete | — |
| **supervisor_admin** | Operations lead | Most ops + payroll-adjacent, audit view-all, 5S resolve/escalate, KPI resolve | No `security:resolve_alerts`, no `kpi:flag_override`, no threshold/period control, no staff creation |
| **system_admin** | Day-to-day ops | Visits/customers create+update, invoices+payments, inventory, schedule edit | Cannot create staff; only `audit:view_self` |
| **hr_admin** | HR / personnel | Create/update admins & techs, `payroll:generate`, highly-sensitive docs, certifications | `payroll:generate` but **not** approve/mark-paid (separation of duties) |
| **ceo_assistant** | Read-only exec + post messages | View inventory/invoices/docs/5S reports, `company:post_message` | No mutation of operational data |
| **inventory_manager** | Stock | Inventory CRUD+adjust, PO create/send/receive, counts | No `po:close_out`, no `count:approve`, no `warehouse:manage_assets`, no personnel |
| **dispatcher** | Scheduling | Visits create/update, schedule edit, manage tech schedule, approve overtime, KPI team view | No money, no inventory, no personnel |
| **warehouse_supervisor** | Warehouse floor | Warehouse manage + inventory + PO close-out + count approve + 5S asset manage | No money, no personnel |

The permission strings are namespaced (`admin:*`, `tech:*`, `customer:*`,
`visit:*`, `invoice:*`, `inventory:*`, `po:*`, `payroll:*`, `kpi:*`, `fs:*`,
`documents:*`, `security:*`, `audit:*`, `schedule:*`, `timesheet:*`,
`warehouse:*`, `company:*`). The complete per-role sets are reproduced verbatim
in the codebase at main.py:210–448; consult that block when adding a route.

**Delegation overlay:** beyond static roles, the `delegations` engine lets an
admin with delegation power grant another admin (or tech) scoped access to a
specific record, a record type, or a power, with read or read-write level and an
expiry. The client-side gate (`PC.canRead`/`canWrite` in `pc_shared.js`)
evaluates role grants + type-level + record-level delegations + self-scope. Note
(per `docs/FIXMES.md`) the server-side `_require_record_access` is only wired
into a subset of endpoint pairs today; the rest still use the legacy
super_admin/role gate.

## 4.2 Authentication flows

All session cookies are `HttpOnly`, `SameSite=Strict`, `Secure=COOKIE_SECURE`,
`path=/`. JWTs are **HS256** signed with `JWT_SECRET`; payload is minimal:
`{sub, type, jti, exp}`. Every session also has a server-side `sessions` row
keyed by `jti` for revocation.

**Admin** (`POST /api/admin/login`, main.py:4218):
1. Rate-limit, then `verify_admin_user(username, password)` (Argon2id).
2. **MFA is mandatory.** If not yet enrolled → returns
   `{requires_mfa_setup, mfa_enrol_token, name}` (5-min token, no cookie). The
   client runs `POST /api/admin/mfa/setup` (returns secret + QR) then
   `POST /api/admin/mfa/activate` (verifies a TOTP code, returns 10 backup
   codes).
3. If enrolled → returns `{requires_mfa, mfa_token, name}` (5-min token).
4. `POST /api/admin/mfa/verify` checks the TOTP (or a backup code), then issues
   the 12-hour `pc_admin_session` cookie and stamps `mfa_verified_at`.

**Technician** (`POST /api/tech/login` → `POST /api/tech/login/mfa`): identical
shape with `tech_code` + PIN, mandatory MFA, 7-day `pc_tech_session`.

**Customer** (`POST /api/portal/login`): PIN or password per `auth_mode`;
per-account lockout (5 fails / 30 min) checked before verify; MFA **optional**;
24-hour `pc_customer_session`. If MFA enabled → `POST /api/portal/login/mfa`.

**Unified** (`POST /api/staff/login`): resolves admin-then-tech, returns a
kind-tagged object that routes to the matching MFA step. Generic
`401 "Invalid credentials"` on a miss in both spaces (anti-enumeration).

## 4.3 Session management, tokens, logout

- **TTLs:** admin 12h, tech 7d, customer 24h; pre-MFA/enrol tokens 5 min.
- **Idle timeouts:** admin 30 min, customer 20 min, tech disabled (0). Enforced
  server-side in `is_session_active()` — an idle breach sets `revoked_at`.
- **Step-up MFA:** Tier-3 (highly-sensitive document) access requires
  `mfa_verified_at` within 15 minutes (`MFA_FRESH_TTL_SEC`), else a 401 with an
  `X-Require-MFA-Reauth` header.
- **Logout:** revokes the current `jti` and clears the cookie.
- **Logout-everywhere:** `POST /api/admin/logout-everywhere` revokes all of the
  admin's sessions.
- **Force-logout:** deactivating an admin revokes all their sessions; a
  self-service password change revokes all sessions *except* the current one.
- **Single-session revoke:** `DELETE /api/admin/sessions/{jti}`.
- Expired/revoked session rows are purged after 90 days.

## 4.4 Password / PIN rules

- **Self-service password change** (`_validate_password_strength`,
  main.py:1258): ≥12 chars, must include letters AND digits, rejected against a
  ~30-entry common-password denylist. The customer portal uses the same strong
  rule.
- ⚠️ **Known discrepancy — admin reset is weaker:** the admin email-link reset
  (`POST /api/admin/reset-password`) and admin-initiated reset
  (`PUT /api/admin/users/{id}/password`) only enforce `len >= 8` with no
  denylist or composition rule. This is a tracked security-debt item (§9).
- **PIN policy** (`validate_pin_policy`, database.py:2750): digits only, 6–16
  digits, no all-same-digit, no monotonic runs, must not match/contain the
  phone on file. (The function's docstring says "10–16" but the constants are
  6–16 — a doc/code mismatch.)
- **MFA:** TOTP (`pyotp`, `valid_window=1`), 10 single-use backup codes
  (`XXXX-XXXX`, Argon2-hashed). `must_change_credentials` forces a reset on
  first login; `must_enrol_mfa` is retained for tracking but MFA is hard-required
  at runtime for admins and techs regardless.

## 4.5 Rate limiting

In-memory sliding-window (per-process — **not** shared across workers/replicas):
- Login: 8 attempts / 15 min per IP+identity (`_enforce_login_rate`).
- Customer portal PIN pacer: 1 attempt / 5s per IP.
- Exports: 10 / hour per admin.
- ⚠️ **Known gap:** the three forgot-* endpoints
  (`/api/portal/forgot-pin`, `/api/tech/forgot-pin`,
  `/api/admin/forgot-password`) have **no** rate limiting (§9).

## 4.6 Secrets management

All secrets come from **environment variables only** — none are hardcoded.
`JWT_SECRET`, `FIELD_ENCRYPTION_KEY`, `RESEND_API_KEY`, `PHOTO_URL_SECRET`
(defaults to `JWT_SECRET`). **`.env` / `.dev.env` is NOT auto-loaded** — there is
no `python-dotenv` import. You must export/source the env yourself before
launching (locally: `set -a; source .dev.env; set +a`; in prod: Railway env
vars). The boot manifest records only a SHA-256 *prefix* of `JWT_SECRET` and key
lengths, never the values.

## 4.7 Audit logging, access logging, retention

- **`audit_log`** (`log_audit`, database.py:5087): append-only, hash-chained,
  PII-redacted before/after JSON. Covers auth events, user management,
  resets/changes, exports, invoices/payments/POs/counts, payroll, security
  events, and access denials.
- **Retention classes** (`_classify_retention`): `system`/auth/security →
  **never purged**; `financial` → **7 years**; `operational` → **24 months**.
- **`access_log`**: per-request read trace; purged after **90 days**.
- **`security_alerts`** + **anomaly detection** (`detect_anomalies_for_actor`):
  flags bulk reads (≥20 distinct customers in 5 min), off-hours activity
  (≥50 reads outside 07:00–20:00 Jamaica time), and permission probing
  (≥10 401/403 in 10 min). Alerts de-dupe on a 30-minute window.
- **Boot manifests:** every boot writes a JSON anchor to `boot_manifests/`
  recording the preflight result and a `jwt_secret_sha256_prefix` — these form
  an audit trail of boots and can detect a tampered restore.

## 4.8 CSRF / CORS / transport

- **CSRF:** `csrf_origin_check` middleware — for cookie-authenticated state-
  changing requests (POST/PUT/DELETE/PATCH), the Origin/Referer host must match
  the request Host (or an allowlist), else 403. Bearer-only requests are exempt.
- **CORS:** dev → `allow_origins=["*"]`, credentials off; prod → explicit
  `CORS_ALLOW_ORIGINS` allowlist with credentials on, **fails closed** if unset.
- **Cache:** all `/api/*` responses get `Cache-Control: no-store` (back-button
  data-leak defense).
- **Encryption in transit:** TLS is terminated at Railway's edge in production
  (`COOKIE_SECURE=true` enforced by preflight). Locally, plain HTTP on
  `127.0.0.1`.
- ⚠️ **No global security-headers middleware** — HSTS, CSP, X-Frame-Options,
  X-Content-Type-Options are not set application-side (§9).

---

# 5. Operational Runbook

## 5.1 Deployment — fresh instance

**Prerequisites:** Python 3.9+, `pip`. No database server needed (SQLite is
embedded).

```bash
# 1. Install dependencies
cd /path/to/primcool
pip install -r requirements.txt

# 2. Create the environment file from the template
cp .env.example .dev.env
# Edit .dev.env and fill the two REQUIRED secrets (≥32 chars each):
#   JWT_SECRET           — python -c "import secrets; print(secrets.token_urlsafe(48))"
#   FIELD_ENCRYPTION_KEY — python -c "import secrets; print(secrets.token_urlsafe(48))"
# Leave PROD_MODE=false and COOKIE_SECURE=false for local dev.
chmod 600 .dev.env   # contains secrets

# 3. (First boot only) bootstrap a super_admin — set in the env, then unset:
#   BOOTSTRAP_ADMIN_USERNAME=...  BOOTSTRAP_ADMIN_PASSWORD=...
#   BOOTSTRAP_ADMIN_EMAIL=...     BOOTSTRAP_ADMIN_NAME="Super Admin"
```

**Required environment variables** (enforced by the preflight gate):

| Var | When required | Rule |
|---|---|---|
| `JWT_SECRET` | always | ≥32 chars, ≥8 distinct chars, not a placeholder |
| `FIELD_ENCRYPTION_KEY` | always | ≥32 chars (rotating it orphans all ciphertext) |
| `DATASTORE_ENCRYPTION_CONFIRMED=yes` | prod only | operator attestation |
| `COOKIE_SECURE=true` | prod only | required when `PROD_MODE=true` |
| `CORS_ALLOW_ORIGINS` | prod only | comma-separated allowlist (fails closed) |

The database schema is created automatically on first boot by `init_db()` — no
manual migration step.

## 5.2 Starting the system

**Local development (the only supported mode today):**
```bash
cd /path/to/primcool
set -a && source .dev.env && set +a          # load env (NOT auto-loaded)
python3 -m uvicorn main:app --host 127.0.0.1 --port 8000
# Add --reload for hot-reload during development.
```

**Expected startup sequence:**
1. `_preflight_run()` validates the 4 gates and writes a boot manifest to
   `boot_manifests/boot-<utc>.json`. **If any check fails the process exits with
   a `RuntimeError` and refuses to serve.**
2. `lifespan` startup: `init_db()` → bootstrap super_admin (if configured & no
   admins) → purge old access-log → dormant-account sweep → purge old audit-log
   → start the four async background loops.
3. Uvicorn binds the port. Verify: `curl -s http://127.0.0.1:8000/health` →
   `{"status":"ok"}`.

**Production (Railway, not currently used):** `railway.toml` defines the start
command with `--proxy-headers --forwarded-allow-ips=*`; healthcheck `/health`;
restart `on_failure`.

> **Login note:** because MFA is mandatory for admins/techs, the first login for
> any staff account forces TOTP enrolment (scan the QR, save backup codes)
> before a session is issued. There is no way to bypass this without code or DB
> changes.

## 5.3 Common operational tasks

| Task | How |
|---|---|
| **Add an admin user** | UI: Admin Users panel (needs `admin:create`). API: `POST /api/admin/users`. |
| **Add a technician** | UI: Technicians/Onboarding panel (`tech:create`). API: `POST /api/admin/techs`. |
| **Add a customer** | UI: Customers panel (`customer:create`). API: `POST /api/admin/customers`. |
| **Reset an admin password** | `PUT /api/admin/users/{id}/password` (`admin:reset_password`). Email-link path: `POST /api/admin/forgot-password`. |
| **Reset a tech PIN** | `POST /api/admin/techs/{id}/pin` (`tech:reset_pin`). |
| **Reset MFA for an account** | No admin UI for an admin's *own* MFA reset today. Operationally: clear the MFA columns in the DB so the next login re-enrols. For admins: `UPDATE admin_users SET mfa_secret=NULL, mfa_enabled=0, backup_codes=NULL WHERE id=?;` (matches `disable_admin_mfa`). For techs there is `POST /api/admin/technicians/{id}/mfa/reset`. |
| **View audit log** | UI: Audit Log panel (`audit:view_all`). Verify chain: `POST /api/admin/audit/verify`. |
| **See who viewed a record** | `access_log` via the admin access endpoints (`aggregate_access_by_target`). |
| **Generate payroll** | UI: Payroll panel — create period, `POST /api/admin/payroll/payslips/generate` (`payroll:generate`), then a super_admin approves and marks paid. |
| **Record an invoice payment** | `POST /api/admin/invoices/{id}/payments/v2` (`invoice:record_payment`). |
| **Reseed test data** | `python3 scripts/seed_30_200.py --apply` (with env sourced; wipes customer-side tables, writes creds to `/tmp/pc_creds_30_200.tsv`). |

## 5.4 Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| **App refuses to boot, `RuntimeError` on stderr** | Preflight failed: `JWT_SECRET`/`FIELD_ENCRYPTION_KEY` missing or <32 chars (env not sourced). | `set -a && source .dev.env && set +a` then re-launch. Check the latest `boot_manifests/*.json` for which check failed. |
| **`database is locked`** | A second writer (e.g. seed script) colliding with the server, or an uncommitted transaction holding the write lock. | Stop the server before bulk-seeding; ensure helpers `commit()` promptly. WAL allows concurrent readers + one writer only. |
| **Login returns `requires_mfa_setup` forever** | Account has no MFA enrolled (expected first-login behavior). | Complete enrolment in the browser, or pre-enrol/reset MFA via the DB. |
| **PII reads return base64 `v1:r:`/`v1:d:` strings** | `FIELD_ENCRYPTION_KEY` differs from the key the data was written with. | You cannot recover data encrypted under a lost key. Restore the matching key, or reseed for test environments. |
| **`no such table` on a fresh DB** | An index created before its table in `init_db()` (a historical bug class). | Ensure `CREATE INDEX` blocks run after their `CREATE TABLE`. Only manifests on a truly fresh DB. |
| **Emails not sending** | `RESEND_API_KEY` unset (by design in dev). | Set the key in env if email is needed; otherwise expected. |
| **Audit-chain verify reports `broken_at_id`** | A row was edited/deleted out-of-band, or a restore reordered rows. | Investigate the break point; a tampered restore is the prime suspect. |

Logs: uvicorn writes to stdout/stderr (locally redirected, e.g.
`/tmp/primecool_server.log`). Preflight failures print to stderr with
`logger.critical`.

## 5.5 Backups & restore

- **Backup:** `scripts/backup.sh` takes an online `sqlite3 .backup` snapshot of
  `submissions.db` plus `uploads/` (the README also notes a simpler
  `submissions.db.bak-<epoch>` copy variant). Production intent is an encrypted
  daily `.tar.gpg`.
- **Restore:** `scripts/restore.sh` decrypts and untars. Manually: **stop the
  server**, `cp submissions.db.bak-<epoch> submissions.db`, restart. The audit
  chain validates from boot — a tampered or partial restore surfaces as a
  `chain_hash` mismatch.
- **Drill:** `scripts/backup_restore_drill.sh` proves the backup→restore
  mechanic without GPG.
- **Frequency / location:** daily intended; backups live alongside the DB (dev)
  or in the encrypted archive (prod). The live DB, WAL/SHM files, and `.bak-*`
  are gitignored.

## 5.6 Monitoring

- **Liveness:** `GET /health` → `{"status":"ok"}` (Railway healthcheck path).
- **Boot health:** the newest `boot_manifests/*.json` should show all four
  checks `ok: true`.
- **Security:** watch `security_alerts` (status `open`) — anomaly detector
  flags bulk reads, off-hours access, and permission probing.
- **Integrity:** run `POST /api/admin/audit/verify` periodically; `ok:true`
  means the audit chain is intact.
- **What "broken" looks like:** process exits at boot (failed preflight); 5xx
  spikes in uvicorn logs; `database is locked` errors; audit-verify returning a
  break id. There is **no built-in metrics/alerting dashboard** today (planned in
  the IT module — see §9).

---

# 6. Codebase Organization

## 6.1 Directory structure

```
primcool/
├── main.py                  # FastAPI app: routes, auth, preflight, middleware, audit
├── database.py              # SQLite schema + all CRUD + audit-chain + crypto wrappers
├── crypto.py                # AES-GCM / AES-SIV field encryption, HKDF, email blind-index
├── requirements.txt         # Python dependencies (pinned with >=)
├── pyproject.toml           # ruff + black + pytest config
├── railway.toml             # Production deploy (Nixpacks, start command, healthcheck)
├── .env.example             # Documented env-var reference (copy to .dev.env)
├── .dev.env                 # Local secrets (gitignored, chmod 600)
├── README.md                # Quick start + architecture
├── admin.html               # Admin SPA (~810 KB)
├── staff_home.html          # Unified /home dashboard (~220 KB)
├── tech.html                # Technician PWA (~157 KB)
├── portal.html              # Customer portal login
├── portal_dashboard.html    # Customer My-Account dashboard (~94 KB)
├── staff_portal.html        # Unified staff login page
├── invoice_print.html       # Printable invoice
├── index.html               # Public holding page (pre-launch)
├── index.full.html          # Full marketing site (not currently served as /)
├── request.html / reviews.html         # Public lead form / reviews
├── admin_reset.html / portal_reset.html / tech_reset.html   # Reset pages
├── manifest-portal.json / manifest-tech.json / sw.js        # PWA assets
├── static/pc_shared.js      # Shared JS (PC namespace: fetch wrapper, access gating)
├── icons/  images/          # Public static mounts
├── scripts/                 # Seed, backup/restore, secret-rotation utilities
├── tests/                   # pytest suite (15 test files + conftest.py)
├── docs/                    # SECURITY.md, FIXMES.md, it-module-todo.md, this runbook
├── uploads/                 # photos/, documents/{public,confidential,highly_sensitive}/, 5s/, checksheets/  (gitignored — PII)
├── boot_manifests/          # Per-boot preflight anchors (gitignored)
└── submissions.db (+ -wal, -shm)   # The live SQLite DB (gitignored)
```

## 6.2 Key files and their purpose

- **`main.py`** (~12,740 lines) — the application. Route handlers, RBAC,
  auth/MFA/session helpers, middleware, the preflight gate, background loops.
- **`database.py`** (~15,628 lines) — the data layer. Every table, every CRUD
  function, encryption wrappers, audit/chain helpers, delegation lookups.
- **`crypto.py`** (~169 lines) — field encryption primitives.
- **`static/pc_shared.js`** — shared frontend `PC` namespace: `PC.apiFetch`
  (cookie-credentialed fetch + error toasts), formatters, and the client-side
  permission gate (`PC.access`, `PC.canRead`, `PC.canWrite`, `PC.gateLink`).
  ⚠️ Note (FIXME in the file): the served copy is under `icons/pc_shared.js` via
  the `/icons` mount because `/static` is not mounted — keep the two copies in
  sync.

## 6.3 Entry points

- **System start:** `uvicorn main:app` → `main.py`. The `app` object is created
  at main.py:1444; `_preflight_run()` runs at import time before that.
- **DB initialization:** `init_db()` (database.py:260), called from `lifespan`
  startup.

## 6.4 Configuration

- **Secrets & runtime flags:** environment variables only (see `.env.example`
  and §10.1). Not auto-loaded — source them.
- **App constants:** defined near the top of `main.py` (cookie names, JWT
  algorithm, TTLs, MFA issuer, upload limits — see §10.2) and `database.py`
  (DB path, PIN policy constants, retention windows).
- **Lint/format/test:** `pyproject.toml` (ruff/black line length 110, pytest
  `testpaths=["tests"]`).

## 6.5 Dependencies

Listed in `requirements.txt` (10 runtime packages — see §1.2). No lockfile;
versions are pinned with `>=` minimums. Python standard library provides
`sqlite3`, `hashlib`, `hmac`, `secrets`, `json`, `asyncio`, `threading`,
`base64`, `io`, `datetime`. Dev tooling (ruff, black, pytest) is configured but
not pinned in `requirements.txt`.

---

# 7. Database Administration

## 7.1 Connecting directly

```bash
cd /path/to/primcool
sqlite3 submissions.db
```
The DB uses WAL mode, so a `submissions.db-wal` and `-shm` file accompany it. Do
**not** copy the main file alone for a backup while the server is running — use
`sqlite3 submissions.db ".backup 'snapshot.db'"` for a consistent snapshot.

> Encrypted columns (`v1:r:` / `v1:d:` prefixed) are unreadable in raw SQL — they
> only decrypt through the application with the correct `FIELD_ENCRYPTION_KEY`.

## 7.2 Backup / restore procedures

See §5.5. Quick consistent snapshot:
```bash
sqlite3 submissions.db ".backup 'submissions.db.bak-$(date +%s)'"
```
Restore: stop the server → `cp <snapshot> submissions.db` → restart → confirm
the boot manifest is clean and `POST /api/admin/audit/verify` returns `ok:true`.

## 7.3 Common queries

```sql
-- Active admins / techs / customers
SELECT COUNT(*) FROM admin_users WHERE active=1;
SELECT COUNT(*) FROM technicians WHERE active=1;
SELECT COUNT(*) FROM customers   WHERE active=1;

-- Recent visits (last 30 days)
SELECT id, customer_id, status, scheduled_date
FROM maintenance_visits
WHERE scheduled_date >= date('now','-30 day')
ORDER BY scheduled_date DESC;

-- Invoice status breakdown
SELECT status, COUNT(*) FROM invoices GROUP BY status;

-- Revenue collected (sum of recorded payments, JMD)
SELECT ROUND(SUM(amount),2) AS collected_jmd FROM invoice_payments;

-- AR outstanding (sent invoices not fully paid)
SELECT id, invoice_number, total, amount_paid, (total-amount_paid) AS balance
FROM invoices WHERE status='sent' AND total > amount_paid ORDER BY due_date;

-- Audit chain row count and latest action
SELECT COUNT(*) FROM audit_log;
SELECT action, created_at FROM audit_log ORDER BY id DESC LIMIT 10;
```

## 7.4 Schema migrations

There is **no migration framework** (no Alembic). All schema evolution lives in
`init_db()` (database.py:260) and runs on every boot:
- New tables: `CREATE TABLE IF NOT EXISTS`.
- New columns: idempotent `ALTER TABLE ADD COLUMN` guarded by a
  `PRAGMA table_info` check so re-running is safe.
- Constraint changes (CHECK/FK, which SQLite cannot `ALTER` in place): a
  **create-copy-drop-rename** table rebuild (examples: `delegations` v2,
  `tech_pto_ledger` v2, `tech_pto_requests` v3, `fs_audit_items`).
- Data normalizations/backfills run after table creation (e.g.
  `'canceled'→'cancelled'`, PRID backfill, field-encryption backfill, audit-chain
  backfill).

**To apply a migration:** edit `init_db()` and restart the app. **To "rollback":**
there is no automated down-migration — restore from a pre-change backup. Always
back up before deploying a schema change.

## 7.5 Data retention

- Audit log: system/security/auth → forever; financial → 7 years; operational →
  2 years (purged at lifespan startup).
- Access log: 90 days. Sessions: 90 days after expiry/revocation.
- Customer data deletion is request-based (`deletion_requested_at` /
  `POST /api/portal/me/deletion-request`) — flagged for operator action, not
  auto-hard-deleted.

---

# 8. Maintenance & Updates

## 8.1 Applying security patches

1. Branch from `main` (`fix/<slug>`).
2. Make the change in `main.py` / `database.py` / `crypto.py`.
3. Run the test suite (`pytest`) and ruff (`ruff check .`).
4. Verify locally end-to-end (boot, login through MFA, exercise the affected
   route, confirm audit rows).
5. Open a PR; merge to `main`; deploy.

Open security-debt items are tracked in `docs/FIXMES.md` and the planned IT
module in `docs/it-module-todo.md` (§9).

## 8.2 Upgrading dependencies

Dependencies are in `requirements.txt`. To upgrade:
`pip install -U <package>`, update the pin, run the full test suite, and verify
the crypto/auth paths specifically (argon2-cffi, PyJWT, cryptography, pyotp are
security-critical). There is no lockfile, so test carefully after bumps.

## 8.3 Testing procedure before deploying

- **Unit/integration:** `pytest` (15 test files under `tests/`, with a
  `conftest.py` providing `dev_env`, `app`, `client`, and role-token fixtures).
  Coverage includes access delegation, access-gate row isolation, DB pragmas,
  XFF-trust (PC-003), consult rate-limit (PC-004), security-alert ordering, the
  `pc_shared` permission-gate shadow test, and the tech-portal suite.
- **Lint:** `ruff check .` and `black --check .` (line length 110).
- **Manual:** boot the app, complete an MFA login, and exercise the changed
  feature in the browser — type checks and unit tests verify code correctness,
  not feature correctness.

⚠️ There is **no JS/DOM test runner** — the `pc_shared.js` permission logic is
covered only by a Python *shadow* reimplementation (`test_pc_shared_gate.py`)
that must be kept in sync manually.

## 8.4 Rollback procedure

- **Code:** redeploy the previous commit (`git revert` or deploy the prior
  build). Railway restarts `on_failure`.
- **Database:** restore the pre-change backup (§5.5). Remember WAL — snapshot/
  restore the whole DB, not just the main file.
- **Encryption key:** never rotate `FIELD_ENCRYPTION_KEY` as part of a rollback
  unless you also restore the data that matches it.

## 8.5 Version control

- Git repo. Main branch: `main`. Work happens on `feature/<slug>`,
  `fix/<slug>`, or `claude/<slug>` worktree branches (current branch at writing:
  `claude/condescending-hermann-568bd5`).
- Commit convention: `feat(scope): …`, `fix(scope): …`, `chore(scope): …`,
  `refactor(scope): …`.
- The live DB, secrets (`.dev.env`/`.env`), `uploads/` PII, and
  `boot_manifests/` are gitignored.

---

# 9. Known Limitations & Tech Debt

Sourced from the code, `docs/FIXMES.md`, and `docs/it-module-todo.md`.

**Security debt / compliance gaps (highest priority):**
1. **Admin reset-password is weaker than the portal rule** — admin reset paths
   accept 8-char passwords with no denylist/complexity, while self-service and
   the customer portal require 12+ with a denylist. (`docs/it-module-todo.md` #
   "tighten admin reset rule".)
2. **The three forgot-* endpoints have no rate limiting**
   (`/api/portal/forgot-pin`, `/api/tech/forgot-pin`,
   `/api/admin/forgot-password`) — token/email-flood and timing-enumeration
   exposure.
3. **Rate limiter is in-memory per-process** — ineffective across multiple
   uvicorn workers/replicas. A shared store (Redis) is needed before
   horizontal scaling.
4. **No global security-headers middleware** — HSTS, CSP, X-Frame-Options,
   X-Content-Type-Options are not set by the app.
5. **`uploads/5s/` photos served as plain static** — unlike the signed-URL
   photo/document paths, the 5S photo path lacks an auth/signature gate.
6. **No per-account lockout for admins/techs independent of IP** (only the
   customer PIN path has per-account lockout). Distributed credential stuffing
   is uncapped. (Planned in the IT module.)
7. **Delegation enforcement is partial server-side** — `_require_record_access`
   is wired into only a subset of endpoint pairs; equipment/5S/parts/payroll
   still use the legacy role gate (per `docs/FIXMES.md`).
8. **No MFA for customers by default** (deliberate operator decision), and no
   session-management UI / security dashboard yet.

**Workarounds / correctness notes:**
9. **PIN policy doc/code mismatch** — `validate_pin_policy` docstring says
   "10–16" digits but the constants allow 6–16.
10. **Hash-chain formats differ across tables** (audit/5S vs payment/credit/
    part-movement) — verification tooling must use the per-table helper.
11. **Role-count doc drift** — README/SECURITY.md say 7 admin roles; the code
    has 8 (`dispatcher`, `warehouse_supervisor` added later). Two copies of the
    client permission set (`pc_shared.js` and `icons/pc_shared.js`) must be kept
    in sync.
12. **Two dead session-issuing code paths** in admin/tech login (unreachable
    because MFA branches return first) — harmless but confusing.
13. **Default `invoices.currency` is `'TTD'`** at the column level though the
    business runs in JMD (`display_currency` defaults to JMD) — a latent
    inconsistency.
14. **Stray staged DB artifact** in git (`submissions.db-shm 2.db-shm`) — a
    runtime SHM file that should be unstaged/removed (it is not source).

**Performance bottlenecks:**
15. **Single-writer SQLite** — WAL allows concurrent reads but only one writer;
    bulk operations (seeding) must not run concurrently with the server, and the
    architecture won't scale to high write concurrency without a different DB.
16. **Monolithic files** — `main.py` (~12.7k lines) and `database.py` (~15.6k
    lines) are single modules; navigation relies on `grep`. A future refactor
    into packages would help maintainability but is not urgent.

**Planned work:** `docs/it-module-todo.md` scopes a dedicated **IT-management
module** (planned start 2026-08-01) covering: tech MFA hardening, per-account
lockout, rate-limiting the forgot-* endpoints, tightening the admin reset rule,
a session-management UI, a security operations dashboard (failed logins, locked
accounts, MFA coverage %, audit-chain status), optional Google Workspace SSO,
and MDM for company devices.

---

# 10. Appendices

## 10.1 Environment variables (quick reference)

From `.env.example`:

| Variable | Required | Default | Purpose |
|---|---|---|---|
| `JWT_SECRET` | **yes** | — | JWT signing key; ≥32 chars, ≥8 distinct. |
| `FIELD_ENCRYPTION_KEY` | **yes** | — | Master field-encryption key (HKDF root); ≥32 chars. |
| `DATASTORE_ENCRYPTION_CONFIRMED` | prod | — | Operator attestation that PII is app-encrypted. |
| `DATASTORE_ENCRYPTION_OVERRIDE` | no | — | Break-glass skip of the above (recorded in manifest). |
| `PROD_MODE` | no | `false` | Tightens preflight (forces COOKIE_SECURE + CORS). |
| `COOKIE_SECURE` | prod | `false` | Adds `Secure` to cookies; required in prod. |
| `CORS_ALLOW_ORIGINS` | prod | (empty) | Comma-separated allowed origins; fails closed in prod. |
| `ADMIN_IDLE_TIMEOUT_SEC` | no | `1800` | Admin idle logout (30 min). |
| `TECH_IDLE_TIMEOUT_SEC` | no | `0` | Tech idle logout (disabled). |
| `CUSTOMER_IDLE_TIMEOUT_SEC` | no | `1200` | Customer idle logout (20 min). |
| `BOOT_MANIFEST_DIR` | no | `boot_manifests` | Where boot anchors are written. |
| `DELEGATION_VERBOSE_AUDIT` | no | `1` | Log every delegated record access. |
| `RESEND_API_KEY` | no | — | Enables outbound email; unset = email disabled. |
| `NOTIFY_EMAIL` | no | — | Recipient for lead/flash-report notifications. |
| `SECURITY_ALERT_EMAIL` | no | — | Recipient for security-alert emails. |
| `PHOTO_URL_SECRET` | no | =`JWT_SECRET` | HMAC key for signed photo/doc URLs. |
| `PHOTO_URL_TTL_SEC` | no | `1800` | Signed-URL lifetime (30 min). |
| `MFA_ISSUER` | no | `PrimeCool Services` | TOTP issuer label. |
| `MFA_FRESH_TTL_SEC` | no | `900` | Step-up MFA freshness window (15 min). |
| `ACCESS_LOG_RETAIN_DAYS` | no | `90` | Access-log retention. |
| `AUDIT_FINANCIAL_RETAIN_DAYS` | no | `2555` (7y) | Financial audit retention. |
| `AUDIT_OPERATIONAL_RETAIN_DAYS` | no | `730` (2y) | Operational audit retention. |
| `DORMANT_DAYS` | no | `90` | Dormant-account flag threshold. |
| `MAX_DOC_SIZE_BYTES` | no | `26214400` (25 MB) | Max document upload size. |
| `BOOTSTRAP_ADMIN_USERNAME/PASSWORD/EMAIL/NAME` | first boot | — | Auto-create first super_admin; remove after. |

## 10.2 Key application constants (in source)

| Constant | Value | Location |
|---|---|---|
| `JWT_ALGORITHM` | `HS256` | main.py:727 |
| Cookie names | `pc_admin_session`, `pc_tech_session`, `pc_customer_session` | main.py:857–859 |
| Session TTLs | admin 12h, tech 7d, customer 24h | `_issue_session` |
| `MFA_TOKEN_TTL` | 5 minutes | main.py:876 |
| Backup codes | 10 codes, `XXXX-XXXX`, Argon2-hashed | main.py:882 |
| `MAX_PHOTO_SIZE` | 12 MB; exts jpg/jpeg/png/webp/heic | main.py:456–457 |
| `DOC_TIERS` | public, confidential, highly_sensitive | main.py:470 |
| `DB_PATH` | `submissions.db` | database.py:22 |
| PIN policy | 6–16 digits, Argon2id, lockout 5 fails / 30 min | database.py:2714–2716 |
| Connection pragmas | WAL, synchronous=FULL, foreign_keys=ON, busy_timeout=5000 | database.py:248–256 |

## 10.3 Boot manifest format (example)

```json
{
  "boot_time_utc": "2026-05-31T20:44:49.303026+00:00",
  "prod_mode": false,
  "python_version": "3.9.6 ...",
  "checks": {
    "jwt_secret":           {"ok": true, "detail": "len=64 distinct=37"},
    "cookie_secure":        {"ok": true, "detail": "PROD_MODE=False COOKIE_SECURE=False"},
    "datastore_encryption": {"ok": true, "detail": "non-prod: skipped"},
    "field_encryption_key": {"ok": true, "detail": "FIELD_ENCRYPTION_KEY present (len=64)"}
  },
  "cookie_secure": false,
  "jwt_secret_sha256_prefix": "7abd808da51540ed",
  "datastore_override_used": false
}
```

## 10.4 Vendors / service providers

| Vendor | Service | Notes |
|---|---|---|
| **Resend** (`resend.com`) | Transactional email | API key in `RESEND_API_KEY`; optional. Sender `onboarding@resend.dev`. |
| **Railway** (`railway.app`) | Hosting (intended prod) | Nixpacks build; edge TLS termination; not currently in production use. |

No other third-party vendors, payment processors, SMS gateways, or cloud storage
are integrated.

## 10.5 Dependency licensing (summary)

All runtime dependencies are permissively licensed (verify before any
redistribution):

| Package | Typical license |
|---|---|
| FastAPI, Starlette | MIT |
| Uvicorn | BSD-3-Clause |
| PyJWT | MIT |
| argon2-cffi | MIT |
| pyotp | MIT |
| qrcode | BSD |
| Pillow | MIT-CMU (HPND) |
| cryptography | Apache-2.0 / BSD-3-Clause |
| resend | MIT |
| python-multipart | Apache-2.0 |

The PrimeCool source itself is marked **Confidential — © PrimeCool, internal use
only, not for redistribution** (README.md).

---

*End of PrimeCool Services — System Operations Runbook v1.0 (2026-05-31).*
*Confidential — Internal use only.*
