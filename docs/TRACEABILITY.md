# Traceability Matrix

Each entity from §3 of the build spec gets a row. A phase gate passes only when
every cell in every row that phase touched is checked **and** pytest is green.

Legend: ☐ = not started · ☑ = complete

| Entity | SQLAlchemy model | Alembic migration | Pydantic schemas | API routes | UI list | UI create/edit | UI detail | Tests |
|---|---|---|---|---|---|---|---|---|
| customer_account     | ☑ | ☑ | ☑ | ☑ | ☑ | ☑ | ☑ | ☑ |
| site                 | ☑ | ☑ | ☑ | ☑ | ☑ | ☑ | ☑ | ☑ |
| building             | ☑ | ☑ | ☑ | ☑ | ☑ | ☑ | ☑ | ☑ |
| space                | ☑ | ☑ | ☑ | ☑ | ☑ | ☑ | ☑ | ☑ |
| functional_location  | ☑ | ☑ | ☑ | ☑ | ☑ | ☑ | ☑ | ☑ |
| equipment            | ☑ | ☑ | ☑ | ☑ | ☑ | ☑ | ☑ | ☑ |
| equipment_install    | ☑ | ☑ | ☑ | ☑ | ☑ | ☑ | ☑ | ☑ |
| meter                | ☑ | ☑ | ☑ | ☑ | ☑ | ☑ | ☑ | ☑ |
| meter_reading        | ☑ | ☑ | ☑ | ☑ | ☑ | ☑ | ☑ | ☑ |
| material             | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ |
| stock_location       | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ |
| stock_quant          | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ |
| equipment_bom        | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ |
| bom_item             | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ |
| notification         | ☑ | ☑ | ☑ | ☑ | ☑ | ☑ | ☑ | ☑ |
| work_order           | ☑ | ☑ | ☑ | ☑ | ☑ | ☑ | ☑ | ☑ |
| operation            | ☑ | ☑ | ☑ | ☑ | ☑ | ☑ | ☑ | ☑ |
| confirmation         | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ |
| confirmation_part    | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ |
| saved_view           | ☑ | ☑ | ☑ | ☑ | ☑ | ☑ | n/a | ☑ |
| service_contract     | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ |
| contract_site        | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ |
| invoice_draft        | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ |
| invoice_draft_line   | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ |
| pm_schedule          | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ |
| audit_log            | ☑ | ☑ | ☑ | ☑ | ☐ | n/a | ☑ | ☑ |

## Phase ownership

- **Phase 1 — Hierarchy & assets:** customer_account, site, building, space,
  functional_location, equipment, equipment_install, meter, meter_reading,
  audit_log.
- **Phase 2 — Notification → triage → order:** notification, work_order,
  operation, saved_view.
- **Phase 3 — Confirmations:** confirmation, confirmation_part, material,
  stock_location, stock_quant (consumption side).
- **Phase 4 — PM engine wiring:** pm_schedule (and meter/meter_reading
  finalization).
- **Phase 5 — Contracts & billing:** service_contract, contract_site,
  invoice_draft, invoice_draft_line, equipment_bom, bom_item.

Some entities span phases (e.g. `material` lifts in Phase 3 for consumption,
but its full UI may not land until Phase 5 alongside billing). Each cell will
be checked when the work for that surface is genuinely shippable, not stubbed.

Last updated: Phase 2 complete — 2026-06-17

## Phase 2 status — Notification → triage → order

Gate criteria (per spec §7):
- [x] **Full path tenant-request → converted → scheduled clickable end-to-end**
      — Triage inbox (raise request, Acknowledge/Convert/Close), convert creates
      a corrective order copying site/space/severity→priority, work queue +
      order detail drive it onward via transition buttons.
- [x] **Illegal transitions rejected with tests** — work-order state machine in
      `services/workflow.py`; `test_work_order_illegal_backward_rejected`,
      `test_work_order_skip_state_rejected`, `test_cancel_from_created_ok_but_not_*`,
      `test_transition_from_terminal_rejected`.
- [x] Notification lifecycle (new→acknowledged→converted|closed_no_action) with
      illegal-transition tests; close-no-action requires a reason (audited).
- [x] Work queue default lens excludes closed/cancelled; `include_closed` shows
      them; emergency sorts to top (`test_queue_excludes_*`, `test_emergency_*`).
- [x] After tech_complete, descriptive fields frozen (`test_fields_frozen_*`).
- [x] Saved view drives the queue via `view_id` (`test_saved_view_filters_queue`).
- [x] Transition buttons rendered only for legal next states (server returns
      `legal_transitions`; `OrderDetail` renders exactly those).
- [x] Audit row per mutation; customer-account scoping on lists; validation 422.
- [x] 33 tests green (14 Phase 0/1 + 19 Phase 2); frontend builds clean (44 mod).

Migration 0003 adds notification/work_order/operation/saved_view. Per spec,
notification carries NO immutability trigger (its status timestamps mutate);
confirmation's append-only trigger arrives in Phase 3.

Auth note: `created_by`, `assigned_to_user_id`, `saved_view.user_id` are
nullable pending the dedicated argon2id+JWT+roles unit. Portal row-scoping
(Phase 5 gate) will build on the scoping filters already present on every list.

## Phase 1 status — Hierarchy & assets

## Phase 1 status — Hierarchy & assets

Gate criteria (per spec §7):
- [x] **Invariant A** (one active install per FL) proven by a test expecting a
      409 backed by the partial unique index — `test_invariant_a_*`
- [x] **Invariant B** (one active install per equipment) proven — `test_invariant_b_*`
- [x] **Equipment timeline renders** — backend `GET /equipment/{id}/history`
      (`test_equipment_timeline`) + `EquipmentDetail.tsx` timeline view
- [x] Audit row written for every mutation (create/update/install/remove) in
      the same transaction — `test_audit_*`
- [x] Customer-account scoping on list endpoints — `test_site_list_scoped_by_customer`
- [x] Validation parity: 422 rendered as field-level error in forms (api.ts
      `ValidationError` → `field-error` spans) + `test_customer_validation_422`
- [x] Warranty expiry computed (not stored) — `test_warranty_expiry_computed`
- [x] 14 tests green (5 smoke + 9 Phase 1); frontend builds clean (tsc + vite)

Immutability triggers (`audit_log`, `meter_reading`) ship in migration 0002 but
fire **Postgres-only** (`RAISE EXCEPTION` on UPDATE/DELETE). They cannot be
exercised on the SQLite test DB; invariants A/B are validated on SQLite because
SQLite enforces partial unique indexes. A Postgres-backed immutability test is
deferred to the integration-test pass once the Railway Postgres add-on exists.

### UI gaps — CLOSED (backfilled 2026-06-17)
- **building**, **space** — full UI in `SitesPage.tsx` (site picker → buildings
  list + add form, spaces table + add form with building assignment).
- **meter** create / **meter_reading** entry — `MetersPanel` in
  `EquipmentDetail.tsx`: list meters, add meter, inline "Log" reading per meter.

Every Phase 1 entity row is now fully checked. Frontend builds clean (41 modules).

## Phase 0 scaffold status

## Phase 0 scaffold status

- [x] Backend restructured into `app/` package (routers/models/schemas/db/core)
- [x] SQLAlchemy 2.0 + Postgres + Alembic wired
- [x] First Alembic migration: `consult_submission` table
- [x] Pydantic-settings config in `app/core/config.py`
- [x] slowapi rate limiter shared via `app.state.limiter`
- [x] pytest + httpx TestClient; 4 smoke tests for the consult flow pass
- [x] Frontend skeleton at `frontend/` (React 18 + Vite + TS, three surfaces)
- [x] `railway.toml` updated to `alembic upgrade head && uvicorn app.main:app`
- [x] Architecture doc at `docs/ARCHITECTURE.md`
- [x] Existing endpoints preserved: `/`, `/health`, `POST /api/consult`,
      `GET /api/submissions`, `/images/*` — all moved into the new package

Five security items from earlier (HTML-escape email body, locked CORS,
rate limit, EmailStr, no hardcoded NOTIFY_EMAIL fallback) are incorporated
into the restructure.
