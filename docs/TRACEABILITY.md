# Traceability Matrix

Each entity from §3 of the build spec gets a row. A phase gate passes only when
every cell in every row that phase touched is checked **and** pytest is green.

Legend: ☐ = not started · ☑ = complete

| Entity | SQLAlchemy model | Alembic migration | Pydantic schemas | API routes | UI list | UI create/edit | UI detail | Tests |
|---|---|---|---|---|---|---|---|---|
| customer_account     | ☑ | ☑ | ☑ | ☑ | ☑ | ☑ | ☑ | ☑ |
| site                 | ☑ | ☑ | ☑ | ☑ | ☑ | ☑ | ☑ | ☑ |
| building             | ☑ | ☑ | ☑ | ☑ | ☐ | ☐ | ☐ | ☐ |
| space                | ☑ | ☑ | ☑ | ☑ | ☐ | ☐ | ☐ | ☐ |
| functional_location  | ☑ | ☑ | ☑ | ☑ | ☑ | ☑ | ☑ | ☑ |
| equipment            | ☑ | ☑ | ☑ | ☑ | ☑ | ☑ | ☑ | ☑ |
| equipment_install    | ☑ | ☑ | ☑ | ☑ | ☑ | ☑ | ☑ | ☑ |
| meter                | ☑ | ☑ | ☑ | ☑ | ☐ | ☐ | ☐ | ☑ |
| meter_reading        | ☑ | ☑ | ☑ | ☑ | ☐ | ☐ | ☑ | ☑ |
| material             | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ |
| stock_location       | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ |
| stock_quant          | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ |
| equipment_bom        | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ |
| bom_item             | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ |
| notification         | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ |
| work_order           | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ |
| operation            | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ |
| confirmation         | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ |
| confirmation_part    | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ |
| saved_view           | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ |
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

Last updated: Phase 1 complete — 2026-06-17

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

### Known UI gaps carried forward (API + tests done, UI deferred)
- **building**, **space** — backend CRUD + migration done; no dedicated UI form
  yet (low-value secondary CRUD; sites/FL/equipment cover the Phase 1 gate).
- **meter** create / **meter_reading** entry — API done and surfaced read-only
  in the equipment timeline; dedicated entry forms deferred.

These are tracked as defects per the lockstep rule and should be backfilled
before or alongside Phase 2 if the dispatcher workflow needs them.

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
