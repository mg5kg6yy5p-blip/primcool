# Phase 0 — Repository Inventory & Survey

Generated: 2026-06-09
Branch: `claude/primecool-systems-access-zkcTg`

## Snapshot

PrimeCool is currently a single-file FastAPI service serving a pre-launch holding
page. There is no CMMS, no business logic beyond a contact-form intake, and none
of the prerequisites the spec's "reuse mandate" assumes exist (PM trigger engine,
auth module, audit-log pattern, ORM, migrations, frontend framework, test suite).

The reuse mandate in §0 of the spec **does not apply** — there is nothing in
this repo to reuse beyond the FastAPI choice itself. This is effectively a
greenfield CMMS build that has to coexist with one existing public endpoint
(`POST /api/consult`) and a holding page.

## Inventory

| Concern | What's here | Spec target |
|---|---|---|
| Web framework | FastAPI (`main.py`, single file, 132 lines) | FastAPI (keep) |
| ORM | None — raw `sqlite3` in `database.py` | SQLAlchemy 2.0 typed |
| Migrations | None | Alembic |
| Validation | Pydantic v2 (implicit via FastAPI) | Pydantic v2 (keep) |
| Database | SQLite (single `submissions` table) | PostgreSQL |
| Auth | `ADMIN_TOKEN` bearer for `/api/submissions` only | argon2id + JWT + roles |
| Tests | None | pytest |
| Frontend | Static `index.html` holding page (no JS) | React/Vite (spec default) |
| Deploy | Railway (`railway.toml`, uvicorn nixpacks) | Keep |
| Email | Resend client | Keep |
| Currency | None | JMD default |

## Existing conventions (carry forward where they fit)

- Single-file FastAPI app, no routers yet
- Module-level `app = FastAPI(lifespan=...)` with startup-time DB init
- Pydantic models defined inline next to routes
- Parameterized SQL only; single global `DB_PATH`
- Env-driven config via `os.environ.get(...)`
- HTML emails composed with f-strings
- Branch naming: `claude/<slug>` for feature work

## Existing endpoints (preserve through the build)

| Route | Purpose |
|---|---|
| `GET /` | Serves the holding page |
| `GET /health` | Railway healthcheck |
| `POST /api/consult` | Public consultation intake → SQLite + Resend email |
| `GET /api/submissions` | Admin list of consults, token-gated (commit `e957def`) |
| `GET /images/*` | Static photo gallery (orphaned by current holding page) |

The consult submissions are **pre-launch marketing leads**, not §3d `notification`
records. They have no `customer_account_id` because the submitter is by
definition not yet a customer. Keep them in a separate table; do not fold into
the new data model.

## Gaps that need decisions before Phase 1

1. **PostgreSQL switch.** Spec requires partial unique indexes, JSONB, and DB
   triggers for immutability (`audit_log`, `confirmation`, `meter_reading`,
   `notification`). SQLite supports none of these well. Options: (a) cut over
   to Postgres now, develop and deploy on it; (b) develop locally on Postgres,
   keep SQLite in prod until the form-only system retires; (c) deviate from
   spec and use SQLite triggers + `CHECK` constraints — loses some guarantees.
2. **Frontend stack.** No JS framework today. Spec defaults to React/Vite for
   three separate UIs (internal app, technician mobile view, customer portal).
   Confirm before scaffolding.
3. **Auth.** No user table. Spec needs argon2id + JWT + four roles (admin,
   dispatcher, technician, portal_user). Confirm building from scratch.
4. **Public site coexistence.** Holding page is live at the root. The new
   internal app, technician mobile, and customer portal are separate surfaces.
   Decision: serve everything from one FastAPI process at sub-paths
   (`/app`, `/tech`, `/portal`), or split to subdomains?
5. **Scope cadence.** The spec's six phases cover ~26 entities, ~50+ endpoints,
   3 UIs, billing engine. This is multi-week work. Recommendation: one phase
   at a time, gate by gate, check in at each gate — not a continuous run.

## Phase 0 gate status

- [x] Repo inventory report (this document)
- [x] Traceability matrix (`docs/TRACEABILITY.md`)
- [x] Conventions documented (above)
- [x] Existing tests green (none exist — trivially passes)

Phase 0 gate is met. No production code changes yet. Awaiting decisions on the
five gap items above before scaffolding for Phase 1.
