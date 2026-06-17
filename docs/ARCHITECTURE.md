# Architecture — PrimeCool Maintenance System

Decisions taken at the end of Phase 0, per the build spec's defaults and the
user's confirmation.

## Stack

| Layer | Choice | Notes |
|---|---|---|
| Web framework | FastAPI | Routers per feature under `app/routers/` |
| ORM | SQLAlchemy 2.0 (typed `Mapped[]`) | `DeclarativeBase` in `app/db/base.py` |
| Migrations | Alembic | `alembic/` at repo root |
| Validation | Pydantic v2 (+ `pydantic-settings`) | All env config in `app/core/config.py` |
| Database | PostgreSQL 16 (psycopg 3 driver) | URL: `postgresql+psycopg://` |
| Auth | argon2id (passlib) + JWT (python-jose) | Roles: admin, dispatcher, technician, portal_user |
| Rate limit | slowapi | Per-IP, shared at `app.state.limiter` |
| Tests | pytest + httpx TestClient | In-memory SQLite for unit tests; Postgres fixture for integration in Phase 1+ |
| Frontend | React 18 + Vite + TypeScript | Single SPA, three surfaces at `/app`, `/tech`, `/portal` |
| Deploy | Railway (nixpacks) | One process; Postgres add-on attached |
| Email | Resend | Existing |

## Directory layout

```
primcool/
├── app/                    # FastAPI application package
│   ├── core/               # Settings, security, rate limiter
│   ├── db/                 # SQLAlchemy engine, session, base
│   ├── models/             # ORM models, one file per aggregate
│   ├── schemas/            # Pydantic request/response, one file per feature
│   ├── routers/            # API routers, one file per feature
│   └── main.py             # FastAPI factory
├── alembic/                # Database migrations
├── frontend/               # React + Vite SPA
├── tests/                  # pytest suite
├── docs/                   # Survey, traceability, architecture
├── images/                 # Legacy job-site photos (served at /images)
├── index.html              # Public holding page (served at /)
├── pyproject.toml          # Tool config (pytest)
├── requirements.txt        # Production dependencies
├── requirements-dev.txt    # + pytest, httpx
├── railway.toml            # Deploy config
└── .env.example            # All env vars documented
```

## URL layout

One FastAPI process serves four surfaces:

| Path | What | Phase |
|---|---|---|
| `/` | "Launching 2028" holding page | 0 (existing) |
| `/health` | Railway healthcheck | 0 (existing) |
| `POST /api/consult` | Public consultation form intake | 0 (existing) |
| `GET /api/submissions` | Admin: list consult leads (token auth) | 0 (existing) |
| `/images/*` | Static assets | 0 (existing) |
| `/api/v1/*` | CMMS REST API | 1+ |
| `/api/auth/*` | Login, refresh, /me | 2+ |
| `/app/*` | Internal SPA (dispatcher, admin) | 2+ |
| `/tech/*` | Technician mobile SPA | 3+ |
| `/portal/*` | Customer portal SPA | 5+ |

Three SPA surfaces share one Vite build; React Router selects the surface from
the path prefix.

## Database cutover plan

Current production runs SQLite (`submissions.db`). To switch:

1. Provision Postgres in Railway; set `DATABASE_URL` on the service.
2. Export existing rows (likely zero — the form was removed from the holding
   page in commit `43ea1f3`). If rows exist, dump to JSON and re-insert via
   the new `consult_submission` model after `alembic upgrade head`.
3. First deploy with new code runs `alembic upgrade head` as a release step
   (to be wired into `railway.toml` in Phase 1).

This branch (`claude/primecool-systems-access-zkcTg`) is NOT merge-ready until
the Postgres add-on exists on Railway. Local dev runs against Docker:

```
docker run --rm -p 5432:5432 \
    -e POSTGRES_PASSWORD=postgres \
    -e POSTGRES_DB=primcool postgres:16
```

Then:

```
pip install -r requirements-dev.txt
alembic upgrade head
uvicorn app.main:app --reload
```

Frontend (separate shell):

```
cd frontend && npm install && npm run dev
```

Vite serves at `http://localhost:5173` and proxies `/api/*` to the FastAPI
server on `:8000`.

## Auth model (skeleton now, full impl in Phase 2)

- Passwords hashed with argon2id via passlib; verification constant-time.
- JWT access tokens (HS256) carry `sub=user_id`, `role`, and for portal users
  `acct=<customer_account_id>`. Default expiry 60 minutes.
- Roles: `admin`, `dispatcher`, `technician`, `portal_user`.
- Portal user queries are filtered by `acct` claim in the query layer; the
  cross-account leak test is part of the Phase 5 gate.

## Out of scope (per spec §8)

Payment processing, accounting/tax engine beyond a single configurable GCT
line, offline-first sync (APIs designed idempotent; offline deferred), e-sig
capture (policy flag only), SMS/email delivery (internal event log instead),
multi-language, multi-org tenancy.
