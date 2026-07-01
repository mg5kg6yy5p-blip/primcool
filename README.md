# PrimeCool

**Internal HVAC PM/CM field-service management system.** Customer & equipment
records, scheduled visits, technician dispatch (PWA), 5S audits, parts &
invoicing, payroll, audit hash-chain, and a customer portal — all behind a
field-level-encrypted SQLite store.

> Confidential. Internal use only. Not for redistribution.

---

## Quick start

```bash
pip install -r requirements.txt
cp .env.example .dev.env && $EDITOR .dev.env   # fill JWT_SECRET, FIELD_ENCRYPTION_KEY
uvicorn main:app --reload
```

First boot: set `BOOTSTRAP_ADMIN_*` env vars (see `.env.example`) to auto-create
a super_admin. Remove them after the account exists.

## Architecture at a glance

```
                       ┌──────────────────┐
   Admin SPA  ────────►│                  │
   Tech PWA   ────────►│  FastAPI         │◄──► crypto.py  (AES-GCM + AES-SIV,
   Portal     ────────►│  (main.py)       │     HKDF sub-keys, _PII_RAND/_DET)
                       │                  │
                       └────────┬─────────┘
                                ▼
                       ┌──────────────────┐
                       │  SQLite          │
                       │  submissions.db  │  + WAL, hash-chain audit rows
                       │  (database.py)   │
                       └──────────────────┘
```

## Where things live

| Path                      | Role                                                          |
|---------------------------|---------------------------------------------------------------|
| `main.py`                 | FastAPI app, routes, auth helpers, preflight gate, audit       |
| `database.py`             | SQLite schema, CRUD, delegation lookups, audit chain helpers  |
| `crypto.py`               | AES-GCM (randomized) + AES-SIV (deterministic) field encryption |
| `admin.html`              | Admin SPA (super_admin + role-based admins)                   |
| `tech.html`               | Technician PWA (offline-capable, visit-execution surface)     |
| `portal.html`             | Customer portal login                                          |
| `portal_dashboard.html`   | Customer My-Account dashboard (equipment, visits, invoices)   |
| `invoice_print.html`      | Printable invoice template                                    |
| `scripts/`                | Seed + backup scripts (see below)                              |
| `uploads/`                | Photos & documents (gitignored — customer PII)                |
| `boot_manifests/`         | Per-boot audit-chain anchors (gitignored — operational)       |
| `docs/`                   | FIXMES tracker, security model                                 |

## Environment variables

See `.env.example` for the full list with comments. Required vars
(`JWT_SECRET`, `FIELD_ENCRYPTION_KEY`, and `DATASTORE_ENCRYPTION_CONFIRMED`
in prod) are checked by the preflight gate at startup; the app refuses
to boot if any check fails.

## Security model

PrimeCool defines **7 admin roles** (super_admin, supervisor_admin,
system_admin, hr_admin, ceo_assistant, inventory_manager, tech) plus a
customer principal. Super_admin is the root of trust — sensitive routes
gate on either `_require_super_admin` or `_require_record_access` (which
also honors the delegation system). Auth uses JWT-in-HttpOnly-cookie with
JTI revocation. PII at rest is encrypted per-field (AES-256-GCM for
randomized, AES-256-SIV for deterministic-searchable). Audit rows are
append-only with a per-row SHA-256 chain_hash. A 4-check preflight gate
runs at boot. See [`docs/SECURITY.md`](docs/SECURITY.md) for detail.

## Development scripts

- `scripts/seed_full_demo.py` — full demo dataset (customers, techs, visits)
- `scripts/seed_demo.py` — smaller seed for spot-checking
- `scripts/backup.sh` — snapshots `submissions.db` to a timestamped `.bak`

## Backups & restore

`scripts/backup.sh` writes `submissions.db.bak-<epoch>` next to the live DB.
To restore: stop the server, `cp submissions.db.bak-<epoch> submissions.db`,
restart. The audit chain validates from boot — a tampered restore will
surface as a chain_hash mismatch in the next boot manifest.

## Branch / commit conventions

- `feat(scope): …` — new functionality
- `fix(scope): …` — bug fix
- `chore(scope): …` — tooling, docs, repo hygiene
- `refactor(scope): …` — no behavior change

Branches: `feature/<slug>`, `fix/<slug>`, or the existing
`claude/<slug>` worktree branches.

## Known limitations / FIXMEs

Tracked in [`docs/FIXMES.md`](docs/FIXMES.md). New FIXMEs belong there,
linked from code with `# FIXME(docs/FIXMES.md#section): note`.

---

*Confidential — © PrimeCool. Internal use only.*
