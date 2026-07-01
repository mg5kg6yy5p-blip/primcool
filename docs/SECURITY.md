# PrimeCool — Security Model

This document summarizes the security posture of PrimeCool. The authoritative
source is the code; this is a map for reviewers and on-call engineers.

## Principals & roles

PrimeCool authenticates three principal classes via separate JWT cookies:

| Principal | Cookie name (HttpOnly) | Helper                            |
|-----------|------------------------|-----------------------------------|
| Admin     | admin session token    | `_get_authenticated_admin`        |
| Tech      | tech session token     | `_get_authenticated_tech`         |
| Customer  | portal session token   | `_get_authenticated_customer`     |

Admin principals carry one of **7 roles**:

1. `super_admin` — root of trust; can do anything (and is the only role
   permitted on most sensitive routes).
2. `supervisor_admin`
3. `system_admin`
4. `hr_admin`
5. `ceo_assistant`
6. `inventory_manager`
7. `tech` (admin-side mirror for technicians who also hold an admin login)

A separate **customer** principal logs in through the portal and is scoped
to its own customer record (and any portal-visible children: equipment,
visits, invoices, payments).

## Authorization helpers (in `main.py`)

| Helper                       | Use                                                      |
|------------------------------|----------------------------------------------------------|
| `_require_perm(role, perm)`  | Role-based permission check on a named permission key.   |
| `_require_super_admin`       | Hard gate: only `super_admin`.                           |
| `_require_record_access`     | Delegation-aware per-record gate (see "Delegation").     |
| `_get_authenticated_admin`   | Pull + validate an admin session.                        |
| `_get_authenticated_tech`    | Pull + validate a tech session.                          |
| `_get_authenticated_customer`| Pull + validate a customer portal session.               |

## Preflight gate

At startup, `main.py` runs a 4-check preflight. **Failure means the app
refuses to serve traffic.**

1. **JWT secret** — `JWT_SECRET` must be present, ≥32 chars, ≥8 distinct
   characters, and not a placeholder.
2. **Field encryption key** — `FIELD_ENCRYPTION_KEY` must be present and
   ≥32 chars.
3. **Datastore acknowledgement (prod only)** — when `PROD_MODE=true`,
   either `DATASTORE_ENCRYPTION_CONFIRMED=yes` or the break-glass
   `DATASTORE_ENCRYPTION_OVERRIDE=yes` must be set.
4. **Cookie security (prod only)** — `COOKIE_SECURE` must be `true` in prod.

Boot writes a manifest to `BOOT_MANIFEST_DIR` (default `boot_manifests/`)
capturing preflight results and the audit chain head for tamper detection
across restarts.

## Field-level encryption

Implemented in `crypto.py`. Two ciphers, one master key:

- **Randomized** (AES-256-GCM) — used for fields that never need search.
  Per-write random nonce; ciphertext is non-deterministic.
- **Deterministic** (AES-256-SIV) — used for fields that need equality
  search (e.g. encrypted email/phone lookup). Same plaintext → same
  ciphertext, but no plaintext leakage.

Per-field sub-keys are HKDF-derived from `FIELD_ENCRYPTION_KEY`. The set
of fields encrypted by each cipher is declared in the `_PII_RAND` and
`_PII_DET` registries inside `database.py`.

Rotating `FIELD_ENCRYPTION_KEY` invalidates existing ciphertext — a
migration is required.

## Audit hash-chain

Audit rows are **append-only**. Each row's `chain_hash` is
`SHA-256(prev_chain_hash || canonical(row))`. A break in the chain is
detected at boot and surfaces in the boot manifest.

Tables that carry `chain_hash`:

- `audit_access` — admin/tech/customer read & action events
- `audit_financial` — invoices, payments, FX adjustments
- `audit_operational` — visits, equipment, 5S, parts movements
- `audit_security` — auth failures, MFA events, JTI revocations
- `audit_delegation` — delegation grants, revocations, delegated accesses

PII is redacted before audit-write via `_redact_pii_for_audit`. Audit-write
failures **never** raise — they fail to stderr to preserve the calling
request.

## Session & cookie hygiene

- All session cookies are `HttpOnly`, `SameSite=strict`, and (in prod)
  `Secure`.
- JWTs include a JTI; revoked JTIs are rejected even if the JWT is
  otherwise valid (logout, password reset, forced sign-out).
- Idle timeouts per principal: admin 30 min (configurable via
  `ADMIN_IDLE_TIMEOUT_SEC`), customer 20 min, tech indefinite by default
  (long shifts).

## File uploads

Photo and document uploads validate by **magic bytes**, not just MIME or
extension. Max size enforced per upload class (e.g. 8 MB for 5S exception
photos, 25 MB for documents). Optional ClamAV integration via `CLAMD_*`
env vars; when `CLAMD_FAIL_CLOSED=true` an unreachable scanner blocks the
upload.

## Delegation system

A super_admin can delegate access in three granularities:

- **Record** — a single record (one customer, one invoice, …).
- **Record-type** — all records of a type (e.g. all invoices).
- **Power** — a broad capability (e.g. "approve payslips").

Delegations carry a `permission_level` (read / write) and are checked by
`_require_record_access`. **Revoking a delegation cascades** — any
delegations the grantee in turn issued from it are revoked too.

⚠️ Only the **four detail/edit endpoint pairs** (customers, visits,
invoices, technicians) currently honor delegation. Equipment, 5S, parts,
payroll, payslip, review, and visit-list endpoints retain the legacy
super_admin gate. See [`FIXMES.md`](FIXMES.md).

## Threat model

**We protect against:**

- Stolen DB file at rest (field-level encryption).
- Insider misuse (least-privilege roles, append-only audit chain).
- Session theft via XSS (HttpOnly cookies; SPAs do not read tokens).
- CSRF (SameSite=strict cookies; `CSRF_ALLOWED_HOSTS` allowlist).
- Tampered restore (boot-manifest chain anchor).
- Malicious uploads (magic-byte check + optional ClamAV).

**We do NOT protect against:**

- Full host compromise (root on the app server reads keys from env).
- Compromise of `FIELD_ENCRYPTION_KEY` (no envelope/HSM tier yet).
- Side-channels on deterministic ciphertext (the AES-SIV registry is
  intentionally minimized to lookup-critical fields only).
- Coordinated multi-admin collusion within their granted scope.
