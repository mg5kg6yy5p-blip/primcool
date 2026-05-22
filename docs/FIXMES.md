# PrimeCool — Known FIXMEs

FIXMEs are tracked here, **NOT in source**. New FIXMEs should be filed
here and linked from the relevant code with a comment like
`# FIXME(docs/FIXMES.md#section): brief note`.

Severity legend: **Security** (auth/PII/audit gap) · **Functional**
(missing feature / placeholder) · **Cosmetic** (label/UX nit).

## Open

| File:Line                  | Severity   | Note |
|----------------------------|------------|------|
| `main.py:124`              | Functional | `# FIXME unblocks` marker on the import block that pulls in the callback / 5S-exception-photo retrofits. Remove once the dependent modules ship. |
| `main.py:4937`             | Security   | Delegation-aware `_require_record_access` is only wired into the 4 detail/edit endpoint pairs (customers, visits, invoices, technicians). Equipment, 5S, parts, payroll, payslip, review, and visit-list endpoints still use the legacy super_admin gate. |
| `main.py:5078`             | Functional | TODO(mfa_required): no dedicated `mfa_required` column on `customers`; commercial accounts are enforced via the portal-login flow instead. Add a column if pre-enforcement is needed. |
| `main.py:5319`             | Functional | FIXME(role-rename): legacy tech role enum (`tech` / `lead_tech` / `apprentice`) is surfaced as the spec labels (level_1/2/3/lead) in the UI; a one-shot migration is pending HR sign-off. |
| `main.py:5475`             | Functional | FIXME(kpi-module): KPI ingest is not active; the endpoint returns `{available: false}` until the KPI module is deployed. |
| `main.py:6072`             | Cosmetic   | Inline comment "8 MB per the FIXME spec" referencing the 5S exception-photo size cap — superseded once the upload spec is finalized. |
| `database.py:2111`         | Functional | FIXME(callback-schema): `maintenance_visits` has no `callback_of_visit_id` column; visit-detail surfaces a placeholder callback block. Add the column + backfill before promising the feature in product comms. |
| `database.py:7116`         | Functional | `callbacks_only` filter on the tech job-history endpoint is accepted but is a no-op until the callback column ships. |
| `database.py:7136, 7196`   | Functional | Tech visit-list output hard-codes `callback_of_visit_id = None` for the same reason as above. |
| `database.py:7435`         | Functional | FIXME(certs-module): `get_technician_certifications` returns `{available: false}` if the `certifications` table is missing. Define the schema (name, issuing body, expiry) and wire it when the certs module ships. |
| `database.py:7486`         | Functional | `set_visit_callback_link` is an unblock shim added for Visit Detail § 9; revisit once the callback schema lands. |
| `database.py:7547`         | Functional | 5S exception-photo helpers were added as an unblock for `tech.html`'s queue; consolidate with the main photo helpers once the 5S module is GA. |
| `database.py:7659`         | Functional | Parts catalog search swallows `OperationalError` when the `parts` table is absent — inventory module not installed. Remove the swallow once the module is required. |

## Pre-Launch Locks (do NOT change until the pre-launch cleanup)

These are deliberate dev-only values that the operator has frozen until
the formal pre-launch credential rotation. They MUST hold across every
re-seed, every fresh DB init, every demo refresh. Changing any of them
silently breaks operator muscle memory and the in-flight test harness.

| Lock | Value | Where enforced |
|---|---|---|
| All admin passwords | `PrimeCool!Dev2026` | `scripts/seed_full_demo.py` (admin seed loop) |
| All tech PINs | `123456` | `scripts/seed_full_demo.py` (tech seed loop) |
| Customer PIN formula | `1000 + customer.id` (4 digits) | `scripts/seed_full_demo.py` (customer seed loop) |
| Bootstrap super_admin | `director` / `PrimeCool!Dev2026` | `.env.example` defaults + first-boot bootstrap in `main.py` |

**Pre-launch cleanup checklist (the unlock point for the rows above):**

1. Rotate `JWT_SECRET`, `FIELD_ENCRYPTION_KEY`, `PHOTO_URL_SECRET` to
   fresh prod values; document the rotation procedure for
   `FIELD_ENCRYPTION_KEY` (which cannot rotate without re-encrypting
   every row — see Phase 2 of the security hardening plan).
2. Force every admin and tech to set a strong password/PIN on first
   prod login (one-shot flag column). Drop the seeded defaults.
3. Resolve `GAP-PIN-STRENGTH` — customer PINs at 4 digits give only
   10⁴ entropy. Decide: raise to 6-digit, OR require MFA for
   commercial customers, OR enforce a per-customer PIN-set-by-user
   step at first portal login.
4. Wipe the dev `submissions.db` and re-seed ONLY real prospect data;
   delete the seeded demo customers + visits + invoices.
5. Tighten CORS `allow_origins` from `*` to the production domain
   (GAP-CORS) and audit the X-Forwarded-For trust scope (PC-003).
6. Confirm GPG is installed on the production host and the encrypted
   backup script (`scripts/backup.sh`) runs end-to-end before the
   first real customer record is written.

Until all six are checked, the dev locks above stay in place.

## Conventions

- Sort by severity (Security → Functional → Cosmetic) within a section.
- When a FIXME is resolved, **move it to `## Resolved`** below with the
  commit SHA that closed it, and remove the source-code comment.

## Resolved

_(none yet)_
