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

1. **[scaffolded]** Rotate `JWT_SECRET`, `FIELD_ENCRYPTION_KEY`,
   `PHOTO_URL_SECRET` to fresh prod values. Use
   `python3 scripts/rotate_secrets.py > .env.prod` to generate
   never-before-used values, then load into the prod secret store.
   **Operator step**: do this BEFORE the first real customer record
   is written, because `FIELD_ENCRYPTION_KEY` can't rotate after
   data exists without a re-encrypt migration (Phase 2 hardening).
2. **[backend done; UI hook pending]** Force every admin and tech
   to set a strong password/PIN on first prod login. Schema:
   `admin_users.must_change_credentials` + `technicians.must_change_credentials`
   (additive ALTER, default 0). `bootstrap_super_admin` sets the
   flag = 1 on the seeded super_admin; `set_admin_password` /
   `set_tech_pin` clear it. Login responses surface
   `must_change_credentials: bool` so the UI can intercept and route
   the user into the change-credential flow before letting them
   reach any other surface. UI side: admin.html + portal.html +
   tech.html need a one-time redirect to a "set new password / PIN"
   modal when the field is true (follow-up).
3. Resolve `GAP-PIN-STRENGTH` — customer PINs at 4 digits give only
   10⁴ entropy. **Needs operator decision**, options:
   * (a) raise customer PIN to 6 digits (10⁶, ~100x stronger; UI
     prompt change only)
   * (b) require MFA for commercial customers (already done — the
     MFA enrol flow at first commercial login is live)
   * (c) per-customer PIN-set-by-user at first portal login (the
     formula `1000 + customer.id` for seeded data goes away; the
     admin generates a one-shot setup token, customer sets their
     own PIN on first login)
   Recommendation: (b) is shipped; for residential PINs adopt (c)
   so no customer keeps a derivable default.
4. **[scripted]** Wipe the dev `submissions.db` and re-seed only
   real prospect data. Use
   `python3 scripts/wipe_and_reseed_prod.py --apply`
   (dry-run by default; refuses to apply without a recent backup).
   Preserves admin/tech logins but flags every active row with
   `must_change_credentials = 1`. Preserves the 7-year financial
   `audit_log` rows; deletes operational ones.
5. **[done]** Tighten CORS `allow_origins` from `*` to the
   production domain (GAP-CORS) and audit the X-Forwarded-For trust
   scope (PC-003). Both shipped:
   * CORS: commit `21db926` — `PROD_MODE=true` + `CORS_ALLOW_ORIGINS`
     env. Fails closed if the env is unset in prod.
   * XFF: commit `465cb2d` + test_pc003_xff_trust.py (5/5 pass).
6. **[mechanic verified; ops install pending]** Confirm GPG is
   installed on the production host and `scripts/backup.sh` runs
   end-to-end. `scripts/backup_restore_drill.sh` verified the
   snapshot/tar/restore mechanic locally (14 tables, all counts
   match, integrity_check OK). Production host still needs GPG
   installed + a recipient key whose private half lives off-host,
   and a `REMOTE_TARGET` (S3 / rclone) for off-site copies. Both
   are operator-side setup, not code.

Until all six are checked, the dev locks above stay in place.

## Conventions

- Sort by severity (Security → Functional → Cosmetic) within a section.
- When a FIXME is resolved, **move it to `## Resolved`** below with the
  commit SHA that closed it, and remove the source-code comment.

## Resolved

_(none yet)_
