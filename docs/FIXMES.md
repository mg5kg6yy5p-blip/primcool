# PrimeCool — Known FIXMEs

FIXMEs are tracked here, **NOT in source**. New FIXMEs should be filed
here and linked from the relevant code with a comment like
`# FIXME(docs/FIXMES.md#section): brief note`.

Severity legend: **Security** (auth/PII/audit gap) · **Functional**
(missing feature / placeholder) · **Cosmetic** (label/UX nit).

Line numbers below are best-effort at time of writing — grep the FIXME
marker text in source if the line has drifted.

## Open

| Source marker                                    | Severity   | Note |
|--------------------------------------------------|------------|------|
| `main.py` `FIXME(docs/FIXMES.md): delegation retrofit gap` | Security | Delegation-aware `_require_record_access` is only wired into the 4 detail/edit endpoint pairs (customers, visits, invoices, technicians). Equipment, 5S, parts, payroll, payslip, review, and visit-list endpoints still use the legacy `super_admin` gate. Delegated supervisors are over-restricted on those surfaces. |
| `main.py` `FIXME(docs/FIXMES.md): role-rename migration` | Functional | Legacy tech role enum (`tech` / `lead_tech` / `apprentice`) is surfaced as the spec labels (level_1/2/3/lead) in the UI; a one-shot DB migration is pending HR sign-off. |
| `main.py` `FIXME(docs/FIXMES.md): tighten response_model` | Cosmetic | Admin customer/visit/invoice/technician/delegation detail routes still use `Dict[str, Any]` as a transitional response_model shape. Tighten incrementally; not blocking. |
| `database.py` `correlate_5s_to_kpi` "kpi module not active" diagnostic | Cosmetic | Returned diagnostic string says "kpi module not active" when a tech has no KPI band data — misleading since the KPI module *is* shipped (phases 5–7). Function works correctly; just update the string to "no KPI band yet for this window". |
| `database.py` `fs_exception_photos` chain-hash helpers | Cosmetic | 5S exception-photo helpers (`record_fs_exception_photo`, `list_fs_exception_photos`) live separately from the main `visit_photos` helpers. The 5S module is GA; a refactor could consolidate them behind a single PII-aware photo abstraction. Not behavior-affecting. |
| Tech `mfa_disable` requires PIN + TOTP/backup | Security | A tech who's lost their authenticator AND used all 10 backup codes is locked out and must use the admin reset endpoint (`/api/admin/technicians/{id}/mfa/reset`). Document the recovery path in operator runbook. |
| `must_enrol_mfa` flag now vestigial at runtime | Cosmetic | The login gate hard-requires MFA for every account regardless of the flag (`commit 2e8ead0`). The column + `bootstrap_super_admin` setter remain as explicit ops-tracking signal. Future cleanup may drop the column if no admin tooling reads it. |
| `record_invoice_payment_v2` 30-second exact-match dedup | Functional | Uses heuristic dedup (same invoice/amount/date/method/recorded_by within 30s) instead of the explicit `idempotency_key` shipped on `record_invoice_payment` (`commit 2edf36f`). Add `idempotency_key` to v2 for parity. |
| Identifier collision on unified `/staff` login | Functional | `/api/staff/login` tries the admin identity space first, then tech. If an admin username equals a tech `tech_code` (e.g. someone names an admin "T01"), the admin path wins and the tech is shadowed. The β migration's unified `staff` table + a single `staff_code` UNIQUE constraint will catch this at the schema level. |
| Per-asset checklist editor — no safety-key validation | Functional | The warehouse manager can add any `item_key` to a checklist override. Keys that should be safety-critical (matching `FS_SAFETY_ITEM_KEYS`) don't get the photo-required flow unless they collide with a known key by spelling. Add a known-keys allowlist editor surface or validation. |
| Receive flow allows "(no location)" fallback | Functional | The Pass C Receive modal exposes a "(no location)" option that triggers the legacy GRN path (no chain-hashed `part_movement`). Useful during transition; should be removed once warehouse staff are trained on the location-aware flow. |

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

2. **[backend done; partial UI hook]** Force every admin and tech to
   set a strong password/PIN on first prod login. Schema:
   `admin_users.must_change_credentials` + `technicians.must_change_credentials`
   (additive ALTER, default 0). `bootstrap_super_admin` sets the
   flag = 1 on the seeded super_admin; `set_admin_password` /
   `set_tech_pin` clear it. Login responses surface
   `must_change_credentials: bool`.
   **UI status**: the unified `/staff` portal (`commit 4597bd5`) now
   handles MFA enrolment as the forced first step. The PIN/password
   change flow on first login is NOT yet wired into `/staff`
   (staff_portal.html doesn't intercept `must_change_credentials`
   yet). Customer portal already prompts customers post-login.
   Follow-up: extend `/staff` JS to redirect into a "set new
   password / PIN" modal when `must_change_credentials` is true.

3. **[Track A + Track B]** Resolve `GAP-PIN-STRENGTH`.
   - ✅ **(a) PIN min 10 digits** — Track A enforced via
     `_validate_pin_or_400` on every PIN-set surface (admin reset,
     tech reset, portal reset, create-tech).
   - ✅ **(b) MFA hard-required for every customer** — Track B
     (`commit 2e8ead0`) flipped the gate from commercial-only to
     ALL customers + every admin + every tech.
   - 🟡 **(c) Per-customer PIN-set-by-user at first login** — still
     desirable so the seeded `1000 + customer.id` formula never
     reaches a real customer. Admin generates a one-shot setup
     token; customer sets their PIN on first portal touch.
     Follow-up: add `customers.must_set_pin` flag + intercept in
     `/api/portal/login`.

4. **[scripted]** Wipe the dev `submissions.db` and re-seed only
   real prospect data. Use
   `python3 scripts/wipe_and_reseed_prod.py --apply`
   (dry-run by default; refuses to apply without a recent backup).
   Preserves admin/tech logins but flags every active row with
   `must_change_credentials = 1` AND `must_enrol_mfa = 1`.
   Preserves the 7-year financial `audit_log` rows; deletes
   operational ones.

5. **[done]** Tighten CORS `allow_origins` from `*` to the
   production domain (GAP-CORS) and audit the X-Forwarded-For trust
   scope (PC-003). Both shipped:
   - CORS: `commit 21db926` — `PROD_MODE=true` + `CORS_ALLOW_ORIGINS`
     env. Fails closed if the env is unset in prod.
   - XFF: `commit 465cb2d` + `test_pc003_xff_trust.py` (5/5 pass).

6. **[mechanic verified; ops install pending]** Confirm GPG is
   installed on the production host and `scripts/backup.sh` runs
   end-to-end. `scripts/backup_restore_drill.sh` verified the
   snapshot/tar/restore mechanic locally (14 tables, all counts
   match, integrity_check OK). Production host still needs:
   - GPG installed + a recipient key whose private half lives
     off-host
   - `REMOTE_TARGET` (S3 / rclone) configured for off-site copies
   Both are operator-side setup, not code.

Until all six are checked, the dev locks above stay in place.

## Conventions

- Sort by severity (Security → Functional → Cosmetic) within a section.
- When a FIXME is resolved, **move it to `## Resolved`** below with the
  commit SHA that closed it, and remove the source-code comment.

## Resolved

### Pre-launch / security hardening

| Resolved | Item | Commit |
|---|---|---|
| 2026-05-23 | **MFA hard-required for every account** — admin / tech / customer. Login intercepts every account without `mfa_enabled` and routes through enrolment before issuing a session. Removed the stale `TODO(mfa_required)` on the customer-type endpoint. | `2e8ead0` |
| 2026-05-23 | **Unified staff portal** at `/staff`. Single welcome ("Welcome to PrimeCool — where you are everything") + façade login that tries admin then tech, returns `kind` + `redirect_to` + MFA state in one shape. Legacy `/admin` and `/tech` redirect to `/staff` when there's no session. | `4597bd5` |
| 2026-05-23 | **PIN strength + phone-as-PIN check** (Track A). Minimum 10 digits enforced everywhere PINs are set. Phone-as-PIN attempt raises a security alert + 422 rejection. | (Track A commits) |
| 2026-05-23 | **CORS** — `allow_origins=["*"]` replaced with `PROD_MODE`-gated allow-list. Fails closed when env is unset in prod. | `21db926` |
| 2026-05-23 | **X-Forwarded-For trust** — proxy chain trust scope audited; `_client_ip` returns actual client host and ignores forged XFF. 5/5 tests pass. | `465cb2d` |
| 2026-05-23 | **Forced-reset flag** schema (`must_change_credentials`) on admin + tech, set on bootstrap + cleared on password/PIN change. | (forced-reset commits) |
| 2026-05-23 | **rotate_secrets.py + wipe_and_reseed_prod.py** scaffolded for pre-launch operator runbook. | (rotation commits) |

### Data-integrity bugs caught + fixed

| Resolved | Item | Commit |
|---|---|---|
| 2026-05-23 | **`canceled` vs `cancelled` AR aging leak** — aging report excluded only the UK spelling; 4 historical rows with US-spelling `'canceled'` (≈ $150k) were inflating outstanding totals. Both filter + `init_db` normalization shipped. | `869181e` |
| 2026-05-23 | **Clock-event race condition** — `record_clock_in` / `record_clock_out` now wrap in `BEGIN IMMEDIATE` with SELECT-then-INSERT idempotency. 20 concurrent threads → 1 row inserted. | `4c67a0c` |
| 2026-05-23 | **5S cycle scoping** — audit gate scoped to the current clock cycle (not "today UTC") AND cycle threshold preserved across midnight UTC. Closes the "2nd sign-in doesn't re-prompt 5S" report. | `4b46545` + `5d34e10` |
| 2026-05-23 | **5S `sustain` CHECK constraint** — `fs_audit_items.section` lacked `'sustain'` in its CHECK; submissions containing sustain items 500'd. Forward-compat migration in `init_db` rebuilds the table with the new constraint. | (Sustain commit) |
| 2026-05-23 | **MFA-enrol redirect loop** for commercial customers — `portal_dashboard.html` bootstrap now detects enrol-token mode and serves the enrolment panel instead of bouncing to `/portal`. | `9c983c4` |
| 2026-05-23 | **Bare `sqlite3.connect("submissions.db")`** in 2 main.py paths replaced with `database._con()` so they inherit WAL / synchronous=FULL / foreign_keys=ON. | `1024555` |
| 2026-05-23 | **`email_hash` leaking** from `/api/tech/me/profile` response. | `9cf5aa8` |
| 2026-05-23 | **Invoice metrics ambiguity** — `outstanding` / `overdue` keys conflated sum-vs-count. Explicit `outstanding_count` + `outstanding_amount_jmd` fields added; legacy aliases preserved. | `adf59f5` |
| 2026-05-23 | **Test fixture isolation** — cookie-jar pollution between `admin_token` and `supervisor_token` caused 3 acceptance tests to fail. Each token fixture now spins up its own ephemeral TestClient. Suite: 4 failing → 0 failing. | `869181e` |
| 2026-05-23 | **Payment idempotency key** — UUID-per-click on Record Payment; UNIQUE INDEX on `(invoice_id, idempotency_key)` blocks duplicates. | `2edf36f` |

### Module placeholders → real modules

| Resolved | Item | Commit |
|---|---|---|
| 2026-05-23 | **Callback schema** — `maintenance_visits.callback_of_visit_id` column added; `callbacks_only` filter on visit-list is functional; `set_visit_callback_link` is now the live helper (not a shim). | (callback module commits) |
| 2026-05-23 | **Tech certifications module** — `tech_certifications` table + helpers + endpoints shipped in TP-1b. The legacy `get_technician_certifications` placeholder migrated to query the real table. | (TP-1b + this commit) |
| 2026-05-23 | **Parts catalog OperationalError swallow** — `parts` table is now populated (130 rows); the swallow is now defensive dead-code (kept for graceful degradation if the inventory module is ever optional in a future deployment, but no longer a missing-module marker). | (inventory module shipped earlier) |
| 2026-05-23 | **8 MB FIXME spec comment** for 5S exception photos — removed when the 5S upload spec was finalized. | (5S photo commits) |
| 2026-05-23 | **`# FIXME unblocks` import block marker** — removed when the dependent modules shipped. | (import-cleanup commits) |

### Tech portal remodel (TP-1 through TP-4)

| Resolved | Item | Commit |
|---|---|---|
| 2026-05-23 | **TP-1a + TP-1b**: schema (7 tables + ~22 helpers) + endpoints + EOD cron | `ffa1933`, `e96d52d` |
| 2026-05-23 | **TP-2**: 2-tab tech landing (Sign In for Work / My Profile) + company message board | `43a92d2` |
| 2026-05-23 | **TP-4**: My Profile (7 cards: identity / schedule / pay / KPI / certs / CV with Request-Edit flow / account) + admin UI for company messages + schedule + CV approvals | `e1f4300`, `7adb9bb` |
| 2026-05-23 | **5S 5th category (Sustain) restored** in default checklist + iteration loop + UI labels | `bbdc39c` |
| 2026-05-23 | **On-call provisions** — `on_call` on `tech_schedules` + per-date `tech_on_call_overrides`; sign-in skips day-off reason + alarm for on-call; EOD cron skips on-call techs; 2h OT grace surfaces live countdown to the landing. | `bbdc39c` |

### Warehouse module (W1 → W2 → Pass A → Pass B → Pass C)

| Resolved | Item | Commit |
|---|---|---|
| 2026-05-23 | **W1: additive β** — `staff_type` + `department` on `technicians`; `list_staff()` helper; `get_all_techs()` filtered to `staff_type='tech'` so warehouse rows don't bleed into legacy tech UIs. | `794f6ab` |
| 2026-05-23 | **W2: warehouse staff endpoints + role permissions** — `/api/admin/staff`, `/api/admin/warehouse/staff`, `/warehouse` anchor, per-staff-type asset auto-provisioning in `create_tech` (truck for runners, PPE locker for floor + manager). | `b3cea2f` |
| 2026-05-23 | **Pass A: warehouse admin tab** — 3 sub-tabs (Staff / Checklists / Month-end sheets) inside admin.html with full backend wiring. | `a9c671d` |
| 2026-05-23 | **Pass B: `part_movements` schema + chain hash + admin endpoints** for inventory movement tracking. | (Pass B commit) |
| 2026-05-23 | **Pass C: receiving queue** — open POs → mark received → chain-hashed inbound movement with destination location → live stock-by-location grid. | `89ac74c` |
