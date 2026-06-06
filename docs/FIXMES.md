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
| `main.py` `FIXME(docs/FIXMES.md): role-rename migration` | Cosmetic | **Operator decision 2026-06-06: do NOT rename.** The legacy tech role enum (`tech` / `lead_tech` / `apprentice`) stays as the storage values; the UI continues to surface spec labels via the existing translation layer (admin.html label maps). No DB migration will be run — keeping the enum stable avoids any risk to KPI tier lookups and to warehouse staff who incidentally carry `role='tech'`. Retained here only as a pointer to the translation layer, not as pending work. |
| `main.py` `FIXME(docs/FIXMES.md): tighten response_model` | Cosmetic | Admin customer/visit/invoice/technician/delegation detail routes still use `Dict[str, Any]` as a transitional response_model shape. Tighten incrementally; not blocking. |
| `database.py` `fs_exception_photos` chain-hash helpers | Cosmetic | 5S exception-photo helpers (`record_fs_exception_photo`, `list_fs_exception_photos`) live separately from the main `visit_photos` helpers. The 5S module is GA; a refactor could consolidate them behind a single PII-aware photo abstraction. Not behavior-affecting. |
| `must_enrol_mfa` flag now vestigial at runtime | Cosmetic | The login gate hard-requires MFA for every account regardless of the flag (`commit 2e8ead0`). The column + `bootstrap_super_admin` setter remain as explicit ops-tracking signal. Future cleanup may drop the column if no admin tooling reads it. |
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

2. **[DONE]** Force every admin and tech to
   set a strong password/PIN on first prod login. Schema:
   `admin_users.must_change_credentials` + `technicians.must_change_credentials`
   (additive ALTER, default 0). `bootstrap_super_admin` sets the
   flag = 1 on the seeded super_admin; `set_admin_password` /
   `set_tech_pin` clear it. Login responses surface
   `must_change_credentials: bool` (incl. the MFA-verify responses
   `/api/admin/mfa/verify` + `/api/tech/login/mfa`, since MFA is the
   path that actually lands the session).
   **UI status**: the unified `/staff` portal now intercepts
   `must_change_credentials` after the session is established
   (`_postSession` → `step-change-cred`) and forces a new-password
   (admin → `/api/admin/me/password`) or new-PIN
   (tech → new `/api/tech/me/pin`) before any dashboard is reachable.
   The current credential is re-submitted automatically from
   `pending.secret`, so the user only types the new value twice.
   `/api/tech/me/pin` mirrors `admin_change_own_password`: requires
   the current PIN (re-auth), validates via `_validate_pin_or_400`,
   calls `set_tech_pin` (clears the flag), and revokes other live
   sessions via `revoke_tech_sessions_except`. Customer portal
   already prompts customers post-login (see #3c).

3. **[Track A + Track B]** Resolve `GAP-PIN-STRENGTH`.
   - ✅ **(a) PIN min 10 digits** — Track A enforced via
     `_validate_pin_or_400` on every PIN-set surface (admin reset,
     tech reset, portal reset, create-tech).
   - ✅ **(b) MFA hard-required for every customer** — Track B
     (`commit 2e8ead0`) flipped the gate from commercial-only to
     ALL customers + every admin + every tech.
   - ✅ **(c) Per-customer PIN-set-by-user at first login** — DONE.
     Added `customers.must_set_pin` flag (additive ALTER, default 0;
     `create_customer` honours it, `set_customer_pin` clears it,
     `wipe_and_reseed_prod.py` sets it on every active customer).
     `/api/portal/login` + `/api/portal/login/mfa` surface
     `must_set_pin` (PIN-auth accounts only); the portal forces a
     set-your-own-PIN step (`enterSetPinMode` → `/api/portal/set-pin`)
     before unlocking, so the seeded `1000 + customer.id` formula can
     never reach a real customer.

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
| 2026-06-06 | **A5 in-app notification centre** — a shared, per-recipient notification feed for every authenticated subject (admin / tech / customer). New `notifications` table + 10 helpers in `database.py` (`create_notification` with kind/severity coercion + optional dedupe-window, `list_notifications`, `count_unread_notifications`, `mark_notification_read` (owner-scoped), `mark_all_notifications_read`). Four identity-gated endpoints in `main.py` behind the new `_require_viewer(request)` (resolves the subject from any of the three session cookies, 401 if none — gated on identity, never a feature permission, per "features for all"): `GET /api/notifications` (+`?unread=1`,`?limit=`), `GET /api/notifications/unread-count`, `POST /api/notifications/{id}/read`, `POST /api/notifications/read-all`. Server scopes every read/write by `(recipient_type, recipient_id)` so there is no cross-subject leak on the shared route — verified live with minted admin/tech/customer sessions (tech sees only tech rows, customer only customer rows, 404 on a non-owned id). Shared bell widget added to `static/pc_shared.js` (auto-mounts on all six SPAs when signed in; floats top-right or into a `[data-pc-notif-bell]` host; 60s unread poll that pauses while the tab is hidden; dropdown list, per-row mark-read + link follow, mark-all-read; brand-palette styling). Three real producers wired (best-effort, never block the underlying flow): invoice send → customer; PTO approve/deny → technician; delegation regrant-request → active super_admins. JS syntax-checked; `?v=` cache-buster bumped on all six SPAs; all test rows + minted sessions cleaned up (DB left pristine, `notifications` seq back to 0). Web-push transport now also shipped (see the next row) — the in-app feed remains the authoritative source of truth and push is a best-effort convenience layer on top. | (A-to-C build) |
| 2026-06-06 | **A5 web-push transport (PWA notifications)** — opt-in browser push layered on top of the in-app feed, built to **avoid any PyPI dependency**: a self-contained `webpush.py` implements RFC 8291 (aes128gcm payload encryption, single-record per RFC 8188) + RFC 8292 (VAPID ES256 JWT) using only the already-vendored `cryptography` lib (no `pywebpush`/`py_vapid`). `webpush.selftest()` validates the encryption against the **RFC 8291 Appendix A worked example** (CEK, nonce, exact byte-for-byte body, and an independent decrypt round-trip) — all four checks pass. New `push_subscriptions` table (UNIQUE(endpoint)) + 6 helpers in `database.py` (`upsert_push_subscription`, `list_push_subscriptions`, `delete_push_subscription`, `mark_push_subscription_failure` (drops after 5 strikes), `mark_push_subscription_sent`). Three identity-gated endpoints in `main.py`: `GET /api/push/vapid-public-key` (returns `{key, configured, enabled}`, no auth), `POST /api/push/subscribe`, `POST /api/push/unsubscribe` (both `_require_viewer`). `_notify(...)` writes the authoritative in-app row first, then calls `_push_fanout(...)` best-effort; fan-out injects an **audience-correct icon** into the payload (`/icons/tech-192.png` for tech, `/icons/customer-192.png` for customer/admin — real PWA assets that resolve 200), and `sw.js` (`push` + `notificationclick` handlers) uses `data.icon` with a real fallback. Client helpers in `pc_shared.js` (`PC.enablePush`/`disablePush`, VAPID-key fetch, `/sw.js` registration, subscribe POST) plus a push toggle in the bell panel footer that hides itself when unsupported or unconfigured. **The single outbound vendor-push POST is the only external call and is gated behind `WEBPUSH_ENABLED` (default off)** — so local dev never makes it; the in-app row still lands and push is silently skipped. VAPID keys live in `.dev.env` (`VAPID_PUBLIC_KEY`/`VAPID_PRIVATE_KEY`/`VAPID_SUBJECT`). Verified live: vapid-public-key endpoint returns `configured:true, enabled:false`; unauthenticated subscribe → 401; authenticated subscribe/unsubscribe round-trip OK; missing keys → 400; `_notify` with push disabled creates the in-app row and skips push without raising. All test rows + minted sessions cleaned up (DB left pristine; `notifications` + `push_subscriptions` seq absent). | (A-to-C build) |
| 2026-06-06 | **Delegation retrofit across remaining super_admin-gated endpoints** — closes the "delegation retrofit gap". Every admin endpoint whose path names a delegatable record now flows through `_require_record_access(request, record_type, record_id, write=…)`: invoice send/cancel/payment/PATCH (write) + payments read; customer visit-history; visit photos + invoice-payment; and the full technician sub-resource set (jobs, 5S, reviews, certifications, payroll-summary, KPI-threshold, 5S-override, review create/edit). Collection / global endpoints with no record to scope (`/invoices/metrics`, `/invoices/list`, `/invoices/export.csv`, `/parts/search`, `/fx-rates` GET+POST+history, `/invoices/v2`) flow through the new `_require_admin_or_power(request)` guard — opened only by the `super_admin` role or a blanket **power** delegation, so a non-delegated non-super admin is denied exactly as `_require_super_admin` denied them (no widening). Two meta-governance surfaces stay hard `super_admin` on purpose — the access-denied audit reader (`/audit/access-denied`) and the delegation regrant-request approve/deny queue — so a power-delegate can't self-approve delegation governance. Verified in-process against the live guards (14/14 checks): super_admin reaches all three classes; non-delegated supervisor denied on collection+record; power grant opens collection + record (read **and** write) but not governance, and revoke re-closes; a `record_type(technician,read)` grant opens the technician record (read) but denies write (insufficient level) and denies the collection endpoint. All test delegation rows + minted sessions cleaned up (DB left pristine). | (A-to-C build) |

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
| 2026-06-06 | **Payment idempotency parity in `record_invoice_payment_v2`** — v2 (chain-hashed/FX path) now honours the client `idempotency_key` as the primary dedup (DB unique-index race caught + resolved), with the 30s heuristic kept only for keyless callers. `/payments/v2` endpoint + the v2 admin modal (`_paySubmit`) now send a per-click UUID. | (A-to-C build) |
| 2026-06-06 | **Identifier collision on unified `/staff` login** — application-layer guard added ahead of the β unified-`staff`-table migration. `staff_identifier_conflict(identifier, space=…)` reciprocal check is wired into `create_tech` (custom `tech_code`) and `create_admin_user` (custom username), raising `ValueError` mapped to 409/400 at the endpoints. `staff_login` surfaces any *pre-existing* collision as a `staff_identifier_collision` security alert (de-duped via `recent_alert_exists`, 30-min window) so ops can rename one account; login still proceeds admin-first. PRIDs were already globally unique via `generate_prid`. | (A-to-C build) |
| 2026-06-06 | **Per-asset checklist editor — safety-key validation** — `set_asset_checklist_override` now normalizes keys server-side (lowercase + spaces→underscore) and **rejects typo'd safety keys**: `fs_safety_near_miss()` flags any key within edit-distance 2 of a `FS_SAFETY_ITEM_KEYS` entry (e.g. `fluid_checked`→`fluids_checked`), which would otherwise silently downgrade a failed audit from `safety_loto` to `normal`. The GET checklist endpoint now returns a `safety_critical` flag per item plus the full known-keys `catalog` (`fs_item_catalog()`), and the warehouse editor UI badges safety/LOTO items, warns on the in-use safety set, and offers a click-to-insert key picker. Genuinely-new custom (non-safety) keys are still allowed. | (A-to-C build) |
| 2026-06-06 | **`correlate_5s_to_kpi` misleading diagnostic** — the no-KPI-band branch said "kpi module not active" even though the KPI module ships (phases 5–7). Now reads "no KPI band yet for this window — using 5S band only". No callers matched the old literal. | (A-to-C build) |
| 2026-06-06 | **Technician MFA lockout recovery documented** — added runbook §5.3.1 covering the full lockout case (lost authenticator + all backup codes spent): admin reset via `POST /api/admin/technicians/{id}/mfa/reset` (`tech:reset_pin`), what it clears + the `must_enrol_mfa=1` re-enrol gate, the `tech.mfa.reset_by_admin` audit trail, out-of-band verification, and the admin self-lockout DB fallback. | (A-to-C build) |
| 2026-06-06 | **KPI add-on modal entry points wired** — the Phase 5–7 add-on modals (coaching log, recognition, team-period note, score annotation, goals & PIPs, HR PIP queue, manual KPI entry, custom KPI) had backend + modal UI but several had **no button to open them**. Added: dashboard top-bar buttons (Team Note, Goals & PIPs, PIP Approvals, Manual Entry, + Custom KPI) revealed in `kpiInitPanel` per the same `can()`-gated pattern as Recompute/Thresholds; a per-tech action bar (Coaching Log / + Recognition / Goals & PIPs) in `kpiRenderScorecard`; and an **Annotate** button on flag cards (`kpiOpenScoreAnnotation(score_id, tech_id)`). Each button is gated by the exact permission its endpoint enforces, so a viewer never sees a 403 button. Period-scoped buttons read `#kpiPeriodSelect` directly (inline handlers can't see the `let kpiCurrentPeriod` binding). | (A-to-C build) |
| 2026-06-06 | **Portal invoice → service-visit cross-reference** — two stale FIXMEs in `portal_dashboard.html` claimed `/api/portal/invoices` lacked `visit_id`; it has carried it all along (`get_all_invoices` selects `i.*`, and the column + full write path via `create_invoice`/`update_invoice`/`InvoiceCreate.visit_id` + the admin "New Invoice (pre-filled from visit)" flow are live). Wired the read side: the overview invoice cards now render a **Service visit: <date>** link line and the My-Account invoices table gained a **Visit** column, both via `PC.gateLinkHtml('visit', …)` → `openVisitDetail()`. The link only renders when the backing visit is present in the customer's loaded history (so `openVisitDetail` can resolve it) and visit read-access is permitted; otherwise it shows an em-dash / is omitted — no dead links. End-to-end verified by temporarily linking invoice 30→visit 132 (cust 11): payload returned `visit_id`, visit was resolvable, then restored. | (A-to-C build) |
| 2026-06-06 | **Portal overview summary tiles clickable** — the four overview cards (Next/Last PM, Next/Last CM) were static. Each populated card now opens its backing visit's detail modal via `PC.gateRow('visit', …)` → `openVisitDetail()`, gated by visit read-access; interactive attributes are reset on each render so an emptied slot doesn't keep a stale clickable state. | (A-to-C build) |
| 2026-06-06 | **Invoice GCT 100× over-charge on the v2 create/patch path** — `admin_invoice_create_v2` + `PATCH /api/admin/invoices/{id}` validate `tax_rate` as a **percent** (0–100, default `DEFAULT_GCT_RATE_PCT=15.0`) but stored it verbatim into the `invoices.tax_rate` column, which `_recompute_invoice_totals` treats as a **fraction** (`tax_amount = subtotal * tax_rate`). A 15%-GCT invoice for J$100 net therefore persisted `tax_amount=1500.00 / total=1600.00` (the v2 edit UI's own preview showed the correct J$15, so the discrepancy was silent until PDF/AR/remittance read the stored value). Never manifested in prod because all 559 seed invoices carry `tax_rate=0`. Canonical convention is **fraction** (env `INVOICE_TAX_RATE=0.15`, the v1 `InvoiceCreate` default, the v1 display `tax_rate*100`, and `_recompute`); only the v2 layer used percent. Fix converts percent→fraction at the v2 server boundary (create + patch) and fraction→percent when loading the v2 edit form, so the round-trip is lossless and the column stays a fraction. Verified end-to-end: a 15% J$100 invoice now stores `tax_amount=15.00 / total=115.00`. | (A-to-C build) |
| 2026-06-06 | **GCT output-tax liability surfaced (A2)** — GCT collected on sales is a TAJ liability, not revenue, but nothing rolled it up. Added `get_gct_liability_report(from,to)` (accrual basis by issue date, **gross output tax only** — input-tax credits are not tracked, so this is not a net GCT-payable figure; excludes draft/cancelled; grouped by month × billing currency via `COALESCE(display_currency, currency, 'JMD')`), the `GET /api/admin/invoices/gct-report` endpoint (`_require_admin_or_power`, audited), a `gct_output_this_month` field on `/invoices/metrics`, a **GCT Collected (Output Tax)** metric tile, and a **GCT Report** modal (date-range, per-period + totals-by-currency table) gated to super_admin / power-delegate to match the endpoint. Labelling on tile + modal + server all state accrual / gross-output-only / excludes input tax. | (A-to-C build) |

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
