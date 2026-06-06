# IT Management Module — Build Scope

**Planned start:** 2026-08-01 (after operations software is complete)
**Filed:** 2026-05-28 during security-audit review

## Why this module exists
The May 2026 security audit surfaced gaps that are better solved by a dedicated IT-management surface than by ad-hoc fixes:
- Techs sign in with PIN only (no MFA) — credential-stuffing risk if PRIDs are enumerable.
- Forgot-password / forgot-PIN endpoints have no rate limit (audit finding #1).
- Admin reset-password rule is weaker than the portal rule (8 chars vs 12 + complexity).
- No per-account lockout independent of source IP — distributed credential stuffing uncapped.
- No session-management UI (list active sessions, force-logout).
- No security dashboard (failed logins, locked accounts, MFA coverage %).

## Already built (will plug into the IT module)
- 8-role `ADMIN_PERMS` dict with granular permissions
- Tamper-evident `audit_log` table with chain_hash
- Argon2id password + PIN hashing
- JWT HS256 cookies for sessions
- MFA enrolment + verify flow for admins
- Field-level AES encryption (`_PII_RAND` / `_PII_DET`)
- Rate-limit helpers (`_enforce_login_rate`, `_enforce_rate`) — partially wired
- Forgot-password / forgot-PIN endpoints
- PrimeCool Org chart with `supervisor_id` chain

## Scope for the IT module

### Authentication hardening
- [x] Tech MFA enrolment (currently PIN-only) — DONE: `/api/tech/mfa/setup|activate|status`, `/api/tech/login/mfa`, forced-enrolment gate in `tech_login`, backup codes.
- [x] Per-account lockout after N failed attempts (not just per-IP) — DONE (2026-06-06): `login_failed_count`/`login_locked_until` on `admin_users` + `technicians`; 5 failures → 30-min lock (`PIN_LOCKOUT_THRESHOLD`/`PIN_LOCKOUT_MINUTES`); wired into `/api/admin/login`, `/api/tech/login`, `/api/staff/login`; raises a high-severity `account_lockout` security alert.
- [x] Rate limit `/api/admin/forgot-password`, `/api/portal/forgot-pin`, `/api/tech/forgot-pin` — DONE (2026-06-06): `_enforce_forgot_rate` — 5/hr per identity + 20/hr per IP, generic 429 (no enumeration leak).
- [x] Tighten admin reset-password rule to match portal (12 chars + complexity + denylist) — DONE (2026-06-06): all admin password-set paths now call `_validate_password_strength` (reset-password, create-user, promote-tech, reset-user-password).
- [ ] Strip auth-token echo from admin login JSON body (cookie is enough)

### Session management
- [ ] Surface active sessions per user (device, IP, last-seen)
- [ ] Force-logout button (single session + all sessions)
- [ ] "Remember this device for 30 days" trust + revocation list

### Account directory hygiene
- [ ] API key / service-account directory for any future integrations
- [ ] Verify `get_all_admin_users()` strips `password_hash`, `mfa_secret`, `mfa_backup_codes_hashed` (audit #12)
- [ ] Confirm no f-string SQL helpers (`database.py` 9579, 9606, 9575, 4462) ever receive request-supplied table/column names (audit #8)

### Security operations dashboard
- [ ] Failed login counter (24h / 7d windows)
- [ ] Locked accounts list
- [ ] MFA coverage % across admins + techs
- [ ] Recent password / PIN resets
- [ ] Recent `timesheet.reopened_by_tech_edit` events
- [ ] Recent `payroll.period_delete` events
- [ ] Audit-chain verification status

### Identity provider integration (SSO)
- [ ] Google Workspace OIDC for admin portal — "Sign in with Google" on /staff
- [ ] Email-to-admin_user mapping table (claim-based lookup)
- [ ] Fallback to PRID + password when IdP unreachable
- [ ] Keep tech / parts-runner / warehouse on PRID + PIN (offline-friendly, no email)
- [ ] Centralized offboarding: disable Google account → revoke all PrimeCool sessions

### Mobile device management (MDM)
- [ ] Pick MDM vendor (Google Workspace built-in vs Hexnode vs Intune)
- [ ] Enrol company-owned phones at provisioning time
- [ ] Force-install PrimeCool PWA + Maps + WhatsApp on enrolment
- [ ] Mandatory device passcode + auto-lock
- [ ] Remote wipe + "retire device" tied to the Terminate flow
- [ ] Location visibility for dispatch (with disclosed-to-staff policy)
- [ ] Sandboxed work container for BYOD scenarios (selective wipe)
- [ ] OS / security-patch enforcement schedule

### Policy + lifecycle
- [ ] Periodic credential rotation reminders
- [ ] Offboarding checklist tied to the existing Terminate flow (covers SSO + MDM + PrimeCool account)
- [ ] Documented incident-response runbook

## Pre-production data (tracked alongside the IT module)
- [x] Payslip employer TRN / NIS Employer # were hardcoded placeholders (`main.py` `_PC_COMPANY`) — DONE (2026-06-06): now read from env (`PC_COMPANY_TRN`, `PC_COMPANY_NIS_ER`, `PC_COMPANY_NAME`, `PC_COMPANY_ADDRESS`, `PC_COMPANY_PHONE`). Unset → payslip prints the sentinel `— not set —` (never a fake number) + a boot warning. **Operator still needs to supply the real TAJ values in the deploy env before the first live payroll run.**

## Items deliberately deferred (low ROI for current scale)
- Phishing-resistant MFA (hardware keys) — TOTP is sufficient for now
- Org-chart PRID redaction — discussed and dropped; MFA covers the stuffing risk for admins, and small-company operational value of seeing PRIDs outweighs the marginal exposure
- CSP / outbound-email sanitization on `/api/consult` — defense-in-depth, not exploitable today

## Build sequence (proposed)
1. Rate-limit the three forgot-* endpoints (1 day) — closes the most practical attack path.
2. Per-account lockout (2 days).
3. Tech MFA enrolment (1 week).
4. Session-management UI (1 week).
5. Security dashboard tile (1 week).
6. Service-account directory + rotation reminders (as needed).
