import hashlib
import json as _json
import os
import secrets
import sqlite3
import threading
from datetime import datetime, timezone, timedelta

# Audit chain serialization — single-process write lock so concurrent
# coroutines can't race the prev-hash read against the insert.
_audit_lock = threading.Lock()

try:
    from argon2 import PasswordHasher
    from argon2.exceptions import VerifyMismatchError, InvalidHashError
    _argon2 = PasswordHasher()
    _ARGON2_AVAILABLE = True
except ImportError:
    _argon2 = None
    _ARGON2_AVAILABLE = False

DB_PATH = "submissions.db"


def _legacy_hash_pbkdf2(secret: str, salt: str, iterations: int = 50_000) -> str:
    """Legacy pbkdf2 format used before Argon2 migration. Kept for backward
    verification only — new hashes always use Argon2.

    Historically PINs used 50k iterations and admin passwords used 100k.
    The hash format doesn't encode the iteration count, so verification
    needs to try both (see _verify_pin)."""
    digest = hashlib.pbkdf2_hmac("sha256", secret.encode(), salt.encode(), iterations).hex()
    return f"{salt}${digest}"


def _hash_pin(pin: str) -> str:
    """Hashes a PIN/password with Argon2id (falls back to pbkdf2 if argon2 is
    unavailable — should never happen in prod since it's in requirements.txt)."""
    if _ARGON2_AVAILABLE:
        return _argon2.hash(pin)
    # Fallback path — should be unreachable
    salt = secrets.token_hex(8)
    return _legacy_hash_pbkdf2(pin, salt)


def _verify_pin(pin: str, stored: str) -> bool:
    """Accepts both Argon2 ($argon2…) and legacy pbkdf2 (salt$hash) formats."""
    if not stored:
        return False
    if stored.startswith("$argon2") and _ARGON2_AVAILABLE:
        try:
            _argon2.verify(stored, pin)
            return True
        except (VerifyMismatchError, InvalidHashError):
            return False
    # Legacy pbkdf2 format — try both historical iteration counts (50k for PINs, 100k for admin passwords)
    if "$" in stored:
        salt, _ = stored.split("$", 1)
        for iters in (50_000, 100_000):
            if secrets.compare_digest(_legacy_hash_pbkdf2(pin, salt, iters), stored):
                return True
    return False


def _needs_rehash(stored: str) -> bool:
    """Returns True if the stored hash should be upgraded to current Argon2 params."""
    if not _ARGON2_AVAILABLE:
        return False
    if not stored or not stored.startswith("$argon2"):
        return True   # legacy pbkdf2 → upgrade
    try:
        return _argon2.check_needs_rehash(stored)
    except Exception:
        return True


def _initials_from_name(name: str) -> str:
    # Strip anything that isn't a letter so initials are always clean
    parts = [''.join(c for c in p if c.isalpha()) for p in name.strip().split()]
    parts = [p for p in parts if p]
    if len(parts) >= 2:
        return (parts[0][0] + parts[-1][0]).upper()
    if len(parts) == 1 and parts[0]:
        return (parts[0][0] * 2).upper()
    return "XX"


def generate_prid(name: str, hire_date: str = None) -> str:
    """PRID format: PC{initials}{DDMMYY} — letters & digits only, no separators.

    hire_date: ISO YYYY-MM-DD, or None (defaults to today UTC).
    Collisions get a letter suffix (A, B, C, ...).
    """
    if hire_date:
        try:
            d = datetime.fromisoformat(hire_date).date()
        except ValueError:
            d = datetime.now(timezone.utc).date()
    else:
        d = datetime.now(timezone.utc).date()
    date_part = d.strftime("%d%m%y")
    initials  = _initials_from_name(name)
    base      = f"PC{initials}{date_part}"

    con = _con()
    candidates = [base] + [f"{base}{chr(c)}" for c in range(ord('A'), ord('Z') + 1)]
    chosen = None
    for cand in candidates:
        exists = con.execute(
            "SELECT 1 FROM admin_users WHERE prid = ? UNION ALL "
            "SELECT 1 FROM technicians WHERE prid = ? LIMIT 1",
            (cand, cand),
        ).fetchone()
        if not exists:
            chosen = cand
            break
    con.close()
    if not chosen:
        # 27+ collisions on the same initials + date is implausible at this scale,
        # but raise rather than overwrite if it ever happens.
        raise RuntimeError("PRID collision space exhausted for this initial+date combo")
    return chosen


# ── Field-level encryption (Phase 2) ─────────────────────────────────────────
# Columns that hold PII or secrets get encrypted at the application layer so a
# logical DB breach (stolen file, leaked backup, SQL injection) yields
# ciphertext. Names + financial totals are intentionally NOT encrypted (see
# Phase 2 inventory in the report) — they're needed for sort/SUM operations
# and disk-FDE is the at-rest mitigation for those.
from crypto import encrypt as _enc, decrypt as _dec, \
                   det_encrypt as _det_enc, det_decrypt as _det_dec, \
                   email_hash as _email_hash

# Map: table → list of column names that get randomized AES-GCM encryption.
_PII_RAND = {
    "customers":            ["phone", "address", "notes", "mfa_secret",
                              "contact_person_phone"],
    "technicians":          ["phone"],
    "admin_users":          ["phone", "mfa_secret"],
    "equipment":            ["serial_number", "location", "notes"],
    "maintenance_visits":   ["work_done", "notes", "parts_replaced",
                              "hazards", "access_codes",
                              "contact_person_phone"],
    "visit_signatures":     ["signature_b64"],
    "payslips":             ["notes"],
    # Photo metadata: free-text catch-all + the full UA are encrypted at rest.
    # Numeric geo / camera fields stay readable so we can render maps later
    # without bulk-decryption. server_ip is short and useful for plain joins.
    "visit_photos":         ["server_ua", "client_meta_json"],
    # 5S workplace-discipline module
    "fs_assets":            ["notes"],
    "fs_audits":            ["client_meta_json"],
    "fs_audit_items":       ["note"],
    "fs_exceptions":        ["description", "resolution_note"],
    "fs_exception_events":  ["note"],
    "fs_exception_photos":  ["client_meta_json"],
    "fs_coaching_log":      ["plan_text", "close_note"],
    # Technician Detail View (Phase: super_admin profile editor)
    "technician_reviews":       ["summary", "action_items"],
    "technician_kpi_overrides": ["reason"],
    "technician_5s_overrides":  ["reason"],
    # PrimeCool Invoicing Module — sensitive free-text on payments/fx + invoice cancellation rationale.
    "invoice_payments":         ["notes"],
    "fx_rates":                 ["notes"],
    "invoices":                 ["canceled_reason"],
    # Delegation module — free-text justification and review notes.
    "delegations":                  ["grantor_notes", "revoke_reason"],
    "delegation_regrant_requests":  ["review_notes"],
    # Employee KPI Tracking Module — free-text on coaching/override/resolution.
    "kpi_flags":                    ["reason", "override_reason", "resolution_notes"],
    # KPI Notes module (phase 5) — all free-text bodies encrypted.
    "kpi_notes":                    ["body"],
    # KPI Goals + PIPs (phase 6) — encrypted title/description/action items/outcome.
    "kpi_goals":                    ["title", "description", "action_items_json", "outcome_summary"],
    "kpi_goal_checkins":            ["notes"],
}
# Columns that need equality lookup → deterministic encryption + blind index.
_PII_DET = {
    "customers":            ["email"],
    "technicians":          ["email"],
    "admin_users":          ["email"],
}


def _enc_dict(table: str, data: dict) -> dict:
    """Returns a copy of data with sensitive fields encrypted. Adds matching
    *_email_hash for any deterministic email column. Caller's dict is left
    untouched so the original plaintext stays available if needed for audit."""
    out = dict(data)
    for col in _PII_RAND.get(table, []):
        if col in out and out[col] is not None:
            out[col] = _enc(out[col])
    for col in _PII_DET.get(table, []):
        if col in out and out[col] is not None:
            plain = out[col]
            out[col] = _det_enc(plain)
            out[col + "_hash"] = _email_hash(plain)
    return out


def _dec_row(table: str, row) -> dict:
    """Decrypts encrypted columns in a row dict before returning to callers."""
    if row is None:
        return None
    d = dict(row)
    for col in _PII_RAND.get(table, []):
        if col in d and d[col] is not None:
            try: d[col] = _dec(d[col])
            except Exception: pass   # pre-migration plaintext or already plain
    for col in _PII_DET.get(table, []):
        if col in d and d[col] is not None:
            try: d[col] = _det_dec(d[col])
            except Exception: pass
    return d


def _dec_rows(table: str, rows):
    return [_dec_row(table, r) for r in rows]


def _con():
    """Open a SQLite connection with the pre-deploy hardening pragmas.

    - journal_mode=WAL: writer + many concurrent readers, crash-safe page
      writes. Persistent in the DB header; setting it on every connection
      is a no-op after the first. Closes C1 (mid-write corruption risk).
    - synchronous=FULL: fsync after every commit — slower but the audit
      chain + chain_hash invariants demand it; partial writes during crash
      would break the chain. Pre-fix this was NORMAL.
    - foreign_keys=ON: per-connection setting that must be re-applied on
      every connect. Closes O1 (orphan rows possible despite FK
      declarations).
    """
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    # Pragmas. WAL is sticky in the DB header, the other two are
    # per-connection. We apply all three on every open so a freshly-created
    # DB also picks up WAL on its first real connection.
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("PRAGMA synchronous=FULL")
    con.execute("PRAGMA foreign_keys=ON")
    return con


def init_db():
    con = sqlite3.connect(DB_PATH)
    con.execute("""
        CREATE TABLE IF NOT EXISTS submissions (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            fname      TEXT NOT NULL,
            lname      TEXT NOT NULL,
            email      TEXT NOT NULL,
            phone      TEXT,
            company    TEXT,
            tier       TEXT NOT NULL,
            msg        TEXT,
            created_at TEXT NOT NULL
        )
    """)
    con.execute("""
        CREATE TABLE IF NOT EXISTS customers (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            customer_code TEXT NOT NULL UNIQUE,
            name          TEXT NOT NULL,
            company       TEXT,
            email         TEXT,
            phone         TEXT,
            address       TEXT,
            notes         TEXT,
            pin_hash      TEXT,
            created_at    TEXT NOT NULL
        )
    """)
    # Idempotent column addition for existing customer DBs
    cust_cols = {row[1] for row in con.execute("PRAGMA table_info(customers)")}
    for col, sql in (
        ("pin_hash",       "ALTER TABLE customers ADD COLUMN pin_hash TEXT"),
        # Client-portal hardening (per portal spec):
        #   auth_mode: 'pin' (residential default) | 'password' (commercial)
        #   password_hash: Argon2-hashed when auth_mode='password'
        #   customer_type: 'residential' | 'commercial' — drives mandatory MFA
        #   MFA TOTP secret/backup codes (same pattern as admin MFA)
        ("auth_mode",      "ALTER TABLE customers ADD COLUMN auth_mode TEXT NOT NULL DEFAULT 'pin'"),
        ("password_hash",  "ALTER TABLE customers ADD COLUMN password_hash TEXT"),
        ("customer_type",  "ALTER TABLE customers ADD COLUMN customer_type TEXT NOT NULL DEFAULT 'residential'"),
        ("mfa_secret",     "ALTER TABLE customers ADD COLUMN mfa_secret TEXT"),
        ("mfa_enabled",    "ALTER TABLE customers ADD COLUMN mfa_enabled INTEGER NOT NULL DEFAULT 0"),
        ("backup_codes",   "ALTER TABLE customers ADD COLUMN backup_codes TEXT"),
        ("deletion_requested_at", "ALTER TABLE customers ADD COLUMN deletion_requested_at TEXT"),
        # Soft-close at contract end. active=0 keeps records (statutory
        # retention) but kills portal access. terminated_at records when.
        ("active",         "ALTER TABLE customers ADD COLUMN active INTEGER NOT NULL DEFAULT 1"),
        ("terminated_at",  "ALTER TABLE customers ADD COLUMN terminated_at TEXT"),
        ("last_login_at",  "ALTER TABLE customers ADD COLUMN last_login_at TEXT"),
        # Phase 2 — blind index for equality lookup on encrypted email.
        ("email_hash",     "ALTER TABLE customers ADD COLUMN email_hash TEXT"),
        # Phase 3 — per-account lockout tracking for PIN auth.
        ("pin_failed_count", "ALTER TABLE customers ADD COLUMN pin_failed_count INTEGER NOT NULL DEFAULT 0"),
        ("pin_locked_until", "ALTER TABLE customers ADD COLUMN pin_locked_until TEXT"),
        # Multi-hub readiness (Tier-1 from the strategy reframe).
        # All current rows default to hub_id=1 (Kingston). Adding the column
        # now is ~free; retrofitting it at multi-hub launch would touch
        # every aggregate query and report. We're buying the option.
        ("hub_id",         "ALTER TABLE customers ADD COLUMN hub_id INTEGER NOT NULL DEFAULT 1"),
        # Optimistic concurrency token for If-Match. Backfilled from created_at
        # for existing rows below.
        ("updated_at",     "ALTER TABLE customers ADD COLUMN updated_at TEXT"),
    ):
        if col not in cust_cols:
            try: con.execute(sql)
            except sqlite3.OperationalError: pass
    # Backfill updated_at = created_at for any customer rows that never had it.
    try:
        con.execute("UPDATE customers SET updated_at = created_at "
                    "WHERE updated_at IS NULL OR updated_at = ''")
    except sqlite3.OperationalError:
        pass

    # Hubs table — single source of truth for branch/region. Seeded with one
    # row (Kingston) so existing FKs from hub_id=1 are valid from boot.
    con.execute("""
        CREATE TABLE IF NOT EXISTS hubs (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            name        TEXT NOT NULL UNIQUE,
            code        TEXT NOT NULL UNIQUE,
            address     TEXT,
            active      INTEGER NOT NULL DEFAULT 1,
            created_at  TEXT NOT NULL
        )
    """)
    con.execute(
        "INSERT OR IGNORE INTO hubs (id, name, code, address, active, created_at) "
        "VALUES (1, 'Kingston', 'KIN', 'Kingston, Jamaica', 1, ?)",
        (datetime.now(timezone.utc).isoformat(),),
    )

    con.execute("""
        CREATE TABLE IF NOT EXISTS customer_pin_resets (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            customer_id INTEGER NOT NULL REFERENCES customers(id),
            token       TEXT NOT NULL UNIQUE,
            expires_at  TEXT NOT NULL,
            used_at     TEXT,
            created_at  TEXT NOT NULL
        )
    """)
    con.execute("""
        CREATE TABLE IF NOT EXISTS equipment (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            customer_id   INTEGER NOT NULL REFERENCES customers(id),
            name          TEXT NOT NULL,
            type          TEXT,
            model         TEXT,
            serial_number TEXT,
            location      TEXT,
            notes         TEXT,
            created_at    TEXT NOT NULL
        )
    """)
    con.execute("""
        CREATE TABLE IF NOT EXISTS technicians (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            tech_code   TEXT NOT NULL UNIQUE,
            pin_hash    TEXT NOT NULL,
            name        TEXT NOT NULL,
            phone       TEXT,
            email       TEXT,
            role        TEXT NOT NULL DEFAULT 'tech',
            prid        TEXT UNIQUE,
            hire_date   TEXT,
            hourly_rate REAL NOT NULL DEFAULT 0,
            active      INTEGER NOT NULL DEFAULT 1,
            employment_status TEXT NOT NULL DEFAULT 'active'
                CHECK (employment_status IN ('active','on_leave','terminated')),
            created_at  TEXT NOT NULL
        )
    """)
    con.execute("""
        CREATE TABLE IF NOT EXISTS visit_parts (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            visit_id    INTEGER NOT NULL REFERENCES maintenance_visits(id),
            part_id     INTEGER NOT NULL REFERENCES parts(id),
            quantity    REAL NOT NULL,
            unit_price  REAL NOT NULL DEFAULT 0,
            notes       TEXT,
            added_by_tech_id INTEGER REFERENCES technicians(id),
            created_at  TEXT NOT NULL
        )
    """)
    con.execute("CREATE INDEX IF NOT EXISTS idx_visit_parts_visit ON visit_parts(visit_id)")
    # Idempotent column additions for existing tech DBs
    tech_cols = {row[1] for row in con.execute("PRAGMA table_info(technicians)")}
    for name, sql in (
        ("role",        "ALTER TABLE technicians ADD COLUMN role TEXT NOT NULL DEFAULT 'tech'"),
        ("prid",        "ALTER TABLE technicians ADD COLUMN prid TEXT"),
        ("hire_date",   "ALTER TABLE technicians ADD COLUMN hire_date TEXT"),
        ("hourly_rate", "ALTER TABLE technicians ADD COLUMN hourly_rate REAL NOT NULL DEFAULT 0"),
        # Supervisor relationship — manager's admin_user.id, NULL if reports
        # directly to director. Drives team-scoped audit visibility.
        ("supervisor_id", "ALTER TABLE technicians ADD COLUMN supervisor_id INTEGER"),
        # Access-lifecycle tracking. terminated_at is the hard-off switch;
        # last_login_at drives dormant-account detection.
        ("terminated_at", "ALTER TABLE technicians ADD COLUMN terminated_at TEXT"),
        ("last_login_at", "ALTER TABLE technicians ADD COLUMN last_login_at TEXT"),
        ("email_hash",    "ALTER TABLE technicians ADD COLUMN email_hash TEXT"),
        # Multi-hub: every tech belongs to a primary hub.
        ("hub_id",        "ALTER TABLE technicians ADD COLUMN hub_id INTEGER NOT NULL DEFAULT 1"),
        # Tri-state employment lifecycle.  active/terminated_at remain in
        # sync (active=0 ⇔ employment_status='terminated'); on_leave keeps
        # active=1 so the technician retains login if they return. SQLite
        # doesn't enforce CHECK on ALTER ADD, so validation lives at the
        # endpoint/helper layer for existing DBs. New DBs get the CHECK in
        # the CREATE block.
        ("employment_status", "ALTER TABLE technicians ADD COLUMN employment_status TEXT NOT NULL DEFAULT 'active'"),
    ):
        if name not in tech_cols:
            try: con.execute(sql)
            except sqlite3.OperationalError: pass

    # One-time backfill for existing rows that pre-date the column. Safe to
    # run on every boot — only touches rows that haven't been populated.
    try:
        con.execute(
            "UPDATE technicians SET employment_status = "
            "CASE WHEN active = 1 THEN 'active' "
            "     WHEN terminated_at IS NOT NULL THEN 'terminated' "
            "     ELSE 'active' END "
            "WHERE employment_status IS NULL OR employment_status = ''"
        )
    except sqlite3.OperationalError:
        pass

    con.execute("""
        CREATE TABLE IF NOT EXISTS admin_users (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            username      TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            name          TEXT NOT NULL,
            email         TEXT NOT NULL UNIQUE,
            phone         TEXT,
            role          TEXT NOT NULL,
            prid          TEXT UNIQUE,
            hire_date     TEXT,
            mfa_secret    TEXT,
            mfa_enabled   INTEGER NOT NULL DEFAULT 0,
            backup_codes  TEXT,
            active        INTEGER NOT NULL DEFAULT 1,
            created_by    INTEGER REFERENCES admin_users(id),
            created_at    TEXT NOT NULL
        )
    """)
    # Idempotent column additions for existing admin DBs
    admin_cols = {row[1] for row in con.execute("PRAGMA table_info(admin_users)")}
    for col, sql in (
        ("hire_date",     "ALTER TABLE admin_users ADD COLUMN hire_date TEXT"),
        ("mfa_secret",    "ALTER TABLE admin_users ADD COLUMN mfa_secret TEXT"),
        ("mfa_enabled",   "ALTER TABLE admin_users ADD COLUMN mfa_enabled INTEGER NOT NULL DEFAULT 0"),
        ("backup_codes",  "ALTER TABLE admin_users ADD COLUMN backup_codes TEXT"),
        ("supervisor_id", "ALTER TABLE admin_users ADD COLUMN supervisor_id INTEGER REFERENCES admin_users(id)"),
        ("terminated_at", "ALTER TABLE admin_users ADD COLUMN terminated_at TEXT"),
        ("last_login_at", "ALTER TABLE admin_users ADD COLUMN last_login_at TEXT"),
        ("email_hash",    "ALTER TABLE admin_users ADD COLUMN email_hash TEXT"),
    ):
        if col not in admin_cols:
            try: con.execute(sql)
            except sqlite3.OperationalError: pass

    con.execute("""
        CREATE TABLE IF NOT EXISTS admin_password_resets (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            admin_id    INTEGER NOT NULL REFERENCES admin_users(id),
            token       TEXT NOT NULL UNIQUE,
            expires_at  TEXT NOT NULL,
            used_at     TEXT,
            created_at  TEXT NOT NULL
        )
    """)

    con.execute("""
        CREATE TABLE IF NOT EXISTS parts (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            sku           TEXT NOT NULL UNIQUE,
            name          TEXT NOT NULL,
            description   TEXT,
            category      TEXT,
            unit          TEXT NOT NULL DEFAULT 'each',
            unit_cost     REAL NOT NULL DEFAULT 0,
            quantity      REAL NOT NULL DEFAULT 0,
            reorder_point REAL NOT NULL DEFAULT 0,
            supplier      TEXT,
            active        INTEGER NOT NULL DEFAULT 1,
            created_at    TEXT NOT NULL,
            updated_at    TEXT NOT NULL
        )
    """)
    con.execute("""
        CREATE TABLE IF NOT EXISTS part_movements (
            id                  INTEGER PRIMARY KEY AUTOINCREMENT,
            part_id             INTEGER NOT NULL REFERENCES parts(id),
            movement_type       TEXT NOT NULL,
            quantity_delta      REAL NOT NULL,
            reason              TEXT,
            visit_id            INTEGER REFERENCES maintenance_visits(id),
            performed_by_type   TEXT,
            performed_by_id     INTEGER,
            performed_by_prid   TEXT,
            performed_by_label  TEXT,
            created_at          TEXT NOT NULL
        )
    """)
    con.execute("CREATE INDEX IF NOT EXISTS idx_part_movements_part ON part_movements(part_id, created_at)")

    con.execute("""
        CREATE TABLE IF NOT EXISTS invoices (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            invoice_number  TEXT NOT NULL UNIQUE,
            customer_id     INTEGER NOT NULL REFERENCES customers(id),
            visit_id        INTEGER REFERENCES maintenance_visits(id),
            issue_date      TEXT NOT NULL,
            due_date        TEXT NOT NULL,
            status          TEXT NOT NULL DEFAULT 'draft',
            subtotal        REAL NOT NULL DEFAULT 0,
            tax_rate        REAL NOT NULL DEFAULT 0,
            tax_amount      REAL NOT NULL DEFAULT 0,
            total           REAL NOT NULL DEFAULT 0,
            amount_paid     REAL NOT NULL DEFAULT 0,
            currency        TEXT NOT NULL DEFAULT 'TTD',
            notes           TEXT,
            sent_at         TEXT,
            paid_at         TEXT,
            created_by      INTEGER REFERENCES admin_users(id),
            created_at      TEXT NOT NULL,
            updated_at      TEXT NOT NULL
        )
    """)
    con.execute("""
        CREATE TABLE IF NOT EXISTS invoice_line_items (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            invoice_id    INTEGER NOT NULL REFERENCES invoices(id) ON DELETE CASCADE,
            line_type     TEXT NOT NULL,
            part_id       INTEGER REFERENCES parts(id),
            description   TEXT NOT NULL,
            quantity      REAL NOT NULL DEFAULT 1,
            unit_price    REAL NOT NULL DEFAULT 0,
            line_total    REAL NOT NULL DEFAULT 0,
            sort_order    INTEGER NOT NULL DEFAULT 0
        )
    """)
    con.execute("""
        CREATE TABLE IF NOT EXISTS invoice_payments (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            invoice_id    INTEGER NOT NULL REFERENCES invoices(id),
            payment_date  TEXT NOT NULL,
            amount        REAL NOT NULL,
            method        TEXT,
            reference     TEXT,
            notes         TEXT,
            recorded_by   INTEGER REFERENCES admin_users(id),
            recorded_by_label TEXT,
            recorded_by_prid  TEXT,
            created_at    TEXT NOT NULL
        )
    """)
    con.execute("CREATE INDEX IF NOT EXISTS idx_invoices_customer ON invoices(customer_id, created_at)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_invoices_status   ON invoices(status, due_date)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_invoice_lines     ON invoice_line_items(invoice_id, sort_order)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_invoice_payments  ON invoice_payments(invoice_id, payment_date)")

    # ── PrimeCool Invoicing Module additions ───────────────────────────────
    # Idempotent column additions on the existing invoices header.
    inv_cols = {row[1] for row in con.execute("PRAGMA table_info(invoices)")}
    for col, sql in (
        ("fx_fee_pct",          "ALTER TABLE invoices ADD COLUMN fx_fee_pct REAL DEFAULT 2.0"),
        ("fx_rate_used",        "ALTER TABLE invoices ADD COLUMN fx_rate_used REAL"),
        ("fx_rate_source",      "ALTER TABLE invoices ADD COLUMN fx_rate_source TEXT"),
        ("fx_rate_fetched_at",  "ALTER TABLE invoices ADD COLUMN fx_rate_fetched_at TEXT"),
        ("display_currency",    "ALTER TABLE invoices ADD COLUMN display_currency TEXT DEFAULT 'JMD'"),
        ("canceled_at",         "ALTER TABLE invoices ADD COLUMN canceled_at TEXT"),
        ("canceled_by",         "ALTER TABLE invoices ADD COLUMN canceled_by INTEGER"),
        ("canceled_reason",     "ALTER TABLE invoices ADD COLUMN canceled_reason TEXT"),
        ("gct_amount",          "ALTER TABLE invoices ADD COLUMN gct_amount REAL DEFAULT 0"),
    ):
        if col not in inv_cols:
            try: con.execute(sql)
            except sqlite3.OperationalError: pass

    # Idempotent additions to invoice_line_items to support labor + part metadata.
    ili_cols = {row[1] for row in con.execute("PRAGMA table_info(invoice_line_items)")}
    for col, sql in (
        ("part_sku",     "ALTER TABLE invoice_line_items ADD COLUMN part_sku TEXT"),
        ("tech_id",      "ALTER TABLE invoice_line_items ADD COLUMN tech_id INTEGER"),
        ("hours",        "ALTER TABLE invoice_line_items ADD COLUMN hours REAL"),
        ("hourly_rate",  "ALTER TABLE invoice_line_items ADD COLUMN hourly_rate REAL"),
        ("created_at",   "ALTER TABLE invoice_line_items ADD COLUMN created_at TEXT"),
        ("updated_at",   "ALTER TABLE invoice_line_items ADD COLUMN updated_at TEXT"),
    ):
        if col not in ili_cols:
            try: con.execute(sql)
            except sqlite3.OperationalError: pass

    # Idempotent additions to invoice_payments (FX + chain-hash + append-only).
    ip_cols = {row[1] for row in con.execute("PRAGMA table_info(invoice_payments)")}
    for col, sql in (
        ("foreign_amount",       "ALTER TABLE invoice_payments ADD COLUMN foreign_amount REAL"),
        ("foreign_currency",     "ALTER TABLE invoice_payments ADD COLUMN foreign_currency TEXT"),
        ("fx_rate_used",         "ALTER TABLE invoice_payments ADD COLUMN fx_rate_used REAL"),
        ("fx_fee_pct_used",      "ALTER TABLE invoice_payments ADD COLUMN fx_fee_pct_used REAL"),
        ("effective_rate_used",  "ALTER TABLE invoice_payments ADD COLUMN effective_rate_used REAL"),
        ("hub_id",               "ALTER TABLE invoice_payments ADD COLUMN hub_id INTEGER NOT NULL DEFAULT 1"),
        ("prior_chain_hash",     "ALTER TABLE invoice_payments ADD COLUMN prior_chain_hash TEXT"),
        ("chain_hash",           "ALTER TABLE invoice_payments ADD COLUMN chain_hash TEXT"),
        ("voided_at",            "ALTER TABLE invoice_payments ADD COLUMN voided_at TEXT"),
    ):
        if col not in ip_cols:
            try: con.execute(sql)
            except sqlite3.OperationalError: pass

    # FX rates cache + manual-override history.
    con.execute("""
        CREATE TABLE IF NOT EXISTS fx_rates (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            from_currency   TEXT NOT NULL,
            to_currency     TEXT NOT NULL DEFAULT 'JMD',
            buy_rate        REAL NOT NULL,
            source          TEXT NOT NULL CHECK (source IN ('manual','api')),
            fetched_at      TEXT NOT NULL,
            effective_date  TEXT NOT NULL,
            entered_by      INTEGER,
            notes           TEXT,
            active          INTEGER NOT NULL DEFAULT 1
        )
    """)
    con.execute("CREATE INDEX IF NOT EXISTS idx_fx_rates_active ON fx_rates(from_currency, effective_date, active)")
    # Tamper-evidence: chain-hash columns on fx_rates (idempotent).
    fx_cols = {row[1] for row in con.execute("PRAGMA table_info(fx_rates)")}
    for col, sql in (
        ("prior_chain_hash", "ALTER TABLE fx_rates ADD COLUMN prior_chain_hash TEXT"),
        ("chain_hash",       "ALTER TABLE fx_rates ADD COLUMN chain_hash TEXT"),
    ):
        if col not in fx_cols:
            try: con.execute(sql)
            except sqlite3.OperationalError: pass

    con.execute("""
        CREATE TABLE IF NOT EXISTS documents (
            id                  INTEGER PRIMARY KEY AUTOINCREMENT,
            stored_filename     TEXT NOT NULL UNIQUE,
            original_filename   TEXT NOT NULL,
            mime_type           TEXT,
            size_bytes          INTEGER NOT NULL,
            sensitivity         TEXT NOT NULL,    -- 'public' | 'confidential' | 'highly_sensitive'
            document_type       TEXT NOT NULL,    -- 'id' | 'trn' | 'certificate' | 'contract' | ...
            title               TEXT NOT NULL,
            description         TEXT,
            linked_to_type      TEXT,             -- 'customer' | 'tech' | 'admin' | 'visit' | NULL
            linked_to_id        INTEGER,
            linked_to_label     TEXT,             -- snapshot for display when linked entity is deleted/renamed
            uploaded_by_type    TEXT NOT NULL,    -- 'admin' | 'tech'
            uploaded_by_id      INTEGER NOT NULL,
            uploaded_by_prid    TEXT,
            uploaded_by_label   TEXT,
            uploaded_at         TEXT NOT NULL,
            expiry_date         TEXT,             -- YYYY-MM-DD; nullable
            last_accessed_at    TEXT,
            deleted_at          TEXT
        )
    """)
    # Idempotent column addition for the expiry field (applies to certs, licenses, insurance, etc.)
    doc_cols = {row[1] for row in con.execute("PRAGMA table_info(documents)")}
    if "expiry_date" not in doc_cols:
        try: con.execute("ALTER TABLE documents ADD COLUMN expiry_date TEXT")
        except sqlite3.OperationalError: pass
    con.execute("CREATE INDEX IF NOT EXISTS idx_doc_linked  ON documents(linked_to_type, linked_to_id)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_doc_sensitivity ON documents(sensitivity)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_doc_uploaded ON documents(uploaded_at)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_doc_expiry   ON documents(expiry_date)")

    con.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            jti             TEXT NOT NULL UNIQUE,
            subject_type    TEXT NOT NULL,         -- 'admin' | 'tech' | 'customer'
            subject_id      INTEGER NOT NULL,
            ip_address      TEXT,
            user_agent      TEXT,
            created_at      TEXT NOT NULL,
            expires_at      TEXT NOT NULL,
            revoked_at      TEXT,
            last_seen_at    TEXT,
            mfa_verified_at TEXT
        )
    """)
    sess_cols = {row[1] for row in con.execute("PRAGMA table_info(sessions)")}
    if "mfa_verified_at" not in sess_cols:
        try: con.execute("ALTER TABLE sessions ADD COLUMN mfa_verified_at TEXT")
        except sqlite3.OperationalError: pass
    con.execute("CREATE INDEX IF NOT EXISTS idx_sessions_subject ON sessions(subject_type, subject_id)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_sessions_jti     ON sessions(jti)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at)")

    con.execute("""
        CREATE TABLE IF NOT EXISTS audit_log (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            actor_type   TEXT NOT NULL,
            actor_id     INTEGER,
            actor_prid   TEXT,
            actor_label  TEXT,
            actor_role   TEXT,
            action       TEXT NOT NULL,
            target_type  TEXT,
            target_id    INTEGER,
            target_label TEXT,
            before_value TEXT,
            after_value  TEXT,
            ip_address   TEXT,
            created_at   TEXT NOT NULL,
            chain_hash   TEXT
        )
    """)
    # Idempotent column add for existing audit DBs
    audit_cols = {row[1] for row in con.execute("PRAGMA table_info(audit_log)")}
    if "chain_hash" not in audit_cols:
        try: con.execute("ALTER TABLE audit_log ADD COLUMN chain_hash TEXT")
        except sqlite3.OperationalError: pass
    # retention_class: 'financial' (7yr) | 'operational' (24mo) | 'system' (kept).
    # Set at write time by log_audit based on action prefix.
    if "retention_class" not in audit_cols:
        try: con.execute("ALTER TABLE audit_log ADD COLUMN retention_class TEXT NOT NULL DEFAULT 'operational'")
        except sqlite3.OperationalError: pass
    con.execute("CREATE INDEX IF NOT EXISTS idx_audit_retention ON audit_log(retention_class, created_at)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_audit_actor   ON audit_log(actor_id, created_at)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_audit_action  ON audit_log(action, created_at)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_audit_target  ON audit_log(target_type, target_id)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log(created_at)")

    # Read-access trail — separate from audit_log so the hash chain stays
    # focused on mutations and security events. Reads are high-volume; this
    # table is append-only and purged on a rolling window.
    con.execute("""
        CREATE TABLE IF NOT EXISTS access_log (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            actor_type   TEXT,                 -- 'admin' | 'tech' | 'customer' | NULL when unauthenticated
            actor_id     INTEGER,
            actor_prid   TEXT,
            actor_label  TEXT,
            method       TEXT NOT NULL,
            path         TEXT NOT NULL,
            query        TEXT,
            status_code  INTEGER NOT NULL,
            ip_address   TEXT,
            user_agent   TEXT,
            created_at   TEXT NOT NULL
        )
    """)
    con.execute("CREATE INDEX IF NOT EXISTS idx_access_actor   ON access_log(actor_id, created_at)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_access_path    ON access_log(path, created_at)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_access_created ON access_log(created_at)")
    # Anomaly alerts raised by the detector that runs after each access_log
    # write. Append-only from the app's perspective; admins can mark
    # resolved/dismissed but not delete.
    con.execute("""
        CREATE TABLE IF NOT EXISTS security_alerts (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            kind         TEXT NOT NULL,             -- 'bulk_read'|'off_hours'|'permission_probe'
            severity     TEXT NOT NULL DEFAULT 'medium',
            actor_type   TEXT,
            actor_id     INTEGER,
            actor_prid   TEXT,
            actor_label  TEXT,
            summary      TEXT NOT NULL,
            details      TEXT,                       -- JSON blob with counts/window
            status       TEXT NOT NULL DEFAULT 'open',   -- 'open'|'resolved'|'dismissed'
            resolved_by  INTEGER,
            resolved_at  TEXT,
            resolution_note TEXT,
            created_at   TEXT NOT NULL
        )
    """)
    con.execute("CREATE INDEX IF NOT EXISTS idx_alerts_status  ON security_alerts(status, created_at)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_alerts_actor   ON security_alerts(actor_id, created_at)")
    con.execute("""
        CREATE TABLE IF NOT EXISTS tech_pin_resets (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            tech_id     INTEGER NOT NULL REFERENCES technicians(id),
            token       TEXT NOT NULL UNIQUE,
            expires_at  TEXT NOT NULL,
            used_at     TEXT,
            created_at  TEXT NOT NULL
        )
    """)
    con.execute("""
        CREATE TABLE IF NOT EXISTS visit_photos (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            visit_id      INTEGER NOT NULL REFERENCES maintenance_visits(id),
            category      TEXT NOT NULL,
            filename      TEXT NOT NULL,
            uploaded_by   INTEGER REFERENCES technicians(id),
            uploaded_at   TEXT NOT NULL
        )
    """)
    # Idempotent additions — chain-of-custody metadata. Two groups:
    #   server_*  → authoritative; stamped by the API on receipt.
    #   client_*  → captured in the PWA at shutter time; can be wrong/missing
    #                 if the user denied permission or the clock is off.
    # We keep both so a reviewer always knows which is which.
    photo_cols = {row[1] for row in con.execute("PRAGMA table_info(visit_photos)")}
    for col, sql in (
        # Authoritative — server-side stamps
        ("server_ip",          "ALTER TABLE visit_photos ADD COLUMN server_ip TEXT"),
        ("server_ua",          "ALTER TABLE visit_photos ADD COLUMN server_ua TEXT"),
        # Client-captured wall-clock at shutter (ISO 8601 with timezone)
        ("client_captured_at", "ALTER TABLE visit_photos ADD COLUMN client_captured_at TEXT"),
        # Geolocation (lat/lng/accuracy in meters; ISO captured_at). Kept
        # plaintext numeric for any future map overlay; if you later need
        # to encrypt, the column types don't have to change.
        ("geo_lat",            "ALTER TABLE visit_photos ADD COLUMN geo_lat REAL"),
        ("geo_lng",            "ALTER TABLE visit_photos ADD COLUMN geo_lng REAL"),
        ("geo_accuracy_m",     "ALTER TABLE visit_photos ADD COLUMN geo_accuracy_m REAL"),
        ("geo_captured_at",    "ALTER TABLE visit_photos ADD COLUMN geo_captured_at TEXT"),
        # Device — short identifiers; the full UA is in server_ua.
        ("device_platform",    "ALTER TABLE visit_photos ADD COLUMN device_platform TEXT"),
        ("device_model",       "ALTER TABLE visit_photos ADD COLUMN device_model TEXT"),
        ("device_screen",      "ALTER TABLE visit_photos ADD COLUMN device_screen TEXT"),
        # Camera (only meaningful when getUserMedia path is used)
        ("camera_facing",      "ALTER TABLE visit_photos ADD COLUMN camera_facing TEXT"),
        ("camera_width",       "ALTER TABLE visit_photos ADD COLUMN camera_width INTEGER"),
        ("camera_height",      "ALTER TABLE visit_photos ADD COLUMN camera_height INTEGER"),
        # Network + app context
        ("network_type",       "ALTER TABLE visit_photos ADD COLUMN network_type TEXT"),
        ("app_version",        "ALTER TABLE visit_photos ADD COLUMN app_version TEXT"),
        # Catch-all for anything we don't promote to a column — encrypted at
        # rest like other free-text PII fields. Kept compact (no images).
        ("client_meta_json",   "ALTER TABLE visit_photos ADD COLUMN client_meta_json TEXT"),
    ):
        if col not in photo_cols:
            try: con.execute(sql)
            except sqlite3.OperationalError: pass
    con.execute("""
        CREATE TABLE IF NOT EXISTS reviews (
            id                  INTEGER PRIMARY KEY AUTOINCREMENT,
            customer_id         INTEGER NOT NULL REFERENCES customers(id),
            visit_id            INTEGER REFERENCES maintenance_visits(id),
            review_type         TEXT NOT NULL,
            rating              INTEGER NOT NULL,
            text                TEXT NOT NULL,
            role                TEXT,
            tech_snapshot       TEXT,
            visit_type_snapshot TEXT,
            status              TEXT NOT NULL DEFAULT 'pending',
            created_at          TEXT NOT NULL,
            approved_at         TEXT
        )
    """)
    con.execute("""
        CREATE TABLE IF NOT EXISTS maintenance_visits (
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            customer_id      INTEGER NOT NULL REFERENCES customers(id),
            equipment_id     INTEGER REFERENCES equipment(id),
            visit_type       TEXT NOT NULL,
            status           TEXT NOT NULL DEFAULT 'scheduled',
            scheduled_date   TEXT,
            scheduled_time   TEXT,
            completed_date   TEXT,
            technician       TEXT,
            work_done        TEXT,
            parts_replaced   TEXT,
            notes            TEXT,
            assigned_tech_id INTEGER REFERENCES technicians(id),
            start_time       TEXT,
            end_time         TEXT,
            created_at       TEXT NOT NULL
        )
    """)

    # Idempotent column additions for existing DBs
    existing_cols = {row[1] for row in con.execute("PRAGMA table_info(maintenance_visits)")}
    for col_sql in (
        ("assigned_tech_id",       "ALTER TABLE maintenance_visits ADD COLUMN assigned_tech_id INTEGER REFERENCES technicians(id)"),
        ("start_time",             "ALTER TABLE maintenance_visits ADD COLUMN start_time TEXT"),
        ("end_time",               "ALTER TABLE maintenance_visits ADD COLUMN end_time TEXT"),
        ("scheduled_time",         "ALTER TABLE maintenance_visits ADD COLUMN scheduled_time TEXT"),
        # Phase 1 — submission lock
        ("submitted_at",           "ALTER TABLE maintenance_visits ADD COLUMN submitted_at TEXT"),
        # Phase 2 — execution context fields the tech needs in-field
        ("scope_of_work",          "ALTER TABLE maintenance_visits ADD COLUMN scope_of_work TEXT"),
        ("estimated_duration_min", "ALTER TABLE maintenance_visits ADD COLUMN estimated_duration_min INTEGER"),
        ("next_pm_due",            "ALTER TABLE maintenance_visits ADD COLUMN next_pm_due TEXT"),
        ("contact_person_name",    "ALTER TABLE maintenance_visits ADD COLUMN contact_person_name TEXT"),
        ("contact_person_phone",   "ALTER TABLE maintenance_visits ADD COLUMN contact_person_phone TEXT"),
        ("hazards",                "ALTER TABLE maintenance_visits ADD COLUMN hazards TEXT"),
        ("access_codes",           "ALTER TABLE maintenance_visits ADD COLUMN access_codes TEXT"),
        # Phase 3 — manager flag-for-review
        ("flagged_for_review",     "ALTER TABLE maintenance_visits ADD COLUMN flagged_for_review INTEGER NOT NULL DEFAULT 0"),
        ("review_note",            "ALTER TABLE maintenance_visits ADD COLUMN review_note TEXT"),
        # Client-facing summary of the work, distinct from the raw work_done
        # field which can contain internal jargon. Spec: portal serves summary.
        ("work_done_summary",      "ALTER TABLE maintenance_visits ADD COLUMN work_done_summary TEXT"),
        # Multi-hub: each visit belongs to a hub for dispatch + reporting scope.
        ("hub_id",                 "ALTER TABLE maintenance_visits ADD COLUMN hub_id INTEGER NOT NULL DEFAULT 1"),
        # Callback link — when a maintenance visit is opened because a prior
        # visit's work failed, this points at the originating visit. SQLite
        # ALTER doesn't enforce FKs, so the helper layer validates the target
        # exists. Unblocks Visit Detail § 9 (Callback History) + the tech
        # detail "callbacks-only" filter.
        ("callback_of_visit_id",   "ALTER TABLE maintenance_visits ADD COLUMN callback_of_visit_id INTEGER"),
    ):
        if col_sql[0] not in existing_cols:
            try: con.execute(col_sql[1])
            except sqlite3.OperationalError: pass

    # Parts: image + location for tech in-field visual confirmation
    part_cols = {row[1] for row in con.execute("PRAGMA table_info(parts)")}
    for c, sql in (
        ("image_filename", "ALTER TABLE parts ADD COLUMN image_filename TEXT"),
        ("location",       "ALTER TABLE parts ADD COLUMN location TEXT"),
        # Multi-hub: inventory is per-hub. Parts in Montego Bay's stockroom
        # are not Kingston's. Default 1 = Kingston for legacy rows.
        ("hub_id",         "ALTER TABLE parts ADD COLUMN hub_id INTEGER NOT NULL DEFAULT 1"),
    ):
        if c not in part_cols:
            try: con.execute(sql)
            except sqlite3.OperationalError: pass

    # Structured field readings per visit (multiple rows allowed for re-checks).
    # Free-text "work_done" stays; this captures the numbers the spec mandates.
    con.execute("""
        CREATE TABLE IF NOT EXISTS visit_readings (
            id                INTEGER PRIMARY KEY AUTOINCREMENT,
            visit_id          INTEGER NOT NULL REFERENCES maintenance_visits(id),
            pressure_high     REAL,
            pressure_low      REAL,
            temp_supply       REAL,
            temp_return       REAL,
            delta_t           REAL,
            superheat         REAL,
            subcool           REAL,
            approach_temp     REAL,
            notes             TEXT,
            recorded_by       INTEGER REFERENCES technicians(id),
            recorded_at       TEXT NOT NULL
        )
    """)
    con.execute("CREATE INDEX IF NOT EXISTS idx_readings_visit ON visit_readings(visit_id)")

    # Digital client signature — write-once. One row per visit, hash stored
    # so any future tamper is detectable.
    con.execute("""
        CREATE TABLE IF NOT EXISTS visit_signatures (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            visit_id        INTEGER NOT NULL UNIQUE REFERENCES maintenance_visits(id),
            signer_name     TEXT NOT NULL,
            signature_b64   TEXT NOT NULL,     -- PNG dataURL captured client-side
            signature_sha256 TEXT NOT NULL,
            captured_by     INTEGER REFERENCES technicians(id),
            captured_at     TEXT NOT NULL
        )
    """)

    # ── Payroll: pay periods + payslips ─────────────────────────────────
    # Separation of duties: hr_admin GENERATES payslips for a period (and
    # the rounded numbers come from timesheets that techs themselves
    # produced). super_admin (director) is the only role that can APPROVE
    # a period — the same person never both generates and approves.
    # Employees see only their own payslips via /api/(admin|tech)/me/payslips.
    con.execute("""
        CREATE TABLE IF NOT EXISTS pay_periods (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            period_start    TEXT NOT NULL,        -- ISO date inclusive
            period_end      TEXT NOT NULL,        -- ISO date inclusive
            label           TEXT NOT NULL,        -- 'May 2026', 'Wk 22 2026', etc
            status          TEXT NOT NULL DEFAULT 'draft',  -- draft|approved|paid|cancelled
            currency        TEXT NOT NULL DEFAULT 'JMD',
            created_by      INTEGER REFERENCES admin_users(id),
            created_at      TEXT NOT NULL,
            approved_by     INTEGER REFERENCES admin_users(id),
            approved_at     TEXT,
            paid_at         TEXT,
            UNIQUE(period_start, period_end)
        )
    """)
    con.execute("CREATE INDEX IF NOT EXISTS idx_payperiods_status ON pay_periods(status, period_end)")
    # Multi-hub: payroll runs per hub. Existing rows default to 1 (Kingston).
    pp_cols = {row[1] for row in con.execute("PRAGMA table_info(pay_periods)")}
    if "hub_id" not in pp_cols:
        try: con.execute("ALTER TABLE pay_periods ADD COLUMN hub_id INTEGER NOT NULL DEFAULT 1")
        except sqlite3.OperationalError: pass
    con.execute("""
        CREATE TABLE IF NOT EXISTS payslips (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            pay_period_id   INTEGER NOT NULL REFERENCES pay_periods(id),
            subject_type    TEXT NOT NULL,        -- 'admin' | 'tech'
            subject_id      INTEGER NOT NULL,
            subject_name    TEXT NOT NULL,        -- snapshot at generation time
            subject_prid    TEXT NOT NULL,
            -- Earnings
            hours_regular   REAL NOT NULL DEFAULT 0,
            hours_overtime  REAL NOT NULL DEFAULT 0,
            hourly_rate     REAL NOT NULL DEFAULT 0,
            overtime_rate   REAL NOT NULL DEFAULT 0,
            fixed_salary    REAL NOT NULL DEFAULT 0,
            bonus           REAL NOT NULL DEFAULT 0,
            gross_pay       REAL NOT NULL DEFAULT 0,
            -- Statutory deductions (computed)
            paye_tax        REAL NOT NULL DEFAULT 0,
            nis             REAL NOT NULL DEFAULT 0,
            nht             REAL NOT NULL DEFAULT 0,
            education_tax   REAL NOT NULL DEFAULT 0,
            other_deductions REAL NOT NULL DEFAULT 0,
            total_deductions REAL NOT NULL DEFAULT 0,
            net_pay         REAL NOT NULL DEFAULT 0,
            -- Free-text notes — encrypted (employer-private)
            notes           TEXT,
            -- Lifecycle
            generated_by    INTEGER REFERENCES admin_users(id),
            generated_at    TEXT NOT NULL,
            viewed_by_employee_at TEXT,
            UNIQUE(pay_period_id, subject_type, subject_id)
        )
    """)
    con.execute("CREATE INDEX IF NOT EXISTS idx_payslips_subject ON payslips(subject_type, subject_id, generated_at)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_payslips_period  ON payslips(pay_period_id)")

    # ── Client portal: service requests ─────────────────────────────────
    # Client requests do NOT directly become visits. They go into a triage
    # queue. Staff with visit:create promote them into the schedule.
    con.execute("""
        CREATE TABLE IF NOT EXISTS service_requests (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            customer_id     INTEGER NOT NULL REFERENCES customers(id),
            equipment_id    INTEGER REFERENCES equipment(id),
            request_type    TEXT NOT NULL,         -- 'maintenance'|'repair'|'quote'|'question'
            subject         TEXT NOT NULL,
            body            TEXT NOT NULL,
            preferred_date  TEXT,
            status          TEXT NOT NULL DEFAULT 'new',  -- 'new'|'triaged'|'scheduled'|'closed'
            triaged_by      INTEGER REFERENCES admin_users(id),
            triaged_at      TEXT,
            visit_id        INTEGER REFERENCES maintenance_visits(id),
            created_at      TEXT NOT NULL,
            ip_address      TEXT
        )
    """)
    con.execute("CREATE INDEX IF NOT EXISTS idx_svcreq_status ON service_requests(status, created_at)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_svcreq_customer ON service_requests(customer_id, created_at)")

    # ── Purchase orders + goods received + physical counts (SoD controls) ──
    # The flow: inventory_manager drafts a PO → "sends" it → goods physically
    # arrive and someone records a goods_received entry against the PO line →
    # supervisor/super_admin closes out the PO with a supplier invoice ref.
    # All three numbers (PO total, GRN total, invoice total) must agree or a
    # variance note is required and audit-logged.
    con.execute("""
        CREATE TABLE IF NOT EXISTS purchase_orders (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            po_number       TEXT NOT NULL UNIQUE,
            supplier        TEXT NOT NULL,
            status          TEXT NOT NULL DEFAULT 'draft',   -- draft|sent|received|closed|cancelled
            expected_total  REAL NOT NULL DEFAULT 0,
            invoice_number  TEXT,
            invoice_total   REAL,
            variance_note   TEXT,
            created_by      INTEGER,
            created_at      TEXT NOT NULL,
            sent_at         TEXT,
            closed_by       INTEGER,
            closed_at       TEXT
        )
    """)
    con.execute("CREATE INDEX IF NOT EXISTS idx_po_status ON purchase_orders(status, created_at)")

    con.execute("""
        CREATE TABLE IF NOT EXISTS purchase_order_lines (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            po_id           INTEGER NOT NULL REFERENCES purchase_orders(id),
            part_id         INTEGER NOT NULL REFERENCES parts(id),
            quantity        REAL NOT NULL,
            expected_unit_cost REAL NOT NULL DEFAULT 0,
            received_qty    REAL NOT NULL DEFAULT 0
        )
    """)
    con.execute("CREATE INDEX IF NOT EXISTS idx_po_lines_po ON purchase_order_lines(po_id)")

    con.execute("""
        CREATE TABLE IF NOT EXISTS goods_received (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            po_id           INTEGER NOT NULL REFERENCES purchase_orders(id),
            po_line_id      INTEGER NOT NULL REFERENCES purchase_order_lines(id),
            part_id         INTEGER NOT NULL REFERENCES parts(id),
            quantity        REAL NOT NULL,
            actual_unit_cost REAL NOT NULL,
            received_by     INTEGER,
            received_at     TEXT NOT NULL,
            notes           TEXT
        )
    """)
    con.execute("CREATE INDEX IF NOT EXISTS idx_grn_po ON goods_received(po_id)")

    # Physical counts. counted_by NEVER also approves — enforced at endpoint level.
    con.execute("""
        CREATE TABLE IF NOT EXISTS physical_counts (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            part_id         INTEGER NOT NULL REFERENCES parts(id),
            system_qty      REAL NOT NULL,
            counted_qty     REAL NOT NULL,
            variance_pct    REAL NOT NULL,
            counted_by      INTEGER NOT NULL,
            counted_at      TEXT NOT NULL,
            approved_by     INTEGER,
            approved_at     TEXT,
            approval_note   TEXT,
            status          TEXT NOT NULL DEFAULT 'pending'   -- pending|approved|escalated
        )
    """)
    con.execute("CREATE INDEX IF NOT EXISTS idx_counts_status ON physical_counts(status, counted_at)")

    # Pre-visit checklist (lightweight: completion of items kept as JSON blob).
    con.execute("""
        CREATE TABLE IF NOT EXISTS visit_checklists (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            visit_id        INTEGER NOT NULL UNIQUE REFERENCES maintenance_visits(id),
            items_json      TEXT NOT NULL,
            completed_at    TEXT NOT NULL,
            completed_by    INTEGER REFERENCES technicians(id)
        )
    """)

    # ── 5S workplace-discipline module ────────────────────────────────────────
    # Assets (vehicles, toolkits, storage bins) that get audited.
    con.execute("""
        CREATE TABLE IF NOT EXISTS fs_assets (
            id                INTEGER PRIMARY KEY AUTOINCREMENT,
            asset_code        TEXT NOT NULL UNIQUE,
            asset_type        TEXT NOT NULL CHECK (asset_type IN ('vehicle','toolkit','storage')),
            label             TEXT NOT NULL,
            hub_id            INTEGER NOT NULL DEFAULT 1,
            assigned_tech_id  INTEGER REFERENCES technicians(id),
            static_location   TEXT,
            photo_ref         TEXT,
            active            INTEGER NOT NULL DEFAULT 1,
            created_at        TEXT NOT NULL,
            notes             TEXT
        )
    """)
    con.execute("CREATE INDEX IF NOT EXISTS idx_fs_assets_tech ON fs_assets(assigned_tech_id)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_fs_assets_hub  ON fs_assets(hub_id)")

    # Catalog of what SHOULD be in each asset (SOP).
    con.execute("""
        CREATE TABLE IF NOT EXISTS fs_asset_items (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            asset_id     INTEGER NOT NULL REFERENCES fs_assets(id),
            item_type    TEXT NOT NULL CHECK (item_type IN ('tool','part','consumable')),
            item_label   TEXT NOT NULL,
            sop_required INTEGER NOT NULL DEFAULT 1,
            location_code TEXT,
            expiry_date  TEXT,
            part_id      INTEGER REFERENCES parts(id),
            active       INTEGER NOT NULL DEFAULT 1,
            created_at   TEXT NOT NULL
        )
    """)
    con.execute("CREATE INDEX IF NOT EXISTS idx_fs_asset_items_asset ON fs_asset_items(asset_id)")

    # Audit headers — APPEND-ONLY. Chain-hashed.
    con.execute("""
        CREATE TABLE IF NOT EXISTS fs_audits (
            id                INTEGER PRIMARY KEY AUTOINCREMENT,
            asset_id          INTEGER NOT NULL REFERENCES fs_assets(id),
            auditor_id        INTEGER NOT NULL,
            auditor_kind      TEXT NOT NULL CHECK (auditor_kind IN ('tech','admin')),
            phase             TEXT NOT NULL CHECK (phase IN ('start_shift','end_shift','weekly_manager')),
            audit_ts          TEXT NOT NULL,
            overall_pass      INTEGER NOT NULL,
            hub_id            INTEGER NOT NULL DEFAULT 1,
            prior_chain_hash  TEXT,
            chain_hash        TEXT NOT NULL,
            client_meta_json  TEXT
        )
    """)
    con.execute("CREATE INDEX IF NOT EXISTS idx_fs_audits_asset ON fs_audits(asset_id)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_fs_audits_auditor ON fs_audits(auditor_id, auditor_kind)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_fs_audits_ts ON fs_audits(audit_ts)")

    # Per-line checklist results.
    con.execute("""
        CREATE TABLE IF NOT EXISTS fs_audit_items (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            audit_id    INTEGER NOT NULL REFERENCES fs_audits(id),
            section     TEXT NOT NULL CHECK (section IN ('sort','set','shine','standardize')),
            item_key    TEXT NOT NULL,
            item_label  TEXT NOT NULL,
            status      TEXT NOT NULL CHECK (status IN ('pass','fail','na')),
            note        TEXT
        )
    """)
    con.execute("CREATE INDEX IF NOT EXISTS idx_fs_audit_items_audit ON fs_audit_items(audit_id)")

    # Exceptions — chain-hashed; state changes recorded as
    # immutable rows in fs_exception_events. Header rows DO get a status update
    # on resolution/escalation; rebuilt chain_hash is OK because the events
    # table is the immutable forensic trail.
    con.execute("""
        CREATE TABLE IF NOT EXISTS fs_exceptions (
            id                 INTEGER PRIMARY KEY AUTOINCREMENT,
            audit_id           INTEGER REFERENCES fs_audits(id),
            asset_id           INTEGER NOT NULL REFERENCES fs_assets(id),
            opened_by_id       INTEGER NOT NULL,
            opened_by_kind     TEXT NOT NULL CHECK (opened_by_kind IN ('tech','admin')),
            opened_at          TEXT NOT NULL,
            severity           TEXT NOT NULL CHECK (severity IN ('normal','safety_loto')),
            category           TEXT NOT NULL,
            description        TEXT,
            status             TEXT NOT NULL CHECK (status IN ('open','resolved','escalated','escalated_director')),
            resolved_by_id     INTEGER,
            resolved_by_kind   TEXT,
            resolved_at        TEXT,
            resolution_note    TEXT,
            escalated_at       TEXT,
            escalated_to_id    INTEGER,
            hub_id             INTEGER NOT NULL DEFAULT 1,
            prior_chain_hash   TEXT,
            chain_hash         TEXT NOT NULL
        )
    """)
    con.execute("CREATE INDEX IF NOT EXISTS idx_fs_exc_status ON fs_exceptions(status)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_fs_exc_asset ON fs_exceptions(asset_id)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_fs_exc_severity ON fs_exceptions(severity)")

    # State-transition events on an exception (APPEND-ONLY).
    con.execute("""
        CREATE TABLE IF NOT EXISTS fs_exception_events (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            exception_id    INTEGER NOT NULL REFERENCES fs_exceptions(id),
            event_type      TEXT NOT NULL CHECK (event_type IN ('opened','resolved','escalated','escalated_director','reopened','override')),
            actor_id        INTEGER NOT NULL,
            actor_kind      TEXT NOT NULL CHECK (actor_kind IN ('tech','admin','system')),
            occurred_at     TEXT NOT NULL,
            from_status     TEXT,
            to_status       TEXT,
            note            TEXT
        )
    """)
    con.execute("CREATE INDEX IF NOT EXISTS idx_fs_exc_evt_exc ON fs_exception_events(exception_id)")

    # Photos attached to a 5S exception (tech-captured evidence of the
    # safety/quality issue). Mirrors the visit_photos chain-of-custody
    # pattern: on-disk blobs, encrypted client_meta_json, per-row chain_hash.
    con.execute("""
        CREATE TABLE IF NOT EXISTS fs_exception_photos (
            id                 INTEGER PRIMARY KEY AUTOINCREMENT,
            exception_id       INTEGER NOT NULL REFERENCES fs_exceptions(id),
            filename           TEXT NOT NULL,
            original_filename  TEXT,
            mime               TEXT NOT NULL,
            size_bytes         INTEGER NOT NULL,
            uploaded_by_id     INTEGER NOT NULL,
            uploaded_by_kind   TEXT NOT NULL CHECK (uploaded_by_kind IN ('tech','admin')),
            uploaded_at        TEXT NOT NULL,
            client_meta_json   TEXT,
            hub_id             INTEGER NOT NULL DEFAULT 1,
            prior_chain_hash   TEXT,
            chain_hash         TEXT NOT NULL
        )
    """)
    con.execute("CREATE INDEX IF NOT EXISTS idx_fs_exc_photos_exc ON fs_exception_photos(exception_id)")

    # Coaching log (Phase 3).
    con.execute("""
        CREATE TABLE IF NOT EXISTS fs_coaching_log (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            tech_id         INTEGER NOT NULL REFERENCES technicians(id),
            opened_by_id    INTEGER NOT NULL,
            opened_at       TEXT NOT NULL,
            band_at_open    TEXT NOT NULL,
            plan_text       TEXT,
            status          TEXT NOT NULL CHECK (status IN ('open','closed')),
            closed_at       TEXT,
            closed_by_id    INTEGER,
            close_note      TEXT,
            hub_id          INTEGER NOT NULL DEFAULT 1,
            chain_hash      TEXT NOT NULL
        )
    """)
    con.execute("CREATE INDEX IF NOT EXISTS idx_fs_coach_tech ON fs_coaching_log(tech_id)")

    # ── Technician Detail View tables (super_admin) ─────────────────────
    # Append-leaning forensic records. technician_reviews mutates status in
    # place (matches fs_exceptions pattern) but the chain_hash protects the
    # state transitions. KPI overrides + 5S overrides are write-once forensic
    # records — they never get deleted.
    con.execute("""
        CREATE TABLE IF NOT EXISTS technician_reviews (
            id                 INTEGER PRIMARY KEY AUTOINCREMENT,
            tech_id            INTEGER NOT NULL REFERENCES technicians(id),
            review_type        TEXT NOT NULL CHECK (review_type IN ('coaching','written_warning','positive_feedback','other')),
            summary            TEXT NOT NULL,
            status             TEXT NOT NULL CHECK (status IN ('open','resolved','archived')) DEFAULT 'open',
            action_items       TEXT,
            followup_date      TEXT,
            reviewer_id        INTEGER NOT NULL,
            created_at         TEXT NOT NULL,
            updated_at         TEXT,
            hub_id             INTEGER NOT NULL DEFAULT 1,
            prior_chain_hash   TEXT,
            chain_hash         TEXT NOT NULL
        )
    """)
    con.execute("CREATE INDEX IF NOT EXISTS idx_tech_reviews_tech ON technician_reviews(tech_id, created_at DESC)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_tech_reviews_status ON technician_reviews(status)")

    con.execute("""
        CREATE TABLE IF NOT EXISTS technician_kpi_overrides (
            id                 INTEGER PRIMARY KEY AUTOINCREMENT,
            tech_id            INTEGER NOT NULL REFERENCES technicians(id),
            kpi_key            TEXT NOT NULL,
            green_threshold    REAL,
            amber_threshold    REAL,
            red_threshold      REAL,
            reason             TEXT NOT NULL,
            effective_from     TEXT NOT NULL,
            effective_until    TEXT,
            created_by         INTEGER NOT NULL,
            created_at         TEXT NOT NULL,
            active             INTEGER NOT NULL DEFAULT 1,
            prior_chain_hash   TEXT,
            chain_hash         TEXT NOT NULL
        )
    """)
    con.execute("CREATE INDEX IF NOT EXISTS idx_tech_kpi_ov_tech ON technician_kpi_overrides(tech_id, active)")

    con.execute("""
        CREATE TABLE IF NOT EXISTS technician_5s_overrides (
            id                 INTEGER PRIMARY KEY AUTOINCREMENT,
            exception_id       INTEGER NOT NULL REFERENCES fs_exceptions(id),
            tech_id            INTEGER NOT NULL,
            reason             TEXT NOT NULL,
            overridden_by      INTEGER NOT NULL,
            overridden_at      TEXT NOT NULL,
            hub_id             INTEGER NOT NULL DEFAULT 1,
            prior_chain_hash   TEXT,
            chain_hash         TEXT NOT NULL
        )
    """)
    con.execute("CREATE INDEX IF NOT EXISTS idx_tech_5s_ov_tech ON technician_5s_overrides(tech_id)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_tech_5s_ov_exc  ON technician_5s_overrides(exception_id)")

    # ── Delegation module ──────────────────────────────────────────────────
    # Task delegation: super_admin (and admins with delegation power) can
    # grant scoped access to other admins. Record-level, type-level, or
    # full power. Chain-hashed append-only audit, mirrored from payments.
    con.execute("""
        CREATE TABLE IF NOT EXISTS delegations (
            id                  INTEGER PRIMARY KEY AUTOINCREMENT,
            grantor_id          INTEGER NOT NULL REFERENCES admin_users(id),
            grantor_role        TEXT NOT NULL,
            recipient_id        INTEGER NOT NULL REFERENCES admin_users(id),
            recipient_kind      TEXT NOT NULL DEFAULT 'admin'
                                  CHECK (recipient_kind = 'admin'),
            delegation_type     TEXT NOT NULL
                                  CHECK (delegation_type IN ('record','record_type','power')),
            scope_record_id     INTEGER,
            scope_record_type   TEXT,
            permission_level    TEXT
                                  CHECK (permission_level IN ('read','read_write') OR permission_level IS NULL),
            valid_until         TEXT,
            grantor_notes       TEXT,
            created_at          TEXT NOT NULL,
            revoked_at          TEXT,
            revoked_by          INTEGER REFERENCES admin_users(id),
            revoke_reason       TEXT,
            revoke_kind         TEXT
                                  CHECK (revoke_kind IN ('manual','auto_expiry','power_cascade') OR revoke_kind IS NULL),
            prior_chain_hash    TEXT,
            chain_hash          TEXT NOT NULL,
            hub_id              INTEGER NOT NULL DEFAULT 1
        )
    """)
    con.execute("CREATE INDEX IF NOT EXISTS idx_deleg_recipient ON delegations(recipient_id, revoked_at)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_deleg_grantor   ON delegations(grantor_id, revoked_at)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_deleg_scope     ON delegations(scope_record_type, scope_record_id, revoked_at)")

    con.execute("""
        CREATE TABLE IF NOT EXISTS delegation_power (
            id                INTEGER PRIMARY KEY AUTOINCREMENT,
            admin_id          INTEGER NOT NULL UNIQUE REFERENCES admin_users(id),
            granted_by_id     INTEGER NOT NULL REFERENCES admin_users(id),
            granted_at        TEXT NOT NULL,
            revoked_at        TEXT,
            revoked_by        INTEGER REFERENCES admin_users(id),
            prior_chain_hash  TEXT,
            chain_hash        TEXT NOT NULL
        )
    """)

    con.execute("""
        CREATE TABLE IF NOT EXISTS delegation_regrant_requests (
            id                      INTEGER PRIMARY KEY AUTOINCREMENT,
            requester_id            INTEGER NOT NULL REFERENCES admin_users(id),
            original_delegation_id  INTEGER NOT NULL REFERENCES delegations(id),
            status                  TEXT NOT NULL DEFAULT 'open'
                                      CHECK (status IN ('open','approved','denied','cancelled')),
            requested_at            TEXT NOT NULL,
            reviewed_by             INTEGER REFERENCES admin_users(id),
            reviewed_at             TEXT,
            review_notes            TEXT,
            new_delegation_id       INTEGER REFERENCES delegations(id),
            prior_chain_hash        TEXT,
            chain_hash              TEXT NOT NULL
        )
    """)

    # has_delegation_power on admin_users — idempotent ALTER.
    if "has_delegation_power" not in admin_cols:
        try:
            con.execute("ALTER TABLE admin_users ADD COLUMN has_delegation_power INTEGER NOT NULL DEFAULT 0")
        except sqlite3.OperationalError:
            pass

    # Seed demo assets (idempotent).
    _now_iso_seed = datetime.now(timezone.utc).isoformat()
    _first_tech = con.execute(
        "SELECT id FROM technicians WHERE active = 1 ORDER BY id ASC LIMIT 1"
    ).fetchone()
    _seed_tech_id = _first_tech[0] if _first_tech else None
    for _seed in (
        ("VAN-KIN-01",  "vehicle", "Kingston Service Van 01", _seed_tech_id, None),
        ("TKIT-KIN-01", "toolkit", "Kingston Toolkit 01",     _seed_tech_id, None),
        ("WH-KIN-A3",   "storage", "Kingston Warehouse Bin A3", None,        "Warehouse Shelf A-3"),
    ):
        con.execute(
            "INSERT OR IGNORE INTO fs_assets "
            "(asset_code, asset_type, label, hub_id, assigned_tech_id, static_location, active, created_at) "
            "VALUES (?, ?, ?, 1, ?, ?, 1, ?)",
            (_seed[0], _seed[1], _seed[2], _seed[3], _seed[4], _now_iso_seed),
        )

    # ── Employee KPI Tracking Module — schema + defaults ───────────────────
    # Defensive coaching-first scoring. All composite scores chain-hashed.
    # Safety RED forces composite RED regardless of weighted average.
    con.execute("""
        CREATE TABLE IF NOT EXISTS kpi_definitions (
            id                   INTEGER PRIMARY KEY,
            kpi_key              TEXT NOT NULL UNIQUE,
            display_name         TEXT NOT NULL,
            description          TEXT,
            direction            TEXT NOT NULL CHECK(direction IN ('higher_better','lower_better')),
            in_composite         INTEGER NOT NULL DEFAULT 1,
            composite_weight_pct REAL NOT NULL DEFAULT 0,
            safety_critical      INTEGER NOT NULL DEFAULT 0,
            active               INTEGER NOT NULL DEFAULT 1,
            created_at           TEXT NOT NULL,
            updated_at           TEXT
        )
    """)
    con.execute("""
        CREATE TABLE IF NOT EXISTS kpi_thresholds (
            id                INTEGER PRIMARY KEY,
            kpi_key           TEXT NOT NULL,
            tier              TEXT NOT NULL CHECK(tier IN ('level_1','level_2','level_3','ops_manager')),
            green_threshold   REAL NOT NULL,
            amber_band        REAL NOT NULL,
            red_floor         REAL NOT NULL,
            effective_from    TEXT NOT NULL,
            effective_until   TEXT,
            active            INTEGER NOT NULL DEFAULT 1,
            created_at        TEXT NOT NULL,
            UNIQUE(kpi_key, tier, effective_from)
        )
    """)
    con.execute("CREATE INDEX IF NOT EXISTS idx_kpi_thresh_lookup ON kpi_thresholds(kpi_key, tier, active)")
    con.execute("""
        CREATE TABLE IF NOT EXISTS kpi_periods (
            id           INTEGER PRIMARY KEY,
            period_key   TEXT NOT NULL UNIQUE,
            start_date   TEXT NOT NULL,
            end_date     TEXT NOT NULL,
            status       TEXT NOT NULL CHECK(status IN ('open','closed')) DEFAULT 'open',
            closed_at    TEXT,
            closed_by    INTEGER,
            created_at   TEXT NOT NULL
        )
    """)
    con.execute("""
        CREATE TABLE IF NOT EXISTS kpi_scores (
            id                  INTEGER PRIMARY KEY,
            tech_id             INTEGER NOT NULL,
            period_key          TEXT NOT NULL,
            kpi_key             TEXT NOT NULL,
            raw_value           REAL,
            sample_size         INTEGER,
            band                TEXT CHECK(band IN ('green','amber','red','insufficient_data')),
            tier_at_computation TEXT,
            computed_at         TEXT NOT NULL,
            recomputed_count    INTEGER NOT NULL DEFAULT 0,
            prior_chain_hash    TEXT,
            chain_hash          TEXT NOT NULL,
            UNIQUE(tech_id, period_key, kpi_key)
        )
    """)
    con.execute("CREATE INDEX IF NOT EXISTS idx_kpi_scores_tech ON kpi_scores(tech_id, period_key)")
    con.execute("""
        CREATE TABLE IF NOT EXISTS kpi_composite_scores (
            id                  INTEGER PRIMARY KEY,
            tech_id             INTEGER NOT NULL,
            period_key          TEXT NOT NULL,
            composite_pct       REAL,
            band                TEXT CHECK(band IN ('green','amber','red','insufficient_data')),
            forced_red_reason   TEXT,
            tier_at_computation TEXT,
            computed_at         TEXT NOT NULL,
            prior_chain_hash    TEXT,
            chain_hash          TEXT NOT NULL,
            UNIQUE(tech_id, period_key)
        )
    """)
    con.execute("CREATE INDEX IF NOT EXISTS idx_kpi_comp_tech ON kpi_composite_scores(tech_id, period_key)")
    con.execute("""
        CREATE TABLE IF NOT EXISTS kpi_flags (
            id                 INTEGER PRIMARY KEY,
            tech_id            INTEGER NOT NULL,
            period_key         TEXT NOT NULL,
            kpi_key            TEXT,
            severity           TEXT NOT NULL CHECK(severity IN (
                'coaching_suggested','coaching_required',
                'written_warning_recommended','immediate_escalation'
            )),
            status             TEXT NOT NULL CHECK(status IN (
                'open','acknowledged','in_progress','resolved','overridden'
            )) DEFAULT 'open',
            reason             TEXT,
            override_reason    TEXT,
            manager_id         INTEGER,
            acknowledged_at    TEXT,
            resolved_at        TEXT,
            resolution_notes   TEXT,
            created_at         TEXT NOT NULL,
            prior_chain_hash   TEXT,
            chain_hash         TEXT NOT NULL
        )
    """)
    con.execute("CREATE INDEX IF NOT EXISTS idx_kpi_flags_tech ON kpi_flags(tech_id, status)")
    con.execute("""
        CREATE TABLE IF NOT EXISTS kpi_recompute_log (
            id              INTEGER PRIMARY KEY,
            triggered_by    TEXT NOT NULL CHECK(triggered_by IN ('cron','manual','visit_event','admin')),
            triggered_by_id INTEGER,
            scope           TEXT NOT NULL CHECK(scope IN ('one_tech','one_period','all_open','all')),
            tech_id         INTEGER,
            period_key      TEXT,
            started_at      TEXT NOT NULL,
            ended_at        TEXT,
            rows_affected   INTEGER,
            error_text      TEXT
        )
    """)

    # Seed kpi_definitions if empty (idempotent).
    _kpi_def_count = con.execute("SELECT COUNT(*) FROM kpi_definitions").fetchone()[0]
    if _kpi_def_count == 0:
        _kpi_now = datetime.now(timezone.utc).isoformat()
        _kpi_defs = [
            ("callback_rate",         "Callback Rate",          "Share of work that came back as a callback. Lower is better.", "lower_better",  1, 30.0, 0),
            ("documentation_quality", "Documentation Quality",  "Readings + photos + summary completeness per visit.",          "higher_better", 1, 20.0, 0),
            ("pm_completion",         "PM Completion",          "Preventive maintenance jobs completed on or before due.",      "higher_better", 1, 20.0, 0),
            ("utilization",           "Utilization",            "Billable minutes over clocked minutes.",                       "higher_better", 1, 15.0, 0),
            ("sla_adherence",         "SLA Adherence",          "CM jobs started within SLA window.",                           "higher_better", 1, 10.0, 0),
            ("safety_compliance",     "Safety Compliance",      "100 percent expected. Any LOTO failure forces composite RED.", "higher_better", 1,  5.0, 1),
            ("first_time_fix",        "First-Time Fix",         "CM jobs that did not generate a callback. Informational.",     "higher_better", 0,  0.0, 0),
            ("revenue_per_tech",      "Revenue per Tech",       "Labor revenue attributed to this tech. Informational.",        "higher_better", 0,  0.0, 0),
        ]
        for k, name, desc, direction, in_comp, weight, safety in _kpi_defs:
            con.execute(
                "INSERT OR IGNORE INTO kpi_definitions (kpi_key, display_name, description, "
                "direction, in_composite, composite_weight_pct, safety_critical, active, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?)",
                (k, name, desc, direction, in_comp, weight, safety, _kpi_now),
            )

    # Seed kpi_thresholds if empty.
    _kpi_thresh_count = con.execute("SELECT COUNT(*) FROM kpi_thresholds").fetchone()[0]
    if _kpi_thresh_count == 0:
        _kpi_now = datetime.now(timezone.utc).isoformat()
        _today = datetime.now(timezone.utc).date().isoformat()
        # (kpi_key, [(tier, green, amber_band, red_floor)])
        # amber_band is the pp tolerance below green (higher_better)
        # or above green (lower_better — callback_rate). red_floor is
        # the side-of-green boundary that flips to RED.
        _thresh = [
            ("callback_rate",         [("level_1", 8.0,  2.0, 12.0), ("level_2", 6.0,  2.0, 12.0), ("level_3", 4.0,  2.0, 12.0)]),
            ("documentation_quality", [("level_1", 80.0, 5.0, 70.0), ("level_2", 85.0, 5.0, 70.0), ("level_3", 90.0, 5.0, 70.0)]),
            ("pm_completion",         [("level_1", 90.0, 5.0, 85.0), ("level_2", 93.0, 5.0, 85.0), ("level_3", 95.0, 5.0, 85.0)]),
            ("utilization",           [("level_1", 65.0, 5.0, 55.0), ("level_2", 72.0, 5.0, 55.0), ("level_3", 78.0, 5.0, 55.0)]),
            ("sla_adherence",         [("level_1", 90.0, 5.0, 85.0), ("level_2", 93.0, 5.0, 85.0), ("level_3", 95.0, 5.0, 85.0)]),
            ("safety_compliance",     [("level_1",100.0, 0.0,100.0), ("level_2",100.0, 0.0,100.0), ("level_3",100.0, 0.0,100.0)]),
            ("first_time_fix",        [("level_1", 75.0, 5.0, 65.0), ("level_2", 80.0, 5.0, 65.0), ("level_3", 85.0, 5.0, 65.0)]),
            ("revenue_per_tech",      [("level_1",  0.0, 0.0,  0.0), ("level_2",  0.0, 0.0,  0.0), ("level_3",  0.0, 0.0,  0.0)]),
        ]
        for kpi_key, rows in _thresh:
            # Replicate level_3 row to ops_manager — they oversee, don't perform.
            l3 = rows[-1]
            full = rows + [("ops_manager", l3[1], l3[2], l3[3])]
            for tier, green, amber, red in full:
                con.execute(
                    "INSERT OR IGNORE INTO kpi_thresholds (kpi_key, tier, green_threshold, "
                    "amber_band, red_floor, effective_from, active, created_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, 1, ?)",
                    (kpi_key, tier, green, amber, red, _today, _kpi_now),
                )

    # ── KPI Notes (Phase 5) ─────────────────────────────────────────────────
    con.execute("""
        CREATE TABLE IF NOT EXISTS kpi_notes (
            id INTEGER PRIMARY KEY,
            note_kind TEXT NOT NULL CHECK(note_kind IN
                ('coaching','tech_response','recognition','team_period','score_annotation')),
            tech_id INTEGER,
            period_key TEXT,
            flag_id INTEGER,
            score_id INTEGER,
            author_id INTEGER NOT NULL,
            author_kind TEXT NOT NULL CHECK(author_kind IN ('admin','tech')),
            body TEXT NOT NULL,
            visibility TEXT NOT NULL CHECK(visibility IN
                ('admins_only','admins_and_subject_tech','admins_and_all_techs')),
            status TEXT NOT NULL CHECK(status IN ('active','edited','archived')) DEFAULT 'active',
            created_at TEXT NOT NULL,
            updated_at TEXT,
            locked_after TEXT,
            prior_chain_hash TEXT,
            chain_hash TEXT,
            hub_id INTEGER NOT NULL DEFAULT 1
        )
    """)
    con.execute("CREATE INDEX IF NOT EXISTS idx_kpi_notes_tech ON kpi_notes(tech_id, note_kind, created_at)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_kpi_notes_flag ON kpi_notes(flag_id)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_kpi_notes_period ON kpi_notes(period_key, note_kind)")

    # ── KPI Goals + PIPs (Phase 6) ──────────────────────────────────────────
    con.execute("""
        CREATE TABLE IF NOT EXISTS kpi_goals (
            id INTEGER PRIMARY KEY,
            goal_kind TEXT NOT NULL CHECK(goal_kind IN ('development_goal','pip')),
            tech_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            start_date TEXT NOT NULL,
            target_date TEXT NOT NULL,
            status TEXT NOT NULL CHECK(status IN
                ('draft','active','in_progress','met','not_met','withdrawn')) DEFAULT 'draft',
            action_items_json TEXT,
            related_kpi_keys TEXT,
            triggering_flag_id INTEGER,
            opened_by_id INTEGER NOT NULL,
            opened_at TEXT NOT NULL,
            activated_at TEXT,
            closed_at TEXT,
            closed_by_id INTEGER,
            outcome_summary TEXT,
            pip_review_dates TEXT,
            pip_severity TEXT,
            hr_acknowledged_at TEXT,
            prior_chain_hash TEXT,
            chain_hash TEXT,
            hub_id INTEGER NOT NULL DEFAULT 1
        )
    """)
    con.execute("CREATE INDEX IF NOT EXISTS idx_kpi_goals_tech ON kpi_goals(tech_id, goal_kind, status)")
    con.execute("""
        CREATE TABLE IF NOT EXISTS kpi_goal_checkins (
            id INTEGER PRIMARY KEY,
            goal_id INTEGER NOT NULL,
            checkin_date TEXT NOT NULL,
            status TEXT NOT NULL CHECK(status IN ('on_track','at_risk','off_track','met')),
            notes TEXT NOT NULL,
            author_id INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            prior_chain_hash TEXT,
            chain_hash TEXT
        )
    """)
    con.execute("CREATE INDEX IF NOT EXISTS idx_kpi_goal_checkins_goal ON kpi_goal_checkins(goal_id, checkin_date)")

    # ── Custom KPI extensions (Phase 7) ─────────────────────────────────────
    _kpi_def_cols = {row[1] for row in con.execute("PRAGMA table_info(kpi_definitions)")}
    for col, sql in (
        ("compute_kind",    "ALTER TABLE kpi_definitions ADD COLUMN compute_kind TEXT NOT NULL DEFAULT 'auto'"),
        ("created_by_id",   "ALTER TABLE kpi_definitions ADD COLUMN created_by_id INTEGER"),
        ("created_at_ext",  "ALTER TABLE kpi_definitions ADD COLUMN created_at_ext TEXT"),
    ):
        if col not in _kpi_def_cols:
            try: con.execute(sql)
            except sqlite3.OperationalError: pass
    try:
        con.execute("UPDATE kpi_definitions SET compute_kind='auto' "
                    "WHERE compute_kind IS NULL OR compute_kind=''")
    except sqlite3.OperationalError:
        pass

    con.commit()
    con.close()
    _backfill_prids()
    _backfill_field_encryption()
    _backfill_audit_pii_redaction()
    _backfill_audit_chain()
    _backfill_table_chains()
    # Reclaim freed pages so plaintext that lived in pre-encryption rows is
    # not recoverable from the raw file. SQLite VACUUM rewrites the whole DB.
    if os.environ.get("FIELD_ENCRYPTION_KEY"):
        try:
            con = _con()
            con.isolation_level = None   # VACUUM needs autocommit
            con.execute("VACUUM")
            con.close()
        except Exception as e:
            print(f"VACUUM after encryption migration failed: {e}")


def _backfill_field_encryption():
    """Idempotent migration. Walks each PII-bearing table and encrypts any
    value that isn't already in our ciphertext envelope. Populates the
    email_hash blind-index columns. Safe to run on every boot — rows that
    are already ciphertext (start with v1:r:/v1:d:) are skipped. Skips
    silently if FIELD_ENCRYPTION_KEY isn't configured yet so Phase 1's
    soft check still allows boot before the operator sets the key."""
    if not os.environ.get("FIELD_ENCRYPTION_KEY"):
        return
    from crypto import is_ciphertext as _is_ct
    con = _con()
    # customers.email + phone + address + notes + email_hash + mfa_secret + contact_person_phone
    for row in con.execute("SELECT id, email, phone, address, notes, mfa_secret FROM customers").fetchall():
        d = dict(row); updates = []; vals = []
        if d.get("email") is not None and not _is_ct(d["email"]):
            updates.append("email = ?, email_hash = ?")
            vals.extend([_det_enc(d["email"]), _email_hash(d["email"])])
        for col in ("phone", "address", "notes", "mfa_secret"):
            v = d.get(col)
            if v is not None and v != "" and not _is_ct(v):
                updates.append(f"{col} = ?")
                vals.append(_enc(v))
        if updates:
            vals.append(d["id"])
            con.execute(f"UPDATE customers SET {', '.join(updates)} WHERE id = ?", vals)
    # technicians
    for row in con.execute("SELECT id, email, phone FROM technicians").fetchall():
        d = dict(row); updates = []; vals = []
        if d.get("email") is not None and not _is_ct(d["email"]):
            updates.append("email = ?, email_hash = ?")
            vals.extend([_det_enc(d["email"]), _email_hash(d["email"])])
        if d.get("phone") is not None and d["phone"] != "" and not _is_ct(d["phone"]):
            updates.append("phone = ?"); vals.append(_enc(d["phone"]))
        if updates:
            vals.append(d["id"])
            con.execute(f"UPDATE technicians SET {', '.join(updates)} WHERE id = ?", vals)
    # admin_users
    for row in con.execute("SELECT id, email, phone, mfa_secret FROM admin_users").fetchall():
        d = dict(row); updates = []; vals = []
        if d.get("email") is not None and not _is_ct(d["email"]):
            updates.append("email = ?, email_hash = ?")
            vals.extend([_det_enc(d["email"]), _email_hash(d["email"])])
        for col in ("phone", "mfa_secret"):
            v = d.get(col)
            if v is not None and v != "" and not _is_ct(v):
                updates.append(f"{col} = ?"); vals.append(_enc(v))
        if updates:
            vals.append(d["id"])
            con.execute(f"UPDATE admin_users SET {', '.join(updates)} WHERE id = ?", vals)
    # equipment
    for row in con.execute("SELECT id, serial_number, location, notes FROM equipment").fetchall():
        d = dict(row); updates = []; vals = []
        for col in ("serial_number", "location", "notes"):
            v = d.get(col)
            if v is not None and v != "" and not _is_ct(v):
                updates.append(f"{col} = ?"); vals.append(_enc(v))
        if updates:
            vals.append(d["id"])
            con.execute(f"UPDATE equipment SET {', '.join(updates)} WHERE id = ?", vals)
    # maintenance_visits
    for row in con.execute(
        "SELECT id, work_done, parts_replaced, notes, contact_person_phone, hazards, access_codes "
        "FROM maintenance_visits").fetchall():
        d = dict(row); updates = []; vals = []
        for col in ("work_done", "parts_replaced", "notes",
                    "contact_person_phone", "hazards", "access_codes"):
            v = d.get(col)
            if v is not None and v != "" and not _is_ct(v):
                updates.append(f"{col} = ?"); vals.append(_enc(v))
        if updates:
            vals.append(d["id"])
            con.execute(f"UPDATE maintenance_visits SET {', '.join(updates)} WHERE id = ?", vals)
    # visit_signatures
    for row in con.execute("SELECT id, signature_b64 FROM visit_signatures").fetchall():
        d = dict(row)
        if d.get("signature_b64") and not _is_ct(d["signature_b64"]):
            con.execute("UPDATE visit_signatures SET signature_b64 = ? WHERE id = ?",
                        (_enc(d["signature_b64"]), d["id"]))
    con.commit()
    con.close()


def _backfill_prids():
    """Give existing techs a PRID if they don't have one (uses created_at as hire date)."""
    con = _con()
    rows = con.execute(
        "SELECT id, name, created_at FROM technicians WHERE prid IS NULL OR prid = ''"
    ).fetchall()
    con.close()
    for r in rows:
        hire = (r["created_at"] or "")[:10] or None
        prid = generate_prid(name=r["name"] or "Tech", hire_date=hire)
        con = _con()
        con.execute("UPDATE technicians SET prid = ? WHERE id = ?", (prid, r["id"]))
        con.commit()
        con.close()


def save_submission(data: dict):
    con = sqlite3.connect(DB_PATH)
    con.execute(
        """
        INSERT INTO submissions (fname, lname, email, phone, company, tier, msg, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            data["fname"],
            data["lname"],
            data["email"],
            data.get("phone", ""),
            data.get("company", ""),
            data["tier"],
            data.get("msg", ""),
            datetime.now(timezone.utc).isoformat(),
        ),
    )
    con.commit()
    con.close()


# ── Customers ────────────────────────────────────────────────────────────────

def get_customer_by_code(code: str):
    con = _con()
    row = con.execute(
        "SELECT * FROM customers WHERE customer_code = ?", (code.strip().upper(),)
    ).fetchone()
    con.close()
    return _dec_row("customers", row)


def get_customer_by_id(customer_id: int):
    con = _con()
    row = con.execute("SELECT * FROM customers WHERE id = ?", (customer_id,)).fetchone()
    con.close()
    return _dec_row("customers", row)


def get_all_customers():
    con = _con()
    rows = con.execute(
        "SELECT id, customer_code, name, company, email, phone, address, notes, "
        "customer_type, active, "
        "(pin_hash IS NOT NULL) AS has_pin, created_at FROM customers ORDER BY name"
    ).fetchall()
    con.close()
    return _dec_rows("customers", rows)


def create_customer(data: dict) -> int:
    pin = data.get("pin", "").strip()
    pin_hash = _hash_pin(pin) if pin else None
    ctype = data.get("customer_type", "residential")
    if ctype not in ("residential", "commercial"):
        ctype = "residential"
    # Encrypt PII columns BEFORE insertion.
    enc = _enc_dict("customers", {
        "email":   data.get("email", ""),
        "phone":   data.get("phone", ""),
        "address": data.get("address", ""),
        "notes":   data.get("notes", ""),
    })
    con = _con()
    cur = con.execute(
        """
        INSERT INTO customers (customer_code, name, company, email, email_hash, phone, address, notes, pin_hash, customer_type, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            data["customer_code"].strip().upper(),
            data["name"],
            data.get("company", ""),
            enc.get("email", ""),
            enc.get("email_hash"),
            enc.get("phone", ""),
            enc.get("address", ""),
            enc.get("notes", ""),
            pin_hash,
            ctype,
            datetime.now(timezone.utc).isoformat(),
        ),
    )
    customer_id = cur.lastrowid
    con.commit()
    con.close()
    return customer_id


def verify_customer(code: str, pin: str):
    cust = get_customer_by_code(code)
    if not cust or not cust.get("pin_hash"):
        return None
    if not _verify_pin(pin, cust["pin_hash"]):
        return None
    if _needs_rehash(cust["pin_hash"]):
        set_customer_pin(cust["id"], pin)
    return cust


# ── PIN policy (Phase 3) ─────────────────────────────────────────────────────
# Public-internet door is hardened: 6+ digits, no repeats, no sequential runs.
# Lockout: 5 failed attempts → 30-minute auto-reset window.
PIN_MIN_LEN              = 6
PIN_MAX_LEN              = 8
PIN_LOCKOUT_THRESHOLD    = 5
PIN_LOCKOUT_MINUTES      = 30


def validate_pin_policy(pin: str):
    """Raises ValueError on weak PINs. Used by every PIN-setting code path
    (customer create, set, reset). The rules:
      - digits only, 6–8 chars
      - reject all-same-digit (000000, 111111…)
      - reject monotonic runs (012345, 123456, 987654, 543210)"""
    if not pin or not pin.isdigit():
        raise ValueError("PIN must be digits only")
    if not (PIN_MIN_LEN <= len(pin) <= PIN_MAX_LEN):
        raise ValueError(f"PIN must be {PIN_MIN_LEN}–{PIN_MAX_LEN} digits")
    if len(set(pin)) == 1:
        raise ValueError("PIN cannot be all the same digit")
    # Sequential: each digit exactly one more (or one less) than the previous.
    diffs = {int(pin[i+1]) - int(pin[i]) for i in range(len(pin)-1)}
    if diffs == {1} or diffs == {-1}:
        raise ValueError("PIN cannot be a sequential run of digits")


def record_pin_failure(customer_id: int) -> dict:
    """Increments pin_failed_count and, if it crosses threshold, sets
    pin_locked_until = now + 30 minutes. Returns {'locked': bool,
    'failed': int, 'locked_until': str|None}."""
    from datetime import timedelta as _td
    con = _con()
    row = con.execute(
        "SELECT pin_failed_count, pin_locked_until FROM customers WHERE id = ?",
        (customer_id,),
    ).fetchone()
    if not row:
        con.close()
        return {"locked": False, "failed": 0, "locked_until": None}
    failed = (row["pin_failed_count"] or 0) + 1
    locked_until = None
    locked = False
    if failed >= PIN_LOCKOUT_THRESHOLD:
        locked = True
        locked_until = (datetime.now(timezone.utc) + _td(minutes=PIN_LOCKOUT_MINUTES)).isoformat()
    con.execute(
        "UPDATE customers SET pin_failed_count = ?, pin_locked_until = ? WHERE id = ?",
        (failed, locked_until, customer_id),
    )
    con.commit()
    con.close()
    return {"locked": locked, "failed": failed, "locked_until": locked_until}


def reset_pin_failures(customer_id: int):
    con = _con()
    con.execute(
        "UPDATE customers SET pin_failed_count = 0, pin_locked_until = NULL WHERE id = ?",
        (customer_id,),
    )
    con.commit()
    con.close()


def is_customer_pin_locked(customer_id: int) -> tuple:
    """Returns (locked: bool, locked_until: str|None). Auto-clears the lock
    if its expiry has passed (so the next failed login is treated as the
    first of a new window)."""
    con = _con()
    row = con.execute(
        "SELECT pin_locked_until FROM customers WHERE id = ?", (customer_id,),
    ).fetchone()
    con.close()
    if not row or not row["pin_locked_until"]:
        return False, None
    locked_until = row["pin_locked_until"]
    if locked_until < datetime.now(timezone.utc).isoformat():
        reset_pin_failures(customer_id)
        return False, None
    return True, locked_until


def set_customer_pin(customer_id: int, pin: str):
    con = _con()
    con.execute("UPDATE customers SET pin_hash = ? WHERE id = ?", (_hash_pin(pin), customer_id))
    con.commit()
    con.close()


def get_customer_by_code_and_email(code: str, email: str):
    """Equality lookup on encrypted email uses the email_hash blind index —
    fast, doesn't decrypt every row, doesn't expose patterns."""
    h = _email_hash(email)
    con = _con()
    row = con.execute(
        "SELECT * FROM customers WHERE customer_code = ? AND email_hash = ?",
        (code.strip().upper(), h),
    ).fetchone()
    con.close()
    return _dec_row("customers", row)


def create_customer_pin_reset(customer_id: int) -> str:
    from datetime import timedelta
    token   = secrets.token_urlsafe(24)
    expires = (datetime.now(timezone.utc) + timedelta(minutes=30)).isoformat()
    con = _con()
    con.execute(
        "INSERT INTO customer_pin_resets (customer_id, token, expires_at, created_at) VALUES (?, ?, ?, ?)",
        (customer_id, token, expires, datetime.now(timezone.utc).isoformat()),
    )
    con.commit()
    con.close()
    return token


def consume_customer_pin_reset(token: str):
    con = _con()
    row = con.execute(
        "SELECT * FROM customer_pin_resets WHERE token = ? AND used_at IS NULL",
        (token,),
    ).fetchone()
    if not row:
        con.close()
        return None
    row = dict(row)
    if row["expires_at"] < datetime.now(timezone.utc).isoformat():
        con.close()
        return None
    con.execute(
        "UPDATE customer_pin_resets SET used_at = ? WHERE id = ?",
        (datetime.now(timezone.utc).isoformat(), row["id"]),
    )
    con.commit()
    con.close()
    return row["customer_id"]


def update_customer(customer_id: int, data: dict):
    con = _con()
    con.execute(
        """
        UPDATE customers SET
            name = ?, company = ?, email = ?, email_hash = ?, phone = ?, address = ?, notes = ?
        WHERE id = ?
        """,
        (
            data["name"].strip(),
            data.get("company", "").strip(),
            _det_enc(data.get("email", "").strip()),
            _email_hash(data.get("email", "").strip()),
            _enc(data.get("phone", "").strip()),
            _enc(data.get("address", "").strip()),
            _enc(data.get("notes", "").strip()),
            customer_id,
        ),
    )
    con.commit()
    con.close()


def delete_customer(customer_id: int):
    con = _con()
    con.execute("DELETE FROM maintenance_visits WHERE customer_id = ?", (customer_id,))
    con.execute("DELETE FROM equipment WHERE customer_id = ?", (customer_id,))
    con.execute("DELETE FROM customers WHERE id = ?", (customer_id,))
    con.commit()
    con.close()


# ── Customer Detail View (super_admin) ──────────────────────────────────────
# Helpers backing the super_admin customer-detail screen. Sensitive columns
# are decrypted on read; redaction at the audit layer keeps plaintext PII
# out of audit_log even when callers pass the full before/after dict.

def get_customer_with_decryption(customer_id: int):
    """Full customer row with PII decrypted. super_admin-only endpoint
    contract — the caller is responsible for gating."""
    return get_customer_by_id(customer_id)


class StaleWriteError(Exception):
    """Raised when an If-Match guard detects a concurrent write."""
    pass


def update_customer_fields(customer_id: int, data: dict,
                           if_match: str = None):
    """Partial update of the customer profile. Only known keys are written;
    sensitive columns are re-encrypted via _enc/_det_enc. Returns the new
    row (decrypted) so callers can echo it back to the UI and audit it.

    If `if_match` is provided, the row's current updated_at must equal it
    or `StaleWriteError` is raised (caller maps to HTTP 409). When omitted
    the call is last-writer-wins (backwards-compat for legacy clients)."""
    allowed_plain     = {"name", "company", "customer_type", "active"}
    allowed_encrypted = {"phone", "address", "notes"}      # _enc
    sets, vals = [], []
    for k, v in data.items():
        if k in allowed_plain:
            sets.append(f"{k} = ?")
            vals.append(v)
        elif k in allowed_encrypted:
            sets.append(f"{k} = ?")
            vals.append(_enc(v if v is not None else ""))
        elif k == "email":
            sets.append("email = ?")
            sets.append("email_hash = ?")
            vals.append(_det_enc(v or ""))
            vals.append(_email_hash(v or ""))
    if not sets:
        return get_customer_by_id(customer_id)
    now = datetime.now(timezone.utc).isoformat()
    sets.append("updated_at = ?"); vals.append(now)
    vals.append(customer_id)
    con = _con()
    if if_match is not None:
        cur = con.execute(
            "SELECT updated_at FROM customers WHERE id = ?", (customer_id,)
        ).fetchone()
        if cur and (cur["updated_at"] or "") != if_match:
            con.close()
            raise StaleWriteError("customer row updated_at does not match If-Match")
    con.execute(f"UPDATE customers SET {', '.join(sets)} WHERE id = ?", vals)
    if data.get("active") == 0:
        con.execute(
            "UPDATE customers SET terminated_at = ? WHERE id = ?",
            (now, customer_id),
        )
    con.commit()
    con.close()
    return get_customer_by_id(customer_id)


def get_customer_equipment_with_visits(customer_id: int):
    """Equipment register joined with the most recent PM + CM dates per unit.
    Sensitive columns (serial_number, location, notes) are decrypted."""
    con = _con()
    rows = con.execute(
        """
        SELECT e.*,
               (SELECT MAX(COALESCE(completed_date, scheduled_date))
                  FROM maintenance_visits v
                  WHERE v.equipment_id = e.id AND v.visit_type = 'PM') AS last_pm_visit,
               (SELECT MAX(COALESCE(completed_date, scheduled_date))
                  FROM maintenance_visits v
                  WHERE v.equipment_id = e.id AND v.visit_type = 'CM') AS last_cm_visit
        FROM equipment e
        WHERE e.customer_id = ?
        ORDER BY e.name
        """,
        (customer_id,),
    ).fetchall()
    con.close()
    return _dec_rows("equipment", rows)


def get_customer_visits_paginated(customer_id: int, page: int = 1, limit: int = 10):
    """Reverse-chronological visit list for one customer, paginated. Returns
    {rows, page, limit, total}. Joins technician name + equipment name."""
    page  = max(1, int(page or 1))
    limit = max(1, min(100, int(limit or 10)))
    offset = (page - 1) * limit
    con = _con()
    total = con.execute(
        "SELECT COUNT(*) AS n FROM maintenance_visits WHERE customer_id = ?",
        (customer_id,),
    ).fetchone()["n"]
    rows = con.execute(
        """
        SELECT v.id, v.customer_id, v.equipment_id, v.visit_type, v.status,
               v.scheduled_date, v.scheduled_time, v.completed_date,
               v.created_at, v.scope_of_work, v.work_done, v.work_done_summary,
               v.assigned_tech_id,
               e.name AS equipment_name,
               COALESCE(t.name, v.technician) AS tech_name
        FROM maintenance_visits v
        LEFT JOIN equipment   e ON v.equipment_id     = e.id
        LEFT JOIN technicians t ON v.assigned_tech_id = t.id
        WHERE v.customer_id = ?
        ORDER BY COALESCE(v.completed_date, v.scheduled_date, v.created_at) DESC,
                 v.id DESC
        LIMIT ? OFFSET ?
        """,
        (customer_id, limit, offset),
    ).fetchall()
    con.close()
    return {
        "rows":  _dec_rows("maintenance_visits", rows),
        "page":  page,
        "limit": limit,
        "total": int(total or 0),
    }


# ── Visit Detail View (super_admin) ─────────────────────────────────────────
# Helpers backing the super_admin visit-detail screen. Mirrors the
# customer-detail pattern: decryption on read, audit redaction in the
# update path, no other invoice columns touched besides payment fields.

def get_visit_full_detail(visit_id: int):
    """Returns the full read-only payload for the Visit Detail View:
    visit + customer + equipment + tech + scope + notes + readings + parts
    (with per-line totals and grand total) + invoice summary + callback info.
    Encrypted columns are decrypted. Returns None if visit not found."""
    con = _con()
    row = con.execute(
        """
        SELECT v.*,
               c.id           AS customer_id,
               c.customer_code,
               c.name         AS customer_name,
               c.company      AS customer_company,
               c.customer_type AS customer_type,
               c.email        AS customer_email,
               c.phone        AS customer_phone,
               c.address      AS customer_address,
               c.active       AS customer_active,
               e.name         AS equipment_name,
               e.type         AS equipment_type,
               e.model        AS equipment_model,
               e.location     AS equipment_location,
               t.id           AS tech_id,
               t.tech_code    AS tech_code,
               t.name         AS tech_name,
               t.hourly_rate  AS tech_hourly_rate
        FROM maintenance_visits v
        JOIN customers c ON v.customer_id = c.id
        LEFT JOIN equipment   e ON v.equipment_id     = e.id
        LEFT JOIN technicians t ON v.assigned_tech_id = t.id
        WHERE v.id = ?
        """,
        (visit_id,),
    ).fetchone()
    if not row:
        con.close()
        return None
    d = dict(row)

    # Decrypt visit-level encrypted columns
    for k in ("work_done", "parts_replaced", "notes",
              "contact_person_phone", "hazards", "access_codes"):
        if d.get(k):
            try: d[k] = _dec(d[k])
            except Exception: pass
    # Decrypt joined-from-customer / equipment encrypted columns
    for k in ("customer_phone", "customer_address", "equipment_location"):
        if d.get(k):
            try: d[k] = _dec(d[k])
            except Exception: pass
    # Customer email is deterministic-encrypted
    if d.get("customer_email"):
        try: d["customer_email"] = _det_dec(d["customer_email"])
        except Exception: pass

    # ── Duration (decimal hours from start_time/end_time) ──────────────────
    duration_hours = None
    if d.get("start_time") and d.get("end_time"):
        try:
            s = datetime.fromisoformat(d["start_time"].replace("Z", "+00:00"))
            e = datetime.fromisoformat(d["end_time"].replace("Z",   "+00:00"))
            duration_hours = round((e - s).total_seconds() / 3600.0, 2)
        except Exception:
            duration_hours = None
    d["duration_hours"] = duration_hours

    # ── Readings ──────────────────────────────────────────────────────────
    readings = [dict(r) for r in con.execute(
        "SELECT * FROM visit_readings WHERE visit_id = ? ORDER BY recorded_at ASC",
        (visit_id,),
    ).fetchall()]
    # Flatten to UI-friendly per-metric rows; skip metrics with no value.
    reading_rows = []
    if readings:
        r0 = readings[0]
        for label, key, unit in [
            ("Pressure (High)", "pressure_high", "psi"),
            ("Pressure (Low)",  "pressure_low",  "psi"),
            ("Supply Temp",     "temp_supply",   "°F"),
            ("Return Temp",     "temp_return",   "°F"),
            ("Delta T",         "delta_t",       "°F"),
            ("Superheat",       "superheat",     "°F"),
            ("Subcool",         "subcool",       "°F"),
            ("Approach Temp",   "approach_temp", "°F"),
        ]:
            val = r0.get(key)
            if val is None or val == "":
                continue
            reading_rows.append({
                "reading": label, "value": val, "unit": unit,
                "notes": r0.get("notes") or "",
            })
    d["readings"] = reading_rows

    # ── Parts used (with per-line + grand total) ──────────────────────────
    part_rows = con.execute(
        """
        SELECT vp.id, vp.visit_id, vp.part_id, vp.quantity, vp.unit_price,
               vp.notes, vp.created_at,
               p.sku, p.name AS part_name, p.unit AS part_unit
        FROM visit_parts vp
        JOIN parts p ON vp.part_id = p.id
        WHERE vp.visit_id = ?
        ORDER BY vp.created_at, vp.id
        """,
        (visit_id,),
    ).fetchall()
    parts_total = 0.0
    parts = []
    for pr in part_rows:
        pr = dict(pr)
        q = float(pr.get("quantity") or 0)
        up = float(pr.get("unit_price") or 0)
        line_total = round(q * up, 2)
        parts_total += line_total
        pr["line_total"] = line_total
        parts.append(pr)
    d["parts_used"] = parts
    d["parts_total"] = round(parts_total, 2)

    # ── Invoice summary (payment fields are the only editable bit) ────────
    inv_row = con.execute(
        """
        SELECT id, invoice_number, issue_date, due_date, status,
               subtotal, tax_rate, tax_amount, total, amount_paid,
               currency, notes, paid_at, updated_at
        FROM invoices WHERE visit_id = ?
        ORDER BY id DESC LIMIT 1
        """,
        (visit_id,),
    ).fetchone()
    if inv_row:
        inv = dict(inv_row)
        # Sum labor lines vs. parts lines for the read-only breakdown
        line_rows = con.execute(
            "SELECT line_type, line_total FROM invoice_line_items WHERE invoice_id = ?",
            (inv["id"],),
        ).fetchall()
        labor_total = 0.0
        parts_line_total = 0.0
        other_total = 0.0
        for li in line_rows:
            lt = float(li["line_total"] or 0)
            kind = (li["line_type"] or "other").lower()
            if   kind == "labor": labor_total += lt
            elif kind == "part":  parts_line_total += lt
            else:                  other_total += lt
        inv["labor_total"]  = round(labor_total, 2)
        inv["parts_total"]  = round(parts_line_total, 2)
        inv["other_total"]  = round(other_total, 2)
        inv["outstanding"]  = round(float(inv["total"] or 0) - float(inv["amount_paid"] or 0), 2)
        # Most-recent recorded payment method/date (read-only mirror for UI)
        last_pay = con.execute(
            "SELECT method, payment_date, notes FROM invoice_payments "
            "WHERE invoice_id = ? ORDER BY payment_date DESC, id DESC LIMIT 1",
            (inv["id"],),
        ).fetchone()
        if last_pay:
            inv["last_payment_method"] = last_pay["method"]
            inv["last_payment_date"]   = last_pay["payment_date"]
            inv["last_payment_notes"]  = last_pay["notes"] or ""
        else:
            inv["last_payment_method"] = None
            inv["last_payment_date"]   = None
            inv["last_payment_notes"]  = ""
        # Derive UI-facing payment_status from invoice.status + amount_paid
        ip = float(inv["amount_paid"] or 0)
        tot = float(inv["total"] or 0)
        if (inv["status"] == "paid") or (tot > 0 and ip >= tot):
            inv["payment_status"] = "fully_paid"
        elif ip > 0:
            inv["payment_status"] = "partially_paid"
        else:
            inv["payment_status"] = "unpaid"
        d["invoice"] = inv
    else:
        d["invoice"] = None

    # ── Callback linkage ──────────────────────────────────────────────────
    parent_id = None
    try:
        cur_row = con.execute(
            "SELECT callback_of_visit_id FROM maintenance_visits WHERE id = ?",
            (visit_id,),
        ).fetchone()
        if cur_row and "callback_of_visit_id" in cur_row.keys():
            parent_id = cur_row["callback_of_visit_id"]
    except Exception:
        parent_id = None
    parent_row = None
    if parent_id:
        try:
            p = con.execute(
                "SELECT id, visit_type, status, completed_date, scheduled_date "
                "FROM maintenance_visits WHERE id = ?", (parent_id,),
            ).fetchone()
            parent_row = dict(p) if p else None
        except Exception:
            parent_row = None
    try:
        children = con.execute(
            "SELECT id, visit_type, status, completed_date, scheduled_date "
            "FROM maintenance_visits WHERE callback_of_visit_id = ? "
            "ORDER BY id ASC", (visit_id,),
        ).fetchall()
        child_rows = [dict(r) for r in children]
    except Exception:
        child_rows = []
    d["callback"] = {
        "is_callback":  parent_row is not None,
        "callback_of":  parent_row,
        "callbacks":    child_rows,
    }

    con.close()
    return d


def get_visit_photos_for_admin(visit_id: int):
    """Admin-facing photo list for the Visit Detail View. Returns a list of
    dicts: photo_id, label (category), timestamp, uploader_name, filename.
    Signed URLs are added by the caller (main.py) via _enrich_photos so the
    HMAC secret stays out of database.py."""
    con = _con()
    rows = con.execute(
        """
        SELECT vp.id, vp.visit_id, vp.category, vp.filename,
               vp.uploaded_by, vp.uploaded_at, vp.client_captured_at,
               t.name AS uploader_name
        FROM visit_photos vp
        LEFT JOIN technicians t ON vp.uploaded_by = t.id
        WHERE vp.visit_id = ?
        ORDER BY vp.category, vp.uploaded_at, vp.id
        """,
        (visit_id,),
    ).fetchall()
    con.close()
    return [dict(r) for r in rows]


def update_invoice_payment_status(invoice_id: int, status: str,
                                  payment_method: str = None,
                                  payment_date: str = None,
                                  notes: str = None,
                                  amount: float = None,
                                  if_match: str = None,
                                  actor_id: int = None,
                                  actor_label: str = None,
                                  actor_prid: str = None):
    """Visit-side payment edit. Both visit-side and invoice-side payment
    edits flow through record_invoice_payment_v2 — single source of truth.

    Behavior:
      * status='fully_paid': append a payment row equal to (total -
        already_paid) via record_invoice_payment_v2 (chain-hashed).
      * status='partially_paid': append a payment row of `amount` (caller
        supplied). If amount is missing, no payment row is written — only
        the header notes get updated.
      * status='unpaid': append a *void* row with negative `amount` =
        -(amount_paid) tagged via the `voided_at` marker so the chain stays
        append-only; the prior payments remain on the books for forensic
        review.
    """
    now = datetime.now(timezone.utc).isoformat()
    con = _con()

    inv = con.execute(
        "SELECT id, total, status, amount_paid, updated_at "
        "FROM invoices WHERE id = ?",
        (invoice_id,),
    ).fetchone()
    if not inv:
        con.close()
        return None
    if if_match is not None and (inv["updated_at"] or "") != if_match:
        con.close()
        raise StaleWriteError("invoice row updated_at does not match If-Match")
    total = float(inv["total"] or 0)
    paid_so_far = float(inv["amount_paid"] or 0)
    con.close()

    if status == "unpaid":
        # Void: append a negative-amount marker row with voided_at set.
        # We do not DELETE — chain stays intact and prior payments remain
        # visible to the auditor.
        if paid_so_far > 0:
            void_payload = {
                "amount_jmd":     -round(paid_so_far, 2),
                "payment_method": (payment_method or "other"),
                "payment_date":   (payment_date or now[:10]),
                "notes":          (notes or "Voided by visit-side payment edit"),
            }
            record_invoice_payment_v2(
                invoice_id, void_payload,
                recorded_by=actor_id,
                recorded_by_label=actor_label,
                recorded_by_prid=actor_prid,
            )
            # Mark the most recent payment row as voided for surfaceable UI.
            c2 = _con()
            c2.execute(
                "UPDATE invoice_payments SET voided_at = ? "
                "WHERE invoice_id = ? AND id = ("
                "  SELECT id FROM invoice_payments WHERE invoice_id = ? "
                "  ORDER BY id DESC LIMIT 1)",
                (now, invoice_id, invoice_id),
            )
            c2.commit()
            c2.close()
    elif status == "fully_paid":
        delta = round(total - paid_so_far, 2)
        if delta > 0.005:
            payload = {
                "amount_jmd":     delta,
                "payment_method": (payment_method or "other"),
                "payment_date":   (payment_date or now[:10]),
                "notes":          (notes or ""),
            }
            record_invoice_payment_v2(
                invoice_id, payload,
                recorded_by=actor_id,
                recorded_by_label=actor_label,
                recorded_by_prid=actor_prid,
            )
    elif status == "partially_paid":
        # Honor explicit amount if supplied; else write header-only update.
        if amount is not None and float(amount) > 0:
            payload = {
                "amount_jmd":     float(amount),
                "payment_method": (payment_method or "other"),
                "payment_date":   (payment_date or now[:10]),
                "notes":          (notes or ""),
            }
            record_invoice_payment_v2(
                invoice_id, payload,
                recorded_by=actor_id,
                recorded_by_label=actor_label,
                recorded_by_prid=actor_prid,
            )

    # Header notes + status text reconciliation (record_invoice_payment_v2
    # already flips to 'paid' when fully covered; we sync the legacy text
    # for the partial/unpaid cases and persist the user-supplied notes).
    con = _con()
    inv_now = con.execute(
        "SELECT status, total, amount_paid FROM invoices WHERE id = ?",
        (invoice_id,),
    ).fetchone()
    new_status = inv_now["status"] or "draft"
    if status == "unpaid" and new_status == "paid":
        new_status = "sent"
    elif status == "partially_paid" and new_status == "paid":
        new_status = "sent"
    con.execute(
        "UPDATE invoices SET status = ?, notes = ?, updated_at = ? "
        "WHERE id = ?",
        (new_status, (notes or ""), now, invoice_id),
    )
    con.commit()
    out = con.execute(
        "SELECT id, invoice_number, status, total, amount_paid, notes, paid_at, updated_at "
        "FROM invoices WHERE id = ?",
        (invoice_id,),
    ).fetchone()
    con.close()
    return dict(out) if out else None


# ── Equipment ─────────────────────────────────────────────────────────────────

def get_equipment_by_id(equipment_id: int):
    con = _con()
    row = con.execute("SELECT * FROM equipment WHERE id = ?", (equipment_id,)).fetchone()
    con.close()
    return _dec_row("equipment", row)


def get_customer_equipment(customer_id: int):
    con = _con()
    rows = con.execute(
        "SELECT * FROM equipment WHERE customer_id = ? ORDER BY name", (customer_id,)
    ).fetchall()
    con.close()
    return _dec_rows("equipment", rows)


def get_customer_equipment_portal_safe(customer_id: int):
    """Portal-safe view of a customer's equipment register. Selects ONLY
    the columns that are appropriate for the self-service portal — never
    returns the decrypted `serial_number` or `notes` columns (admin-only
    PII). Used by GET /api/portal/me to plug the equipment leak.
    """
    con = _con()
    rows = con.execute(
        "SELECT id, customer_id, name, type, model, location, created_at "
        "FROM equipment WHERE customer_id = ? ORDER BY name",
        (customer_id,),
    ).fetchall()
    con.close()
    # `location` is encrypted at rest — we still decrypt it because the
    # portal already shows the install location to the customer. Serial
    # numbers and free-form notes are admin-only and never returned here.
    out = []
    for r in rows:
        d = dict(r)
        d["location"] = _dec(d.get("location") or "")
        out.append(d)
    return out


def create_equipment(data: dict) -> int:
    con = _con()
    cur = con.execute(
        """
        INSERT INTO equipment (customer_id, name, type, model, serial_number, location, notes, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            data["customer_id"],
            data["name"],
            data.get("type", ""),
            data.get("model", ""),
            _enc(data.get("serial_number", "")),
            _enc(data.get("location", "")),
            _enc(data.get("notes", "")),
            datetime.now(timezone.utc).isoformat(),
        ),
    )
    equipment_id = cur.lastrowid
    con.commit()
    con.close()
    return equipment_id


def delete_equipment(equipment_id: int):
    con = _con()
    con.execute("DELETE FROM maintenance_visits WHERE equipment_id = ?", (equipment_id,))
    con.execute("DELETE FROM equipment WHERE id = ?", (equipment_id,))
    con.commit()
    con.close()


# ── Maintenance Visits ────────────────────────────────────────────────────────

def get_customer_visits(customer_id: int):
    con = _con()
    rows = con.execute(
        """
        SELECT v.*, e.name AS equipment_name
        FROM maintenance_visits v
        LEFT JOIN equipment e ON v.equipment_id = e.id
        WHERE v.customer_id = ?
        ORDER BY COALESCE(v.scheduled_date, v.created_at) DESC
        """,
        (customer_id,),
    ).fetchall()
    con.close()
    return _dec_rows("maintenance_visits", rows)


def get_all_visits():
    con = _con()
    rows = con.execute(
        """
        SELECT v.*, c.name AS customer_name, c.customer_code, e.name AS equipment_name
        FROM maintenance_visits v
        JOIN customers c ON v.customer_id = c.id
        LEFT JOIN equipment e ON v.equipment_id = e.id
        ORDER BY COALESCE(v.scheduled_date, v.created_at) DESC
        """,
    ).fetchall()
    con.close()
    return _dec_rows("maintenance_visits", rows)


def create_visit(data: dict) -> int:
    con = _con()
    cur = con.execute(
        """
        INSERT INTO maintenance_visits
            (customer_id, equipment_id, visit_type, status, scheduled_date,
             scheduled_time, completed_date, technician, work_done, parts_replaced,
             notes, assigned_tech_id, start_time, end_time, created_at,
             scope_of_work, estimated_duration_min, contact_person_name,
             contact_person_phone, hazards, access_codes)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            data["customer_id"],
            data.get("equipment_id") or None,
            data["visit_type"].upper(),
            data.get("status", "scheduled"),
            data.get("scheduled_date") or None,
            data.get("scheduled_time") or None,
            data.get("completed_date") or None,
            data.get("technician", ""),
            _enc(data.get("work_done", "")),
            _enc(data.get("parts_replaced", "")),
            _enc(data.get("notes", "")),
            data.get("assigned_tech_id") or None,
            data.get("start_time") or None,
            data.get("end_time") or None,
            datetime.now(timezone.utc).isoformat(),
            data.get("scope_of_work", ""),
            data.get("estimated_duration_min") or None,
            data.get("contact_person_name", ""),
            _enc(data.get("contact_person_phone", "")),
            _enc(data.get("hazards", "")),
            _enc(data.get("access_codes", "")),
        ),
    )
    visit_id = cur.lastrowid
    con.commit()
    con.close()
    return visit_id


def update_visit(visit_id: int, data: dict):
    con = _con()
    con.execute(
        """
        UPDATE maintenance_visits SET
            equipment_id           = ?,
            visit_type             = ?,
            status                 = ?,
            scheduled_date         = ?,
            scheduled_time         = ?,
            completed_date         = ?,
            technician             = ?,
            work_done              = ?,
            parts_replaced         = ?,
            notes                  = ?,
            assigned_tech_id       = ?,
            scope_of_work          = ?,
            estimated_duration_min = ?,
            contact_person_name    = ?,
            contact_person_phone   = ?,
            hazards                = ?,
            access_codes           = ?
        WHERE id = ?
        """,
        (
            data.get("equipment_id") or None,
            data["visit_type"].upper(),
            data["status"],
            data.get("scheduled_date") or None,
            data.get("scheduled_time") or None,
            data.get("completed_date") or None,
            data.get("technician", ""),
            _enc(data.get("work_done", "")),
            _enc(data.get("parts_replaced", "")),
            _enc(data.get("notes", "")),
            data.get("assigned_tech_id") or None,
            data.get("scope_of_work", ""),
            data.get("estimated_duration_min") or None,
            data.get("contact_person_name", ""),
            _enc(data.get("contact_person_phone", "")),
            _enc(data.get("hazards", "")),
            _enc(data.get("access_codes", "")),
            visit_id,
        ),
    )
    con.commit()
    con.close()


def get_visit_by_id(visit_id: int, with_parts: bool = False):
    con = _con()
    row = con.execute(
        """
        SELECT v.*, c.name AS customer_name, c.company AS customer_company,
               c.phone AS customer_phone, c.address AS customer_address,
               c.customer_code, e.name AS equipment_name, e.type AS equipment_type,
               e.model AS equipment_model, e.location AS equipment_location,
               t.name AS tech_name, t.hourly_rate AS tech_hourly_rate
        FROM maintenance_visits v
        JOIN customers c ON v.customer_id = c.id
        LEFT JOIN equipment   e ON v.equipment_id     = e.id
        LEFT JOIN technicians t ON v.assigned_tech_id = t.id
        WHERE v.id = ?
        """,
        (visit_id,),
    ).fetchone()
    con.close()
    if not row:
        return None
    # Decrypt joined customer + equipment + visit fields. The JOIN aliases
    # (customer_phone, customer_address, equipment_location) hold encrypted
    # ciphertext from the source tables — wrap them with the right table
    # decrypt mapping.
    d = dict(row)
    for k in ("work_done", "parts_replaced", "notes",
              "contact_person_phone", "hazards", "access_codes"):
        if d.get(k):
            try: d[k] = _dec(d[k])
            except Exception: pass
    for k in ("customer_phone", "customer_address", "equipment_location"):
        if d.get(k):
            try: d[k] = _dec(d[k])
            except Exception: pass
    if with_parts:
        d["parts_used"] = get_visit_parts(visit_id)
    return d


def update_visit_time(visit_id: int, field: str, value: str):
    """field: 'start_time' or 'end_time'"""
    if field not in ("start_time", "end_time"):
        raise ValueError("invalid field")
    con = _con()
    con.execute(f"UPDATE maintenance_visits SET {field} = ? WHERE id = ?", (value, visit_id))
    con.commit()
    con.close()


def tech_complete_visit(visit_id: int, work_done: str, parts: str, notes: str,
                        end_time: str, completed_date: str,
                        next_pm_due: str = None):
    """Marks the visit completed AND submitted. submitted_at is the lock:
    once set, the tech-side complete endpoint refuses further edits."""
    con = _con()
    con.execute(
        """
        UPDATE maintenance_visits SET
            status         = 'completed',
            work_done      = ?,
            parts_replaced = ?,
            notes          = ?,
            end_time       = ?,
            completed_date = ?,
            next_pm_due    = COALESCE(?, next_pm_due),
            submitted_at   = COALESCE(submitted_at, ?)
        WHERE id = ?
        """,
        (_enc(work_done), _enc(parts), _enc(notes),
         end_time, completed_date, next_pm_due, end_time, visit_id),
    )
    con.commit()
    con.close()


def get_tech_jobs(tech_id: int):
    """Tech-facing job list. Customer phone is intentionally NOT included —
    per spec the tech only sees the contact_person fields on the visit,
    never the client's primary phone. The address is included for routing."""
    con = _con()
    rows = con.execute(
        """
        SELECT v.id, v.customer_id, v.equipment_id, v.visit_type, v.status,
               v.scheduled_date, v.scheduled_time, v.completed_date,
               v.start_time, v.end_time, v.work_done, v.parts_replaced,
               v.notes, v.assigned_tech_id, v.created_at,
               v.submitted_at, v.scope_of_work, v.estimated_duration_min,
               v.next_pm_due, v.contact_person_name, v.contact_person_phone,
               v.hazards, v.access_codes, v.flagged_for_review, v.review_note,
               c.name AS customer_name, c.company AS customer_company,
               c.address AS customer_address, c.customer_code,
               e.name AS equipment_name
        FROM maintenance_visits v
        JOIN customers c ON v.customer_id = c.id
        LEFT JOIN equipment e ON v.equipment_id = e.id
        WHERE v.assigned_tech_id = ?
        ORDER BY COALESCE(v.scheduled_date, v.created_at) ASC
        """,
        (tech_id,),
    ).fetchall()
    con.close()
    out = []
    for r in rows:
        d = dict(r)
        for k in ("work_done", "parts_replaced", "notes",
                  "contact_person_phone", "hazards", "access_codes",
                  "customer_address"):
            if d.get(k):
                try: d[k] = _dec(d[k])
                except Exception: pass
        out.append(d)
    return out


def delete_visit(visit_id: int):
    con = _con()
    con.execute("DELETE FROM maintenance_visits WHERE id = ?", (visit_id,))
    con.commit()
    con.close()


# ── Reviews ───────────────────────────────────────────────────────────────────

def create_review(data: dict) -> int:
    con = _con()
    cur = con.execute(
        """
        INSERT INTO reviews
            (customer_id, visit_id, review_type, rating, text, role,
             tech_snapshot, visit_type_snapshot, status, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?)
        """,
        (
            data["customer_id"],
            data.get("visit_id"),
            data["review_type"],
            int(data["rating"]),
            data["text"],
            data.get("role", ""),
            data.get("tech_snapshot", ""),
            data.get("visit_type_snapshot", ""),
            datetime.now(timezone.utc).isoformat(),
        ),
    )
    review_id = cur.lastrowid
    con.commit()
    con.close()
    return review_id


def get_review_for_visit(customer_id: int, visit_id: int):
    con = _con()
    row = con.execute(
        "SELECT * FROM reviews WHERE customer_id = ? AND visit_id = ?",
        (customer_id, visit_id),
    ).fetchone()
    con.close()
    return dict(row) if row else None


def get_customer_reviews(customer_id: int):
    con = _con()
    rows = con.execute(
        "SELECT * FROM reviews WHERE customer_id = ? ORDER BY created_at DESC",
        (customer_id,),
    ).fetchall()
    con.close()
    return [dict(r) for r in rows]


def get_all_reviews(status: str = None):
    con = _con()
    sql = """
        SELECT r.*, c.name AS customer_name, c.company AS customer_company, c.customer_code
        FROM reviews r
        JOIN customers c ON r.customer_id = c.id
    """
    args = ()
    if status:
        sql += " WHERE r.status = ?"
        args = (status,)
    sql += " ORDER BY r.created_at DESC"
    rows = con.execute(sql, args).fetchall()
    con.close()
    return [dict(r) for r in rows]


def get_approved_reviews(limit: int = None):
    con = _con()
    sql = """
        SELECT r.rating, r.text, r.role, r.review_type, r.tech_snapshot,
               r.created_at, r.approved_at,
               c.name AS customer_name, c.company AS customer_company
        FROM reviews r
        JOIN customers c ON r.customer_id = c.id
        WHERE r.status = 'approved'
        ORDER BY COALESCE(r.approved_at, r.created_at) DESC
    """
    if limit:
        sql += f" LIMIT {int(limit)}"
    rows = con.execute(sql).fetchall()
    con.close()
    return [dict(r) for r in rows]


def update_review_status(review_id: int, status: str):
    con = _con()
    approved_at = datetime.now(timezone.utc).isoformat() if status == "approved" else None
    con.execute(
        "UPDATE reviews SET status = ?, approved_at = ? WHERE id = ?",
        (status, approved_at, review_id),
    )
    con.commit()
    con.close()


def delete_review(review_id: int):
    con = _con()
    con.execute("DELETE FROM reviews WHERE id = ?", (review_id,))
    con.commit()
    con.close()


# ── Technicians ───────────────────────────────────────────────────────────────

def get_tech_by_code(code: str):
    con = _con()
    row = con.execute(
        "SELECT * FROM technicians WHERE tech_code = ? AND active = 1",
        (code.strip().upper(),),
    ).fetchone()
    con.close()
    return _dec_row("technicians", row)


def get_tech_by_id(tech_id: int):
    con = _con()
    row = con.execute("SELECT * FROM technicians WHERE id = ?", (tech_id,)).fetchone()
    con.close()
    return _dec_row("technicians", row)


def verify_tech(code: str, pin: str):
    tech = get_tech_by_code(code)
    if not tech or not _verify_pin(pin, tech["pin_hash"]):
        return None
    if _needs_rehash(tech["pin_hash"]):
        set_tech_pin(tech["id"], pin)
    return tech


def get_all_techs():
    con = _con()
    rows = con.execute(
        """
        SELECT t.id, t.tech_code, t.name, t.phone, t.email, t.role, t.prid,
               t.hourly_rate, t.active, t.created_at,
               (SELECT COUNT(*) FROM maintenance_visits v
                WHERE v.assigned_tech_id = t.id AND v.status != 'completed') AS active_jobs
        FROM technicians t
        ORDER BY t.active DESC, t.name
        """
    ).fetchall()
    con.close()
    return _dec_rows("technicians", rows)


def create_tech(data: dict) -> tuple:
    """Returns (tech_id, prid). If `tech_code` not provided, PRID is used as the tech_code."""
    hire_date = (data.get("hire_date") or "").strip() or None
    prid      = generate_prid(name=data["name"], hire_date=hire_date)
    raw_code  = (data.get("tech_code") or "").strip().upper()
    tech_code = raw_code if raw_code else prid
    con = _con()
    cur = con.execute(
        """
        INSERT INTO technicians
            (tech_code, pin_hash, name, phone, email, email_hash, role, prid, hire_date, hourly_rate, active, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?)
        """,
        (
            tech_code,
            _hash_pin(data["pin"]),
            data["name"],
            _enc(data.get("phone", "")),
            _det_enc(data.get("email", "")),
            _email_hash(data.get("email", "")),
            data.get("role", "tech"),
            prid,
            hire_date,
            float(data.get("hourly_rate") or 0),
            datetime.now(timezone.utc).isoformat(),
        ),
    )
    tech_id = cur.lastrowid
    con.commit()
    con.close()
    return tech_id, prid


def set_tech_pin(tech_id: int, pin: str):
    con = _con()
    con.execute("UPDATE technicians SET pin_hash = ? WHERE id = ?", (_hash_pin(pin), tech_id))
    con.commit()
    con.close()


def update_tech(tech_id: int, data: dict):
    con = _con()
    con.execute(
        "UPDATE technicians SET name = ?, phone = ?, email = ?, email_hash = ?, role = ?, hourly_rate = ?, active = ? WHERE id = ?",
        (
            data.get("name", ""),
            _enc(data.get("phone", "")),
            _det_enc(data.get("email", "")),
            _email_hash(data.get("email", "")),
            data.get("role", "tech"),
            float(data.get("hourly_rate") or 0),
            1 if data.get("active", True) else 0,
            tech_id,
        ),
    )
    con.commit()
    con.close()


def get_tech_by_code_and_email(code: str, email: str):
    con = _con()
    row = con.execute(
        "SELECT * FROM technicians WHERE tech_code = ? AND email_hash = ? AND active = 1",
        (code.strip().upper(), _email_hash(email)),
    ).fetchone()
    con.close()
    return _dec_row("technicians", row)


def create_pin_reset_token(tech_id: int) -> str:
    from datetime import timedelta
    token   = secrets.token_urlsafe(24)
    expires = (datetime.now(timezone.utc) + timedelta(minutes=30)).isoformat()
    con = _con()
    con.execute(
        "INSERT INTO tech_pin_resets (tech_id, token, expires_at, created_at) VALUES (?, ?, ?, ?)",
        (tech_id, token, expires, datetime.now(timezone.utc).isoformat()),
    )
    con.commit()
    con.close()
    return token


def consume_pin_reset_token(token: str):
    con = _con()
    row = con.execute(
        "SELECT * FROM tech_pin_resets WHERE token = ? AND used_at IS NULL",
        (token,),
    ).fetchone()
    if not row:
        con.close()
        return None
    row = dict(row)
    if row["expires_at"] < datetime.now(timezone.utc).isoformat():
        con.close()
        return None
    con.execute(
        "UPDATE tech_pin_resets SET used_at = ? WHERE id = ?",
        (datetime.now(timezone.utc).isoformat(), row["id"]),
    )
    con.commit()
    con.close()
    return row["tech_id"]


def delete_tech(tech_id: int):
    con = _con()
    con.execute("UPDATE maintenance_visits SET assigned_tech_id = NULL WHERE assigned_tech_id = ?", (tech_id,))
    con.execute("DELETE FROM technicians WHERE id = ?", (tech_id,))
    con.commit()
    con.close()


# ── Visit Photos ──────────────────────────────────────────────────────────────

_PHOTO_META_COLS = (
    "server_ip", "server_ua",
    "client_captured_at",
    "geo_lat", "geo_lng", "geo_accuracy_m", "geo_captured_at",
    "device_platform", "device_model", "device_screen",
    "camera_facing", "camera_width", "camera_height",
    "network_type", "app_version",
    "client_meta_json",
)


def create_photo(visit_id: int, category: str, filename: str,
                  tech_id: int = None, metadata: dict = None) -> int:
    """metadata is a dict whose keys are a subset of _PHOTO_META_COLS.
    Encrypted columns (server_ua, client_meta_json) go through _enc_dict.
    Unknown keys are silently ignored."""
    import json as _json
    md = dict(metadata or {})
    # Normalise: client_meta_json may arrive as a dict — store as JSON string.
    if isinstance(md.get("client_meta_json"), (dict, list)):
        md["client_meta_json"] = _json.dumps(md["client_meta_json"])
    # Encrypt the at-rest columns named in the registry.
    md_enc = _enc_dict("visit_photos", md)
    # Build dynamic INSERT including only the meta columns the caller passed.
    cols  = ["visit_id", "category", "filename", "uploaded_by", "uploaded_at"]
    vals  = [visit_id, category, filename, tech_id,
             datetime.now(timezone.utc).isoformat()]
    for k in _PHOTO_META_COLS:
        if k in md_enc and md_enc[k] is not None:
            cols.append(k)
            vals.append(md_enc[k])
    placeholders = ", ".join("?" for _ in vals)
    con = _con()
    cur = con.execute(
        f"INSERT INTO visit_photos ({', '.join(cols)}) VALUES ({placeholders})",
        vals,
    )
    photo_id = cur.lastrowid
    con.commit()
    con.close()
    return photo_id


def get_visit_photos(visit_id: int):
    con = _con()
    rows = con.execute(
        "SELECT * FROM visit_photos WHERE visit_id = ? ORDER BY category, uploaded_at",
        (visit_id,),
    ).fetchall()
    con.close()
    return _dec_rows("visit_photos", rows)


def get_photo_by_id(photo_id: int):
    con = _con()
    row = con.execute("SELECT * FROM visit_photos WHERE id = ?", (photo_id,)).fetchone()
    con.close()
    return _dec_row("visit_photos", row) if row else None


def delete_photo(photo_id: int):
    con = _con()
    con.execute("DELETE FROM visit_photos WHERE id = ?", (photo_id,))
    con.commit()
    con.close()


# ── Admin Users ───────────────────────────────────────────────────────────────

def _hash_password(pw: str) -> str:
    """Argon2id is the modern default. Pbkdf2 legacy verification kept for migration."""
    return _hash_pin(pw)  # same Argon2 hasher for passwords + PINs


def _verify_password(pw: str, stored: str) -> bool:
    return _verify_pin(pw, stored)


def get_admin_user_by_username(username: str):
    """Accepts either the username (legacy / bootstrap admins) OR the PRID
    (auto-generated for everyone else). One lookup, two columns, so an admin
    never has to remember which identifier their account uses."""
    con = _con()
    row = con.execute(
        """SELECT * FROM admin_users
             WHERE (LOWER(username) = LOWER(?) OR LOWER(prid) = LOWER(?))
               AND active = 1""",
        (username.strip(), username.strip()),
    ).fetchone()
    con.close()
    return _dec_row("admin_users", row)


def get_admin_user_by_id(admin_id: int):
    con = _con()
    row = con.execute("SELECT * FROM admin_users WHERE id = ?", (admin_id,)).fetchone()
    con.close()
    return _dec_row("admin_users", row)


def verify_admin_user(username: str, password: str):
    admin = get_admin_user_by_username(username)
    if not admin or not _verify_password(password, admin["password_hash"]):
        return None
    # Transparent rehash if stored format is outdated
    if _needs_rehash(admin["password_hash"]):
        set_admin_password(admin["id"], password)
    return admin


def count_active_admins(role: str = None) -> int:
    con = _con()
    if role:
        n = con.execute(
            "SELECT COUNT(*) AS n FROM admin_users WHERE active = 1 AND role = ?",
            (role,),
        ).fetchone()["n"]
    else:
        n = con.execute("SELECT COUNT(*) AS n FROM admin_users WHERE active = 1").fetchone()["n"]
    con.close()
    return n


def get_all_admin_users():
    con = _con()
    rows = con.execute(
        "SELECT id, username, name, email, phone, role, prid, active, created_at "
        "FROM admin_users ORDER BY active DESC, name"
    ).fetchall()
    con.close()
    return _dec_rows("admin_users", rows)


def create_admin_user(data: dict, created_by: int = None) -> tuple:
    """Returns (admin_id, prid). If `username` not provided, PRID is used as username."""
    hire_date = (data.get("hire_date") or "").strip() or None
    prid      = generate_prid(name=data["name"], hire_date=hire_date)
    raw_user  = (data.get("username") or "").strip()
    username  = raw_user.lower() if raw_user else prid.lower()
    con = _con()
    cur = con.execute(
        """
        INSERT INTO admin_users
            (username, password_hash, name, email, email_hash, phone, role, prid, hire_date, active, created_by, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
        """,
        (
            username,
            _hash_password(data["password"]),
            data["name"].strip(),
            _det_enc(data["email"].strip().lower()),
            _email_hash(data["email"].strip().lower()),
            _enc(data.get("phone", "").strip()),
            data["role"],
            prid,
            hire_date,
            created_by,
            datetime.now(timezone.utc).isoformat(),
        ),
    )
    admin_id = cur.lastrowid
    con.commit()
    con.close()
    return admin_id, prid


def update_admin_user(admin_id: int, data: dict):
    con = _con()
    con.execute(
        "UPDATE admin_users SET name = ?, email = ?, email_hash = ?, phone = ? WHERE id = ?",
        (
            data["name"].strip(),
            _det_enc(data["email"].strip().lower()),
            _email_hash(data["email"].strip().lower()),
            _enc(data.get("phone", "").strip()),
            admin_id,
        ),
    )
    con.commit()
    con.close()


def set_admin_role(admin_id: int, role: str):
    con = _con()
    con.execute("UPDATE admin_users SET role = ? WHERE id = ?", (role, admin_id))
    con.commit()
    con.close()


def set_admin_active(admin_id: int, active: bool):
    con = _con()
    con.execute("UPDATE admin_users SET active = ? WHERE id = ?", (1 if active else 0, admin_id))
    con.commit()
    con.close()


def set_admin_password(admin_id: int, password: str):
    con = _con()
    con.execute(
        "UPDATE admin_users SET password_hash = ? WHERE id = ?",
        (_hash_password(password), admin_id),
    )
    con.commit()
    con.close()


# ── Admin MFA ────────────────────────────────────────────────────────────────

def set_admin_mfa_pending(admin_id: int, secret: str):
    """Stores the candidate secret (AES-GCM encrypted). mfa_enabled stays 0 until activated."""
    con = _con()
    con.execute(
        "UPDATE admin_users SET mfa_secret = ?, mfa_enabled = 0 WHERE id = ?",
        (_enc(secret), admin_id),
    )
    con.commit()
    con.close()


def activate_admin_mfa(admin_id: int, backup_code_hashes: list):
    """Flips mfa_enabled to 1 and stores hashed backup codes (JSON list)."""
    import json as _json
    con = _con()
    con.execute(
        "UPDATE admin_users SET mfa_enabled = 1, backup_codes = ? WHERE id = ?",
        (_json.dumps([{"hash": h, "used_at": None} for h in backup_code_hashes]), admin_id),
    )
    con.commit()
    con.close()


def disable_admin_mfa(admin_id: int):
    con = _con()
    con.execute(
        "UPDATE admin_users SET mfa_secret = NULL, mfa_enabled = 0, backup_codes = NULL WHERE id = ?",
        (admin_id,),
    )
    con.commit()
    con.close()


def replace_admin_backup_codes(admin_id: int, backup_code_hashes: list):
    import json as _json
    con = _con()
    con.execute(
        "UPDATE admin_users SET backup_codes = ? WHERE id = ?",
        (_json.dumps([{"hash": h, "used_at": None} for h in backup_code_hashes]), admin_id),
    )
    con.commit()
    con.close()


def consume_admin_backup_code(admin_id: int, code: str) -> bool:
    """Returns True if the code matches an unused stored code and marks it used."""
    import json as _json
    admin = get_admin_user_by_id(admin_id)
    if not admin or not admin.get("backup_codes"):
        return False
    try:
        codes = _json.loads(admin["backup_codes"])
    except Exception:
        return False
    matched_idx = None
    for i, entry in enumerate(codes):
        if entry.get("used_at"):
            continue
        if _verify_pin(code, entry.get("hash", "")):
            matched_idx = i
            break
    if matched_idx is None:
        return False
    codes[matched_idx]["used_at"] = datetime.now(timezone.utc).isoformat()
    con = _con()
    con.execute(
        "UPDATE admin_users SET backup_codes = ? WHERE id = ?",
        (_json.dumps(codes), admin_id),
    )
    con.commit()
    con.close()
    return True


def get_admin_backup_codes_status(admin_id: int):
    """Returns {total, unused, used} counts (does NOT return the codes themselves)."""
    import json as _json
    admin = get_admin_user_by_id(admin_id)
    if not admin or not admin.get("backup_codes"):
        return {"total": 0, "unused": 0, "used": 0}
    try:
        codes = _json.loads(admin["backup_codes"])
    except Exception:
        return {"total": 0, "unused": 0, "used": 0}
    used = sum(1 for c in codes if c.get("used_at"))
    return {"total": len(codes), "unused": len(codes) - used, "used": used}


def get_admin_by_email(email: str):
    con = _con()
    row = con.execute(
        "SELECT * FROM admin_users WHERE email_hash = ? AND active = 1",
        (_email_hash(email),),
    ).fetchone()
    con.close()
    return _dec_row("admin_users", row)


def create_admin_password_reset(admin_id: int) -> str:
    from datetime import timedelta
    token   = secrets.token_urlsafe(24)
    expires = (datetime.now(timezone.utc) + timedelta(minutes=30)).isoformat()
    con = _con()
    con.execute(
        "INSERT INTO admin_password_resets (admin_id, token, expires_at, created_at) VALUES (?, ?, ?, ?)",
        (admin_id, token, expires, datetime.now(timezone.utc).isoformat()),
    )
    con.commit()
    con.close()
    return token


def consume_admin_password_reset(token: str):
    con = _con()
    row = con.execute(
        "SELECT * FROM admin_password_resets WHERE token = ? AND used_at IS NULL",
        (token,),
    ).fetchone()
    if not row:
        con.close()
        return None
    row = dict(row)
    if row["expires_at"] < datetime.now(timezone.utc).isoformat():
        con.close()
        return None
    con.execute(
        "UPDATE admin_password_resets SET used_at = ? WHERE id = ?",
        (datetime.now(timezone.utc).isoformat(), row["id"]),
    )
    con.commit()
    con.close()
    return row["admin_id"]


# ── Audit Log ────────────────────────────────────────────────────────────────

AUDIT_GENESIS = "GENESIS"   # chain anchor when there's no previous row


def _audit_canonical_payload(row: dict) -> str:
    """Stable canonical JSON for a row's hashable content. Field order matters."""
    return _json.dumps({
        "actor_type":   row.get("actor_type"),
        "actor_id":     row.get("actor_id"),
        "actor_prid":   row.get("actor_prid"),
        "actor_label":  row.get("actor_label"),
        "actor_role":   row.get("actor_role"),
        "action":       row.get("action"),
        "target_type":  row.get("target_type"),
        "target_id":    row.get("target_id"),
        "target_label": row.get("target_label"),
        "before_value": row.get("before_value"),
        "after_value":  row.get("after_value"),
        "ip_address":   row.get("ip_address"),
        "created_at":   row.get("created_at"),
    }, sort_keys=True, separators=(",", ":"))


def _audit_compute_hash(prev_hash: str, row: dict) -> str:
    payload = (prev_hash or AUDIT_GENESIS) + "\n" + _audit_canonical_payload(row)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _classify_retention(action: str) -> str:
    """Per audit spec, financial/legal-grade events are retained ~7 years;
    operational events are retained ~24 months. Anything labelled 'system'
    (retention purges, schema bootstraps) is kept indefinitely so we always
    know what was discarded and when."""
    a = (action or "").lower()
    if a.startswith(("system.", "auth.", "admin.login", "admin.logout",
                     "admin.mfa", "security.")):
        return "system"
    if a.startswith(("invoice.", "payment.", "po.", "count.",
                     "inventory.received", "inventory.export",
                     "customer.export", "tech.export", "visit.export",
                     "payroll.", "payslip.")):
        return "financial"
    return "operational"


def _backfill_audit_pii_redaction():
    """One-time (per-deploy) sweep that redacts PII from existing audit_log
    before/after JSON blobs and rebuilds the chain so the (redacted) rows
    still verify. Idempotent — rows already containing only [redacted]
    markers or no sensitive keys remain unchanged but their hashes are
    still recomputed deterministically.

    The hash chain BREAKS on the boundary where redaction happened: any
    party that previously recorded a chain_hash externally will see it
    differ. We surface that intentional break with a system.audit_redacted
    row at the very end of the chain so the discontinuity is itself
    audited."""
    if not os.environ.get("FIELD_ENCRYPTION_KEY"):
        return
    con = _con()
    rows = con.execute(
        "SELECT id, before_value, after_value FROM audit_log ORDER BY id ASC"
    ).fetchall()
    if not rows:
        con.close()
        return
    # Was any row carrying PII keys before redaction? Only then do we touch.
    needs = False
    for r in rows:
        for blob_col in ("before_value", "after_value"):
            blob = r[blob_col]
            if not blob:
                continue
            try:
                v = _json.loads(blob)
            except Exception:
                continue
            redacted = _redact_pii_for_audit(v)
            if _json.dumps(redacted, sort_keys=True) != _json.dumps(v, sort_keys=True):
                needs = True
                break
        if needs:
            break
    if not needs:
        con.close()
        return
    # Redact + rebuild chain.
    prev_hash = AUDIT_GENESIS
    for r in rows:
        d = dict(r)
        for blob_col in ("before_value", "after_value"):
            if d[blob_col]:
                try:
                    v = _json.loads(d[blob_col])
                    d[blob_col] = _json.dumps(_redact_pii_for_audit(v))
                except Exception:
                    pass
        # Re-read the rest of the row to recompute the chain hash properly.
        full = con.execute(
            """SELECT actor_type, actor_id, actor_prid, actor_label, actor_role,
                      action, target_type, target_id, target_label,
                      ip_address, created_at
                 FROM audit_log WHERE id = ?""", (d["id"],)
        ).fetchone()
        row_for_hash = dict(full)
        row_for_hash["before_value"] = d["before_value"]
        row_for_hash["after_value"]  = d["after_value"]
        chain_hash = _audit_compute_hash(prev_hash, row_for_hash)
        con.execute(
            "UPDATE audit_log SET before_value = ?, after_value = ?, chain_hash = ? WHERE id = ?",
            (d["before_value"], d["after_value"], chain_hash, d["id"]),
        )
        prev_hash = chain_hash
    con.commit()
    con.close()


# ── Audit-log PII redaction ─────────────────────────────────────────────────
# The audit trail intentionally records before/after snapshots of mutations
# for forensic replay. WITHOUT redaction, every customer/tech/admin create or
# update writes plaintext PII (phone, email, address, notes, mfa_secret) into
# audit_log.after_value as JSON — defeating Phase 2's encryption-at-rest for
# anyone who exfiltrates the database.
#
# Strategy: pull the same _PII_RAND / _PII_DET registry used by the column
# encryption layer and null out matching keys in any dict passed as before/after.
# We preserve key NAMES (so the structure of the change is still visible) but
# replace the value with a marker — the audit log can still tell you "this
# field changed" without telling an attacker WHAT it changed to.
_AUDIT_PII_KEYS = set()
for _cols in list(_PII_RAND.values()) + list(_PII_DET.values()):
    _AUDIT_PII_KEYS.update(_cols)
# Always redact these top-level keys regardless of table — defensive against
# new endpoints accidentally passing raw bodies into the audit log.
_AUDIT_PII_KEYS.update({"pin", "password", "new_password", "current_password",
                         "current_pin", "signature_b64", "backup_codes",
                         "mfa_secret", "password_hash", "pin_hash"})


def _redact_pii_for_audit(value):
    """Recursively walks a value (dict / list / scalar) and replaces any
    PII-bearing field with '[redacted]'. Idempotent on already-redacted data.
    Returns a new object — does not mutate the caller's dict."""
    if value is None:
        return None
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            if k in _AUDIT_PII_KEYS and v not in (None, ""):
                out[k] = "[redacted]"
            else:
                out[k] = _redact_pii_for_audit(v)
        return out
    if isinstance(value, list):
        return [_redact_pii_for_audit(x) for x in value]
    return value


def log_audit(
    actor_type: str,
    actor_id: int = None,
    actor_prid: str = None,
    actor_label: str = None,
    actor_role: str = None,
    action: str = "",
    target_type: str = None,
    target_id: int = None,
    target_label: str = None,
    before_value=None,
    after_value=None,
    ip_address: str = None,
):
    row = {
        "actor_type":   actor_type,
        "actor_id":     actor_id,
        "actor_prid":   actor_prid,
        "actor_label":  actor_label,
        "actor_role":   actor_role,
        "action":       action,
        "target_type":  target_type,
        "target_id":    target_id,
        "target_label": target_label,
        # Strip PII before the audit row is committed. Phase 2's column
        # encryption is moot if we keep plaintext copies here.
        "before_value": _json.dumps(_redact_pii_for_audit(before_value)) if before_value is not None else None,
        "after_value":  _json.dumps(_redact_pii_for_audit(after_value))  if after_value  is not None else None,
        "ip_address":   ip_address,
        "created_at":   datetime.now(timezone.utc).isoformat(),
    }
    retention_class = _classify_retention(action)

    # Serialize prev-read + insert so concurrent writers can't break the chain
    with _audit_lock:
        con = _con()
        prev = con.execute(
            "SELECT chain_hash FROM audit_log ORDER BY id DESC LIMIT 1"
        ).fetchone()
        prev_hash = (dict(prev)["chain_hash"] if prev else None) or AUDIT_GENESIS
        chain_hash = _audit_compute_hash(prev_hash, row)
        con.execute(
            """
            INSERT INTO audit_log
                (actor_type, actor_id, actor_prid, actor_label, actor_role,
                 action, target_type, target_id, target_label,
                 before_value, after_value, ip_address, created_at, chain_hash,
                 retention_class)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                row["actor_type"],   row["actor_id"],   row["actor_prid"],
                row["actor_label"],  row["actor_role"], row["action"],
                row["target_type"],  row["target_id"],  row["target_label"],
                row["before_value"], row["after_value"],row["ip_address"],
                row["created_at"],   chain_hash,        retention_class,
            ),
        )
        con.commit()
        con.close()


def _backfill_audit_chain():
    """Compute chain_hash for any audit rows that don't have one yet (in order).
    Idempotent — does nothing if every row already has a hash."""
    with _audit_lock:
        con = _con()
        rows = con.execute(
            "SELECT id, actor_type, actor_id, actor_prid, actor_label, actor_role, "
            "action, target_type, target_id, target_label, before_value, after_value, "
            "ip_address, created_at, chain_hash FROM audit_log ORDER BY id ASC"
        ).fetchall()
        if not rows:
            con.close()
            return
        prev_hash = AUDIT_GENESIS
        updates = []
        for r in rows:
            d = dict(r)
            existing = d.get("chain_hash")
            if existing:
                prev_hash = existing
                continue
            new_hash = _audit_compute_hash(prev_hash, d)
            updates.append((new_hash, d["id"]))
            prev_hash = new_hash
        if updates:
            con.executemany("UPDATE audit_log SET chain_hash = ? WHERE id = ?", updates)
            con.commit()
        con.close()


def verify_audit_chain(limit: int = None) -> dict:
    """Walks the audit log in id-order and recomputes each hash.
    Returns {ok: bool, total: N, broken_at_id: int|None, broken_at_index: int|None, last_id: int|None}."""
    con = _con()
    sql = ("SELECT id, actor_type, actor_id, actor_prid, actor_label, actor_role, "
           "action, target_type, target_id, target_label, before_value, after_value, "
           "ip_address, created_at, chain_hash FROM audit_log ORDER BY id ASC")
    if limit:
        sql += f" LIMIT {int(limit)}"
    rows = con.execute(sql).fetchall()
    con.close()
    prev_hash = AUDIT_GENESIS
    for i, r in enumerate(rows):
        d = dict(r)
        expected = _audit_compute_hash(prev_hash, d)
        if d.get("chain_hash") != expected:
            return {
                "ok":              False,
                "total":           len(rows),
                "broken_at_id":    d["id"],
                "broken_at_index": i,
                "expected_hash":   expected,
                "stored_hash":     d.get("chain_hash"),
                "last_id":         rows[-1]["id"] if rows else None,
            }
        prev_hash = d["chain_hash"]
    return {
        "ok":              True,
        "total":           len(rows),
        "broken_at_id":    None,
        "broken_at_index": None,
        "last_id":         rows[-1]["id"] if rows else None,
    }


def get_timesheet_data(start_iso: str, end_iso: str, tech_id: int = None):
    """Returns clock-in entries within the date range (visits with start_time set).
    Includes both completed and in-progress visits."""
    sql = """
        SELECT
            v.id AS visit_id,
            v.visit_type,
            v.status,
            v.start_time,
            v.end_time,
            v.scheduled_date,
            v.assigned_tech_id AS tech_id,
            t.name      AS tech_name,
            t.tech_code AS tech_code,
            t.prid      AS tech_prid,
            t.role      AS tech_role,
            c.name      AS customer_name,
            c.customer_code,
            e.name      AS equipment_name
        FROM maintenance_visits v
        LEFT JOIN technicians t ON v.assigned_tech_id = t.id
        LEFT JOIN customers   c ON v.customer_id      = c.id
        LEFT JOIN equipment   e ON v.equipment_id     = e.id
        WHERE v.start_time IS NOT NULL
          AND v.start_time >= ?
          AND v.start_time <  ?
    """
    args = [start_iso, end_iso]
    if tech_id is not None:
        sql += " AND v.assigned_tech_id = ?"
        args.append(tech_id)
    sql += " ORDER BY v.start_time ASC"
    con = _con()
    rows = con.execute(sql, args).fetchall()
    con.close()
    return [dict(r) for r in rows]


def query_audit_log(
    actor_id: int = None,
    action_prefix: str = None,
    target_type: str = None,
    since: str = None,
    until: str = None,
    limit: int = 200,
):
    sql = "SELECT * FROM audit_log WHERE 1=1"
    args = []
    if actor_id is not None:
        sql += " AND actor_id = ?"; args.append(actor_id)
    if action_prefix:
        sql += " AND action LIKE ?"; args.append(action_prefix + "%")
    if target_type:
        sql += " AND target_type = ?"; args.append(target_type)
    if since:
        sql += " AND created_at >= ?"; args.append(since)
    if until:
        sql += " AND created_at <= ?"; args.append(until)
    sql += " ORDER BY created_at DESC LIMIT ?"; args.append(int(limit))

    con = _con()
    rows = con.execute(sql, args).fetchall()
    con.close()
    return [dict(r) for r in rows]


# ── Parts / Inventory ────────────────────────────────────────────────────────

def get_all_parts(include_inactive: bool = False):
    con = _con()
    sql = "SELECT * FROM parts"
    if not include_inactive:
        sql += " WHERE active = 1"
    sql += " ORDER BY name"
    rows = con.execute(sql).fetchall()
    con.close()
    return [dict(r) for r in rows]


def get_part_by_id(part_id: int):
    con = _con()
    row = con.execute("SELECT * FROM parts WHERE id = ?", (part_id,)).fetchone()
    con.close()
    return dict(row) if row else None


def create_part(data: dict) -> int:
    now = datetime.now(timezone.utc).isoformat()
    con = _con()
    cur = con.execute(
        """
        INSERT INTO parts
            (sku, name, description, category, unit, unit_cost, quantity,
             reorder_point, supplier, location, active, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
        """,
        (
            data["sku"].strip().upper(),
            data["name"].strip(),
            data.get("description", "").strip(),
            data.get("category", "").strip(),
            (data.get("unit") or "each").strip(),
            float(data.get("unit_cost") or 0),
            float(data.get("quantity") or 0),
            float(data.get("reorder_point") or 0),
            data.get("supplier", "").strip(),
            data.get("location", "").strip(),
            now, now,
        ),
    )
    part_id = cur.lastrowid
    con.commit()
    con.close()
    return part_id


def update_part(part_id: int, data: dict):
    con = _con()
    con.execute(
        """
        UPDATE parts SET
            name = ?, description = ?, category = ?, unit = ?,
            unit_cost = ?, reorder_point = ?, supplier = ?, location = ?,
            active = ?, updated_at = ?
        WHERE id = ?
        """,
        (
            data["name"].strip(),
            data.get("description", "").strip(),
            data.get("category", "").strip(),
            (data.get("unit") or "each").strip(),
            float(data.get("unit_cost") or 0),
            float(data.get("reorder_point") or 0),
            data.get("supplier", "").strip(),
            data.get("location", "").strip(),
            1 if data.get("active", True) else 0,
            datetime.now(timezone.utc).isoformat(),
            part_id,
        ),
    )
    con.commit()
    con.close()


def delete_part(part_id: int):
    """Soft delete: mark inactive. Hard delete only if no movements exist."""
    con = _con()
    n = con.execute("SELECT COUNT(*) AS n FROM part_movements WHERE part_id = ?",
                    (part_id,)).fetchone()["n"]
    if n > 0:
        con.execute("UPDATE parts SET active = 0 WHERE id = ?", (part_id,))
    else:
        con.execute("DELETE FROM parts WHERE id = ?", (part_id,))
    con.commit()
    con.close()


def adjust_part_quantity(part_id: int, movement_type: str, quantity_delta: float,
                         reason: str = "", visit_id: int = None,
                         performed_by_type: str = None, performed_by_id: int = None,
                         performed_by_prid: str = None, performed_by_label: str = None) -> dict:
    """Apply a movement and update the part's running quantity.
    Returns (new_quantity, movement_id).
    """
    now = datetime.now(timezone.utc).isoformat()
    con = _con()
    # Load current to validate
    row = con.execute("SELECT quantity FROM parts WHERE id = ?", (part_id,)).fetchone()
    if not row:
        con.close()
        raise ValueError("Part not found")
    current = float(row["quantity"])
    new_qty = current + float(quantity_delta)
    if new_qty < 0:
        con.close()
        raise ValueError(f"Insufficient stock — current {current}, requested change {quantity_delta}")
    # Insert movement
    cur = con.execute(
        """
        INSERT INTO part_movements
            (part_id, movement_type, quantity_delta, reason, visit_id,
             performed_by_type, performed_by_id, performed_by_prid, performed_by_label, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (part_id, movement_type, float(quantity_delta), reason, visit_id,
         performed_by_type, performed_by_id, performed_by_prid, performed_by_label, now),
    )
    movement_id = cur.lastrowid
    con.execute("UPDATE parts SET quantity = ?, updated_at = ? WHERE id = ?",
                (new_qty, now, part_id))
    con.commit()
    con.close()
    return {"new_quantity": new_qty, "movement_id": movement_id}


def get_part_movements(part_id: int, limit: int = 100):
    con = _con()
    rows = con.execute(
        """
        SELECT m.*, v.visit_type AS visit_type_label, c.name AS customer_name
        FROM part_movements m
        LEFT JOIN maintenance_visits v ON m.visit_id = v.id
        LEFT JOIN customers c          ON v.customer_id = c.id
        WHERE m.part_id = ?
        ORDER BY m.created_at DESC
        LIMIT ?
        """,
        (part_id, limit),
    ).fetchall()
    con.close()
    return [dict(r) for r in rows]


# ── Visit Parts (parts used by a tech on a specific visit) ───────────────────

def get_visit_parts(visit_id: int):
    con = _con()
    rows = con.execute(
        """
        SELECT vp.*, p.sku, p.name AS part_name, p.unit AS part_unit,
               p.unit_cost AS current_unit_cost, t.name AS tech_name
        FROM visit_parts vp
        JOIN parts p ON vp.part_id = p.id
        LEFT JOIN technicians t ON vp.added_by_tech_id = t.id
        WHERE vp.visit_id = ?
        ORDER BY vp.created_at
        """,
        (visit_id,),
    ).fetchall()
    con.close()
    return [dict(r) for r in rows]


def add_visit_part(visit_id: int, part_id: int, quantity: float,
                   added_by_tech_id: int = None, notes: str = "",
                   tech_prid: str = None, tech_label: str = None) -> int:
    """Records a part used on a visit and auto-deducts inventory.
    Unit price is snapshotted from the part's current unit_cost.
    Raises ValueError if stock is insufficient."""
    if quantity <= 0:
        raise ValueError("Quantity must be positive")
    part = get_part_by_id(part_id)
    if not part:
        raise ValueError("Part not found")

    # Deduct inventory first — this will fail if insufficient stock
    adjust_part_quantity(
        part_id, "used", -float(quantity),
        reason=f"Used on visit #{visit_id}",
        visit_id=visit_id,
        performed_by_type="tech",
        performed_by_id=added_by_tech_id,
        performed_by_prid=tech_prid,
        performed_by_label=tech_label,
    )

    now = datetime.now(timezone.utc).isoformat()
    con = _con()
    cur = con.execute(
        """
        INSERT INTO visit_parts (visit_id, part_id, quantity, unit_price, notes, added_by_tech_id, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (visit_id, part_id, float(quantity), float(part["unit_cost"]),
         notes, added_by_tech_id, now),
    )
    vp_id = cur.lastrowid
    con.commit()
    con.close()
    return vp_id


def remove_visit_part(vp_id: int, removed_by_tech_id: int = None,
                      tech_prid: str = None, tech_label: str = None):
    """Removes a part usage record and reverses the inventory adjustment."""
    con = _con()
    row = con.execute("SELECT * FROM visit_parts WHERE id = ?", (vp_id,)).fetchone()
    if not row:
        con.close()
        raise ValueError("Visit part not found")
    row = dict(row)
    con.execute("DELETE FROM visit_parts WHERE id = ?", (vp_id,))
    con.commit()
    con.close()
    # Reverse the inventory deduction
    adjust_part_quantity(
        row["part_id"], "received", float(row["quantity"]),
        reason=f"Reversed: removed from visit #{row['visit_id']}",
        visit_id=row["visit_id"],
        performed_by_type="tech",
        performed_by_id=removed_by_tech_id,
        performed_by_prid=tech_prid,
        performed_by_label=tech_label,
    )


def get_visit_part_by_id(vp_id: int):
    con = _con()
    row = con.execute("SELECT * FROM visit_parts WHERE id = ?", (vp_id,)).fetchone()
    con.close()
    return dict(row) if row else None


def build_invoice_lines_from_visit(visit_id: int):
    """Returns a dict with default invoice payload pre-built from a completed visit:
       - labor line: (tracked hours) × tech's hourly_rate (0 if no rate set)
       - part lines: one per visit_parts row
       - default issue_date = today, due_date = today + 30
    """
    from datetime import timedelta as _td
    con = _con()
    v = con.execute(
        """
        SELECT v.*, c.id AS customer_id, t.name AS tech_name, t.hourly_rate, t.prid AS tech_prid
        FROM maintenance_visits v
        JOIN customers c   ON v.customer_id      = c.id
        LEFT JOIN technicians t ON v.assigned_tech_id = t.id
        WHERE v.id = ?
        """,
        (visit_id,),
    ).fetchone()
    con.close()
    if not v:
        return None
    v = dict(v)

    line_items = []

    # Labor from tracked time
    if v.get("start_time") and v.get("end_time"):
        try:
            start = datetime.fromisoformat(v["start_time"].replace("Z", "+00:00"))
            end   = datetime.fromisoformat(v["end_time"].replace("Z",   "+00:00"))
            hours = round((end - start).total_seconds() / 3600.0, 2)
        except Exception:
            hours = 0
    else:
        hours = 0
    rate = float(v.get("hourly_rate") or 0)
    tech_label = v.get("tech_name") or "Technician"
    visit_type_label = "Preventive Maintenance" if v.get("visit_type") == "PM" else "Corrective Maintenance"
    if hours > 0:
        line_items.append({
            "line_type":   "labor",
            "part_id":     None,
            "description": f"{visit_type_label} — labor ({tech_label}, {hours}h)",
            "quantity":    hours,
            "unit_price":  rate,
        })

    # Parts
    for vp in get_visit_parts(visit_id):
        line_items.append({
            "line_type":   "part",
            "part_id":     vp["part_id"],
            "description": f"{vp['sku']} — {vp['part_name']}",
            "quantity":    float(vp["quantity"]),
            "unit_price":  float(vp["unit_price"]),
        })

    today = datetime.now(timezone.utc).date()
    due   = today + _td(days=30)
    return {
        "customer_id": v["customer_id"],
        "visit_id":    visit_id,
        "issue_date":  today.isoformat(),
        "due_date":    due.isoformat(),
        "line_items":  line_items,
        "tracked_hours": hours,
        "hourly_rate":   rate,
    }


# ── Invoices ─────────────────────────────────────────────────────────────────

def _next_invoice_number() -> str:
    """Sequential year-prefixed: INV-2026-0001."""
    year = datetime.now(timezone.utc).year
    prefix = f"INV-{year}-"
    con = _con()
    row = con.execute(
        "SELECT MAX(CAST(SUBSTR(invoice_number, ?) AS INTEGER)) AS max_seq "
        "FROM invoices WHERE invoice_number LIKE ?",
        (len(prefix) + 1, f"{prefix}%"),
    ).fetchone()
    con.close()
    next_seq = (row["max_seq"] or 0) + 1
    return f"{prefix}{next_seq:04d}"


def _recompute_invoice_totals(con, invoice_id: int):
    """Recompute subtotal, tax_amount, total from line items + tax_rate.
    Caller is responsible for committing."""
    inv = con.execute("SELECT tax_rate FROM invoices WHERE id = ?", (invoice_id,)).fetchone()
    if not inv:
        return
    tax_rate = float(inv["tax_rate"] or 0)
    subtotal = con.execute(
        "SELECT COALESCE(SUM(line_total), 0) AS s FROM invoice_line_items WHERE invoice_id = ?",
        (invoice_id,),
    ).fetchone()["s"]
    subtotal = round(float(subtotal), 2)
    tax_amount = round(subtotal * tax_rate, 2)
    total      = round(subtotal + tax_amount, 2)
    paid = con.execute(
        "SELECT COALESCE(SUM(amount), 0) AS p FROM invoice_payments WHERE invoice_id = ?",
        (invoice_id,),
    ).fetchone()["p"]
    paid = round(float(paid), 2)
    con.execute(
        "UPDATE invoices SET subtotal=?, tax_amount=?, total=?, amount_paid=?, updated_at=? WHERE id=?",
        (subtotal, tax_amount, total, paid, datetime.now(timezone.utc).isoformat(), invoice_id),
    )


def create_invoice(data: dict, created_by: int = None) -> int:
    now = datetime.now(timezone.utc).isoformat()
    inv_no = _next_invoice_number()
    con = _con()
    cur = con.execute(
        """
        INSERT INTO invoices
            (invoice_number, customer_id, visit_id, issue_date, due_date,
             status, tax_rate, currency, notes, created_by, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, 'draft', ?, ?, ?, ?, ?, ?)
        """,
        (
            inv_no,
            int(data["customer_id"]),
            data.get("visit_id") or None,
            data["issue_date"],
            data["due_date"],
            float(data.get("tax_rate") or 0),
            data.get("currency") or "TTD",
            data.get("notes", ""),
            created_by, now, now,
        ),
    )
    invoice_id = cur.lastrowid
    for idx, li in enumerate(data.get("line_items", []) or []):
        qty   = float(li.get("quantity") or 0)
        price = float(li.get("unit_price") or 0)
        con.execute(
            """
            INSERT INTO invoice_line_items
                (invoice_id, line_type, part_id, description, quantity, unit_price, line_total, sort_order)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (invoice_id, li.get("line_type", "other"), li.get("part_id") or None,
             li.get("description", ""), qty, price, round(qty * price, 2), idx),
        )
    _recompute_invoice_totals(con, invoice_id)
    con.commit()
    con.close()
    return invoice_id


def update_invoice(invoice_id: int, data: dict):
    """Replaces line items wholesale and updates header fields."""
    now = datetime.now(timezone.utc).isoformat()
    con = _con()
    con.execute(
        """
        UPDATE invoices SET
            customer_id = ?, visit_id = ?, issue_date = ?, due_date = ?,
            tax_rate = ?, notes = ?, updated_at = ?
        WHERE id = ?
        """,
        (
            int(data["customer_id"]),
            data.get("visit_id") or None,
            data["issue_date"],
            data["due_date"],
            float(data.get("tax_rate") or 0),
            data.get("notes", ""),
            now, invoice_id,
        ),
    )
    con.execute("DELETE FROM invoice_line_items WHERE invoice_id = ?", (invoice_id,))
    for idx, li in enumerate(data.get("line_items", []) or []):
        qty   = float(li.get("quantity") or 0)
        price = float(li.get("unit_price") or 0)
        con.execute(
            """
            INSERT INTO invoice_line_items
                (invoice_id, line_type, part_id, description, quantity, unit_price, line_total, sort_order)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (invoice_id, li.get("line_type", "other"), li.get("part_id") or None,
             li.get("description", ""), qty, price, round(qty * price, 2), idx),
        )
    _recompute_invoice_totals(con, invoice_id)
    con.commit()
    con.close()


def get_invoice_by_id(invoice_id: int, with_lines: bool = True):
    con = _con()
    row = con.execute(
        """
        SELECT i.*, c.name AS customer_name, c.company AS customer_company,
               c.customer_code, c.email AS customer_email, c.phone AS customer_phone,
               c.address AS customer_address
        FROM invoices i
        JOIN customers c ON i.customer_id = c.id
        WHERE i.id = ?
        """,
        (invoice_id,),
    ).fetchone()
    if not row:
        con.close()
        return None
    inv = dict(row)
    if with_lines:
        inv["line_items"] = [dict(r) for r in con.execute(
            "SELECT * FROM invoice_line_items WHERE invoice_id = ? ORDER BY sort_order, id",
            (invoice_id,),
        ).fetchall()]
        inv["payments"] = [dict(r) for r in con.execute(
            "SELECT * FROM invoice_payments WHERE invoice_id = ? ORDER BY payment_date, id",
            (invoice_id,),
        ).fetchall()]
    con.close()
    return inv


def get_all_invoices(status: str = None, customer_id: int = None):
    con = _con()
    sql = """
        SELECT i.*, c.name AS customer_name, c.customer_code
        FROM invoices i
        JOIN customers c ON i.customer_id = c.id
    """
    args = []
    where = []
    if status:
        where.append("i.status = ?"); args.append(status)
    if customer_id is not None:
        where.append("i.customer_id = ?"); args.append(customer_id)
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY i.created_at DESC"
    rows = con.execute(sql, args).fetchall()
    con.close()
    return [dict(r) for r in rows]


def get_customer_invoices(customer_id: int):
    return get_all_invoices(customer_id=customer_id)


def set_invoice_status(invoice_id: int, status: str):
    now = datetime.now(timezone.utc).isoformat()
    extra_sql = ""
    extra_args = ()
    if status == "sent":
        extra_sql = ", sent_at = COALESCE(sent_at, ?)"
        extra_args = (now,)
    elif status == "paid":
        extra_sql = ", paid_at = COALESCE(paid_at, ?)"
        extra_args = (now,)
    con = _con()
    con.execute(
        f"UPDATE invoices SET status = ?, updated_at = ? {extra_sql} WHERE id = ?",
        (status, now, *extra_args, invoice_id),
    )
    con.commit()
    con.close()


def delete_invoice(invoice_id: int):
    con = _con()
    con.execute("DELETE FROM invoice_payments  WHERE invoice_id = ?", (invoice_id,))
    con.execute("DELETE FROM invoice_line_items WHERE invoice_id = ?", (invoice_id,))
    con.execute("DELETE FROM invoices WHERE id = ?", (invoice_id,))
    con.commit()
    con.close()


def record_invoice_payment(invoice_id: int, data: dict,
                            recorded_by: int = None,
                            recorded_by_label: str = None,
                            recorded_by_prid: str = None) -> int:
    now = datetime.now(timezone.utc).isoformat()
    con = _con()
    cur = con.execute(
        """
        INSERT INTO invoice_payments
            (invoice_id, payment_date, amount, method, reference, notes,
             recorded_by, recorded_by_label, recorded_by_prid, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            invoice_id,
            data["payment_date"],
            float(data["amount"]),
            data.get("method", ""),
            data.get("reference", ""),
            data.get("notes", ""),
            recorded_by, recorded_by_label, recorded_by_prid, now,
        ),
    )
    payment_id = cur.lastrowid
    _recompute_invoice_totals(con, invoice_id)
    # Auto-flip to paid if fully covered
    row = con.execute("SELECT total, amount_paid FROM invoices WHERE id = ?", (invoice_id,)).fetchone()
    if row and float(row["amount_paid"]) >= float(row["total"]) - 0.005 and float(row["total"]) > 0:
        con.execute(
            "UPDATE invoices SET status='paid', paid_at = COALESCE(paid_at, ?), updated_at=? WHERE id=?",
            (now, now, invoice_id),
        )
    con.commit()
    con.close()
    return payment_id


# ── Sessions ─────────────────────────────────────────────────────────────────

def create_session(jti: str, subject_type: str, subject_id: int,
                   expires_at: str, ip_address: str = None, user_agent: str = None):
    now = datetime.now(timezone.utc).isoformat()
    con = _con()
    con.execute(
        """
        INSERT INTO sessions
            (jti, subject_type, subject_id, ip_address, user_agent, created_at, expires_at, last_seen_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (jti, subject_type, int(subject_id), ip_address, user_agent, now, expires_at, now),
    )
    con.commit()
    con.close()


def get_session_by_jti(jti: str):
    if not jti:
        return None
    con = _con()
    row = con.execute("SELECT * FROM sessions WHERE jti = ?", (jti,)).fetchone()
    con.close()
    return dict(row) if row else None


def is_session_active(jti: str, idle_timeout_by_type: dict = None,
                       expected_subject_type: str = None) -> bool:
    """Returns True if the session row exists, isn't revoked, isn't past expiry,
    matches expected_subject_type if supplied, and (optionally) hasn't been
    idle past its per-type limit. Bumps last_seen_at on success.

    expected_subject_type is the second layer of token-type defense: a JWT
    whose 'type' claim has been tampered to claim another actor type is
    rejected here even if the signature is valid, because the original
    session row was created with the real subject_type.

    idle_timeout_by_type: {'admin': 1800, 'tech': 0, 'customer': 0} — 0 disables.
    """
    if not jti:
        return False
    now_dt  = datetime.now(timezone.utc)
    now_iso = now_dt.isoformat()
    con = _con()
    row = con.execute(
        "SELECT id, subject_type, revoked_at, expires_at, last_seen_at "
        "FROM sessions WHERE jti = ?",
        (jti,),
    ).fetchone()
    if not row:
        con.close()
        return False
    r = dict(row)
    if r["revoked_at"]:
        con.close()
        return False
    if r["expires_at"] and r["expires_at"] < now_iso:
        con.close()
        return False
    # Subject_type cross-check — defense against type-flip JWT tampering.
    if expected_subject_type and r["subject_type"] != expected_subject_type:
        con.close()
        return False
    # Idle timeout check — based on per-role configuration
    if idle_timeout_by_type and r.get("last_seen_at"):
        limit_sec = int(idle_timeout_by_type.get(r["subject_type"], 0) or 0)
        if limit_sec > 0:
            try:
                last = datetime.fromisoformat(r["last_seen_at"].replace("Z", "+00:00"))
                idle = (now_dt - last).total_seconds()
            except Exception:
                idle = 0
            if idle > limit_sec:
                con.execute("UPDATE sessions SET revoked_at = ? WHERE id = ?",
                            (now_iso, r["id"]))
                con.commit()
                con.close()
                return False
    con.execute("UPDATE sessions SET last_seen_at = ? WHERE id = ?", (now_iso, r["id"]))
    con.commit()
    con.close()
    return True


# ── Access log (read traceability via middleware) ────────────────────────────

def log_access(actor_type: str = None, actor_id: int = None,
               actor_prid: str = None, actor_label: str = None,
               method: str = "", path: str = "", query: str = "",
               status_code: int = 0,
               ip_address: str = None, user_agent: str = None):
    """Appends a row to access_log. Designed to be called from a request
    middleware after the response is produced. Fast — no chain, no commit
    batching, just one insert."""
    con = _con()
    con.execute(
        """
        INSERT INTO access_log
            (actor_type, actor_id, actor_prid, actor_label,
             method, path, query, status_code, ip_address, user_agent, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            actor_type, actor_id, actor_prid, actor_label,
            method.upper(), path[:512], (query or "")[:512],
            int(status_code), ip_address, (user_agent or "")[:255],
            datetime.now(timezone.utc).isoformat(),
        ),
    )
    con.commit()
    con.close()


def query_access_log(actor_id: int = None, path_prefix: str = None,
                     since: str = None, until: str = None,
                     limit: int = 200):
    sql = "SELECT * FROM access_log WHERE 1=1"
    args = []
    if actor_id is not None:
        sql += " AND actor_id = ?"; args.append(actor_id)
    if path_prefix:
        sql += " AND path LIKE ?"; args.append(path_prefix + "%")
    if since:
        sql += " AND created_at >= ?"; args.append(since)
    if until:
        sql += " AND created_at <= ?"; args.append(until)
    sql += " ORDER BY created_at DESC LIMIT ?"; args.append(int(limit))
    con = _con()
    rows = con.execute(sql, args).fetchall()
    con.close()
    return [dict(r) for r in rows]


def aggregate_access_by_target(since: str = None, until: str = None,
                                actor_id: int = None, target_type: str = None,
                                min_views: int = 1, limit: int = 200):
    """Aggregate access_log entries by (actor, target_type, target_id).

    Parses the request path to extract the resource and numeric id, then
    counts views per (actor, target). Used by admin "who viewed what" panel
    to surface unusual access patterns like "Tech X viewed Customer Y 47 times".
    Only counts successful reads (GET with 2xx)."""
    import re as _re
    sql = """
        SELECT actor_type, actor_id, actor_prid, actor_label, path,
               COUNT(*) AS hits, MAX(created_at) AS last_seen
        FROM access_log
        WHERE method = 'GET' AND status_code >= 200 AND status_code < 300
          AND actor_id IS NOT NULL
    """
    args = []
    if since:
        sql += " AND created_at >= ?"; args.append(since)
    if until:
        sql += " AND created_at <= ?"; args.append(until)
    if actor_id is not None:
        sql += " AND actor_id = ?"; args.append(actor_id)
    sql += " GROUP BY actor_type, actor_id, path"
    con = _con()
    rows = con.execute(sql, args).fetchall()
    con.close()

    # Path → (target_type, target_id) extraction.
    patterns = [
        (_re.compile(r"^/api/admin/customers/(\d+)(?:/|$)"),  "customer"),
        (_re.compile(r"^/api/admin/visits/(\d+)(?:/|$)"),     "visit"),
        (_re.compile(r"^/api/admin/techs/(\d+)(?:/|$)"),      "tech"),
        (_re.compile(r"^/api/admin/invoices/(\d+)(?:/|$)"),   "invoice"),
        (_re.compile(r"^/api/admin/reviews/(\d+)(?:/|$)"),    "review"),
        (_re.compile(r"^/api/tech/visits/(\d+)(?:/|$)"),      "visit"),
        (_re.compile(r"^/api/tech/customers/(\d+)(?:/|$)"),   "customer"),
        (_re.compile(r"^/api/documents/(\d+)(?:/|$)"),        "document"),
    ]
    bucket = {}
    for r in rows:
        path = r["path"] or ""
        tt, tid = None, None
        for rx, name in patterns:
            m = rx.match(path)
            if m:
                tt, tid = name, int(m.group(1)); break
        if not tt:
            continue
        if target_type and tt != target_type:
            continue
        key = (r["actor_type"], r["actor_id"], tt, tid)
        slot = bucket.get(key)
        if slot is None:
            bucket[key] = {
                "actor_type":  r["actor_type"],
                "actor_id":    r["actor_id"],
                "actor_prid":  r["actor_prid"],
                "actor_label": r["actor_label"],
                "target_type": tt,
                "target_id":   tid,
                "hits":        r["hits"],
                "last_seen":   r["last_seen"],
            }
        else:
            slot["hits"] += r["hits"]
            if r["last_seen"] > slot["last_seen"]:
                slot["last_seen"] = r["last_seen"]
    out = [v for v in bucket.values() if v["hits"] >= min_views]
    out.sort(key=lambda x: (-x["hits"], x["last_seen"]))
    return out[:limit]


def purge_old_access_log(days: int = 90) -> int:
    """Deletes access_log rows older than `days` and returns the count deleted.
    Caller is responsible for writing the meta-audit row."""
    from datetime import timedelta as _td
    cutoff = (datetime.now(timezone.utc) - _td(days=days)).isoformat()
    con = _con()
    n = con.execute("SELECT COUNT(*) AS n FROM access_log WHERE created_at < ?", (cutoff,)).fetchone()["n"]
    con.execute("DELETE FROM access_log WHERE created_at < ?", (cutoff,))
    con.commit()
    con.close()
    return int(n)


def purge_old_audit_log(financial_days: int = 365*7, operational_days: int = 365*2) -> dict:
    """Two-tier audit-log retention. Financial/legal-class rows are kept the
    full statutory window; operational rows roll off sooner. 'system' rows
    (retention purges, security events) are NEVER purged — we always keep the
    record that the record was deleted."""
    from datetime import timedelta as _td
    now = datetime.now(timezone.utc)
    fin_cutoff = (now - _td(days=financial_days)).isoformat()
    ops_cutoff = (now - _td(days=operational_days)).isoformat()
    con = _con()
    n_fin = con.execute(
        "SELECT COUNT(*) AS n FROM audit_log WHERE retention_class='financial' AND created_at < ?",
        (fin_cutoff,),
    ).fetchone()["n"]
    n_ops = con.execute(
        "SELECT COUNT(*) AS n FROM audit_log WHERE retention_class='operational' AND created_at < ?",
        (ops_cutoff,),
    ).fetchone()["n"]
    con.execute("DELETE FROM audit_log WHERE retention_class='financial'   AND created_at < ?", (fin_cutoff,))
    con.execute("DELETE FROM audit_log WHERE retention_class='operational' AND created_at < ?", (ops_cutoff,))
    con.commit()
    con.close()
    return {"financial_purged": int(n_fin), "operational_purged": int(n_ops),
            "financial_cutoff": fin_cutoff, "operational_cutoff": ops_cutoff}


def get_entity_history(target_type: str, target_id: int, limit: int = 500):
    """Merge audit_log mutations + access_log reads for a given entity into a
    single time-sorted timeline. For "customer" the lifecycle cascades to the
    customer's equipment, visits, and invoices so the timeline matches the
    spec's example: 'every hand that touched [the client], in order'.
    The access_log doesn't carry target_type/id — we parse the path."""
    import re as _re
    con = _con()
    # Build the set of (target_type, target_id) pairs to look up.
    target_pairs = [(target_type, int(target_id))]
    if target_type == "customer":
        for eq in con.execute("SELECT id FROM equipment WHERE customer_id = ?", (int(target_id),)).fetchall():
            target_pairs.append(("equipment", eq["id"]))
        for v in con.execute("SELECT id FROM maintenance_visits WHERE customer_id = ?", (int(target_id),)).fetchall():
            target_pairs.append(("visit", v["id"]))
        try:
            for i in con.execute("SELECT id FROM invoices WHERE customer_id = ?", (int(target_id),)).fetchall():
                target_pairs.append(("invoice", i["id"]))
        except Exception:
            pass   # invoices table may not exist in very old test DBs
    # Mutations: indexed by target_type+target_id directly.
    where_pairs = " OR ".join(["(target_type=? AND target_id=?)"] * len(target_pairs))
    pair_args = [v for pair in target_pairs for v in pair]
    audits = con.execute(
        f"""SELECT id, actor_type, actor_id, actor_prid, actor_label, actor_role,
                  action, target_type, target_id, target_label,
                  before_value, after_value, ip_address, created_at, chain_hash,
                  retention_class
             FROM audit_log
            WHERE {where_pairs}
            ORDER BY created_at DESC LIMIT ?""",
        (*pair_args, limit),
    ).fetchall()
    # Reads: paths that mention this entity.
    # Map target_type → URL path patterns.
    path_map = {
        "customer": ["/api/admin/customers/%d", "/api/admin/customers/%d/%%",
                      "/api/tech/customers/%d"],
        "visit":    ["/api/admin/visits/%d", "/api/admin/visits/%d/%%",
                      "/api/tech/visits/%d", "/api/tech/jobs/%d"],
        "tech":     ["/api/admin/techs/%d", "/api/admin/techs/%d/%%"],
        "invoice":  ["/api/admin/invoices/%d", "/api/admin/invoices/%d/%%"],
        "part":     ["/api/admin/parts/%d", "/api/admin/parts/%d/%%"],
        "purchase_order": ["/api/admin/purchase-orders/%d", "/api/admin/purchase-orders/%d/%%"],
        "review":   ["/api/admin/reviews/%d", "/api/admin/reviews/%d/%%"],
        "document": ["/api/documents/%d", "/api/documents/%d/%%"],
    }
    patterns = [pat % int(target_id) for pat in path_map.get(target_type, [])]
    reads = []
    if patterns:
        ph = " OR ".join("path LIKE ?" for _ in patterns)
        reads = con.execute(
            f"""SELECT id, actor_type, actor_id, actor_prid, actor_label,
                       method, path, status_code, ip_address, created_at
                  FROM access_log
                 WHERE ({ph})
                 ORDER BY created_at DESC LIMIT ?""",
            (*patterns, limit),
        ).fetchall()
    con.close()
    # Merge into a uniform shape.
    out = []
    for r in audits:
        d = dict(r); d["event_kind"] = "mutation"; out.append(d)
    for r in reads:
        d = dict(r)
        d["event_kind"]  = "read"
        d["action"]      = f"read.{d.get('method','GET')}"
        d["target_type"] = target_type
        d["target_id"]   = int(target_id)
        d["target_label"] = d.get("path")
        out.append(d)
    out.sort(key=lambda e: e["created_at"], reverse=True)
    return out[:limit]


# ── Watcher logging (debounced) ──────────────────────────────────────────────
# Logging the act of querying the audit log itself, per spec. We debounce by
# (actor, action_kind) so refreshing the audit tab doesn't fill the chain
# with one row per HTTP refresh.
_WATCHER_DEBOUNCE_SEC = 30
_watcher_seen: dict = {}
_watcher_lock = threading.Lock()


def watcher_should_log(actor_id: int, kind: str) -> bool:
    """Returns True if this (actor, kind) pair hasn't been logged in the last
    _WATCHER_DEBOUNCE_SEC seconds. Updates the cache as a side effect."""
    import time as _time
    now = _time.time()
    key = (actor_id or 0, kind)
    with _watcher_lock:
        last = _watcher_seen.get(key, 0)
        if now - last < _WATCHER_DEBOUNCE_SEC:
            return False
        _watcher_seen[key] = now
        # Prune occasionally to keep memory bounded
        if len(_watcher_seen) > 1000:
            cutoff = now - 3600
            for k in list(_watcher_seen.keys()):
                if _watcher_seen[k] < cutoff:
                    del _watcher_seen[k]
    return True


# ── Supervisor relationship (team-scoped audit view) ─────────────────────────
def subordinate_ids_for(supervisor_admin_id: int) -> dict:
    """Returns {admin_ids: [...], tech_ids: [...]} of users reporting to this
    supervisor. Used to scope audit:view_all for supervisor_admin."""
    con = _con()
    admin_rows = con.execute(
        "SELECT id FROM admin_users WHERE supervisor_id = ?", (supervisor_admin_id,),
    ).fetchall()
    tech_rows = con.execute(
        "SELECT id FROM technicians WHERE supervisor_id = ?", (supervisor_admin_id,),
    ).fetchall()
    con.close()
    return {
        "admin_ids": [r["id"] for r in admin_rows],
        "tech_ids":  [r["id"] for r in tech_rows],
    }


def set_admin_supervisor(admin_id: int, supervisor_id):
    con = _con()
    con.execute("UPDATE admin_users SET supervisor_id = ? WHERE id = ?",
                (int(supervisor_id) if supervisor_id else None, admin_id))
    con.commit()
    con.close()


def set_tech_supervisor(tech_id: int, supervisor_id):
    con = _con()
    con.execute("UPDATE technicians SET supervisor_id = ? WHERE id = ?",
                (int(supervisor_id) if supervisor_id else None, tech_id))
    con.commit()
    con.close()


def query_audit_log_team(supervisor_admin_id: int, action_prefix: str = None,
                          target_type: str = None, since: str = None,
                          until: str = None, limit: int = 200):
    """Same shape as query_audit_log but filtered to actions by this
    supervisor's subordinates OR by themselves. Admin-side and tech-side
    subordinates both included."""
    subs = subordinate_ids_for(supervisor_admin_id)
    admin_ids = subs["admin_ids"] + [supervisor_admin_id]
    tech_ids  = subs["tech_ids"]
    where = []
    args  = []
    # Build the actor filter: (actor_type='admin' AND actor_id IN admin_ids)
    #                      OR (actor_type='tech'  AND actor_id IN tech_ids)
    clauses = []
    if admin_ids:
        clauses.append(f"(actor_type='admin' AND actor_id IN ({','.join(['?']*len(admin_ids))}))")
        args.extend(admin_ids)
    if tech_ids:
        clauses.append(f"(actor_type='tech'  AND actor_id IN ({','.join(['?']*len(tech_ids))}))")
        args.extend(tech_ids)
    if not clauses:
        # No subordinates and somehow no self-id: nothing visible
        return []
    where.append("(" + " OR ".join(clauses) + ")")
    if action_prefix:
        where.append("action LIKE ?"); args.append(action_prefix + "%")
    if target_type:
        where.append("target_type = ?"); args.append(target_type)
    if since:
        where.append("created_at >= ?"); args.append(since)
    if until:
        where.append("created_at <= ?"); args.append(until)
    sql = "SELECT * FROM audit_log WHERE " + " AND ".join(where) + " ORDER BY created_at DESC LIMIT ?"
    args.append(int(limit))
    con = _con()
    rows = con.execute(sql, args).fetchall()
    con.close()
    return [dict(r) for r in rows]


# ── Security alerts (anomaly detection) ──────────────────────────────────────
def create_security_alert(kind: str, summary: str, *,
                          severity: str = "medium",
                          actor_type: str = None, actor_id: int = None,
                          actor_prid: str = None, actor_label: str = None,
                          details: dict = None):
    """Insert a new open alert. Caller should de-dupe before calling — the
    detector uses recent_alert_exists() to avoid spamming."""
    import json as _json
    con = _con()
    cur = con.execute(
        """INSERT INTO security_alerts
            (kind, severity, actor_type, actor_id, actor_prid, actor_label,
             summary, details, status, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'open', ?)""",
        (kind, severity, actor_type, actor_id, actor_prid, actor_label,
         summary, _json.dumps(details or {}),
         datetime.now(timezone.utc).isoformat()),
    )
    aid = cur.lastrowid
    con.commit()
    con.close()
    return aid


def recent_alert_exists(kind: str, actor_id: int, within_minutes: int = 30) -> bool:
    """Was an alert of this kind raised for this actor in the last N minutes?
    Used to de-dupe so the detector doesn't fire repeatedly on the same burst."""
    from datetime import timedelta as _td
    cutoff = (datetime.now(timezone.utc) - _td(minutes=within_minutes)).isoformat()
    con = _con()
    row = con.execute(
        "SELECT 1 FROM security_alerts WHERE kind = ? AND actor_id IS ? AND created_at >= ? LIMIT 1",
        (kind, actor_id, cutoff),
    ).fetchone()
    con.close()
    return row is not None


def list_security_alerts(status: str = None, limit: int = 100):
    sql = "SELECT * FROM security_alerts"
    args = []
    if status:
        sql += " WHERE status = ?"; args.append(status)
    sql += " ORDER BY created_at DESC LIMIT ?"; args.append(int(limit))
    con = _con()
    rows = con.execute(sql, args).fetchall()
    con.close()
    return [dict(r) for r in rows]


def count_open_security_alerts() -> int:
    con = _con()
    n = con.execute("SELECT COUNT(*) AS n FROM security_alerts WHERE status = 'open'").fetchone()["n"]
    con.close()
    return int(n)


def resolve_security_alert(alert_id: int, admin_id: int, note: str = "", status: str = "resolved"):
    con = _con()
    con.execute(
        """UPDATE security_alerts SET status = ?, resolved_by = ?, resolved_at = ?, resolution_note = ?
           WHERE id = ?""",
        (status, admin_id, datetime.now(timezone.utc).isoformat(), note or "", alert_id),
    )
    con.commit()
    con.close()


def detect_anomalies_for_actor(actor_type: str, actor_id: int) -> list:
    """Run the standard checks against this actor's recent access_log.
    Returns a list of (kind, severity, summary, details) tuples for any
    triggered rules. Caller decides whether to insert them.

    Rules:
      A. bulk_read       — ≥20 distinct customer IDs viewed in 5 min
      B. off_hours       — ≥50 reads outside 07:00–20:00 Jamaica time today
      C. permission_probe — ≥10 403/401 responses in 10 min
    """
    from datetime import timedelta as _td
    if actor_id is None:
        return []
    now = datetime.now(timezone.utc)
    out = []
    con = _con()

    # A. distinct customers viewed in last 5 min
    cutoff_5 = (now - _td(minutes=5)).isoformat()
    rows = con.execute(
        """SELECT path FROM access_log
            WHERE actor_id = ? AND method = 'GET'
              AND status_code >= 200 AND status_code < 300
              AND created_at >= ?
              AND (path LIKE '/api/admin/customers/%' OR path LIKE '/api/tech/customers/%')""",
        (actor_id, cutoff_5),
    ).fetchall()
    import re as _re
    rx = _re.compile(r"/customers/(\d+)")
    ids = set()
    for r in rows:
        m = rx.search(r["path"] or "")
        if m: ids.add(m.group(1))
    if len(ids) >= 20:
        out.append((
            "bulk_read", "high",
            f"{actor_type} #{actor_id} viewed {len(ids)} distinct customers in 5 minutes",
            {"distinct_customers": len(ids), "window_minutes": 5},
        ))

    # B. off-hours volume today (Jamaica = UTC-5, no DST)
    # 07:00 JA = 12:00 UTC; 20:00 JA = 01:00 UTC next day. Off-hours UTC: 01:00–12:00.
    today = now.date().isoformat()
    n_off = con.execute(
        """SELECT COUNT(*) AS n FROM access_log
            WHERE actor_id = ? AND method = 'GET' AND created_at LIKE ?
              AND substr(created_at, 12, 2) >= '01' AND substr(created_at, 12, 2) < '12'""",
        (actor_id, today + "%"),
    ).fetchone()["n"]
    if n_off >= 50:
        out.append((
            "off_hours", "medium",
            f"{actor_type} #{actor_id} made {n_off} reads outside 07:00–20:00 Jamaica time today",
            {"reads_off_hours": int(n_off), "date_utc": today},
        ))

    # C. permission probing — repeated 401/403 in last 10 min
    cutoff_10 = (now - _td(minutes=10)).isoformat()
    n_denied = con.execute(
        """SELECT COUNT(*) AS n FROM access_log
            WHERE actor_id = ? AND status_code IN (401, 403)
              AND created_at >= ?""",
        (actor_id, cutoff_10),
    ).fetchone()["n"]
    if n_denied >= 10:
        out.append((
            "permission_probe", "high",
            f"{actor_type} #{actor_id} hit {n_denied} denied responses (401/403) in 10 minutes",
            {"denied_count": int(n_denied), "window_minutes": 10},
        ))

    con.close()
    return out


def revoke_session(jti: str) -> bool:
    if not jti:
        return False
    now = datetime.now(timezone.utc).isoformat()
    con = _con()
    cur = con.execute(
        "UPDATE sessions SET revoked_at = ? WHERE jti = ? AND revoked_at IS NULL",
        (now, jti),
    )
    n = cur.rowcount
    con.commit()
    con.close()
    return n > 0


def revoke_all_sessions_for(subject_type: str, subject_id: int) -> int:
    now = datetime.now(timezone.utc).isoformat()
    con = _con()
    cur = con.execute(
        "UPDATE sessions SET revoked_at = ? "
        "WHERE subject_type = ? AND subject_id = ? AND revoked_at IS NULL",
        (now, subject_type, int(subject_id)),
    )
    n = cur.rowcount
    con.commit()
    con.close()
    return n


def mark_session_mfa_verified(jti: str):
    """Records that the session's holder has just passed an MFA check.
    Used to gate access to Tier-3 data — see _require_recent_mfa() in main.py."""
    if not jti:
        return
    now = datetime.now(timezone.utc).isoformat()
    con = _con()
    con.execute("UPDATE sessions SET mfa_verified_at = ? WHERE jti = ?", (now, jti))
    con.commit()
    con.close()


def get_active_sessions_for(subject_type: str, subject_id: int):
    now = datetime.now(timezone.utc).isoformat()
    con = _con()
    rows = con.execute(
        """
        SELECT * FROM sessions
        WHERE subject_type = ? AND subject_id = ?
          AND revoked_at IS NULL AND expires_at > ?
        ORDER BY created_at DESC
        """,
        (subject_type, int(subject_id), now),
    ).fetchall()
    con.close()
    return [dict(r) for r in rows]


def purge_expired_sessions():
    """Removes expired/revoked sessions older than 90 days."""
    from datetime import timedelta as _td
    cutoff = (datetime.now(timezone.utc) - _td(days=90)).isoformat()
    con = _con()
    con.execute(
        "DELETE FROM sessions WHERE (expires_at < ? OR revoked_at < ?)",
        (cutoff, cutoff),
    )
    con.commit()
    con.close()


# ── Documents (DMS) ──────────────────────────────────────────────────────────

def create_document(data: dict) -> int:
    now = datetime.now(timezone.utc).isoformat()
    con = _con()
    cur = con.execute(
        """
        INSERT INTO documents
            (stored_filename, original_filename, mime_type, size_bytes,
             sensitivity, document_type, title, description,
             linked_to_type, linked_to_id, linked_to_label,
             uploaded_by_type, uploaded_by_id, uploaded_by_prid, uploaded_by_label,
             uploaded_at, expiry_date)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            data["stored_filename"],
            data["original_filename"],
            data.get("mime_type"),
            int(data["size_bytes"]),
            data["sensitivity"],
            data["document_type"],
            data["title"],
            data.get("description", ""),
            data.get("linked_to_type"),
            data.get("linked_to_id"),
            data.get("linked_to_label"),
            data["uploaded_by_type"],
            int(data["uploaded_by_id"]),
            data.get("uploaded_by_prid"),
            data.get("uploaded_by_label"),
            now,
            data.get("expiry_date") or None,
        ),
    )
    doc_id = cur.lastrowid
    con.commit()
    con.close()
    return doc_id


def get_expiring_documents(sensitivity_in: list, within_days: int = 30):
    """Returns docs whose expiry_date is within the next N days OR already past,
    sorted by expiry_date asc. Includes a `days_to_expiry` (negative = expired)."""
    from datetime import date as _d, timedelta as _td
    today      = _d.today()
    cutoff_iso = (today + _td(days=within_days)).isoformat()
    placeholders = ",".join("?" for _ in sensitivity_in)
    con = _con()
    rows = con.execute(
        f"""
        SELECT * FROM documents
        WHERE deleted_at IS NULL
          AND expiry_date IS NOT NULL
          AND expiry_date != ''
          AND expiry_date <= ?
          AND sensitivity IN ({placeholders})
        ORDER BY expiry_date ASC
        """,
        (cutoff_iso, *sensitivity_in),
    ).fetchall()
    con.close()
    out = []
    for r in rows:
        d = dict(r)
        try:
            exp = _d.fromisoformat(d["expiry_date"][:10])
            d["days_to_expiry"] = (exp - today).days
        except Exception:
            d["days_to_expiry"] = None
        out.append(d)
    return out


def get_document_by_id(doc_id: int, include_deleted: bool = False):
    con = _con()
    if include_deleted:
        row = con.execute("SELECT * FROM documents WHERE id = ?", (doc_id,)).fetchone()
    else:
        row = con.execute("SELECT * FROM documents WHERE id = ? AND deleted_at IS NULL",
                          (doc_id,)).fetchone()
    con.close()
    return dict(row) if row else None


def query_documents(
    sensitivity_in: list = None,
    document_type: str = None,
    linked_to_type: str = None,
    linked_to_id: int = None,
    search: str = None,
    include_deleted: bool = False,
    limit: int = 500,
):
    sql = "SELECT * FROM documents WHERE 1=1"
    args = []
    if not include_deleted:
        sql += " AND deleted_at IS NULL"
    if sensitivity_in:
        placeholders = ",".join("?" for _ in sensitivity_in)
        sql += f" AND sensitivity IN ({placeholders})"
        args.extend(sensitivity_in)
    if document_type:
        sql += " AND document_type = ?"
        args.append(document_type)
    if linked_to_type:
        sql += " AND linked_to_type = ?"
        args.append(linked_to_type)
    if linked_to_id is not None:
        sql += " AND linked_to_id = ?"
        args.append(linked_to_id)
    if search:
        sql += " AND (title LIKE ? OR description LIKE ? OR original_filename LIKE ?)"
        like = f"%{search}%"
        args.extend([like, like, like])
    sql += " ORDER BY uploaded_at DESC LIMIT ?"
    args.append(int(limit))
    con = _con()
    rows = con.execute(sql, args).fetchall()
    con.close()
    return [dict(r) for r in rows]


def touch_document_accessed(doc_id: int):
    con = _con()
    con.execute("UPDATE documents SET last_accessed_at = ? WHERE id = ?",
                (datetime.now(timezone.utc).isoformat(), doc_id))
    con.commit()
    con.close()


def soft_delete_document(doc_id: int):
    con = _con()
    con.execute("UPDATE documents SET deleted_at = ? WHERE id = ?",
                (datetime.now(timezone.utc).isoformat(), doc_id))
    con.commit()
    con.close()


def hard_delete_document(doc_id: int):
    con = _con()
    con.execute("DELETE FROM documents WHERE id = ?", (doc_id,))
    con.commit()
    con.close()


# ── Bootstrap first super admin ──────────────────────────────────────────────

def bootstrap_super_admin(username: str, password: str, name: str, email: str):
    """Creates the first super_admin if no admin_users exist. Returns (id, prid) or None."""
    con = _con()
    n = con.execute("SELECT COUNT(*) AS n FROM admin_users").fetchone()["n"]
    con.close()
    if n > 0:
        return None
    return create_admin_user(
        {
            "username": username,
            "password": password,
            "name": name,
            "email": email,
            "role": "super_admin",
        },
        created_by=None,
    )


# ── Visit readings (structured HVAC measurements) ────────────────────────────
def add_visit_reading(visit_id: int, tech_id: int, data: dict) -> int:
    """One reading row per recording — multiple allowed per visit so a tech
    can capture before-service and after-service numbers."""
    con = _con()
    cur = con.execute(
        """INSERT INTO visit_readings
            (visit_id, pressure_high, pressure_low, temp_supply, temp_return,
             delta_t, superheat, subcool, approach_temp, notes,
             recorded_by, recorded_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (visit_id,
         data.get("pressure_high"), data.get("pressure_low"),
         data.get("temp_supply"),  data.get("temp_return"),
         data.get("delta_t"),      data.get("superheat"),
         data.get("subcool"),      data.get("approach_temp"),
         data.get("notes") or "",
         tech_id, datetime.now(timezone.utc).isoformat()),
    )
    rid = cur.lastrowid
    con.commit()
    con.close()
    return rid


def get_visit_readings(visit_id: int):
    con = _con()
    rows = con.execute(
        "SELECT * FROM visit_readings WHERE visit_id = ? ORDER BY recorded_at ASC",
        (visit_id,),
    ).fetchall()
    con.close()
    return [dict(r) for r in rows]


# ── Visit signatures (write-once digital signature from client) ──────────────
def set_visit_signature(visit_id: int, signer_name: str,
                         signature_b64: str, captured_by: int) -> int:
    """Insert-only — UNIQUE constraint on visit_id prevents overwrite even
    if the endpoint is called twice. SHA-256 of the PLAINTEXT PNG dataURL is
    stored alongside the ENCRYPTED blob; the hash binds to the original
    content so tamper-detection survives the encryption layer."""
    import hashlib as _h
    digest = _h.sha256(signature_b64.encode("utf-8")).hexdigest()
    con = _con()
    cur = con.execute(
        """INSERT INTO visit_signatures
            (visit_id, signer_name, signature_b64, signature_sha256,
             captured_by, captured_at)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (visit_id, signer_name.strip(), _enc(signature_b64), digest,
         captured_by, datetime.now(timezone.utc).isoformat()),
    )
    sid = cur.lastrowid
    con.commit()
    con.close()
    return sid


def get_visit_signature(visit_id: int):
    con = _con()
    row = con.execute(
        "SELECT * FROM visit_signatures WHERE visit_id = ?", (visit_id,),
    ).fetchone()
    con.close()
    return _dec_row("visit_signatures", row)


# ── Visit checklists (pre-visit) ─────────────────────────────────────────────
def set_visit_checklist(visit_id: int, items: list, tech_id: int):
    import json as _json
    con = _con()
    con.execute(
        """INSERT OR REPLACE INTO visit_checklists
            (visit_id, items_json, completed_at, completed_by)
           VALUES (?, ?, ?, ?)""",
        (visit_id, _json.dumps(items),
         datetime.now(timezone.utc).isoformat(), tech_id),
    )
    con.commit()
    con.close()


def get_visit_checklist(visit_id: int):
    import json as _json
    con = _con()
    row = con.execute(
        "SELECT * FROM visit_checklists WHERE visit_id = ?", (visit_id,),
    ).fetchone()
    con.close()
    if not row:
        return None
    out = dict(row)
    try:
        out["items"] = _json.loads(out["items_json"])
    except Exception:
        out["items"] = []
    return out


# ── Part image filename helper ───────────────────────────────────────────────
def set_part_image(part_id: int, filename: str):
    con = _con()
    con.execute(
        "UPDATE parts SET image_filename = ?, updated_at = ? WHERE id = ?",
        (filename, datetime.now(timezone.utc).isoformat(), part_id),
    )
    con.commit()
    con.close()


# ── Inventory cost-spike guard ───────────────────────────────────────────────
def get_recent_unit_cost_avg(part_id: int, days: int = 90):
    """Mean unit_cost of received movements over the trailing window.
    Used to flag suspicious cost-per-unit spikes. Returns None if no history."""
    from datetime import timedelta as _td
    cutoff = (datetime.now(timezone.utc) - _td(days=days)).isoformat()
    con = _con()
    row = con.execute(
        """SELECT AVG(actual_unit_cost) AS avg_cost
           FROM goods_received WHERE part_id = ? AND received_at >= ?""",
        (part_id, cutoff),
    ).fetchone()
    con.close()
    return row["avg_cost"] if row and row["avg_cost"] is not None else None


# ── Purchase orders ──────────────────────────────────────────────────────────
def _next_po_number():
    con = _con()
    today = datetime.now(timezone.utc).strftime("%Y%m%d")
    n = con.execute(
        "SELECT COUNT(*) AS n FROM purchase_orders WHERE po_number LIKE ?",
        (f"PO-{today}-%",),
    ).fetchone()["n"]
    con.close()
    return f"PO-{today}-{n+1:03d}"


def create_purchase_order(supplier: str, lines: list, created_by: int) -> dict:
    """Lines: [{part_id, quantity, expected_unit_cost}]. Returns the new PO."""
    po_num = _next_po_number()
    expected_total = sum(float(l["quantity"]) * float(l.get("expected_unit_cost", 0)) for l in lines)
    now = datetime.now(timezone.utc).isoformat()
    con = _con()
    cur = con.execute(
        """INSERT INTO purchase_orders
            (po_number, supplier, status, expected_total, created_by, created_at)
           VALUES (?, ?, 'draft', ?, ?, ?)""",
        (po_num, supplier.strip(), expected_total, created_by, now),
    )
    po_id = cur.lastrowid
    for l in lines:
        con.execute(
            """INSERT INTO purchase_order_lines
                (po_id, part_id, quantity, expected_unit_cost)
               VALUES (?, ?, ?, ?)""",
            (po_id, int(l["part_id"]), float(l["quantity"]),
             float(l.get("expected_unit_cost", 0))),
        )
    con.commit()
    con.close()
    return {"id": po_id, "po_number": po_num, "expected_total": expected_total}


def list_purchase_orders(status: str = None):
    sql = "SELECT * FROM purchase_orders"
    args = []
    if status:
        sql += " WHERE status = ?"; args.append(status)
    sql += " ORDER BY created_at DESC LIMIT 500"
    con = _con()
    rows = con.execute(sql, args).fetchall()
    con.close()
    return [dict(r) for r in rows]


def get_purchase_order(po_id: int):
    con = _con()
    po = con.execute("SELECT * FROM purchase_orders WHERE id = ?", (po_id,)).fetchone()
    if not po:
        con.close()
        return None
    out = dict(po)
    lines = con.execute(
        """SELECT pol.*, p.sku, p.name AS part_name
           FROM purchase_order_lines pol JOIN parts p ON pol.part_id = p.id
           WHERE pol.po_id = ?""",
        (po_id,),
    ).fetchall()
    grn = con.execute(
        """SELECT g.*, p.sku, p.name AS part_name
           FROM goods_received g JOIN parts p ON g.part_id = p.id
           WHERE g.po_id = ?""",
        (po_id,),
    ).fetchall()
    con.close()
    out["lines"]    = [dict(r) for r in lines]
    out["received"] = [dict(r) for r in grn]
    out["received_total"] = sum(r["quantity"] * r["actual_unit_cost"] for r in out["received"])
    return out


def mark_po_sent(po_id: int):
    con = _con()
    con.execute(
        "UPDATE purchase_orders SET status='sent', sent_at=? WHERE id=? AND status='draft'",
        (datetime.now(timezone.utc).isoformat(), po_id),
    )
    con.commit()
    con.close()


def record_goods_received(po_id: int, po_line_id: int, part_id: int,
                           quantity: float, actual_unit_cost: float,
                           received_by: int, notes: str = "") -> int:
    """Records a GRN row AND updates the PO line's received_qty + the part
    inventory quantity. Also writes a part_movement row so the existing
    inventory dashboards reflect the receipt."""
    now = datetime.now(timezone.utc).isoformat()
    con = _con()
    # Update PO line
    con.execute(
        "UPDATE purchase_order_lines SET received_qty = received_qty + ? WHERE id = ?",
        (float(quantity), po_line_id),
    )
    # Update stock
    con.execute(
        "UPDATE parts SET quantity = quantity + ?, updated_at = ? WHERE id = ?",
        (float(quantity), now, part_id),
    )
    # Insert GRN
    cur = con.execute(
        """INSERT INTO goods_received
            (po_id, po_line_id, part_id, quantity, actual_unit_cost,
             received_by, received_at, notes)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (po_id, po_line_id, part_id, float(quantity),
         float(actual_unit_cost), received_by, now, notes or ""),
    )
    grn_id = cur.lastrowid
    # Mirror as a part_movement so movement reports still show the receipt
    con.execute(
        """INSERT INTO part_movements
            (part_id, movement_type, quantity_delta, reason, visit_id,
             performed_by_type, performed_by_id, created_at)
           VALUES (?, 'received', ?, ?, NULL, 'admin', ?, ?)""",
        (part_id, float(quantity), f"PO {po_id} GRN #{grn_id}", received_by, now),
    )
    # If all lines fully received, flip PO to 'received'
    pending = con.execute(
        """SELECT COUNT(*) AS n FROM purchase_order_lines
           WHERE po_id = ? AND received_qty < quantity""",
        (po_id,),
    ).fetchone()["n"]
    if pending == 0:
        con.execute("UPDATE purchase_orders SET status='received' WHERE id=? AND status IN ('sent','draft')",
                    (po_id,))
    con.commit()
    con.close()
    return grn_id


def close_purchase_order(po_id: int, invoice_number: str, invoice_total: float,
                          variance_note: str, closed_by: int) -> dict:
    """Three-way match: PO expected_total ↔ GRN actual total ↔ supplier invoice.
    If any of the three diverge beyond 1%, variance_note becomes mandatory."""
    po = get_purchase_order(po_id)
    if not po:
        raise ValueError("PO not found")
    if po["status"] == "closed":
        raise ValueError("PO already closed")
    expected = float(po["expected_total"])
    grn_tot  = float(po["received_total"])
    inv_tot  = float(invoice_total)
    matched  = all(abs(a - b) <= max(0.01 * max(a, b, 1), 0.01)
                   for a, b in ((expected, grn_tot), (grn_tot, inv_tot), (expected, inv_tot)))
    if not matched and not variance_note.strip():
        raise ValueError(
            f"Three-way mismatch (PO={expected:.2f}, GRN={grn_tot:.2f}, Invoice={inv_tot:.2f}). "
            "variance_note is required."
        )
    con = _con()
    con.execute(
        """UPDATE purchase_orders SET
              status='closed', invoice_number=?, invoice_total=?,
              variance_note=?, closed_by=?, closed_at=?
            WHERE id=?""",
        (invoice_number.strip(), inv_tot, variance_note.strip() or None,
         closed_by, datetime.now(timezone.utc).isoformat(), po_id),
    )
    con.commit()
    con.close()
    return {"matched": matched, "expected": expected,
            "received_total": grn_tot, "invoice_total": inv_tot}


# ── Physical counts (segregation: counted_by ≠ approved_by) ──────────────────
def create_physical_count(part_id: int, counted_qty: float, counted_by: int) -> dict:
    """Snapshots the system quantity at count time and computes variance.
    ≥5% variance flips status to 'escalated' so it can't be silently approved."""
    con = _con()
    row = con.execute("SELECT quantity FROM parts WHERE id = ?", (part_id,)).fetchone()
    if not row:
        con.close()
        raise ValueError("part not found")
    sys_qty = float(row["quantity"])
    cnt_qty = float(counted_qty)
    if sys_qty == 0 and cnt_qty == 0:
        variance = 0.0
    elif sys_qty == 0:
        variance = 100.0
    else:
        variance = abs(cnt_qty - sys_qty) / sys_qty * 100.0
    status = "escalated" if variance >= 5.0 else "pending"
    cur = con.execute(
        """INSERT INTO physical_counts
            (part_id, system_qty, counted_qty, variance_pct,
             counted_by, counted_at, status)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (part_id, sys_qty, cnt_qty, round(variance, 2),
         counted_by, datetime.now(timezone.utc).isoformat(), status),
    )
    cid = cur.lastrowid
    con.commit()
    con.close()
    return {"id": cid, "variance_pct": round(variance, 2), "status": status,
            "system_qty": sys_qty, "counted_qty": cnt_qty}


def list_physical_counts(status: str = None):
    sql = """SELECT pc.*, p.sku, p.name AS part_name
             FROM physical_counts pc JOIN parts p ON pc.part_id = p.id"""
    args = []
    if status:
        sql += " WHERE pc.status = ?"; args.append(status)
    sql += " ORDER BY pc.counted_at DESC LIMIT 200"
    con = _con()
    rows = con.execute(sql, args).fetchall()
    con.close()
    return [dict(r) for r in rows]


def approve_physical_count(count_id: int, approved_by: int, note: str = "",
                            adjust_stock: bool = True):
    """Approves a count and (optionally) adjusts the system stock to match.
    Caller must verify approved_by != counted_by — endpoint enforces this."""
    con = _con()
    row = con.execute("SELECT * FROM physical_counts WHERE id = ?", (count_id,)).fetchone()
    if not row:
        con.close()
        raise ValueError("count not found")
    r = dict(row)
    if r["status"] == "approved":
        con.close()
        raise ValueError("already approved")
    now = datetime.now(timezone.utc).isoformat()
    con.execute(
        """UPDATE physical_counts SET status='approved',
              approved_by=?, approved_at=?, approval_note=? WHERE id=?""",
        (approved_by, now, note or "", count_id),
    )
    if adjust_stock:
        delta = float(r["counted_qty"]) - float(r["system_qty"])
        if delta != 0:
            con.execute(
                "UPDATE parts SET quantity = ?, updated_at = ? WHERE id = ?",
                (float(r["counted_qty"]), now, r["part_id"]),
            )
            con.execute(
                """INSERT INTO part_movements
                    (part_id, movement_type, quantity_delta, reason,
                     performed_by_type, performed_by_id, created_at)
                   VALUES (?, 'adjusted', ?, ?, 'admin', ?, ?)""",
                (r["part_id"], delta,
                 f"Physical count #{count_id} approved (variance {r['variance_pct']}%)",
                 approved_by, now),
            )
    con.commit()
    con.close()


# ── Flag for review (manager only) ───────────────────────────────────────────
def set_visit_flag(visit_id: int, flagged: bool, note: str = ""):
    con = _con()
    con.execute(
        """UPDATE maintenance_visits
              SET flagged_for_review = ?, review_note = ?
            WHERE id = ?""",
        (1 if flagged else 0, note or "", visit_id),
    )
    con.commit()
    con.close()



# ── Client-portal hardening ──────────────────────────────────────────────────
def set_customer_password(customer_id: int, password: str):
    """Argon2-hash a customer password and flip auth_mode → 'password'.
    Caller is responsible for validating length/strength."""
    con = _con()
    con.execute(
        "UPDATE customers SET password_hash = ?, auth_mode = 'password' WHERE id = ?",
        (_hash_pin(password), customer_id),
    )
    con.commit()
    con.close()


def verify_customer_password(code: str, password: str):
    """Same shape as verify_customer() but reads password_hash. Used when the
    customer has auth_mode='password' (commercial accounts)."""
    cust = get_customer_by_code(code)
    if not cust:
        return None
    if cust.get("auth_mode") != "password":
        return None
    if not cust.get("password_hash"):
        return None
    if not _verify_pin(password, cust["password_hash"]):
        return None
    if _needs_rehash(cust["password_hash"]):
        set_customer_password(cust["id"], password)
    return cust


def set_customer_mfa(customer_id: int, secret: str, enabled: bool,
                     backup_codes_hashed: list = None):
    import json as _json
    con = _con()
    con.execute(
        """UPDATE customers SET
              mfa_secret = ?, mfa_enabled = ?, backup_codes = ?
            WHERE id = ?""",
        (_enc(secret) if secret else None, 1 if enabled else 0,
         _json.dumps(backup_codes_hashed) if backup_codes_hashed else None,
         customer_id),
    )
    con.commit()
    con.close()


def set_customer_type(customer_id: int, customer_type: str):
    if customer_type not in ("residential", "commercial"):
        raise ValueError("customer_type must be 'residential' or 'commercial'")
    con = _con()
    con.execute("UPDATE customers SET customer_type = ? WHERE id = ?",
                (customer_type, customer_id))
    con.commit()
    con.close()


def mark_customer_deletion_requested(customer_id: int):
    con = _con()
    con.execute(
        "UPDATE customers SET deletion_requested_at = ? WHERE id = ?",
        (datetime.now(timezone.utc).isoformat(), customer_id),
    )
    con.commit()
    con.close()


def get_customer_full_export(customer_id: int) -> dict:
    """Privacy-compliance data export. Returns every record this customer
    has direct visibility into, plus contractual data they're a party to.
    Excludes internal-only fields (raw findings, tech identity, costs)."""
    con = _con()
    cust = con.execute(
        """SELECT id, customer_code, name, company, email, phone, address,
                  notes, customer_type, auth_mode, created_at, deletion_requested_at
             FROM customers WHERE id = ?""", (customer_id,)).fetchone()
    if not cust:
        con.close()
        return {}
    out = {"customer": dict(cust)}
    out["equipment"] = [dict(r) for r in con.execute(
        "SELECT * FROM equipment WHERE customer_id = ?", (customer_id,)
    ).fetchall()]
    out["visits"] = [dict(r) for r in con.execute(
        """SELECT id, visit_type, status, scheduled_date, scheduled_time,
                  completed_date, work_done_summary AS work_summary,
                  next_pm_due, equipment_id, created_at
             FROM maintenance_visits WHERE customer_id = ?""", (customer_id,)
    ).fetchall()]
    try:
        out["invoices"] = [dict(r) for r in con.execute(
            """SELECT id, invoice_number, issue_date, due_date, subtotal,
                      gct_amount, total, amount_paid, status, created_at
                 FROM invoices WHERE customer_id = ?""", (customer_id,)
        ).fetchall()]
    except Exception:
        out["invoices"] = []
    out["reviews"] = [dict(r) for r in con.execute(
        "SELECT * FROM reviews WHERE customer_id = ?", (customer_id,)
    ).fetchall()]
    out["service_requests"] = [dict(r) for r in con.execute(
        """SELECT id, request_type, subject, body, preferred_date, status,
                  visit_id, created_at FROM service_requests WHERE customer_id = ?""",
        (customer_id,),
    ).fetchall()]
    con.close()
    return out


# ── Service requests (client-portal triage queue) ────────────────────────────
def create_service_request(customer_id: int, data: dict, ip_address: str = None) -> int:
    con = _con()
    cur = con.execute(
        """INSERT INTO service_requests
            (customer_id, equipment_id, request_type, subject, body,
             preferred_date, status, created_at, ip_address)
           VALUES (?, ?, ?, ?, ?, ?, 'new', ?, ?)""",
        (customer_id,
         int(data["equipment_id"]) if data.get("equipment_id") else None,
         data.get("request_type", "question"),
         data["subject"].strip()[:200],
         data["body"].strip()[:4000],
         data.get("preferred_date") or None,
         datetime.now(timezone.utc).isoformat(),
         (ip_address or "")[:64] or None),
    )
    rid = cur.lastrowid
    con.commit()
    con.close()
    return rid


def list_service_requests(status: str = None, customer_id: int = None, limit: int = 200):
    sql = """SELECT sr.*, c.name AS customer_name, c.customer_code,
                    e.name AS equipment_name
               FROM service_requests sr
               JOIN customers c ON sr.customer_id = c.id
          LEFT JOIN equipment e ON sr.equipment_id = e.id"""
    where = []
    args  = []
    if status:
        where.append("sr.status = ?"); args.append(status)
    if customer_id is not None:
        where.append("sr.customer_id = ?"); args.append(customer_id)
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY sr.created_at DESC LIMIT ?"
    args.append(int(limit))
    con = _con()
    rows = con.execute(sql, args).fetchall()
    con.close()
    return [dict(r) for r in rows]


def get_service_request(req_id: int):
    con = _con()
    row = con.execute("SELECT * FROM service_requests WHERE id = ?", (req_id,)).fetchone()
    con.close()
    return dict(row) if row else None


def update_service_request_status(req_id: int, status: str, admin_id: int,
                                   visit_id: int = None):
    con = _con()
    con.execute(
        """UPDATE service_requests SET
              status = ?,
              triaged_by = COALESCE(triaged_by, ?),
              triaged_at = COALESCE(triaged_at, ?),
              visit_id   = COALESCE(visit_id, ?)
            WHERE id = ?""",
        (status, admin_id, datetime.now(timezone.utc).isoformat(),
         visit_id, req_id),
    )
    con.commit()
    con.close()


# ── Visit findings split (client-facing summary) ─────────────────────────────
def set_visit_work_summary(visit_id: int, summary: str):
    con = _con()
    con.execute("UPDATE maintenance_visits SET work_done_summary = ? WHERE id = ?",
                (summary or "", visit_id))
    con.commit()
    con.close()


# ── Customer visits filtered to the customer-facing shape ────────────────────
def get_customer_visits_portal(customer_id: int):
    """Returns visits with ONLY the fields the customer is allowed to see.
    Strips raw work_done, internal notes, parts_replaced, assigned_tech_id,
    hazards, access_codes — anything operational/identifying."""
    con = _con()
    rows = con.execute(
        """SELECT v.id, v.visit_type, v.status, v.scheduled_date, v.scheduled_time,
                  v.completed_date, v.work_done_summary, v.next_pm_due,
                  v.equipment_id, v.submitted_at, v.created_at,
                  e.name AS equipment_name
             FROM maintenance_visits v
        LEFT JOIN equipment e ON v.equipment_id = e.id
            WHERE v.customer_id = ?
            ORDER BY COALESCE(v.completed_date, v.scheduled_date, v.created_at) DESC""",
        (customer_id,),
    ).fetchall()
    con.close()
    return [dict(r) for r in rows]


# ── Access lifecycle ─────────────────────────────────────────────────────────
# Single module governing every state transition: hire/promote/demote already
# live in their own helpers; the destructive transitions (terminate, soft-close,
# dormant detection) all funnel through here so we can audit, revoke, and
# enforce consistently.

def bump_last_login(subject_type: str, subject_id: int):
    """Stamp last_login_at on the actor's row. Called by login endpoints
    after a successful auth + MFA pass. Used by dormant-account sweeps."""
    table = {"admin": "admin_users", "tech": "technicians",
             "customer": "customers"}.get(subject_type)
    if not table:
        return
    con = _con()
    con.execute(f"UPDATE {table} SET last_login_at = ? WHERE id = ?",
                (datetime.now(timezone.utc).isoformat(), int(subject_id)))
    con.commit()
    con.close()


def terminate_account(subject_type: str, subject_id: int) -> dict:
    """Hard-off: flips active=0, stamps terminated_at, and immediately revokes
    every session for this principal. Caller is responsible for audit + perm
    check. Returns counts so the endpoint can report what was killed."""
    table = {"admin": "admin_users", "tech": "technicians",
             "customer": "customers"}.get(subject_type)
    if not table:
        raise ValueError("unknown subject_type")
    now = datetime.now(timezone.utc).isoformat()
    con = _con()
    con.execute(f"UPDATE {table} SET active = 0, terminated_at = ? WHERE id = ?",
                (now, int(subject_id)))
    con.commit()
    con.close()
    sessions_killed = revoke_all_sessions_for(subject_type, subject_id)
    return {"terminated_at": now, "sessions_revoked": sessions_killed}


def reinstate_account(subject_type: str, subject_id: int):
    """Reverses terminate_account — clears terminated_at and re-activates.
    Sessions remain revoked; user must sign in again."""
    table = {"admin": "admin_users", "tech": "technicians",
             "customer": "customers"}.get(subject_type)
    if not table:
        raise ValueError("unknown subject_type")
    con = _con()
    con.execute(f"UPDATE {table} SET active = 1, terminated_at = NULL WHERE id = ?",
                (int(subject_id),))
    con.commit()
    con.close()


def find_dormant_accounts(days: int = 90) -> dict:
    """Returns {admin: [...], tech: [...], customer: [...]} of active accounts
    that haven't logged in for `days` or more. Accounts that have never logged
    in are included once they're older than `days` (created_at as fallback)."""
    from datetime import timedelta as _td
    cutoff = (datetime.now(timezone.utc) - _td(days=days)).isoformat()
    con = _con()
    out = {}
    for subj, table, label_col in (
        ("admin",    "admin_users",  "username"),
        ("tech",     "technicians",  "tech_code"),
        ("customer", "customers",    "customer_code"),
    ):
        rows = con.execute(
            f"""SELECT id, {label_col} AS label, last_login_at, created_at
                  FROM {table}
                 WHERE active = 1
                   AND (last_login_at IS NULL OR last_login_at < ?)
                   AND created_at < ?""",
            (cutoff, cutoff),
        ).fetchall()
        out[subj] = [dict(r) for r in rows]
    con.close()
    return out


def get_account_exit_report(subject_type: str, subject_id: int, days: int = 30) -> dict:
    """Surface for the S3 'did they take anything' question. Aggregates the
    last `days` of activity for one principal: read counts, distinct
    customers touched, exports, accounts created/edited, last login.
    All from existing audit_log + access_log — no new data store."""
    from datetime import timedelta as _td
    since = (datetime.now(timezone.utc) - _td(days=days)).isoformat()
    con = _con()
    # Mutations
    mutations = con.execute(
        """SELECT action, COUNT(*) AS n FROM audit_log
            WHERE actor_type = ? AND actor_id = ? AND created_at >= ?
            GROUP BY action ORDER BY n DESC""",
        (subject_type, int(subject_id), since),
    ).fetchall()
    # Reads: total, distinct customers, distinct visits
    reads_total = con.execute(
        """SELECT COUNT(*) AS n FROM access_log
            WHERE actor_type = ? AND actor_id = ? AND method = 'GET'
              AND status_code >= 200 AND status_code < 300
              AND created_at >= ?""",
        (subject_type, int(subject_id), since),
    ).fetchone()["n"]
    # Distinct customers touched (via path)
    paths = con.execute(
        """SELECT path FROM access_log
            WHERE actor_type = ? AND actor_id = ? AND method = 'GET'
              AND status_code >= 200 AND status_code < 300
              AND created_at >= ?
              AND (path LIKE '/api/admin/customers/%' OR path LIKE '/api/tech/customers/%')""",
        (subject_type, int(subject_id), since),
    ).fetchall()
    import re as _re
    rx = _re.compile(r"/customers/(\d+)")
    customer_ids = set()
    for r in paths:
        m = rx.search(r["path"] or "")
        if m: customer_ids.add(int(m.group(1)))
    # Exports + account-mutation events (the high-signal "preparing to leave" actions)
    exports = con.execute(
        """SELECT action, target_label, created_at FROM audit_log
            WHERE actor_type = ? AND actor_id = ? AND created_at >= ?
              AND action LIKE '%.export'
            ORDER BY created_at DESC LIMIT 200""",
        (subject_type, int(subject_id), since),
    ).fetchall()
    account_changes = con.execute(
        """SELECT action, target_type, target_id, target_label, created_at
             FROM audit_log
            WHERE actor_type = ? AND actor_id = ? AND created_at >= ?
              AND (action LIKE 'admin.%' OR action LIKE 'tech.set_supervisor%')
            ORDER BY created_at DESC LIMIT 200""",
        (subject_type, int(subject_id), since),
    ).fetchall()
    # Last login from the user's table
    table = {"admin":"admin_users","tech":"technicians","customer":"customers"}.get(subject_type)
    last_login = None
    if table:
        row = con.execute(f"SELECT last_login_at FROM {table} WHERE id = ?",
                          (int(subject_id),)).fetchone()
        if row: last_login = row["last_login_at"]
    con.close()
    return {
        "subject_type":          subject_type,
        "subject_id":            int(subject_id),
        "window_days":           days,
        "last_login_at":         last_login,
        "reads_total":           int(reads_total or 0),
        "distinct_customers":    len(customer_ids),
        "mutations_by_action":   [dict(r) for r in mutations],
        "exports":               [dict(r) for r in exports],
        "account_changes":       [dict(r) for r in account_changes],
    }


# ── Payroll helpers ─────────────────────────────────────────────────────────
def create_pay_period(start: str, end: str, label: str, created_by: int,
                       currency: str = "JMD") -> int:
    con = _con()
    cur = con.execute(
        """INSERT INTO pay_periods (period_start, period_end, label, status,
                                     currency, created_by, created_at)
           VALUES (?, ?, ?, 'draft', ?, ?, ?)""",
        (start, end, label, currency, created_by,
         datetime.now(timezone.utc).isoformat()),
    )
    pid = cur.lastrowid
    con.commit()
    con.close()
    return pid


def list_pay_periods(limit: int = 100):
    con = _con()
    rows = con.execute(
        """SELECT pp.*, a1.name AS created_by_name, a2.name AS approved_by_name
             FROM pay_periods pp
        LEFT JOIN admin_users a1 ON pp.created_by  = a1.id
        LEFT JOIN admin_users a2 ON pp.approved_by = a2.id
            ORDER BY pp.period_end DESC LIMIT ?""", (int(limit),),
    ).fetchall()
    con.close()
    return [dict(r) for r in rows]


def get_pay_period(period_id: int):
    con = _con()
    row = con.execute("SELECT * FROM pay_periods WHERE id = ?", (period_id,)).fetchone()
    con.close()
    return dict(row) if row else None


# Payroll rates — single source of truth lives in main.JAMAICA_TAX_REFERENCE
# and is pushed here at startup via set_payroll_rates(). The defaults below
# match the Tax Administration Jamaica rates published at the time of writing
# and are used if main never overrides (e.g. unit tests importing database
# directly). When TAJ changes rates, update main.JAMAICA_TAX_REFERENCE; no
# other file needs to change.
PAYROLL_RATES = {
    "paye_threshold":      1_700_000.0,   # tax-free annual income
    "paye_band1_rate":     0.25,          # threshold → band2_min
    "paye_band2_min":      6_000_000.0,
    "paye_band2_rate":     0.30,          # above band2_min
    "nis_employee_rate":   0.03,
    "nht_employee_rate":   0.02,
    "education_tax_rate":  0.0225,
}


def set_payroll_rates(payroll_section: dict):
    """Called once from main.py at module init to push the canonical
    JAMAICA_TAX_REFERENCE['payroll'] values into PAYROLL_RATES so
    compute_payslip_amounts() pulls from the same dict the API exposes."""
    if not payroll_section:
        return
    paye = payroll_section.get("paye", {})
    PAYROLL_RATES["paye_threshold"]     = float(paye.get("annual_threshold",  PAYROLL_RATES["paye_threshold"]))
    PAYROLL_RATES["paye_band1_rate"]    = float(paye.get("band1_rate",        PAYROLL_RATES["paye_band1_rate"]))
    PAYROLL_RATES["paye_band2_min"]     = float(paye.get("band2_min_annual",  PAYROLL_RATES["paye_band2_min"]))
    PAYROLL_RATES["paye_band2_rate"]    = float(paye.get("band2_rate",        PAYROLL_RATES["paye_band2_rate"]))
    PAYROLL_RATES["nis_employee_rate"]  = float(payroll_section.get("nis", {}).get("employee_rate",          PAYROLL_RATES["nis_employee_rate"]))
    PAYROLL_RATES["nht_employee_rate"]  = float(payroll_section.get("nht", {}).get("employee_rate",          PAYROLL_RATES["nht_employee_rate"]))
    PAYROLL_RATES["education_tax_rate"] = float(payroll_section.get("education_tax", {}).get("employee_rate", PAYROLL_RATES["education_tax_rate"]))


def _calc_paye(annual_gross: float) -> float:
    """Jamaica PAYE bands. Reads from PAYROLL_RATES so a TAJ rate change is
    one dict edit in main.JAMAICA_TAX_REFERENCE — no surgery here."""
    r = PAYROLL_RATES
    if annual_gross <= r["paye_threshold"]:
        return 0.0
    taxed_band1 = min(annual_gross, r["paye_band2_min"]) - r["paye_threshold"]
    paye = taxed_band1 * r["paye_band1_rate"]
    if annual_gross > r["paye_band2_min"]:
        paye += (annual_gross - r["paye_band2_min"]) * r["paye_band2_rate"]
    return paye


def compute_payslip_amounts(hours_regular: float, hours_overtime: float,
                              hourly_rate: float, overtime_rate: float,
                              fixed_salary: float, bonus: float,
                              other_deductions: float,
                              pay_periods_per_year: int = 26) -> dict:
    """All numbers in JMD. Deductions are EMPLOYEE-side only (employer side
    goes on the company expense report, not the payslip)."""
    r = PAYROLL_RATES
    gross = (hours_regular * hourly_rate
             + hours_overtime * overtime_rate
             + fixed_salary
             + bonus)
    annualised = gross * pay_periods_per_year
    paye_annual = _calc_paye(annualised)
    paye_period = paye_annual / pay_periods_per_year if pay_periods_per_year else 0
    nis           = gross * r["nis_employee_rate"]
    nht           = gross * r["nht_employee_rate"]
    education_tax = gross * r["education_tax_rate"]
    total_ded     = round(paye_period + nis + nht + education_tax + (other_deductions or 0), 2)
    net           = round(gross - total_ded, 2)
    return {
        "gross_pay":        round(gross, 2),
        "paye_tax":         round(paye_period, 2),
        "nis":              round(nis, 2),
        "nht":              round(nht, 2),
        "education_tax":    round(education_tax, 2),
        "other_deductions": round(other_deductions or 0, 2),
        "total_deductions": total_ded,
        "net_pay":          net,
    }


def upsert_payslip(period_id: int, subject_type: str, subject_id: int,
                    subject_name: str, subject_prid: str,
                    data: dict, generated_by: int) -> int:
    """Create or update the payslip for (period, subject). Computes amounts
    from the supplied hours / rate / fixed salary so callers can't pass
    inconsistent gross/net numbers. notes column goes through field
    encryption via _enc_dict."""
    calc = compute_payslip_amounts(
        hours_regular   = float(data.get("hours_regular", 0)),
        hours_overtime  = float(data.get("hours_overtime", 0)),
        hourly_rate     = float(data.get("hourly_rate", 0)),
        overtime_rate   = float(data.get("overtime_rate", 0)),
        fixed_salary    = float(data.get("fixed_salary", 0)),
        bonus           = float(data.get("bonus", 0)),
        other_deductions= float(data.get("other_deductions", 0)),
        pay_periods_per_year = int(data.get("pay_periods_per_year", 26)),
    )
    notes_enc = _enc(data.get("notes") or "")
    now = datetime.now(timezone.utc).isoformat()
    con = _con()
    cur = con.execute(
        """INSERT INTO payslips
            (pay_period_id, subject_type, subject_id, subject_name, subject_prid,
             hours_regular, hours_overtime, hourly_rate, overtime_rate,
             fixed_salary, bonus, gross_pay,
             paye_tax, nis, nht, education_tax, other_deductions,
             total_deductions, net_pay, notes,
             generated_by, generated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT(pay_period_id, subject_type, subject_id) DO UPDATE SET
             subject_name=excluded.subject_name,
             subject_prid=excluded.subject_prid,
             hours_regular=excluded.hours_regular,
             hours_overtime=excluded.hours_overtime,
             hourly_rate=excluded.hourly_rate,
             overtime_rate=excluded.overtime_rate,
             fixed_salary=excluded.fixed_salary,
             bonus=excluded.bonus,
             gross_pay=excluded.gross_pay,
             paye_tax=excluded.paye_tax,
             nis=excluded.nis,
             nht=excluded.nht,
             education_tax=excluded.education_tax,
             other_deductions=excluded.other_deductions,
             total_deductions=excluded.total_deductions,
             net_pay=excluded.net_pay,
             notes=excluded.notes,
             generated_by=excluded.generated_by,
             generated_at=excluded.generated_at
        """,
        (period_id, subject_type, int(subject_id), subject_name, subject_prid,
         float(data.get("hours_regular", 0)), float(data.get("hours_overtime", 0)),
         float(data.get("hourly_rate", 0)), float(data.get("overtime_rate", 0)),
         float(data.get("fixed_salary", 0)), float(data.get("bonus", 0)),
         calc["gross_pay"],
         calc["paye_tax"], calc["nis"], calc["nht"], calc["education_tax"],
         calc["other_deductions"], calc["total_deductions"], calc["net_pay"],
         notes_enc, generated_by, now),
    )
    rid = cur.lastrowid
    con.commit()
    con.close()
    return rid


def list_payslips_for_period(period_id: int):
    con = _con()
    rows = con.execute(
        """SELECT p.*, a.name AS generated_by_name
             FROM payslips p
        LEFT JOIN admin_users a ON p.generated_by = a.id
            WHERE p.pay_period_id = ?
            ORDER BY p.subject_type, p.subject_name""",
        (period_id,),
    ).fetchall()
    con.close()
    return _dec_rows("payslips", rows)


def list_payslips_for_subject(subject_type: str, subject_id: int, limit: int = 50):
    """Returns ONLY payslips for the named employee. Used by the
    self-service endpoints. Drafts (period.status='draft') are hidden —
    the employee should not see numbers until the period is approved."""
    con = _con()
    rows = con.execute(
        """SELECT p.*, pp.label AS period_label, pp.period_start, pp.period_end,
                  pp.status AS period_status, pp.currency
             FROM payslips p
             JOIN pay_periods pp ON p.pay_period_id = pp.id
            WHERE p.subject_type = ? AND p.subject_id = ?
              AND pp.status IN ('approved','paid')
            ORDER BY pp.period_end DESC LIMIT ?""",
        (subject_type, int(subject_id), int(limit)),
    ).fetchall()
    con.close()
    return _dec_rows("payslips", rows)


def get_payslip(payslip_id: int):
    con = _con()
    row = con.execute(
        """SELECT p.*, pp.label AS period_label, pp.period_start, pp.period_end,
                  pp.status AS period_status, pp.currency,
                  a.name AS generated_by_name
             FROM payslips p
             JOIN pay_periods pp ON p.pay_period_id = pp.id
        LEFT JOIN admin_users a ON p.generated_by  = a.id
            WHERE p.id = ?""", (payslip_id,)
    ).fetchone()
    con.close()
    return _dec_row("payslips", row) if row else None


def mark_payslip_viewed(payslip_id: int):
    """Stamp viewed_by_employee_at the first time the owning employee opens
    their payslip. Subsequent views don't overwrite — the timestamp records
    'employee acknowledged receipt'."""
    con = _con()
    con.execute(
        "UPDATE payslips SET viewed_by_employee_at = COALESCE(viewed_by_employee_at, ?) WHERE id = ?",
        (datetime.now(timezone.utc).isoformat(), payslip_id),
    )
    con.commit()
    con.close()


def approve_pay_period(period_id: int, approved_by: int) -> dict:
    """SoD: super_admin only. Endpoint also enforces approved_by != created_by
    as defense in depth so HR can never approve their own batch."""
    con = _con()
    row = con.execute("SELECT created_by, status FROM pay_periods WHERE id = ?", (period_id,)).fetchone()
    if not row:
        con.close()
        raise ValueError("pay period not found")
    if row["status"] != "draft":
        con.close()
        raise ValueError(f"pay period is {row['status']}, only draft can be approved")
    if row["created_by"] == approved_by:
        con.close()
        raise ValueError("approver cannot be the same admin who created the period")
    now = datetime.now(timezone.utc).isoformat()
    con.execute(
        "UPDATE pay_periods SET status='approved', approved_by=?, approved_at=? WHERE id=?",
        (approved_by, now, period_id),
    )
    con.commit()
    con.close()
    return {"status": "approved", "approved_at": now}


def mark_pay_period_paid(period_id: int):
    con = _con()
    con.execute(
        "UPDATE pay_periods SET status='paid', paid_at=? WHERE id=? AND status='approved'",
        (datetime.now(timezone.utc).isoformat(), period_id),
    )
    con.commit()
    con.close()


# ── Hubs (multi-hub readiness, seeded with Kingston in init_db) ──────────────
def list_hubs(include_inactive: bool = False):
    con = _con()
    sql = "SELECT * FROM hubs"
    if not include_inactive:
        sql += " WHERE active = 1"
    sql += " ORDER BY id ASC"
    rows = con.execute(sql).fetchall()
    con.close()
    return [dict(r) for r in rows]


def get_hub_by_id(hub_id: int):
    con = _con()
    row = con.execute("SELECT * FROM hubs WHERE id = ?", (int(hub_id),)).fetchone()
    con.close()
    return dict(row) if row else None


def create_hub(name: str, code: str, address: str = "") -> int:
    con = _con()
    cur = con.execute(
        "INSERT INTO hubs (name, code, address, active, created_at) VALUES (?, ?, ?, 1, ?)",
        (name.strip(), code.strip().upper(), address or "",
         datetime.now(timezone.utc).isoformat()),
    )
    hid = cur.lastrowid
    con.commit()
    con.close()
    return hid


# ── AR Aging (Tier-0 doctrine organ: cash discipline) ────────────────────────
def get_ar_aging(as_of: str = None) -> dict:
    """Returns aging buckets for every invoice with outstanding balance.
    Buckets follow standard AR convention (relative to due_date):
      not_yet_due  → due_date >  as_of
      bucket_0_30  → 0 ≤ days_overdue ≤ 30
      bucket_31_60 → 31 ≤ days_overdue ≤ 60
      bucket_61_90 → 61 ≤ days_overdue ≤ 90
      bucket_90+   → days_overdue > 90

    'Outstanding' = (total - amount_paid) > 0.01 AND status != 'draft' AND
    status != 'cancelled'. Drafts and cancelled don't carry receivable.
    """
    from datetime import date as _d, datetime as _dt, timedelta as _td
    if as_of is None:
        as_of = _dt.now(timezone.utc).date().isoformat()
    con = _con()
    rows = con.execute(
        """SELECT i.id, i.invoice_number, i.customer_id, c.name AS customer_name,
                  c.customer_code, i.issue_date, i.due_date, i.total,
                  i.amount_paid, i.status, i.currency
             FROM invoices i
             JOIN customers c ON i.customer_id = c.id
            WHERE i.status NOT IN ('draft', 'cancelled')
              AND (i.total - i.amount_paid) > 0.01
            ORDER BY i.due_date ASC"""
    ).fetchall()
    con.close()

    buckets = {
        "not_yet_due":   {"label": "Not yet due", "count": 0, "total_outstanding": 0.0, "invoices": []},
        "bucket_0_30":   {"label": "0–30 days",   "count": 0, "total_outstanding": 0.0, "invoices": []},
        "bucket_31_60":  {"label": "31–60 days",  "count": 0, "total_outstanding": 0.0, "invoices": []},
        "bucket_61_90":  {"label": "61–90 days",  "count": 0, "total_outstanding": 0.0, "invoices": []},
        "bucket_90plus": {"label": "90+ days",    "count": 0, "total_outstanding": 0.0, "invoices": []},
    }
    grand_total = 0.0
    customer_rollup = {}    # customer_id → totals
    for r in rows:
        d = dict(r)
        outstanding = round(float(d["total"]) - float(d["amount_paid"]), 2)
        if outstanding <= 0:
            continue
        try:
            due = _d.fromisoformat(d["due_date"])
            today = _d.fromisoformat(as_of)
            days_overdue = (today - due).days
        except Exception:
            days_overdue = 0
        if days_overdue < 0:
            bucket = "not_yet_due"
        elif days_overdue <= 30:
            bucket = "bucket_0_30"
        elif days_overdue <= 60:
            bucket = "bucket_31_60"
        elif days_overdue <= 90:
            bucket = "bucket_61_90"
        else:
            bucket = "bucket_90plus"
        d["outstanding"]  = outstanding
        d["days_overdue"] = days_overdue
        d["bucket"]       = bucket
        buckets[bucket]["count"] += 1
        buckets[bucket]["total_outstanding"] = round(buckets[bucket]["total_outstanding"] + outstanding, 2)
        buckets[bucket]["invoices"].append(d)
        grand_total += outstanding
        cid = d["customer_id"]
        if cid not in customer_rollup:
            customer_rollup[cid] = {
                "customer_id":         cid,
                "customer_code":       d["customer_code"],
                "customer_name":       d["customer_name"],
                "invoice_count":       0,
                "total_outstanding":   0.0,
                "oldest_days_overdue": 0,
            }
        cr = customer_rollup[cid]
        cr["invoice_count"]       += 1
        cr["total_outstanding"]    = round(cr["total_outstanding"] + outstanding, 2)
        cr["oldest_days_overdue"]  = max(cr["oldest_days_overdue"], days_overdue)
    by_customer = sorted(customer_rollup.values(),
                          key=lambda c: c["total_outstanding"], reverse=True)
    return {
        "as_of":             as_of,
        "grand_total":       round(grand_total, 2),
        "buckets":           buckets,
        "by_customer":       by_customer,
    }


# ── CM margin rollup (Tier-0 doctrine organ: gross margin signal) ───────────
def get_cm_margin(start_date: str = None, end_date: str = None) -> dict:
    """Per-visit CM margin AND aggregate rollup for the date window.

      visit_revenue  = invoice.subtotal (NET of GCT; GCT is liability, not rev)
      parts_cost     = SUM(visit_parts.quantity * parts.unit_cost)
      labor_cost     = (end_time - start_time) hours × technicians.hourly_rate
      margin         = visit_revenue - parts_cost - labor_cost
      margin_pct     = margin / visit_revenue × 100  (None if revenue == 0)

    Only includes CM visits with status='completed'. PM visits roll under the
    PM contract module (Tier-0 still to build). Visits without an invoice
    contribute parts/labor cost but zero revenue → margin negative for that
    row; surfaces unbilled completed work which is itself a useful signal.
    """
    if not start_date:
        from datetime import date as _d, timedelta as _td
        start_date = (_d.today() - _td(days=90)).isoformat()
    if not end_date:
        from datetime import date as _d
        end_date = _d.today().isoformat()

    con = _con()
    visits = con.execute(
        """SELECT v.id AS visit_id, v.customer_id, v.visit_type, v.status,
                  v.scheduled_date, v.completed_date,
                  v.start_time, v.end_time, v.assigned_tech_id,
                  c.name AS customer_name, c.customer_code,
                  t.name AS tech_name, t.hourly_rate
             FROM maintenance_visits v
             JOIN customers c   ON v.customer_id = c.id
        LEFT JOIN technicians t ON v.assigned_tech_id = t.id
            WHERE UPPER(v.visit_type) = 'CM'
              AND v.status = 'completed'
              AND COALESCE(v.completed_date, v.scheduled_date) BETWEEN ? AND ?
            ORDER BY COALESCE(v.completed_date, v.scheduled_date) DESC""",
        (start_date, end_date),
    ).fetchall()

    out_rows = []
    agg = {"revenue": 0.0, "parts_cost": 0.0, "labor_cost": 0.0,
           "margin": 0.0, "visit_count": 0, "unbilled_count": 0}

    for v in visits:
        vid = v["visit_id"]
        # Parts cost — sum of visit_parts × parts.unit_cost.
        parts_cost = con.execute(
            """SELECT COALESCE(SUM(vp.quantity * p.unit_cost), 0) AS pc
                 FROM visit_parts vp JOIN parts p ON vp.part_id = p.id
                WHERE vp.visit_id = ?""", (vid,)
        ).fetchone()["pc"] or 0.0

        # Labor cost — duration × tech hourly rate (only if both timestamps).
        labor_cost = 0.0
        if v["start_time"] and v["end_time"] and v["hourly_rate"]:
            try:
                from datetime import datetime as _dt
                s = _dt.fromisoformat(v["start_time"].replace("Z","+00:00"))
                e = _dt.fromisoformat(v["end_time"].replace("Z","+00:00"))
                hours = max(0.0, (e - s).total_seconds() / 3600.0)
                labor_cost = round(hours * float(v["hourly_rate"]), 2)
            except Exception:
                labor_cost = 0.0

        # Revenue — invoice.subtotal (NET of GCT).
        inv = con.execute(
            """SELECT id AS invoice_id, invoice_number, subtotal, total,
                      amount_paid, status
                 FROM invoices
                WHERE visit_id = ? AND status != 'cancelled'
                ORDER BY id DESC LIMIT 1""", (vid,)
        ).fetchone()
        revenue = float(inv["subtotal"]) if inv else 0.0

        margin = round(revenue - float(parts_cost) - labor_cost, 2)
        margin_pct = round(margin / revenue * 100.0, 1) if revenue > 0 else None

        out_rows.append({
            "visit_id":        vid,
            "customer_id":     v["customer_id"],
            "customer_code":   v["customer_code"],
            "customer_name":   v["customer_name"],
            "tech_name":       v["tech_name"],
            "scheduled_date":  v["scheduled_date"],
            "completed_date":  v["completed_date"],
            "revenue":         round(revenue, 2),
            "parts_cost":      round(float(parts_cost), 2),
            "labor_cost":      labor_cost,
            "margin":          margin,
            "margin_pct":      margin_pct,
            "invoice_id":      inv["invoice_id"]      if inv else None,
            "invoice_number":  inv["invoice_number"]  if inv else None,
            "invoice_status":  inv["status"]          if inv else None,
            "billed":          bool(inv),
        })
        agg["revenue"]      += revenue
        agg["parts_cost"]   += float(parts_cost)
        agg["labor_cost"]   += labor_cost
        agg["margin"]       += margin
        agg["visit_count"]  += 1
        if not inv:
            agg["unbilled_count"] += 1

    con.close()

    agg["revenue"]    = round(agg["revenue"],    2)
    agg["parts_cost"] = round(agg["parts_cost"], 2)
    agg["labor_cost"] = round(agg["labor_cost"], 2)
    agg["margin"]     = round(agg["margin"],     2)
    agg["margin_pct"] = round(agg["margin"] / agg["revenue"] * 100.0, 1) if agg["revenue"] > 0 else None
    return {
        "start_date": start_date,
        "end_date":   end_date,
        "aggregate":  agg,
        "visits":     out_rows,
    }


# ── 5S workplace-discipline module ───────────────────────────────────────────
# Constants
FS_BAND_GREEN  = "green"
FS_BAND_AMBER  = "amber"
FS_BAND_RED    = "red"
FS_VALID_PHASES = ("start_shift", "end_shift", "weekly_manager")

# Item-keys that are safety/LOTO failures (auto-elevate exception severity).
FS_SAFETY_ITEM_KEYS = {
    "fluids_checked", "tires_visual_ok", "lights_working",
    "safety_gear_present", "tools_no_damage", "any_spills_cleaned",
    "no_pest_evidence", "no_new_damage", "damage_reported",
}

def _fs_label(key: str) -> str:
    return key.replace("_", " ").strip().capitalize()

# Default checklist by (asset_type, phase). Each section maps to ordered item keys.
FS_DEFAULT_CHECKLIST = {
    ("vehicle", "start_shift"): {
        "sort":        ["unauthorized_items_removed", "personal_items_stowed"],
        "set":         ["tools_in_assigned_locations", "parts_in_assigned_bins"],
        "shine":       ["exterior_clean", "interior_clean", "fluids_checked", "tires_visual_ok", "lights_working"],
        "standardize": ["odometer_logged", "fuel_logged", "no_new_damage", "safety_gear_present"],
    },
    ("vehicle", "end_shift"): {
        "sort":        ["van_decluttered", "trash_removed"],
        "set":         ["tools_returned_to_locations", "remaining_parts_to_bins"],
        "shine":       ["interior_wipedown", "any_spills_cleaned"],
        "standardize": ["parts_used_logged", "odometer_logged", "fuel_logged", "damage_reported"],
    },
    ("toolkit", "start_shift"): {
        "sort":        ["only_sop_tools_present"],
        "set":         ["each_tool_in_slot"],
        "shine":       ["tools_clean", "tools_no_corrosion", "tools_no_damage"],
        "standardize": ["tool_count_matches"],
    },
    ("toolkit", "end_shift"): {
        "sort":        ["no_extraneous_items"],
        "set":         ["all_tools_returned_to_slots"],
        "shine":       ["tools_wiped_down"],
        "standardize": ["tool_count_matches", "any_damage_logged"],
    },
    ("storage", "weekly_manager"): {
        "sort":        ["expired_items_removed", "obsolete_items_removed"],
        "set":         ["bins_labeled", "items_in_correct_bins"],
        "shine":       ["shelves_clean", "no_pest_evidence"],
        "standardize": ["par_levels_recorded", "expiry_scan_completed"],
    },
    ("vehicle", "weekly_manager"): {
        "sort":        ["van_decluttered", "trash_removed", "unauthorized_items_removed"],
        "set":         ["tools_returned_to_locations", "remaining_parts_to_bins"],
        "shine":       ["exterior_clean", "interior_clean", "fluids_checked", "tires_visual_ok",
                        "lights_working", "any_spills_cleaned"],
        "standardize": ["odometer_logged", "fuel_logged", "no_new_damage", "safety_gear_present",
                        "tool_wear_assessment", "photographic_record_taken"],
    },
    ("toolkit", "weekly_manager"): {
        "sort":        ["only_sop_tools_present", "no_extraneous_items"],
        "set":         ["each_tool_in_slot", "all_tools_returned_to_slots"],
        "shine":       ["tools_clean", "tools_no_corrosion", "tools_no_damage", "tools_wiped_down"],
        "standardize": ["tool_count_matches", "any_damage_logged",
                        "tool_wear_assessment", "part_expiry_scan_passed", "photographic_record_taken"],
    },
}


def get_checklist_for_phase(asset_id: int, phase: str):
    """Returns ordered list[ {section, item_key, item_label} ] for the given
    asset_id and phase. If the asset_type/phase combination is missing from
    FS_DEFAULT_CHECKLIST, returns [] (caller can reject)."""
    if phase not in FS_VALID_PHASES:
        return []
    asset = get_asset_by_id(asset_id)
    if not asset:
        return []
    tpl = FS_DEFAULT_CHECKLIST.get((asset["asset_type"], phase))
    if not tpl:
        return []
    out = []
    for section in ("sort", "set", "shine", "standardize"):
        for key in tpl.get(section, []):
            out.append({
                "section":    section,
                "item_key":   key,
                "item_label": _fs_label(key),
            })
    return out


# ── Asset CRUD ───────────────────────────────────────────────────────────────
def create_asset(asset_code, asset_type, label, hub_id=1,
                 assigned_tech_id=None, static_location=None, notes=None):
    if asset_type not in ("vehicle", "toolkit", "storage"):
        raise ValueError("invalid asset_type")
    now = datetime.now(timezone.utc).isoformat()
    enc = _enc_dict("fs_assets", {"notes": notes}) if notes else {"notes": None}
    con = _con()
    cur = con.execute(
        "INSERT INTO fs_assets (asset_code, asset_type, label, hub_id, "
        "assigned_tech_id, static_location, active, created_at, notes) "
        "VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?)",
        (asset_code, asset_type, label, hub_id, assigned_tech_id,
         static_location, now, enc.get("notes")),
    )
    aid = cur.lastrowid
    con.commit()
    con.close()
    return aid


def list_assets(hub_id=None, asset_type=None, tech_id=None, active_only=True):
    sql  = "SELECT * FROM fs_assets WHERE 1=1"
    args = []
    if active_only:
        sql += " AND active = 1"
    if hub_id is not None:
        sql += " AND hub_id = ?"; args.append(hub_id)
    if asset_type is not None:
        sql += " AND asset_type = ?"; args.append(asset_type)
    if tech_id is not None:
        sql += " AND assigned_tech_id = ?"; args.append(tech_id)
    sql += " ORDER BY asset_type, asset_code"
    con = _con()
    rows = con.execute(sql, args).fetchall()
    con.close()
    return _dec_rows("fs_assets", rows)


def get_asset_by_id(asset_id: int):
    con = _con()
    row = con.execute("SELECT * FROM fs_assets WHERE id = ?", (asset_id,)).fetchone()
    con.close()
    return _dec_row("fs_assets", row) if row else None


def update_asset(asset_id: int, **fields):
    allowed = {"label", "assigned_tech_id", "static_location", "active", "asset_type"}
    sets, vals = [], []
    enc_in = {}
    if "notes" in fields:
        enc_in["notes"] = fields.pop("notes")
    if enc_in:
        enc = _enc_dict("fs_assets", enc_in)
        sets.append("notes = ?"); vals.append(enc["notes"])
    for k, v in fields.items():
        if k in allowed:
            sets.append(f"{k} = ?"); vals.append(v)
    if not sets:
        return False
    vals.append(asset_id)
    con = _con()
    con.execute(f"UPDATE fs_assets SET {', '.join(sets)} WHERE id = ?", vals)
    con.commit()
    con.close()
    return True


def add_asset_item(asset_id, item_type, item_label, sop_required=True,
                   location_code=None, expiry_date=None, part_id=None):
    if item_type not in ("tool", "part", "consumable"):
        raise ValueError("invalid item_type")
    now = datetime.now(timezone.utc).isoformat()
    con = _con()
    cur = con.execute(
        "INSERT INTO fs_asset_items (asset_id, item_type, item_label, sop_required, "
        "location_code, expiry_date, part_id, active, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?)",
        (asset_id, item_type, item_label, 1 if sop_required else 0,
         location_code, expiry_date, part_id, now),
    )
    iid = cur.lastrowid
    con.commit()
    con.close()
    return iid


def list_asset_items(asset_id, active_only=True):
    sql = "SELECT * FROM fs_asset_items WHERE asset_id = ?"
    args = [asset_id]
    if active_only:
        sql += " AND active = 1"
    sql += " ORDER BY item_type, item_label"
    con = _con()
    rows = con.execute(sql, args).fetchall()
    con.close()
    return [dict(r) for r in rows]


def remove_asset_item(item_id: int):
    con = _con()
    con.execute("UPDATE fs_asset_items SET active = 0 WHERE id = ?", (item_id,))
    con.commit()
    con.close()


# ── FS chain-hash helpers (separate chain per table) ─────────────────────────
def _fs_canonical(row: dict, fields: tuple) -> str:
    return _json.dumps({f: row.get(f) for f in fields}, sort_keys=True, separators=(",", ":"))


def _fs_compute_hash(prev_hash: str, row: dict, fields: tuple) -> str:
    payload = (prev_hash or AUDIT_GENESIS) + "\n" + _fs_canonical(row, fields)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


_FS_AUDIT_HASH_FIELDS = (
    "asset_id", "auditor_id", "auditor_kind", "phase",
    "audit_ts", "overall_pass", "hub_id",
)
_FS_EXC_HASH_FIELDS = (
    "asset_id", "audit_id", "opened_by_id", "opened_by_kind", "opened_at",
    "severity", "category", "status",
    "resolved_by_id", "resolved_at", "escalated_at", "escalated_to_id", "hub_id",
)
_FS_COACH_HASH_FIELDS = (
    "tech_id", "opened_by_id", "opened_at", "band_at_open", "status",
    "closed_at", "closed_by_id", "hub_id",
)


def _fs_last_audit_hash(con) -> str:
    r = con.execute("SELECT chain_hash FROM fs_audits ORDER BY id DESC LIMIT 1").fetchone()
    return (dict(r)["chain_hash"] if r else None) or AUDIT_GENESIS


def _fs_last_exc_hash(con) -> str:
    r = con.execute("SELECT chain_hash FROM fs_exceptions ORDER BY id DESC LIMIT 1").fetchone()
    return (dict(r)["chain_hash"] if r else None) or AUDIT_GENESIS


def _fs_last_coach_hash(con) -> str:
    r = con.execute("SELECT chain_hash FROM fs_coaching_log ORDER BY id DESC LIMIT 1").fetchone()
    return (dict(r)["chain_hash"] if r else None) or AUDIT_GENESIS


# ── Submit audit (atomic) ────────────────────────────────────────────────────
def submit_audit(asset_id: int, auditor_id: int, auditor_kind: str,
                 phase: str, items: list, client_meta=None):
    """Atomic insert: fs_audits header + fs_audit_items rows + auto-create
    fs_exceptions for any fail. Returns dict with audit_id and exception_ids."""
    if auditor_kind not in ("tech", "admin"):
        raise ValueError("invalid auditor_kind")
    if phase not in FS_VALID_PHASES:
        raise ValueError("invalid phase")
    asset = get_asset_by_id(asset_id)
    if not asset:
        raise ValueError("asset not found")

    expected = get_checklist_for_phase(asset_id, phase)
    if not expected:
        raise ValueError("no checklist defined for this asset_type+phase")
    expected_keys = {e["item_key"] for e in expected}
    label_by_key  = {e["item_key"]: e["item_label"] for e in expected}
    section_by_key = {e["item_key"]: e["section"] for e in expected}
    seen = {}
    for it in items:
        k = it.get("item_key")
        if not k or k not in expected_keys:
            raise ValueError(f"unexpected or missing item_key: {k!r}")
        if it.get("status") not in ("pass", "fail", "na"):
            raise ValueError(f"invalid status for {k!r}")
        seen[k] = it
    missing = expected_keys - set(seen.keys())
    if missing:
        raise ValueError(f"missing items: {sorted(missing)}")

    now = datetime.now(timezone.utc).isoformat()
    overall_pass = 1 if all(s["status"] != "fail" for s in seen.values()) else 0
    enc_meta = None
    if client_meta:
        try:
            enc_meta = _enc("fs", _json.dumps(client_meta)) if False else _enc_dict(
                "fs_audits", {"client_meta_json": _json.dumps(client_meta)}
            )["client_meta_json"]
        except Exception:
            enc_meta = None

    con = _con()
    try:
        con.execute("BEGIN")
        prev = _fs_last_audit_hash(con)
        header = {
            "asset_id": asset_id, "auditor_id": auditor_id, "auditor_kind": auditor_kind,
            "phase": phase, "audit_ts": now, "overall_pass": overall_pass,
            "hub_id": asset.get("hub_id") or 1,
        }
        chain = _fs_compute_hash(prev, header, _FS_AUDIT_HASH_FIELDS)
        cur = con.execute(
            "INSERT INTO fs_audits (asset_id, auditor_id, auditor_kind, phase, "
            "audit_ts, overall_pass, hub_id, prior_chain_hash, chain_hash, client_meta_json) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (asset_id, auditor_id, auditor_kind, phase, now,
             overall_pass, header["hub_id"], prev, chain, enc_meta),
        )
        audit_id = cur.lastrowid

        exception_ids = []
        for key in (e["item_key"] for e in expected):
            it = seen[key]
            note_plain = it.get("note")
            note_enc = None
            if note_plain:
                note_enc = _enc_dict("fs_audit_items", {"note": note_plain})["note"]
            con.execute(
                "INSERT INTO fs_audit_items (audit_id, section, item_key, item_label, status, note) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (audit_id, section_by_key[key], key, label_by_key[key], it["status"], note_enc),
            )
            if it["status"] == "fail":
                severity = "safety_loto" if key in FS_SAFETY_ITEM_KEYS else "normal"
                desc_plain = note_plain or f"Auto-opened from failed checklist item: {label_by_key[key]}"
                desc_enc = _enc_dict("fs_exceptions", {"description": desc_plain})["description"]
                prev_e = _fs_last_exc_hash(con)
                er = {
                    "asset_id": asset_id, "audit_id": audit_id,
                    "opened_by_id": auditor_id, "opened_by_kind": auditor_kind,
                    "opened_at": now, "severity": severity, "category": key,
                    "status": "open", "resolved_by_id": None, "resolved_at": None,
                    "escalated_at": None, "escalated_to_id": None,
                    "hub_id": header["hub_id"],
                }
                ch = _fs_compute_hash(prev_e, er, _FS_EXC_HASH_FIELDS)
                cur2 = con.execute(
                    "INSERT INTO fs_exceptions (audit_id, asset_id, opened_by_id, opened_by_kind, "
                    "opened_at, severity, category, description, status, hub_id, "
                    "prior_chain_hash, chain_hash) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'open', ?, ?, ?)",
                    (audit_id, asset_id, auditor_id, auditor_kind, now,
                     severity, key, desc_enc, header["hub_id"], prev_e, ch),
                )
                eid = cur2.lastrowid
                con.execute(
                    "INSERT INTO fs_exception_events (exception_id, event_type, actor_id, "
                    "actor_kind, occurred_at, from_status, to_status, note) "
                    "VALUES (?, 'opened', ?, ?, ?, NULL, 'open', NULL)",
                    (eid, auditor_id, auditor_kind, now),
                )
                exception_ids.append(eid)
        con.commit()
    except Exception:
        con.rollback()
        con.close()
        raise
    con.close()
    return {"audit_id": audit_id, "overall_pass": bool(overall_pass),
            "exception_ids": exception_ids}


# ── Audit queries ────────────────────────────────────────────────────────────
def list_audits(hub_id=None, tech_id=None, asset_id=None, phase=None,
                date_from=None, date_to=None, limit=200):
    sql  = "SELECT * FROM fs_audits WHERE 1=1"
    args = []
    if hub_id is not None:   sql += " AND hub_id = ?";   args.append(hub_id)
    if tech_id is not None:
        sql += " AND ((auditor_kind='tech' AND auditor_id = ?) OR asset_id IN "
        sql += "(SELECT id FROM fs_assets WHERE assigned_tech_id = ?))"
        args.extend([tech_id, tech_id])
    if asset_id is not None: sql += " AND asset_id = ?"; args.append(asset_id)
    if phase is not None:    sql += " AND phase = ?";    args.append(phase)
    if date_from:            sql += " AND audit_ts >= ?"; args.append(date_from)
    if date_to:              sql += " AND audit_ts <= ?"; args.append(date_to)
    sql += " ORDER BY id DESC LIMIT ?"; args.append(int(limit))
    con = _con()
    rows = con.execute(sql, args).fetchall()
    con.close()
    return _dec_rows("fs_audits", rows)


def get_audit_with_items(audit_id: int):
    con = _con()
    h = con.execute("SELECT * FROM fs_audits WHERE id = ?", (audit_id,)).fetchone()
    if not h:
        con.close()
        return None
    items = con.execute(
        "SELECT * FROM fs_audit_items WHERE audit_id = ? ORDER BY id ASC",
        (audit_id,),
    ).fetchall()
    con.close()
    out = _dec_row("fs_audits", h)
    out["items"] = _dec_rows("fs_audit_items", items)
    return out


def list_exceptions(status=None, hub_id=None, asset_id=None,
                    severity=None, tech_id=None, limit=200):
    sql  = "SELECT e.* FROM fs_exceptions e "
    sql += "LEFT JOIN fs_assets a ON a.id = e.asset_id WHERE 1=1"
    args = []
    if status is not None:   sql += " AND e.status = ?";   args.append(status)
    if hub_id is not None:   sql += " AND e.hub_id = ?";   args.append(hub_id)
    if asset_id is not None: sql += " AND e.asset_id = ?"; args.append(asset_id)
    if severity is not None: sql += " AND e.severity = ?"; args.append(severity)
    if tech_id is not None:
        sql += " AND ((e.opened_by_kind='tech' AND e.opened_by_id = ?) OR a.assigned_tech_id = ?)"
        args.extend([tech_id, tech_id])
    sql += " ORDER BY e.id DESC LIMIT ?"; args.append(int(limit))
    con = _con()
    rows = con.execute(sql, args).fetchall()
    con.close()
    return _dec_rows("fs_exceptions", rows)


def get_exception(exception_id: int):
    con = _con()
    row = con.execute("SELECT * FROM fs_exceptions WHERE id = ?", (exception_id,)).fetchone()
    con.close()
    return _dec_row("fs_exceptions", row) if row else None


def resolve_exception(exception_id: int, resolved_by_id: int,
                      resolved_by_kind: str, resolution_note: str = ""):
    if resolved_by_kind not in ("tech", "admin"):
        raise ValueError("invalid resolved_by_kind")
    now = datetime.now(timezone.utc).isoformat()
    note_enc = _enc_dict("fs_exceptions",
                         {"resolution_note": resolution_note or ""})["resolution_note"]
    con = _con()
    cur = con.execute("SELECT * FROM fs_exceptions WHERE id = ?", (exception_id,)).fetchone()
    if not cur:
        con.close()
        raise ValueError("exception not found")
    cur = dict(cur)
    if cur["status"] in ("resolved",):
        con.close()
        return {"already_resolved": True}
    prev = _fs_last_exc_hash(con)
    new_row = {**cur, "status": "resolved",
               "resolved_by_id": resolved_by_id, "resolved_at": now}
    ch = _fs_compute_hash(prev, new_row, _FS_EXC_HASH_FIELDS)
    con.execute(
        "UPDATE fs_exceptions SET status='resolved', resolved_by_id=?, "
        "resolved_by_kind=?, resolved_at=?, resolution_note=?, "
        "prior_chain_hash=?, chain_hash=? WHERE id=?",
        (resolved_by_id, resolved_by_kind, now, note_enc, prev, ch, exception_id),
    )
    con.execute(
        "INSERT INTO fs_exception_events (exception_id, event_type, actor_id, "
        "actor_kind, occurred_at, from_status, to_status, note) "
        "VALUES (?, 'resolved', ?, ?, ?, ?, 'resolved', NULL)",
        (exception_id, resolved_by_id, resolved_by_kind, now, cur["status"]),
    )
    con.commit()
    con.close()
    return {"ok": True}


def escalate_exception(exception_id: int, escalated_to_id: int,
                       actor_id: int, actor_kind: str = "system",
                       target_status: str = "escalated"):
    """target_status is 'escalated' (to manager) or 'escalated_director'."""
    if target_status not in ("escalated", "escalated_director"):
        raise ValueError("invalid target_status")
    now = datetime.now(timezone.utc).isoformat()
    con = _con()
    cur = con.execute("SELECT * FROM fs_exceptions WHERE id = ?", (exception_id,)).fetchone()
    if not cur:
        con.close()
        raise ValueError("exception not found")
    cur = dict(cur)
    if cur["status"] == target_status or cur["status"] == "resolved":
        con.close()
        return {"no_change": True, "status": cur["status"]}
    prev = _fs_last_exc_hash(con)
    new_row = {**cur, "status": target_status,
               "escalated_at": now, "escalated_to_id": escalated_to_id}
    ch = _fs_compute_hash(prev, new_row, _FS_EXC_HASH_FIELDS)
    con.execute(
        "UPDATE fs_exceptions SET status=?, escalated_at=?, escalated_to_id=?, "
        "prior_chain_hash=?, chain_hash=? WHERE id=?",
        (target_status, now, escalated_to_id, prev, ch, exception_id),
    )
    con.execute(
        "INSERT INTO fs_exception_events (exception_id, event_type, actor_id, "
        "actor_kind, occurred_at, from_status, to_status, note) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, NULL)",
        (exception_id, target_status, actor_id, actor_kind, now,
         cur["status"], target_status),
    )
    con.commit()
    con.close()
    return {"ok": True, "status": target_status}


def find_overdue_exceptions(now_iso: str = None):
    """Returns dict {to_manager: [...], to_director: [...]} of exception ids."""
    now = now_iso or datetime.now(timezone.utc).isoformat()
    now_dt = datetime.fromisoformat(now)
    con = _con()
    rows = con.execute(
        "SELECT id, status, opened_at, escalated_at, asset_id FROM fs_exceptions "
        "WHERE status IN ('open','escalated')"
    ).fetchall()
    con.close()
    to_mgr, to_dir = [], []
    for r in rows:
        d = dict(r)
        try:
            if d["status"] == "open":
                opened = datetime.fromisoformat(d["opened_at"])
                if (now_dt - opened) > timedelta(hours=24):
                    to_mgr.append(d["id"])
            elif d["status"] == "escalated":
                base = d.get("escalated_at") or d.get("opened_at")
                if base:
                    base_dt = datetime.fromisoformat(base)
                    if (now_dt - base_dt) > timedelta(hours=48):
                        to_dir.append(d["id"])
        except Exception:
            continue
    return {"to_manager": to_mgr, "to_director": to_dir}


# We need timedelta — make sure it's imported.
from datetime import timedelta as _td  # noqa: E402
# alias so the function above works regardless of import order
timedelta = _td


# ── Compliance scoring ──────────────────────────────────────────────────────
def _band_for_pct(pct: float) -> str:
    if pct >= 90: return FS_BAND_GREEN
    if pct >= 75: return FS_BAND_AMBER
    return FS_BAND_RED


def compute_compliance_score(tech_id: int, window_days: int = 30) -> dict:
    now = datetime.now(timezone.utc)
    cutoff = (now - timedelta(days=window_days)).isoformat()
    con = _con()
    rows = con.execute(
        "SELECT overall_pass, audit_ts FROM fs_audits "
        "WHERE auditor_kind='tech' AND auditor_id = ? AND audit_ts >= ?",
        (tech_id, cutoff),
    ).fetchall()
    total = len(rows)
    passed = sum(1 for r in rows if r["overall_pass"] == 1)
    pct = (passed / total * 100.0) if total else 0.0
    band = _band_for_pct(pct) if total else FS_BAND_RED
    # safety-red override
    safety = con.execute(
        "SELECT 1 FROM fs_exceptions e JOIN fs_assets a ON a.id = e.asset_id "
        "WHERE e.severity = 'safety_loto' AND e.status IN ('open','escalated','escalated_director') "
        "AND (a.assigned_tech_id = ? OR (e.opened_by_kind='tech' AND e.opened_by_id = ?)) "
        "LIMIT 1",
        (tech_id, tech_id),
    ).fetchone()
    safety_red = bool(safety)
    if safety_red:
        band = FS_BAND_RED
    # 4-week trend
    trend = []
    for w in range(4, 0, -1):
        wk_end   = (now - timedelta(days=(w - 1) * 7)).isoformat()
        wk_start = (now - timedelta(days=w * 7)).isoformat()
        wk = con.execute(
            "SELECT overall_pass FROM fs_audits "
            "WHERE auditor_kind='tech' AND auditor_id=? AND audit_ts >= ? AND audit_ts < ?",
            (tech_id, wk_start, wk_end),
        ).fetchall()
        wt = len(wk); wp = sum(1 for r in wk if r["overall_pass"] == 1)
        trend.append({
            "week_start": wk_start[:10],
            "audits":     wt,
            "pct":        round((wp / wt * 100.0) if wt else 0.0, 1),
        })
    con.close()
    return {
        "tech_id":      tech_id,
        "window_days":  window_days,
        "score_pct":    round(pct, 1),
        "total_audits": total,
        "pass_audits":  passed,
        "band":         band,
        "safety_red":   safety_red,
        "trend":        trend,
    }


def list_compliance_overview(hub_id=None, window_days: int = 30):
    con = _con()
    sql = "SELECT id, name, prid, hub_id FROM technicians WHERE active = 1"
    args = []
    if hub_id is not None:
        # technicians table may or may not have hub_id; skip hub filter if absent
        cols = {r[1] for r in con.execute("PRAGMA table_info(technicians)")}
        if "hub_id" in cols:
            sql += " AND hub_id = ?"; args.append(hub_id)
    techs = con.execute(sql, args).fetchall()
    con.close()
    out = []
    for t in techs:
        score = compute_compliance_score(t["id"], window_days=window_days)
        score["name"] = t["name"]
        score["prid"] = t["prid"]
        out.append(score)
    return out


# ── KPI correlation (Phase 4) ────────────────────────────────────────────────
def _kpi_band_for_tech(tech_id: int, window_days: int = 30):
    """Best-effort: looks for a KPI signal in existing tables. If no KPI module
    exists yet, returns None — the endpoint will degrade gracefully."""
    now = datetime.now(timezone.utc)
    cutoff = (now - timedelta(days=window_days)).isoformat()
    con = _con()
    # Heuristic proxy: completed-on-time vs flagged visits in window.
    try:
        rows = con.execute(
            "SELECT status, flagged FROM maintenance_visits "
            "WHERE assigned_tech_id = ? AND (completed_at >= ? OR created_at >= ?)",
            (tech_id, cutoff, cutoff),
        ).fetchall()
    except Exception:
        con.close()
        return None
    con.close()
    total = len(rows)
    if total == 0:
        return None
    flagged = sum(1 for r in rows if (r["flagged"] if "flagged" in r.keys() else 0) == 1)
    bad_pct = (flagged / total) * 100.0
    # band: <5% flagged green; 5-15 amber; >15 red.
    if bad_pct < 5: return "green"
    if bad_pct < 15: return "amber"
    return "red"


def correlate_5s_to_kpi(tech_id: int, window_days: int = 30) -> dict:
    fs = compute_compliance_score(tech_id, window_days=window_days)
    kpi_band = _kpi_band_for_tech(tech_id, window_days=window_days)
    fs_band = fs["band"]
    if kpi_band is None:
        diagnostic = "kpi module not active — using 5S band only"
    elif fs_band == "red" and kpi_band == "red":
        diagnostic = "systemic — investigate conditions before performance"
    elif fs_band == "green" and kpi_band == "red":
        diagnostic = "performance — coaching needed"
    elif fs_band == "red" and kpi_band == "green":
        diagnostic = "lucky — conditions failing, will catch up"
    elif fs_band == "green" and kpi_band == "green":
        diagnostic = "healthy"
    else:
        diagnostic = f"{fs_band} 5S / {kpi_band} KPI — mixed"
    return {
        "tech_id":    tech_id,
        "fs_band":    fs_band,
        "kpi_band":   kpi_band,
        "diagnostic": diagnostic,
        "fs":         fs,
    }


# ── Coaching log (Phase 3) ───────────────────────────────────────────────────
def open_coaching(tech_id: int, opened_by_id: int, band_at_open: str,
                  plan_text: str = "", hub_id: int = 1) -> int:
    now = datetime.now(timezone.utc).isoformat()
    plan_enc = _enc_dict("fs_coaching_log",
                         {"plan_text": plan_text or ""})["plan_text"]
    con = _con()
    prev = _fs_last_coach_hash(con)
    row = {"tech_id": tech_id, "opened_by_id": opened_by_id, "opened_at": now,
           "band_at_open": band_at_open, "status": "open",
           "closed_at": None, "closed_by_id": None, "hub_id": hub_id}
    ch = _fs_compute_hash(prev, row, _FS_COACH_HASH_FIELDS)
    cur = con.execute(
        "INSERT INTO fs_coaching_log (tech_id, opened_by_id, opened_at, "
        "band_at_open, plan_text, status, hub_id, chain_hash) "
        "VALUES (?, ?, ?, ?, ?, 'open', ?, ?)",
        (tech_id, opened_by_id, now, band_at_open, plan_enc, hub_id, ch),
    )
    cid = cur.lastrowid
    con.commit()
    con.close()
    return cid


def close_coaching(coaching_id: int, closed_by_id: int, close_note: str = ""):
    now = datetime.now(timezone.utc).isoformat()
    note_enc = _enc_dict("fs_coaching_log",
                         {"close_note": close_note or ""})["close_note"]
    con = _con()
    cur = con.execute("SELECT * FROM fs_coaching_log WHERE id = ?", (coaching_id,)).fetchone()
    if not cur:
        con.close(); raise ValueError("coaching log not found")
    cur = dict(cur)
    prev = _fs_last_coach_hash(con)
    row = {**cur, "status": "closed",
           "closed_at": now, "closed_by_id": closed_by_id}
    ch = _fs_compute_hash(prev, row, _FS_COACH_HASH_FIELDS)
    con.execute(
        "UPDATE fs_coaching_log SET status='closed', closed_at=?, "
        "closed_by_id=?, close_note=?, chain_hash=? WHERE id=?",
        (now, closed_by_id, note_enc, ch, coaching_id),
    )
    con.commit()
    con.close()
    return True


def list_coaching(tech_id=None, status=None, limit=100):
    sql = "SELECT * FROM fs_coaching_log WHERE 1=1"
    args = []
    if tech_id is not None: sql += " AND tech_id = ?"; args.append(tech_id)
    if status  is not None: sql += " AND status = ?";  args.append(status)
    sql += " ORDER BY id DESC LIMIT ?"; args.append(int(limit))
    con = _con()
    rows = con.execute(sql, args).fetchall()
    con.close()
    return _dec_rows("fs_coaching_log", rows)


# ── "Today" status for tech ──────────────────────────────────────────────────
def fs_today_status_for_tech(tech_id: int) -> dict:
    """Returns whether tech has submitted start_shift / end_shift audits today
    for each of their assigned assets that requires them."""
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    assets = list_assets(tech_id=tech_id, active_only=True)
    out = {"date": today, "assets": []}
    con = _con()
    for a in assets:
        if a["asset_type"] not in ("vehicle", "toolkit"):
            continue
        start_done = bool(con.execute(
            "SELECT 1 FROM fs_audits WHERE asset_id=? AND auditor_id=? "
            "AND auditor_kind='tech' AND phase='start_shift' AND substr(audit_ts,1,10)=?",
            (a["id"], tech_id, today),
        ).fetchone())
        end_done = bool(con.execute(
            "SELECT 1 FROM fs_audits WHERE asset_id=? AND auditor_id=? "
            "AND auditor_kind='tech' AND phase='end_shift' AND substr(audit_ts,1,10)=?",
            (a["id"], tech_id, today),
        ).fetchone())
        out["assets"].append({
            "asset_id":   a["id"],
            "asset_code": a["asset_code"],
            "label":      a["label"],
            "asset_type": a["asset_type"],
            "start_shift_done": start_done,
            "end_shift_done":   end_done,
        })
    con.close()
    return out


# ── Export ──────────────────────────────────────────────────────────────────
def fs_export_all() -> dict:
    """Returns the full immutable 5S trail for export (CSV/JSON serialized by caller)."""
    con = _con()
    audits = [dict(r) for r in con.execute(
        "SELECT id, asset_id, auditor_id, auditor_kind, phase, audit_ts, "
        "overall_pass, hub_id, prior_chain_hash, chain_hash FROM fs_audits ORDER BY id ASC"
    ).fetchall()]
    items  = [dict(r) for r in con.execute(
        "SELECT id, audit_id, section, item_key, item_label, status FROM fs_audit_items ORDER BY id ASC"
    ).fetchall()]
    excs   = [dict(r) for r in con.execute(
        "SELECT id, audit_id, asset_id, opened_by_id, opened_by_kind, opened_at, "
        "severity, category, status, resolved_by_id, resolved_at, escalated_at, "
        "escalated_to_id, hub_id, prior_chain_hash, chain_hash FROM fs_exceptions ORDER BY id ASC"
    ).fetchall()]
    events = [dict(r) for r in con.execute(
        "SELECT id, exception_id, event_type, actor_id, actor_kind, occurred_at, "
        "from_status, to_status FROM fs_exception_events ORDER BY id ASC"
    ).fetchall()]
    con.close()
    return {"audits": audits, "audit_items": items,
            "exceptions": excs, "exception_events": events}


# ── Technician Detail View helpers (super_admin) ────────────────────────────
# Mirror naming conventions of the customer-detail / visit-detail patterns.
# Encrypted fields are decrypted on read via _dec_row("<table>"). Chain hashes
# protect the forensic timeline.

_TECH_REVIEW_HASH_FIELDS = (
    "tech_id", "review_type", "status", "reviewer_id",
    "created_at", "updated_at", "followup_date", "hub_id",
)
_TECH_KPI_OV_HASH_FIELDS = (
    "tech_id", "kpi_key", "green_threshold", "amber_threshold", "red_threshold",
    "effective_from", "effective_until", "created_by", "created_at", "active",
)
_TECH_5S_OV_HASH_FIELDS = (
    "exception_id", "tech_id", "overridden_by", "overridden_at", "hub_id",
)
_FX_RATE_HASH_FIELDS = (
    "from_currency", "to_currency", "buy_rate", "source",
    "fetched_at", "effective_date", "entered_by", "active",
)


def _backfill_table_chains():
    """Idempotent chain backfill for tables that recently grew chain_hash
    columns or that may have legacy rows missing them. Walks each table in
    deterministic id ASC order and hashes any row that has NULL chain_hash
    using the same `_fs_compute_hash` helper. Safe to re-run."""
    targets = (
        ("technician_reviews",        _TECH_REVIEW_HASH_FIELDS),
        ("technician_kpi_overrides",  _TECH_KPI_OV_HASH_FIELDS),
        ("technician_5s_overrides",   _TECH_5S_OV_HASH_FIELDS),
        ("fx_rates",                  _FX_RATE_HASH_FIELDS),
    )
    con = _con()
    for table, fields in targets:
        try:
            cols = {r[1] for r in con.execute(f"PRAGMA table_info({table})")}
            if "chain_hash" not in cols:
                continue
            rows = con.execute(
                f"SELECT * FROM {table} ORDER BY id ASC"
            ).fetchall()
            prev = AUDIT_GENESIS
            updates = []
            for r in rows:
                d = dict(r)
                existing = d.get("chain_hash")
                if existing:
                    prev = existing
                    continue
                ch = _fs_compute_hash(prev, d, fields)
                updates.append((prev, ch, d["id"]))
                prev = ch
            if updates:
                con.executemany(
                    f"UPDATE {table} SET prior_chain_hash = ?, "
                    f"chain_hash = ? WHERE id = ?",
                    updates,
                )
        except sqlite3.OperationalError:
            # Table missing or column missing — skip silently.
            pass
    con.commit()
    con.close()


def _last_chain(con, table: str) -> str:
    r = con.execute(f"SELECT chain_hash FROM {table} ORDER BY id DESC LIMIT 1").fetchone()
    return (dict(r)["chain_hash"] if r else None) or AUDIT_GENESIS


def get_technician_with_decryption(tech_id: int):
    """Full decrypted technician row + lightweight aggregates so the detail
    view's first paint has everything. Returns None if missing."""
    con = _con()
    row = con.execute("SELECT * FROM technicians WHERE id = ?", (tech_id,)).fetchone()
    if not row:
        con.close()
        return None
    tech = _dec_row("technicians", row)
    # Quick aggregates (cheap counts, NOT full joins)
    try:
        last_job = con.execute(
            "SELECT id, visit_type, status, COALESCE(completed_date, scheduled_date, created_at) AS when_ts "
            "FROM maintenance_visits WHERE assigned_tech_id = ? "
            "ORDER BY COALESCE(completed_date, scheduled_date, created_at) DESC, id DESC LIMIT 1",
            (tech_id,),
        ).fetchone()
        tech["last_job"] = dict(last_job) if last_job else None
    except Exception:
        tech["last_job"] = None
    try:
        last_review_row = con.execute(
            "SELECT id, review_type, status, summary, created_at "
            "FROM technician_reviews WHERE tech_id = ? ORDER BY id DESC LIMIT 1",
            (tech_id,),
        ).fetchone()
        if last_review_row:
            last_review = _dec_row("technician_reviews", last_review_row)
            tech["last_review"] = {
                "id":          last_review["id"],
                "review_type": last_review["review_type"],
                "status":      last_review["status"],
                "created_at":  last_review["created_at"],
            }
        else:
            tech["last_review"] = None
    except Exception:
        tech["last_review"] = None
    con.close()
    # Don't leak the PIN hash to the API surface.
    tech.pop("pin_hash", None)
    return tech


def update_technician_fields(tech_id: int, data: dict):
    """Partial update — phone/email re-encrypted, role/hourly_rate/active
    plain. Returns the new decrypted row. Mirror of update_customer_fields."""
    allowed_plain     = {"role", "active", "name"}
    allowed_encrypted = {"phone"}
    sets, vals = [], []
    for k, v in data.items():
        if k in allowed_plain:
            sets.append(f"{k} = ?")
            vals.append(v)
        elif k in allowed_encrypted:
            sets.append(f"{k} = ?")
            vals.append(_enc(v if v is not None else ""))
        elif k == "email":
            sets.append("email = ?")
            sets.append("email_hash = ?")
            vals.append(_det_enc(v or ""))
            vals.append(_email_hash(v or ""))
        elif k == "hourly_rate":
            sets.append("hourly_rate = ?")
            vals.append(float(v or 0))
        elif k == "employment_status":
            # Tri-state lifecycle. App-level validation only (CHECK isn't
            # enforced on ALTER ADD in SQLite). Keep `active` in lockstep:
            # terminated → 0; active/on_leave → 1.
            if v not in ("active", "on_leave", "terminated"):
                raise ValueError(f"invalid employment_status: {v!r}")
            sets.append("employment_status = ?")
            vals.append(v)
            sets.append("active = ?")
            vals.append(0 if v == "terminated" else 1)
    if not sets:
        return get_technician_with_decryption(tech_id)
    vals.append(tech_id)
    con = _con()
    con.execute(f"UPDATE technicians SET {', '.join(sets)} WHERE id = ?", vals)
    if data.get("active") == 0 or data.get("employment_status") == "terminated":
        con.execute(
            "UPDATE technicians SET terminated_at = ? WHERE id = ?",
            (datetime.now(timezone.utc).isoformat(), tech_id),
        )
    con.commit()
    con.close()
    return get_technician_with_decryption(tech_id)


def get_technician_jobs_paginated(tech_id: int, page: int = 1, limit: int = 20,
                                  filters: dict = None):
    """Reverse-chronological job history for the tech, paginated. Mirrors
    get_customer_visits_paginated. Filters: visit_type, date_from, date_to,
    status, callbacks_only (honors maintenance_visits.callback_of_visit_id)."""
    filters = filters or {}
    page  = max(1, int(page or 1))
    limit = max(1, min(100, int(limit or 20)))
    offset = (page - 1) * limit

    where  = ["v.assigned_tech_id = ?"]
    args   = [tech_id]
    if filters.get("visit_type"):
        where.append("UPPER(v.visit_type) = ?")
        args.append(filters["visit_type"].upper())
    if filters.get("status"):
        where.append("v.status = ?")
        args.append(filters["status"])
    if filters.get("date_from"):
        where.append("COALESCE(v.completed_date, v.scheduled_date, v.created_at) >= ?")
        args.append(filters["date_from"])
    if filters.get("date_to"):
        where.append("COALESCE(v.completed_date, v.scheduled_date, v.created_at) <= ?")
        args.append(filters["date_to"])
    if filters.get("callbacks_only"):
        where.append("v.callback_of_visit_id IS NOT NULL")
    where_sql = " AND ".join(where)

    con = _con()
    total = con.execute(
        f"SELECT COUNT(*) AS n FROM maintenance_visits v WHERE {where_sql}",
        args,
    ).fetchone()["n"]
    rows = con.execute(
        f"""
        SELECT v.id, v.customer_id, v.equipment_id, v.visit_type, v.status,
               v.scheduled_date, v.scheduled_time, v.completed_date,
               v.created_at, v.start_time, v.end_time,
               v.scope_of_work, v.work_done_summary,
               v.callback_of_visit_id,
               e.name AS equipment_name,
               c.name AS customer_name,
               c.customer_code AS customer_code
        FROM maintenance_visits v
        LEFT JOIN equipment e ON v.equipment_id = e.id
        LEFT JOIN customers c ON v.customer_id  = c.id
        WHERE {where_sql}
        ORDER BY COALESCE(v.completed_date, v.scheduled_date, v.created_at) DESC,
                 v.id DESC
        LIMIT ? OFFSET ?
        """,
        args + [limit, offset],
    ).fetchall()
    # Enrich each row with parts cost + revenue (computed from invoice if present).
    out_rows = []
    for r in rows:
        d = dict(r)
        # Parts cost (sum of visit_parts qty * unit_price)
        pc = con.execute(
            "SELECT COALESCE(SUM(quantity * unit_price), 0) AS pc "
            "FROM visit_parts WHERE visit_id = ?",
            (d["id"],),
        ).fetchone()
        d["parts_cost"] = float(pc["pc"] or 0)
        # Invoice total + balance (if any)
        inv = con.execute(
            "SELECT total, amount_paid FROM invoices WHERE visit_id = ? "
            "ORDER BY id DESC LIMIT 1",
            (d["id"],),
        ).fetchone()
        d["revenue"]      = float(inv["total"] or 0) if inv else None
        d["amount_paid"]  = float(inv["amount_paid"] or 0) if inv else None
        # Duration (minutes) if start/end set
        if d.get("start_time") and d.get("end_time"):
            try:
                from datetime import datetime as _dt
                a = _dt.fromisoformat(d["start_time"])
                b = _dt.fromisoformat(d["end_time"])
                d["duration_min"] = int((b - a).total_seconds() // 60)
            except Exception:
                d["duration_min"] = None
        else:
            d["duration_min"] = None
        # callback_of_visit_id already populated from SELECT above
        out_rows.append(d)
    con.close()
    return {"rows": out_rows, "page": page, "limit": limit, "total": int(total or 0)}


# ── Reviews ─────────────────────────────────────────────────────────────────
def list_technician_reviews(tech_id: int, status: str = None, limit: int = 50):
    con = _con()
    sql  = "SELECT * FROM technician_reviews WHERE tech_id = ?"
    args = [tech_id]
    if status:
        sql += " AND status = ?"
        args.append(status)
    sql += " ORDER BY id DESC LIMIT ?"
    args.append(int(limit))
    rows = con.execute(sql, args).fetchall()
    # Join reviewer name (admin_users) for display
    out = []
    for r in rows:
        d = _dec_row("technician_reviews", r)
        rev = con.execute(
            "SELECT name FROM admin_users WHERE id = ?", (d.get("reviewer_id"),),
        ).fetchone()
        d["reviewer_name"] = (dict(rev)["name"] if rev else None)
        out.append(d)
    con.close()
    return out


def create_technician_review(tech_id: int, review_type: str, summary: str,
                             reviewer_id: int, status: str = "open",
                             action_items: str = None, followup_date: str = None,
                             hub_id: int = 1):
    if review_type not in ("coaching", "written_warning", "positive_feedback", "other"):
        raise ValueError("invalid review_type")
    if status not in ("open", "resolved", "archived"):
        raise ValueError("invalid status")
    now = datetime.now(timezone.utc).isoformat()
    enc = _enc_dict("technician_reviews", {
        "summary":      summary or "",
        "action_items": action_items or "",
    })
    con = _con()
    prev = _last_chain(con, "technician_reviews")
    canonical = {
        "tech_id": tech_id, "review_type": review_type, "status": status,
        "reviewer_id": reviewer_id, "created_at": now, "updated_at": None,
        "followup_date": followup_date, "hub_id": hub_id,
    }
    ch = _fs_compute_hash(prev, canonical, _TECH_REVIEW_HASH_FIELDS)
    cur = con.execute(
        "INSERT INTO technician_reviews (tech_id, review_type, summary, status, "
        "action_items, followup_date, reviewer_id, created_at, hub_id, "
        "prior_chain_hash, chain_hash) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (tech_id, review_type, enc["summary"], status,
         enc.get("action_items") if action_items else None,
         followup_date, reviewer_id, now, hub_id, prev, ch),
    )
    rid = cur.lastrowid
    con.commit()
    con.close()
    return rid


def update_technician_review(review_id: int, **fields):
    """Allowed mutations: status, summary, action_items, followup_date.
    Refuses if the row is not in 'open' status (resolved/archived = locked)."""
    con = _con()
    row = con.execute(
        "SELECT * FROM technician_reviews WHERE id = ?", (review_id,)
    ).fetchone()
    if not row:
        con.close()
        raise ValueError("review not found")
    cur = dict(row)
    if cur["status"] != "open":
        con.close()
        raise ValueError("review is not editable (status != open)")
    now = datetime.now(timezone.utc).isoformat()
    sets, vals = [], []
    if "status" in fields and fields["status"] is not None:
        if fields["status"] not in ("open", "resolved", "archived"):
            con.close()
            raise ValueError("invalid status")
        sets.append("status = ?"); vals.append(fields["status"])
    if "summary" in fields and fields["summary"] is not None:
        sets.append("summary = ?")
        vals.append(_enc(fields["summary"]))
    if "action_items" in fields and fields["action_items"] is not None:
        sets.append("action_items = ?")
        vals.append(_enc(fields["action_items"]) if fields["action_items"] else None)
    if "followup_date" in fields:
        sets.append("followup_date = ?"); vals.append(fields.get("followup_date"))
    sets.append("updated_at = ?"); vals.append(now)
    # Recompute chain hash based on new canonical fields
    new_canonical = {
        "tech_id": cur["tech_id"],
        "review_type": cur["review_type"],
        "status": fields.get("status", cur["status"]),
        "reviewer_id": cur["reviewer_id"],
        "created_at": cur["created_at"],
        "updated_at": now,
        "followup_date": fields.get("followup_date", cur.get("followup_date")),
        "hub_id": cur.get("hub_id", 1),
    }
    prev = _last_chain(con, "technician_reviews")
    ch = _fs_compute_hash(prev, new_canonical, _TECH_REVIEW_HASH_FIELDS)
    sets.append("prior_chain_hash = ?"); vals.append(prev)
    sets.append("chain_hash = ?");      vals.append(ch)
    vals.append(review_id)
    con.execute(
        f"UPDATE technician_reviews SET {', '.join(sets)} WHERE id = ?", vals
    )
    con.commit()
    con.close()
    return True


# ── KPI threshold overrides ────────────────────────────────────────────────
def list_kpi_threshold_overrides(tech_id: int, active_only: bool = True):
    con = _con()
    sql = "SELECT * FROM technician_kpi_overrides WHERE tech_id = ?"
    args = [tech_id]
    if active_only:
        sql += " AND active = 1"
    sql += " ORDER BY id DESC"
    rows = con.execute(sql, args).fetchall()
    con.close()
    return _dec_rows("technician_kpi_overrides", rows)


def create_kpi_threshold_override(tech_id: int, kpi_key: str, reason: str,
                                  created_by: int,
                                  green_threshold=None, amber_threshold=None,
                                  red_threshold=None,
                                  effective_from: str = None,
                                  effective_until: str = None):
    if not kpi_key:
        raise ValueError("kpi_key required")
    if not reason:
        raise ValueError("reason required")
    now = datetime.now(timezone.utc).isoformat()
    effective_from = effective_from or now
    enc_reason = _enc(reason or "")
    con = _con()
    prev = _last_chain(con, "technician_kpi_overrides")
    canonical = {
        "tech_id": tech_id, "kpi_key": kpi_key,
        "green_threshold": green_threshold, "amber_threshold": amber_threshold,
        "red_threshold": red_threshold,
        "effective_from": effective_from, "effective_until": effective_until,
        "created_by": created_by, "created_at": now, "active": 1,
    }
    ch = _fs_compute_hash(prev, canonical, _TECH_KPI_OV_HASH_FIELDS)
    cur = con.execute(
        "INSERT INTO technician_kpi_overrides (tech_id, kpi_key, green_threshold, "
        "amber_threshold, red_threshold, reason, effective_from, effective_until, "
        "created_by, created_at, active, prior_chain_hash, chain_hash) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)",
        (tech_id, kpi_key, green_threshold, amber_threshold, red_threshold,
         enc_reason, effective_from, effective_until, created_by, now, prev, ch),
    )
    new_id = cur.lastrowid
    con.commit()
    con.close()
    return new_id


# ── 5S exception overrides ─────────────────────────────────────────────────
def list_5s_overrides(tech_id: int):
    con = _con()
    rows = con.execute(
        "SELECT * FROM technician_5s_overrides WHERE tech_id = ? ORDER BY id DESC",
        (tech_id,),
    ).fetchall()
    con.close()
    return _dec_rows("technician_5s_overrides", rows)


def create_5s_override(exception_id: int, tech_id: int, reason: str,
                       overridden_by: int, hub_id: int = 1):
    if not reason:
        raise ValueError("reason required")
    # IDOR safety: caller (main.py) must already have verified the exception
    # belongs to this tech, but we also re-check here.
    con = _con()
    exc = con.execute(
        "SELECT e.id, a.assigned_tech_id, e.opened_by_id, e.opened_by_kind "
        "FROM fs_exceptions e LEFT JOIN fs_assets a ON a.id = e.asset_id "
        "WHERE e.id = ?",
        (exception_id,),
    ).fetchone()
    if not exc:
        con.close()
        raise ValueError("exception not found")
    e = dict(exc)
    belongs = (e.get("assigned_tech_id") == tech_id) or (
        e.get("opened_by_kind") == "tech" and e.get("opened_by_id") == tech_id
    )
    if not belongs:
        con.close()
        raise ValueError("exception does not belong to this technician")
    now = datetime.now(timezone.utc).isoformat()
    enc_reason = _enc(reason or "")
    prev = _last_chain(con, "technician_5s_overrides")
    canonical = {
        "exception_id": exception_id, "tech_id": tech_id,
        "overridden_by": overridden_by, "overridden_at": now, "hub_id": hub_id,
    }
    ch = _fs_compute_hash(prev, canonical, _TECH_5S_OV_HASH_FIELDS)
    cur = con.execute(
        "INSERT INTO technician_5s_overrides (exception_id, tech_id, reason, "
        "overridden_by, overridden_at, hub_id, prior_chain_hash, chain_hash) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (exception_id, tech_id, enc_reason, overridden_by, now, hub_id, prev, ch),
    )
    new_id = cur.lastrowid
    # Append a forensic event into fs_exception_events (kind 'override') so
    # the original 5S audit trail also reflects the action. The fs_exceptions
    # header row itself is NOT mutated.
    try:
        con.execute(
            "INSERT INTO fs_exception_events (exception_id, event_type, actor_id, "
            "actor_kind, occurred_at, from_status, to_status, note) "
            "VALUES (?, 'override', ?, 'admin', ?, NULL, NULL, NULL)",
            (exception_id, overridden_by, now),
        )
    except Exception:
        pass
    con.commit()
    con.close()
    return new_id


# ── Certifications + payroll summary (dependency-aware) ────────────────────
def get_technician_certifications(tech_id: int):
    """Returns rows if a `certifications` table exists; else returns
    {'available': False}.
    FIXME(docs/FIXMES.md): certifications module pending — define schema
    (cert name, issuing body, expiry) and wire it here when it ships."""
    con = _con()
    has = con.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='certifications'"
    ).fetchone()
    if not has:
        con.close()
        return {"available": False,
                "message": "Certifications module not yet active"}
    try:
        rows = con.execute(
            "SELECT * FROM certifications WHERE tech_id = ? ORDER BY expiry_date ASC",
            (tech_id,),
        ).fetchall()
        out = [dict(r) for r in rows]
    except Exception:
        out = []
    con.close()
    return {"available": True, "rows": out}


def get_technician_payroll_summary(tech_id: int, limit: int = 6):
    """Returns last `limit` pay periods + the tech's payslip in each (if any).
    Degrades gracefully if pay_periods/payslips tables are absent."""
    con = _con()
    have = {r[0] for r in con.execute(
        "SELECT name FROM sqlite_master WHERE type='table' "
        "AND name IN ('pay_periods','payslips')"
    ).fetchall()}
    if "pay_periods" not in have or "payslips" not in have:
        con.close()
        return {"available": False}
    rows = con.execute(
        """
        SELECT pp.id AS period_id, pp.label, pp.period_start, pp.period_end,
               pp.status AS period_status,
               ps.gross_pay, ps.bonus, ps.net_pay, ps.hours_regular, ps.hours_overtime
        FROM pay_periods pp
        LEFT JOIN payslips ps ON ps.pay_period_id = pp.id
                              AND ps.subject_type = 'tech'
                              AND ps.subject_id = ?
        ORDER BY pp.period_end DESC
        LIMIT ?
        """,
        (tech_id, int(limit)),
    ).fetchall()
    con.close()
    return {"available": True, "rows": [dict(r) for r in rows]}


# ── Visit callback link (Visit Detail § 9) ──────────────────────────────────
def set_visit_callback_link(visit_id: int, originates_from_visit_id: int) -> None:
    """Mark `visit_id` as a callback generated by `originates_from_visit_id`.
    Both visits must exist; the link must not be self-referential. Idempotent —
    re-pointing at the same source is a no-op."""
    if visit_id == originates_from_visit_id:
        raise ValueError("a visit cannot be a callback of itself")
    con = _con()
    a = con.execute(
        "SELECT id FROM maintenance_visits WHERE id = ?", (visit_id,)
    ).fetchone()
    b = con.execute(
        "SELECT id FROM maintenance_visits WHERE id = ?", (originates_from_visit_id,)
    ).fetchone()
    if not a or not b:
        con.close()
        raise ValueError("visit not found")
    con.execute(
        "UPDATE maintenance_visits SET callback_of_visit_id = ? WHERE id = ?",
        (originates_from_visit_id, visit_id),
    )
    con.commit()
    con.close()


def get_visit_callback_chain(visit_id: int) -> dict:
    """Returns the callback wiring for a visit:
        {
          "is_callback_of":   {id, visit_type, status, completed_date} | None,
          "generated_callbacks": [ {id, ...}, ... ],
        }
    Both directions are returned regardless of which side the caller is on."""
    con = _con()
    cur = con.execute(
        "SELECT callback_of_visit_id FROM maintenance_visits WHERE id = ?",
        (visit_id,),
    ).fetchone()
    if not cur:
        con.close()
        return {"is_callback_of": None, "generated_callbacks": []}
    is_callback_of = None
    parent_id = cur["callback_of_visit_id"] if "callback_of_visit_id" in cur.keys() else None
    if parent_id:
        p = con.execute(
            "SELECT id, visit_type, status, completed_date, scheduled_date "
            "FROM maintenance_visits WHERE id = ?", (parent_id,),
        ).fetchone()
        if p:
            is_callback_of = dict(p)
    children = con.execute(
        "SELECT id, visit_type, status, completed_date, scheduled_date "
        "FROM maintenance_visits WHERE callback_of_visit_id = ? ORDER BY id ASC",
        (visit_id,),
    ).fetchall()
    con.close()
    return {
        "is_callback_of": is_callback_of,
        "generated_callbacks": [dict(r) for r in children],
    }


# ── 5S exception photos (tech.html queue) ───────────────────────────────────
_FS_EXC_PHOTO_HASH_FIELDS = (
    "exception_id", "filename", "mime", "size_bytes",
    "uploaded_by_id", "uploaded_by_kind", "uploaded_at", "hub_id",
)


def _fs_last_exc_photo_hash(con) -> str:
    r = con.execute(
        "SELECT chain_hash FROM fs_exception_photos ORDER BY id DESC LIMIT 1"
    ).fetchone()
    return (dict(r)["chain_hash"] if r else None) or AUDIT_GENESIS


def create_exception_photo(exception_id: int, filename: str, mime: str,
                            size_bytes: int, uploaded_by_id: int,
                            uploaded_by_kind: str, original_filename: str = None,
                            client_meta: dict = None, hub_id: int = 1) -> dict:
    """Insert a fs_exception_photos row + chain-hash it. Returns the new id +
    uploaded_at. Matches the chain-hash discipline of fs_exceptions."""
    if uploaded_by_kind not in ("tech", "admin"):
        raise ValueError("invalid uploaded_by_kind")
    now = datetime.now(timezone.utc).isoformat()
    enc_meta = None
    if client_meta is not None:
        try:
            payload = _json.dumps(client_meta) if not isinstance(client_meta, str) else client_meta
            enc_meta = _enc_dict(
                "fs_exception_photos", {"client_meta_json": payload}
            )["client_meta_json"]
        except Exception:
            enc_meta = None
    con = _con()
    try:
        con.execute("BEGIN")
        prev = _fs_last_exc_photo_hash(con)
        row = {
            "exception_id": exception_id, "filename": filename, "mime": mime,
            "size_bytes": int(size_bytes), "uploaded_by_id": uploaded_by_id,
            "uploaded_by_kind": uploaded_by_kind, "uploaded_at": now,
            "hub_id": int(hub_id or 1),
        }
        ch = _fs_compute_hash(prev, row, _FS_EXC_PHOTO_HASH_FIELDS)
        cur = con.execute(
            "INSERT INTO fs_exception_photos "
            "(exception_id, filename, original_filename, mime, size_bytes, "
            " uploaded_by_id, uploaded_by_kind, uploaded_at, client_meta_json, "
            " hub_id, prior_chain_hash, chain_hash) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (exception_id, filename, original_filename, mime, int(size_bytes),
             uploaded_by_id, uploaded_by_kind, now, enc_meta,
             int(hub_id or 1), prev, ch),
        )
        new_id = cur.lastrowid
        con.commit()
    except Exception:
        con.rollback()
        con.close()
        raise
    con.close()
    return {"id": new_id, "exception_id": exception_id,
            "filename": filename, "uploaded_at": now}


def list_exception_photos(exception_id: int) -> list:
    """All photos for an exception, oldest-first. client_meta_json decrypted
    on the way out so callers don't have to know about the encryption layer."""
    con = _con()
    rows = con.execute(
        "SELECT id, exception_id, filename, original_filename, mime, size_bytes, "
        "uploaded_by_id, uploaded_by_kind, uploaded_at, client_meta_json, hub_id "
        "FROM fs_exception_photos WHERE exception_id = ? ORDER BY id ASC",
        (exception_id,),
    ).fetchall()
    con.close()
    return _dec_rows("fs_exception_photos", rows)


# ── PrimeCool Invoicing Module ─────────────────────────────────────────────
# Spec doctrine:
#   * GCT default 15% (configurable per-invoice)
#   * FX processing fee default 2% (configurable per-invoice)
#   * Inventory is deducted at visit parts-used flow, NEVER on invoice line creation
#   * Base currency = JMD; foreign currency is display-only
#   * Payments are append-only and chain-hashed

def search_parts_catalog(q: str, limit: int = 20) -> list:
    """Searchable inventory lookup for the Parts line type in the invoice
    edit view. Reads SKU / name / description from the existing parts table.
    Returns minimal, non-sensitive fields for typeahead (no markup/cost-percent
    leakage beyond the unit_cost which is already exposed in the parts panel)."""
    con = _con()
    try:
        q_clean = (q or "").strip()
        if not q_clean:
            rows = con.execute(
                "SELECT id, sku, name, description, unit, unit_cost, quantity "
                "FROM parts WHERE active = 1 "
                "ORDER BY name ASC LIMIT ?",
                (int(limit or 20),),
            ).fetchall()
        else:
            like = f"%{q_clean}%"
            rows = con.execute(
                "SELECT id, sku, name, description, unit, unit_cost, quantity "
                "FROM parts "
                "WHERE active = 1 "
                "  AND (sku LIKE ? OR name LIKE ? OR COALESCE(description,'') LIKE ?) "
                "ORDER BY (sku = ?) DESC, name ASC LIMIT ?",
                (like, like, like, q_clean, int(limit or 20)),
            ).fetchall()
    except sqlite3.OperationalError:
        # parts table missing → degrade gracefully (inventory module optional)
        con.close()
        return []
    con.close()
    out = []
    for r in rows:
        d = dict(r)
        out.append({
            "id":          d["id"],
            "sku":         d["sku"],
            "name":        d["name"],
            "description": d.get("description") or "",
            "unit":        d.get("unit") or "each",
            "unit_price":  float(d.get("unit_cost") or 0),
            "on_hand_qty": float(d.get("quantity") or 0),
        })
    return out


# ── FX rates ───────────────────────────────────────────────────────────────
def get_active_fx_rate(from_currency: str, effective_date: str = None) -> dict:
    """Returns the most recent active fx_rates row for from_currency on or
    before effective_date (default today UTC). None if no rate exists."""
    if effective_date is None:
        effective_date = datetime.now(timezone.utc).date().isoformat()
    con = _con()
    row = con.execute(
        "SELECT * FROM fx_rates "
        "WHERE from_currency = ? AND active = 1 AND effective_date <= ? "
        "ORDER BY effective_date DESC, id DESC LIMIT 1",
        (from_currency, effective_date),
    ).fetchone()
    con.close()
    if not row:
        return None
    return _dec_row("fx_rates", row)


def set_fx_rate_manual(from_currency: str, buy_rate: float,
                       effective_date: str, entered_by: int,
                       notes: str = None) -> int:
    """Manual rate override by super_admin. Deactivates any prior active row
    for the same (from_currency, effective_date) tuple, then inserts a new
    active row with source='manual'. Returns inserted id."""
    now = datetime.now(timezone.utc).isoformat()
    con = _con()
    con.execute(
        "UPDATE fx_rates SET active = 0 "
        "WHERE from_currency = ? AND effective_date = ? AND active = 1",
        (from_currency, effective_date),
    )
    payload = _enc_dict("fx_rates", {"notes": notes}) if notes else {"notes": None}
    prev = _last_chain(con, "fx_rates")
    canonical = {
        "from_currency": from_currency, "to_currency": "JMD",
        "buy_rate": float(buy_rate), "source": "manual",
        "fetched_at": now, "effective_date": effective_date,
        "entered_by": entered_by, "active": 1,
    }
    ch = _fs_compute_hash(prev, canonical, _FX_RATE_HASH_FIELDS)
    cur = con.execute(
        "INSERT INTO fx_rates (from_currency, to_currency, buy_rate, source, "
        "fetched_at, effective_date, entered_by, notes, active, "
        "prior_chain_hash, chain_hash) "
        "VALUES (?, 'JMD', ?, 'manual', ?, ?, ?, ?, 1, ?, ?)",
        (from_currency, float(buy_rate), now, effective_date, entered_by,
         payload.get("notes"), prev, ch),
    )
    con.commit()
    rid = cur.lastrowid
    con.close()
    return rid


def set_fx_rate_from_api(from_currency: str, buy_rate: float,
                         fetched_at: str = None) -> int:
    """Helper for a future scheduled fetcher. Only inserts source='api' rows.
    No scheduler is registered in v1 — call this only from inside an
    env-gated background job. Caller is responsible for env checks."""
    now = fetched_at or datetime.now(timezone.utc).isoformat()
    effective_date = now[:10]
    con = _con()
    con.execute(
        "UPDATE fx_rates SET active = 0 "
        "WHERE from_currency = ? AND effective_date = ? AND active = 1",
        (from_currency, effective_date),
    )
    prev = _last_chain(con, "fx_rates")
    canonical = {
        "from_currency": from_currency, "to_currency": "JMD",
        "buy_rate": float(buy_rate), "source": "api",
        "fetched_at": now, "effective_date": effective_date,
        "entered_by": None, "active": 1,
    }
    ch = _fs_compute_hash(prev, canonical, _FX_RATE_HASH_FIELDS)
    cur = con.execute(
        "INSERT INTO fx_rates (from_currency, to_currency, buy_rate, source, "
        "fetched_at, effective_date, entered_by, notes, active, "
        "prior_chain_hash, chain_hash) "
        "VALUES (?, 'JMD', ?, 'api', ?, ?, NULL, NULL, 1, ?, ?)",
        (from_currency, float(buy_rate), now, effective_date, prev, ch),
    )
    con.commit()
    rid = cur.lastrowid
    con.close()
    return rid


def list_fx_rate_history(from_currency: str, limit: int = 30) -> list:
    """Recent rate history for the currency, newest first."""
    con = _con()
    rows = con.execute(
        "SELECT * FROM fx_rates WHERE from_currency = ? "
        "ORDER BY effective_date DESC, id DESC LIMIT ?",
        (from_currency, int(limit or 30)),
    ).fetchall()
    con.close()
    return _dec_rows("fx_rates", rows)


def compute_fx_display(jmd_total: float, foreign_currency: str,
                       buy_rate: float, fee_pct: float) -> dict:
    """Locked math from spec §3.3:
        effective_rate = buy_rate × (1 + fee_pct/100)
        foreign_total  = jmd_total / effective_rate
        jmd_fee_earned = jmd_total × (fee_pct/100)
    """
    br = float(buy_rate or 0)
    fp = float(fee_pct or 0)
    eff = br * (1.0 + fp / 100.0) if br > 0 else 0.0
    foreign_total = (float(jmd_total) / eff) if eff > 0 else 0.0
    jmd_fee_earned = float(jmd_total) * (fp / 100.0)
    return {
        "effective_rate":  round(eff, 6),
        "foreign_total":   round(foreign_total, 2),
        "jmd_fee_earned":  round(jmd_fee_earned, 2),
        "foreign_currency": foreign_currency,
        "buy_rate":        round(br, 6),
        "fee_pct":         round(fp, 4),
    }


# ── Metrics + listing + CSV export ─────────────────────────────────────────
def get_invoice_metrics(today: str = None) -> dict:
    """Returns top-of-tab tile data: outstanding, overdue, invoiced_mtd,
    collected_mtd. All amounts in JMD (the base currency)."""
    if today is None:
        today = datetime.now(timezone.utc).date().isoformat()
    month_prefix = today[:7]  # YYYY-MM
    con = _con()
    row = con.execute(
        "SELECT COALESCE(SUM(total - amount_paid),0) AS outstanding "
        "FROM invoices WHERE status='sent' AND (total - amount_paid) > 0.01"
    ).fetchone()
    outstanding = float(row["outstanding"] or 0)

    row = con.execute(
        "SELECT COALESCE(SUM(total - amount_paid),0) AS overdue "
        "FROM invoices WHERE status='sent' AND due_date < ? "
        "AND (total - amount_paid) > 0.01",
        (today,),
    ).fetchone()
    overdue = float(row["overdue"] or 0)

    row = con.execute(
        "SELECT COALESCE(SUM(total),0) AS inv_mtd "
        "FROM invoices WHERE substr(issue_date,1,7) = ? "
        "AND status NOT IN ('draft','cancelled','canceled')",
        (month_prefix,),
    ).fetchone()
    invoiced_mtd = float(row["inv_mtd"] or 0)

    row = con.execute(
        "SELECT COALESCE(SUM(amount),0) AS collected_mtd "
        "FROM invoice_payments WHERE substr(COALESCE(created_at,payment_date),1,7) = ? "
        "AND COALESCE(voided_at,'') = ''",
        (month_prefix,),
    ).fetchone()
    collected_mtd = float(row["collected_mtd"] or 0)
    con.close()
    return {
        "outstanding":          round(outstanding, 2),
        "overdue":              round(overdue, 2),
        "invoiced_this_month":  round(invoiced_mtd, 2),
        "collected_this_month": round(collected_mtd, 2),
        "as_of":                today,
    }


def list_invoices(filters: dict, page: int = 1, limit: int = 20) -> dict:
    """Paginated list with optional filters: status, from, to, customer_id.
    Returns {rows, total, page, limit}."""
    page  = max(1, int(page or 1))
    limit = min(100, max(1, int(limit or 20)))
    where, args = [], []
    if filters.get("status"):
        st = filters["status"]
        if st == "overdue":
            today = datetime.now(timezone.utc).date().isoformat()
            where.append("i.status='sent' AND i.due_date < ? AND (i.total - i.amount_paid) > 0.01")
            args.append(today)
        else:
            where.append("i.status = ?"); args.append(st)
    if filters.get("from"):
        where.append("i.issue_date >= ?"); args.append(filters["from"])
    if filters.get("to"):
        where.append("i.issue_date <= ?"); args.append(filters["to"])
    if filters.get("customer_id") is not None:
        where.append("i.customer_id = ?"); args.append(int(filters["customer_id"]))
    where_sql = (" WHERE " + " AND ".join(where)) if where else ""
    con = _con()
    total = con.execute(
        f"SELECT COUNT(*) AS n FROM invoices i {where_sql}", args
    ).fetchone()["n"]
    rows = con.execute(
        f"SELECT i.*, c.name AS customer_name, c.company AS customer_company, "
        f"       c.customer_code "
        f"FROM invoices i JOIN customers c ON i.customer_id = c.id "
        f"{where_sql} ORDER BY i.issue_date DESC, i.id DESC "
        f"LIMIT ? OFFSET ?",
        args + [limit, (page - 1) * limit],
    ).fetchall()
    con.close()
    return {
        "rows":  [dict(r) for r in rows],
        "total": int(total),
        "page":  page,
        "limit": limit,
    }


def export_invoices_csv(filters: dict):
    """Returns an iterable of dicts ready for csv.DictWriter. Columns match
    the invoices-tab table the user sees."""
    today = datetime.now(timezone.utc).date().isoformat()
    page  = list_invoices(filters, page=1, limit=10000)
    out = []
    for r in page["rows"]:
        try:
            from datetime import date as _d
            due = _d.fromisoformat(r["due_date"]) if r.get("due_date") else None
            tod = _d.fromisoformat(today)
            days_overdue = max(0, (tod - due).days) if due else 0
        except Exception:
            days_overdue = 0
        total = float(r.get("total") or 0)
        paid  = float(r.get("amount_paid") or 0)
        # FX columns: blank when invoice is JMD-only; computed via
        # compute_fx_display for foreign-currency invoices so finance
        # exports show the locked-rate JMD-vs-foreign breakdown.
        dc            = (r.get("display_currency") or "JMD").upper()
        fx_rate_used  = r.get("fx_rate_used")
        fx_source     = r.get("fx_rate_source") or ""
        fx_fee_pct    = r.get("fx_fee_pct")
        foreign_total = ""
        if dc != "JMD" and fx_rate_used:
            try:
                disp = compute_fx_display(
                    total, dc, float(fx_rate_used),
                    float(fx_fee_pct if fx_fee_pct is not None else 2.0),
                )
                foreign_total = round(disp["foreign_total"], 2)
            except Exception:
                foreign_total = ""
        out.append({
            "invoice_number":     r.get("invoice_number"),
            "customer_name":      r.get("customer_name") or "",
            "company":            r.get("customer_company") or "",
            "issue_date":         r.get("issue_date") or "",
            "due_date":           r.get("due_date") or "",
            "total_jmd":          round(total, 2),
            "amount_paid_jmd":    round(paid, 2),
            "outstanding_jmd":    round(total - paid, 2),
            "status":             r.get("status") or "",
            "days_overdue":       days_overdue,
            "display_currency":   dc,
            "fx_rate_used":       fx_rate_used if fx_rate_used is not None else "",
            "fx_rate_source":     fx_source,
            "fx_fee_pct":         fx_fee_pct if fx_fee_pct is not None else "",
            "foreign_total_due":  foreign_total,
        })
    return out


def get_invoice_full(invoice_id: int) -> dict:
    """Header + lines + payments + customer + visit ref + active fx_rate.
    Decrypts canceled_reason; payments and fx fields decrypted via helpers."""
    base = get_invoice_by_id(invoice_id, with_lines=True)
    if not base:
        return None
    base = _dec_row("invoices", base)
    # decrypt payments notes
    if base.get("payments"):
        base["payments"] = [_dec_row("invoice_payments", p) for p in base["payments"]]
    # attach active fx for display_currency if foreign
    dc = (base.get("display_currency") or "JMD").upper()
    if dc != "JMD":
        rate = get_active_fx_rate(dc, base.get("issue_date"))
        base["active_fx_rate"] = rate
    return base


# ── Payments (chain-hashed, append-only) ───────────────────────────────────
def _chain_hash_payment(prior_hash: str, row: dict) -> str:
    import hashlib, json as _j
    keys = ("invoice_id", "amount", "payment_date", "method",
            "foreign_amount", "foreign_currency", "fx_rate_used",
            "recorded_by", "created_at")
    payload = {k: row.get(k) for k in keys}
    body = (prior_hash or "") + _j.dumps(payload, sort_keys=True, default=str)
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def record_invoice_payment_v2(invoice_id: int, data: dict,
                              recorded_by: int = None,
                              recorded_by_label: str = None,
                              recorded_by_prid: str = None) -> dict:
    """Append-only invoice-side payment record. Stores JMD amount in `amount`
    (legacy column); foreign breakdown in fx fields. Idempotency: if an
    identical (invoice_id, amount, payment_date, method, recorded_by) row
    exists within 30s, return the existing id and a duplicate flag."""
    now = datetime.now(timezone.utc).isoformat()
    amount_jmd = float(data.get("amount_jmd") if "amount_jmd" in data else data.get("amount"))
    method     = (data.get("payment_method") or data.get("method") or "other").lower()
    payment_date = data["payment_date"]
    foreign_amount   = data.get("foreign_amount")
    foreign_currency = data.get("foreign_currency")
    fx_rate_used     = data.get("fx_rate_used")
    fx_fee_pct_used  = data.get("fx_fee_pct_used")
    effective_rate   = data.get("effective_rate_used")
    notes_plain      = data.get("notes") or ""

    con = _con()
    # Idempotency window — last 30 seconds
    dup = con.execute(
        "SELECT id FROM invoice_payments WHERE invoice_id = ? AND amount = ? "
        "AND payment_date = ? AND COALESCE(method,'') = ? AND COALESCE(recorded_by,0) = ? "
        "AND created_at >= datetime('now','-30 seconds') "
        "ORDER BY id DESC LIMIT 1",
        (invoice_id, amount_jmd, payment_date, method, recorded_by or 0),
    ).fetchone()
    if dup:
        con.close()
        return {"id": dup["id"], "duplicate": True}

    prior = con.execute(
        "SELECT chain_hash FROM invoice_payments "
        "ORDER BY id DESC LIMIT 1"
    ).fetchone()
    prior_hash = (prior["chain_hash"] if prior else "") or ""

    enc = _enc_dict("invoice_payments", {"notes": notes_plain})
    row_for_hash = {
        "invoice_id": invoice_id, "amount": amount_jmd,
        "payment_date": payment_date, "method": method,
        "foreign_amount": foreign_amount, "foreign_currency": foreign_currency,
        "fx_rate_used": fx_rate_used, "recorded_by": recorded_by,
        "created_at": now,
    }
    chash = _chain_hash_payment(prior_hash, row_for_hash)

    cur = con.execute(
        "INSERT INTO invoice_payments "
        "(invoice_id, payment_date, amount, method, reference, notes, "
        " recorded_by, recorded_by_label, recorded_by_prid, created_at, "
        " foreign_amount, foreign_currency, fx_rate_used, fx_fee_pct_used, "
        " effective_rate_used, hub_id, prior_chain_hash, chain_hash) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)",
        (invoice_id, payment_date, amount_jmd, method,
         data.get("reference", ""), enc.get("notes"),
         recorded_by, recorded_by_label, recorded_by_prid, now,
         foreign_amount, foreign_currency, fx_rate_used, fx_fee_pct_used,
         effective_rate, prior_hash, chash),
    )
    payment_id = cur.lastrowid
    _recompute_invoice_totals(con, invoice_id)
    # Auto-flip to paid if covered
    inv = con.execute(
        "SELECT total, amount_paid FROM invoices WHERE id = ?", (invoice_id,)
    ).fetchone()
    if inv and float(inv["amount_paid"]) >= float(inv["total"]) - 0.005 \
            and float(inv["total"]) > 0:
        con.execute(
            "UPDATE invoices SET status='paid', "
            "paid_at = COALESCE(paid_at, ?), updated_at=? WHERE id=?",
            (now, now, invoice_id),
        )
    con.commit()
    con.close()
    return {"id": payment_id, "duplicate": False, "chain_hash": chash}


# ── Status transition helper ───────────────────────────────────────────────
_LEGAL_TRANSITIONS = {
    "draft":     {"sent", "cancelled", "canceled"},
    "sent":      {"paid", "cancelled", "canceled"},
    "paid":      {"cancelled", "canceled"},
    "cancelled": set(),
    "canceled":  set(),
}


def transition_invoice_status(invoice_id: int, new_status: str,
                              actor_id: int = None,
                              reason: str = None) -> bool:
    """Enforces legal state transitions. Returns True on success.
    Raises ValueError for invalid transitions. Encrypts canceled_reason."""
    now = datetime.now(timezone.utc).isoformat()
    con = _con()
    row = con.execute(
        "SELECT status FROM invoices WHERE id = ?", (invoice_id,)
    ).fetchone()
    if not row:
        con.close()
        raise ValueError("Invoice not found")
    cur_status = row["status"]
    allowed = _LEGAL_TRANSITIONS.get(cur_status, set())
    if new_status not in allowed and new_status != cur_status:
        con.close()
        raise ValueError(f"Illegal transition: {cur_status} → {new_status}")
    if new_status in ("cancelled", "canceled"):
        enc = _enc_dict("invoices", {"canceled_reason": (reason or "")})
        con.execute(
            "UPDATE invoices SET status = ?, canceled_at = ?, canceled_by = ?, "
            "canceled_reason = ?, updated_at = ? WHERE id = ?",
            (new_status, now, actor_id, enc.get("canceled_reason"), now,
             invoice_id),
        )
    elif new_status == "sent":
        con.execute(
            "UPDATE invoices SET status='sent', sent_at = COALESCE(sent_at, ?), "
            "updated_at = ? WHERE id = ?",
            (now, now, invoice_id),
        )
    elif new_status == "paid":
        con.execute(
            "UPDATE invoices SET status='paid', paid_at = COALESCE(paid_at, ?), "
            "updated_at = ? WHERE id = ?",
            (now, now, invoice_id),
        )
    else:
        con.execute(
            "UPDATE invoices SET status = ?, updated_at = ? WHERE id = ?",
            (new_status, now, invoice_id),
        )
    con.commit()
    con.close()
    return True


# ── Header + lines atomic write supporting new column set ──────────────────
def create_invoice_with_lines(data: dict, created_by: int = None) -> int:
    """Wrapper around create_invoice that also persists the new columns:
    display_currency, fx_fee_pct, fx_rate_used + source + fetched_at,
    plus extended line metadata (tech_id, hours, hourly_rate, part_sku)."""
    invoice_id = create_invoice(data, created_by=created_by)
    now = datetime.now(timezone.utc).isoformat()
    con = _con()
    con.execute(
        "UPDATE invoices SET display_currency = ?, fx_fee_pct = ?, "
        "fx_rate_used = ?, fx_rate_source = ?, fx_rate_fetched_at = ?, "
        "updated_at = ? WHERE id = ?",
        (
            (data.get("display_currency") or "JMD").upper(),
            float(data.get("fx_fee_pct") if data.get("fx_fee_pct") is not None else 2.0),
            data.get("fx_rate_used"),
            data.get("fx_rate_source"),
            data.get("fx_rate_fetched_at"),
            now, invoice_id,
        ),
    )
    # Backfill extended line metadata for any rows we just inserted.
    lines = data.get("line_items") or []
    rows = con.execute(
        "SELECT id, sort_order FROM invoice_line_items "
        "WHERE invoice_id = ? ORDER BY sort_order, id",
        (invoice_id,),
    ).fetchall()
    for r, li in zip(rows, lines):
        con.execute(
            "UPDATE invoice_line_items SET part_sku = ?, tech_id = ?, "
            "hours = ?, hourly_rate = ?, created_at = COALESCE(created_at, ?), "
            "updated_at = ? WHERE id = ?",
            (li.get("part_sku"), li.get("tech_id"), li.get("hours"),
             li.get("hourly_rate"), now, now, r["id"]),
        )
    con.commit()
    con.close()
    return invoice_id


def update_invoice_with_lines(invoice_id: int, data: dict,
                              if_match: str = None):
    """Atomic header + replace-lines update including the new columns.

    If `if_match` is provided, current invoices.updated_at must match it or
    StaleWriteError is raised. Bumps updated_at to now on success."""
    if if_match is not None:
        _con_check = _con()
        cur = _con_check.execute(
            "SELECT updated_at FROM invoices WHERE id = ?", (invoice_id,)
        ).fetchone()
        _con_check.close()
        if cur and (cur["updated_at"] or "") != if_match:
            raise StaleWriteError("invoice row updated_at does not match If-Match")
    update_invoice(invoice_id, data)
    now = datetime.now(timezone.utc).isoformat()
    con = _con()
    con.execute(
        "UPDATE invoices SET display_currency = ?, fx_fee_pct = ?, "
        "fx_rate_used = ?, fx_rate_source = ?, fx_rate_fetched_at = ?, "
        "updated_at = ? WHERE id = ?",
        (
            (data.get("display_currency") or "JMD").upper(),
            float(data.get("fx_fee_pct") if data.get("fx_fee_pct") is not None else 2.0),
            data.get("fx_rate_used"),
            data.get("fx_rate_source"),
            data.get("fx_rate_fetched_at"),
            now, invoice_id,
        ),
    )
    lines = data.get("line_items") or []
    rows = con.execute(
        "SELECT id, sort_order FROM invoice_line_items "
        "WHERE invoice_id = ? ORDER BY sort_order, id",
        (invoice_id,),
    ).fetchall()
    for r, li in zip(rows, lines):
        con.execute(
            "UPDATE invoice_line_items SET part_sku = ?, tech_id = ?, "
            "hours = ?, hourly_rate = ?, updated_at = ? WHERE id = ?",
            (li.get("part_sku"), li.get("tech_id"), li.get("hours"),
             li.get("hourly_rate"), now, r["id"]),
        )
    con.commit()
    con.close()


# ═══════════════════════════════════════════════════════════════════════════
# Delegation module — helpers
# ═══════════════════════════════════════════════════════════════════════════
# Chain-hashed append-only audit on delegations + delegation_power. Mirrors
# `_chain_hash_payment` shape. Notes/reasons/review_notes get _PII_RAND
# field-level encryption via _enc_dict on write, _dec_row on read.


def _chain_hash_delegation(prior_hash: str, row: dict) -> str:
    import hashlib, json as _j
    keys = ("grantor_id", "recipient_id", "delegation_type",
            "scope_record_id", "scope_record_type", "permission_level",
            "valid_until", "created_at", "revoked_at", "revoked_by",
            "revoke_kind")
    payload = {k: row.get(k) for k in keys}
    body = (prior_hash or "") + _j.dumps(payload, sort_keys=True, default=str)
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def _chain_hash_delegation_power(prior_hash: str, row: dict) -> str:
    import hashlib, json as _j
    keys = ("admin_id", "granted_by_id", "granted_at",
            "revoked_at", "revoked_by")
    payload = {k: row.get(k) for k in keys}
    body = (prior_hash or "") + _j.dumps(payload, sort_keys=True, default=str)
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def _last_delegation_chain(con=None) -> str:
    own = con is None
    if own: con = _con()
    r = con.execute("SELECT chain_hash FROM delegations ORDER BY id DESC LIMIT 1").fetchone()
    if own: con.close()
    return (r["chain_hash"] if r else "") or ""


def _last_delegation_power_chain(con=None) -> str:
    own = con is None
    if own: con = _con()
    r = con.execute("SELECT chain_hash FROM delegation_power ORDER BY id DESC LIMIT 1").fetchone()
    if own: con.close()
    return (r["chain_hash"] if r else "") or ""


def _last_regrant_chain(con=None) -> str:
    own = con is None
    if own: con = _con()
    r = con.execute("SELECT chain_hash FROM delegation_regrant_requests ORDER BY id DESC LIMIT 1").fetchone()
    if own: con.close()
    return (r["chain_hash"] if r else "") or ""


def create_delegation(grantor_id: int, grantor_role: str,
                      recipient_id: int, recipient_kind: str,
                      delegation_type: str,
                      scope_record_id: int = None,
                      scope_record_type: str = None,
                      permission_level: str = None,
                      valid_until: str = None,
                      grantor_notes: str = "") -> int:
    """Chain-hashed insert. Returns new id. Caller validates business rules."""
    now = datetime.now(timezone.utc).isoformat()
    enc = _enc_dict("delegations", {"grantor_notes": grantor_notes or ""})
    con = _con()
    prior = _last_delegation_chain(con)
    row_for_hash = {
        "grantor_id": grantor_id, "recipient_id": recipient_id,
        "delegation_type": delegation_type,
        "scope_record_id": scope_record_id,
        "scope_record_type": scope_record_type,
        "permission_level": permission_level,
        "valid_until": valid_until, "created_at": now,
        "revoked_at": None, "revoked_by": None, "revoke_kind": None,
    }
    chash = _chain_hash_delegation(prior, row_for_hash)
    cur = con.execute(
        "INSERT INTO delegations "
        "(grantor_id, grantor_role, recipient_id, recipient_kind, "
        " delegation_type, scope_record_id, scope_record_type, permission_level, "
        " valid_until, grantor_notes, created_at, prior_chain_hash, chain_hash, hub_id) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)",
        (grantor_id, grantor_role, recipient_id, recipient_kind,
         delegation_type, scope_record_id, scope_record_type, permission_level,
         valid_until, enc.get("grantor_notes"), now, prior, chash),
    )
    new_id = cur.lastrowid
    # If type=power, flip recipient flag in the same transaction.
    if delegation_type == "power":
        p_prior = _last_delegation_power_chain(con)
        p_row = {"admin_id": recipient_id, "granted_by_id": grantor_id,
                 "granted_at": now, "revoked_at": None, "revoked_by": None}
        p_chash = _chain_hash_delegation_power(p_prior, p_row)
        con.execute(
            "INSERT OR REPLACE INTO delegation_power "
            "(admin_id, granted_by_id, granted_at, revoked_at, revoked_by, "
            " prior_chain_hash, chain_hash) "
            "VALUES (?, ?, ?, NULL, NULL, ?, ?)",
            (recipient_id, grantor_id, now, p_prior, p_chash),
        )
        con.execute("UPDATE admin_users SET has_delegation_power = 1 WHERE id = ?",
                    (recipient_id,))
    con.commit()
    con.close()
    return new_id


def revoke_delegation(delegation_id: int, revoked_by: int,
                      reason: str = "", revoke_kind: str = "manual",
                      con=None) -> bool:
    """UPDATE row; recompute chain hash for the now-revoked row.
    If `con` provided, uses it (no commit/close) — for cascade transactions."""
    now = datetime.now(timezone.utc).isoformat()
    own = con is None
    if own: con = _con()
    row = con.execute("SELECT * FROM delegations WHERE id = ?", (delegation_id,)).fetchone()
    if not row:
        if own: con.close()
        return False
    if row["revoked_at"]:
        if own: con.close()
        return False
    enc = _enc_dict("delegations", {"revoke_reason": reason or ""})
    prior = _last_delegation_chain(con)
    row_for_hash = dict(row)
    row_for_hash.update({"revoked_at": now, "revoked_by": revoked_by,
                         "revoke_kind": revoke_kind})
    chash = _chain_hash_delegation(prior, row_for_hash)
    con.execute(
        "UPDATE delegations SET revoked_at = ?, revoked_by = ?, "
        "revoke_reason = ?, revoke_kind = ?, "
        "prior_chain_hash = ?, chain_hash = ? WHERE id = ?",
        (now, revoked_by, enc.get("revoke_reason"), revoke_kind,
         prior, chash, delegation_id),
    )
    if own:
        con.commit()
        con.close()
    return True


def cascade_revoke_power(admin_id: int, revoked_by: int) -> list:
    """Single transaction: clear has_delegation_power flag on admin, revoke
    delegation_power row, AND revoke every active delegation granted by this
    admin (revoke_kind='power_cascade'). Returns the list of cascaded
    delegation IDs so the caller can audit each one."""
    now = datetime.now(timezone.utc).isoformat()
    cascaded = []
    con = _con()
    try:
        con.execute("UPDATE admin_users SET has_delegation_power = 0 WHERE id = ?",
                    (admin_id,))
        p_row = con.execute(
            "SELECT * FROM delegation_power WHERE admin_id = ? AND revoked_at IS NULL",
            (admin_id,),
        ).fetchone()
        if p_row:
            p_prior = _last_delegation_power_chain(con)
            new_row = dict(p_row)
            new_row.update({"revoked_at": now, "revoked_by": revoked_by})
            p_chash = _chain_hash_delegation_power(p_prior, new_row)
            con.execute(
                "UPDATE delegation_power SET revoked_at = ?, revoked_by = ?, "
                "prior_chain_hash = ?, chain_hash = ? WHERE id = ?",
                (now, revoked_by, p_prior, p_chash, p_row["id"]),
            )
        active = con.execute(
            "SELECT id FROM delegations WHERE grantor_id = ? AND revoked_at IS NULL",
            (admin_id,),
        ).fetchall()
        for r in active:
            if revoke_delegation(r["id"], revoked_by,
                                 reason="Power cascade",
                                 revoke_kind="power_cascade", con=con):
                cascaded.append(r["id"])
        con.commit()
    except Exception:
        con.rollback()
        con.close()
        raise
    con.close()
    return cascaded


def list_active_delegations_for_recipient(admin_id: int) -> list:
    con = _con()
    rows = con.execute(
        "SELECT * FROM delegations "
        "WHERE recipient_id = ? AND revoked_at IS NULL "
        "ORDER BY created_at DESC", (admin_id,),
    ).fetchall()
    con.close()
    return [_dec_row("delegations", r) for r in rows]


def list_cascade_revoked_recent(admin_id: int, days: int = 30) -> list:
    """For the 'Request re-grant' banner."""
    con = _con()
    rows = con.execute(
        "SELECT * FROM delegations "
        "WHERE recipient_id = ? AND revoke_kind = 'power_cascade' "
        "AND revoked_at >= datetime('now', ?) "
        "ORDER BY revoked_at DESC", (admin_id, f"-{int(days)} days"),
    ).fetchall()
    con.close()
    return [_dec_row("delegations", r) for r in rows]


def lookup_record_delegation(admin_id: int, record_type: str,
                             record_id: int) -> dict:
    """Find the strongest active delegation that grants this admin access to
    the given record. Power > record_type > record. Auto-revokes expired rows
    encountered during the scan. Returns the matching row dict or None."""
    now = datetime.now(timezone.utc).isoformat()
    con = _con()
    rows = con.execute(
        "SELECT * FROM delegations "
        "WHERE recipient_id = ? AND revoked_at IS NULL",
        (admin_id,),
    ).fetchall()
    con.close()
    candidates = []
    for r in rows:
        d = dict(r)
        if d["valid_until"] and d["valid_until"] < now:
            try:
                revoke_delegation(d["id"], revoked_by=admin_id,
                                  reason="lazy auto-expiry",
                                  revoke_kind="auto_expiry")
                try:
                    log_audit(actor_type="system",
                              action="delegation.auto_expired",
                              target_type="delegations", target_id=d["id"])
                except Exception as _e:
                    import sys
                    print(f"[delegation] audit-write failed: {_e}", file=sys.stderr)
            except Exception as _e:
                import sys
                print(f"[delegation] auto-expiry failed: {_e}", file=sys.stderr)
            continue
        if d["delegation_type"] == "power":
            candidates.append((3, d)); continue
        if d["delegation_type"] == "record_type" and d["scope_record_type"] == record_type:
            candidates.append((2, d)); continue
        if d["delegation_type"] == "record" and d["scope_record_type"] == record_type \
                and int(d["scope_record_id"] or 0) == int(record_id):
            candidates.append((1, d)); continue
    if not candidates:
        return None
    candidates.sort(key=lambda x: -x[0])
    return _dec_row("delegations", candidates[0][1])


def expire_delegations_sweep() -> int:
    """Cron-driven sweep — revoke delegations whose valid_until has passed.
    Returns count of rows revoked."""
    now = datetime.now(timezone.utc).isoformat()
    con = _con()
    rows = con.execute(
        "SELECT id FROM delegations WHERE revoked_at IS NULL "
        "AND valid_until IS NOT NULL AND valid_until < ?", (now,),
    ).fetchall()
    con.close()
    count = 0
    for r in rows:
        try:
            if revoke_delegation(r["id"], revoked_by=0,
                                 reason="cron auto-expiry",
                                 revoke_kind="auto_expiry"):
                count += 1
                try:
                    log_audit(actor_type="system",
                              action="delegation.auto_expired",
                              target_type="delegations", target_id=r["id"])
                except Exception as _e:
                    import sys
                    print(f"[delegation] audit-write failed: {_e}", file=sys.stderr)
        except Exception as _e:
            import sys
            print(f"[delegation] sweep skip {r['id']}: {_e}", file=sys.stderr)
    return count


def list_delegations(filters: dict = None) -> list:
    """For the admin UI table. Filters: grantor_id, recipient_id, status,
    delegation_type."""
    filters = filters or {}
    where, params = ["1=1"], []
    if filters.get("grantor_id") is not None:
        where.append("grantor_id = ?"); params.append(filters["grantor_id"])
    if filters.get("recipient_id") is not None:
        where.append("recipient_id = ?"); params.append(filters["recipient_id"])
    if filters.get("delegation_type"):
        where.append("delegation_type = ?"); params.append(filters["delegation_type"])
    status = filters.get("status")
    if status == "active":
        where.append("revoked_at IS NULL "
                     "AND (valid_until IS NULL OR valid_until > datetime('now'))")
    elif status == "expired":
        where.append("revoked_at IS NOT NULL AND revoke_kind = 'auto_expiry'")
    elif status == "revoked":
        where.append("revoked_at IS NOT NULL AND revoke_kind != 'auto_expiry'")
    con = _con()
    rows = con.execute(
        f"SELECT * FROM delegations WHERE {' AND '.join(where)} "
        "ORDER BY created_at DESC", params,
    ).fetchall()
    con.close()
    return [_dec_row("delegations", r) for r in rows]


def get_delegation(delegation_id: int) -> dict:
    con = _con()
    r = con.execute("SELECT * FROM delegations WHERE id = ?", (delegation_id,)).fetchone()
    con.close()
    return _dec_row("delegations", r) if r else None


def create_regrant_request(requester_id: int,
                           original_delegation_id: int,
                           notes: str = "") -> int:
    now = datetime.now(timezone.utc).isoformat()
    con = _con()
    prior = _last_regrant_chain(con)
    enc = _enc_dict("delegation_regrant_requests", {"review_notes": notes or ""})
    import hashlib, json as _j
    payload = {"requester_id": requester_id,
               "original_delegation_id": original_delegation_id,
               "requested_at": now, "status": "open"}
    chash = hashlib.sha256(((prior or "") + _j.dumps(payload, sort_keys=True)).encode()).hexdigest()
    cur = con.execute(
        "INSERT INTO delegation_regrant_requests "
        "(requester_id, original_delegation_id, status, requested_at, "
        " review_notes, prior_chain_hash, chain_hash) "
        "VALUES (?, ?, 'open', ?, ?, ?, ?)",
        (requester_id, original_delegation_id, now,
         enc.get("review_notes"), prior, chash),
    )
    rid = cur.lastrowid
    con.commit()
    con.close()
    return rid


def _update_regrant_chain(con, rid: int, payload: dict) -> str:
    import hashlib, json as _j
    prior = _last_regrant_chain(con)
    chash = hashlib.sha256(((prior or "") + _j.dumps(payload, sort_keys=True, default=str)).encode()).hexdigest()
    con.execute("UPDATE delegation_regrant_requests SET prior_chain_hash = ?, chain_hash = ? WHERE id = ?",
                (prior, chash, rid))
    return chash


def approve_regrant_request(request_id: int, reviewer_id: int,
                            review_notes: str = "") -> dict:
    """Copies the original delegation's scope/perm into a new active row.
    Returns {request_id, new_delegation_id}."""
    now = datetime.now(timezone.utc).isoformat()
    con = _con()
    req = con.execute(
        "SELECT * FROM delegation_regrant_requests WHERE id = ? AND status = 'open'",
        (request_id,),
    ).fetchone()
    if not req:
        con.close()
        raise ValueError("Request not found or not open")
    orig = con.execute("SELECT * FROM delegations WHERE id = ?",
                       (req["original_delegation_id"],)).fetchone()
    if not orig:
        con.close()
        raise ValueError("Original delegation missing")
    con.close()
    new_id = create_delegation(
        grantor_id=reviewer_id, grantor_role="super_admin",
        recipient_id=orig["recipient_id"], recipient_kind="admin",
        delegation_type=orig["delegation_type"],
        scope_record_id=orig["scope_record_id"],
        scope_record_type=orig["scope_record_type"],
        permission_level=orig["permission_level"],
        valid_until=orig["valid_until"],
        grantor_notes=f"Re-grant via request #{request_id}",
    )
    con = _con()
    enc = _enc_dict("delegation_regrant_requests", {"review_notes": review_notes or ""})
    con.execute(
        "UPDATE delegation_regrant_requests SET status = 'approved', "
        "reviewed_by = ?, reviewed_at = ?, review_notes = ?, "
        "new_delegation_id = ? WHERE id = ?",
        (reviewer_id, now, enc.get("review_notes"), new_id, request_id),
    )
    _update_regrant_chain(con, request_id, {
        "status": "approved", "reviewed_by": reviewer_id,
        "reviewed_at": now, "new_delegation_id": new_id,
    })
    con.commit()
    con.close()
    return {"request_id": request_id, "new_delegation_id": new_id}


def deny_regrant_request(request_id: int, reviewer_id: int,
                         review_notes: str = "") -> bool:
    now = datetime.now(timezone.utc).isoformat()
    con = _con()
    req = con.execute(
        "SELECT id FROM delegation_regrant_requests WHERE id = ? AND status = 'open'",
        (request_id,),
    ).fetchone()
    if not req:
        con.close()
        return False
    enc = _enc_dict("delegation_regrant_requests", {"review_notes": review_notes or ""})
    con.execute(
        "UPDATE delegation_regrant_requests SET status = 'denied', "
        "reviewed_by = ?, reviewed_at = ?, review_notes = ? WHERE id = ?",
        (reviewer_id, now, enc.get("review_notes"), request_id),
    )
    _update_regrant_chain(con, request_id, {
        "status": "denied", "reviewed_by": reviewer_id, "reviewed_at": now,
    })
    con.commit()
    con.close()
    return True


def list_regrant_requests(status: str = "open") -> list:
    con = _con()
    if status:
        rows = con.execute(
            "SELECT * FROM delegation_regrant_requests WHERE status = ? "
            "ORDER BY requested_at DESC", (status,),
        ).fetchall()
    else:
        rows = con.execute(
            "SELECT * FROM delegation_regrant_requests "
            "ORDER BY requested_at DESC"
        ).fetchall()
    con.close()
    return [_dec_row("delegation_regrant_requests", r) for r in rows]


# ════════════════════════════════════════════════════════════════════════════
# Employee KPI Tracking Module — period + threshold + chain-hash helpers
# Phase 1 surface. Compute engine + recompute orchestrator live below.
# ════════════════════════════════════════════════════════════════════════════

def iso_week_key(date_str_or_today=None) -> str:
    """Return 'YYYY-WNN' ISO-week key. Accepts an ISO date string or None
    (current UTC date)."""
    if date_str_or_today is None:
        d = datetime.now(timezone.utc).date()
    elif isinstance(date_str_or_today, str):
        # Accept full ISO timestamps or plain dates
        d = datetime.fromisoformat(date_str_or_today.replace("Z", "+00:00")).date() \
            if "T" in date_str_or_today else datetime.fromisoformat(date_str_or_today).date()
    else:
        d = date_str_or_today
    yr, wk, _ = d.isocalendar()
    return f"{yr:04d}-W{wk:02d}"


def iso_week_bounds(period_key: str):
    """Return (start_date, end_date) ISO date strings for an ISO-week key."""
    yr_s, wk_s = period_key.split("-W")
    yr, wk = int(yr_s), int(wk_s)
    # ISO Monday is day 1, Sunday is day 7.
    from datetime import date, timedelta
    monday = date.fromisocalendar(yr, wk, 1)
    sunday = monday + timedelta(days=6)
    return monday.isoformat(), sunday.isoformat()


def ensure_period_exists(period_key: str) -> int:
    """Idempotent insert into kpi_periods. Returns the row id."""
    start, end = iso_week_bounds(period_key)
    now = datetime.now(timezone.utc).isoformat()
    con = _con()
    con.execute(
        "INSERT OR IGNORE INTO kpi_periods (period_key, start_date, end_date, "
        "status, created_at) VALUES (?, ?, ?, 'open', ?)",
        (period_key, start, end, now),
    )
    con.commit()
    row = con.execute("SELECT id FROM kpi_periods WHERE period_key=?", (period_key,)).fetchone()
    con.close()
    return row["id"] if row else None


def get_or_create_period(date_or_today=None) -> str:
    """Return the period_key for the given date (default: today), ensuring it
    exists in kpi_periods."""
    key = iso_week_key(date_or_today)
    ensure_period_exists(key)
    return key


def close_period(period_key: str, closed_by: int) -> bool:
    """Flip period status to closed. Returns False if already closed or
    missing. Closed periods are immutable for recompute callers."""
    now = datetime.now(timezone.utc).isoformat()
    con = _con()
    row = con.execute("SELECT status FROM kpi_periods WHERE period_key=?",
                       (period_key,)).fetchone()
    if not row:
        con.close(); return False
    if row["status"] == "closed":
        con.close(); return False
    con.execute(
        "UPDATE kpi_periods SET status='closed', closed_at=?, closed_by=? "
        "WHERE period_key=?", (now, closed_by, period_key),
    )
    con.commit(); con.close()
    return True


def list_kpi_periods(status: str = None, limit: int = 100) -> list:
    con = _con()
    if status:
        rows = con.execute(
            "SELECT * FROM kpi_periods WHERE status=? "
            "ORDER BY start_date DESC LIMIT ?", (status, limit),
        ).fetchall()
    else:
        rows = con.execute(
            "SELECT * FROM kpi_periods ORDER BY start_date DESC LIMIT ?",
            (limit,),
        ).fetchall()
    con.close()
    return [dict(r) for r in rows]


def list_kpi_definitions(active_only: bool = True) -> list:
    con = _con()
    sql = "SELECT * FROM kpi_definitions"
    if active_only:
        sql += " WHERE active=1"
    sql += " ORDER BY in_composite DESC, composite_weight_pct DESC, kpi_key ASC"
    rows = con.execute(sql).fetchall()
    con.close()
    return [dict(r) for r in rows]


def list_kpi_thresholds(tier: str = None, kpi_key: str = None,
                         active_only: bool = True) -> list:
    con = _con()
    where = []
    args = []
    if active_only:
        where.append("active=1")
    if tier:
        where.append("tier=?"); args.append(tier)
    if kpi_key:
        where.append("kpi_key=?"); args.append(kpi_key)
    sql = "SELECT * FROM kpi_thresholds"
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY kpi_key, tier"
    rows = con.execute(sql, args).fetchall()
    con.close()
    return [dict(r) for r in rows]


def upsert_kpi_threshold(kpi_key: str, tier: str, green: float,
                          amber_band: float, red_floor: float,
                          effective_from: str = None) -> int:
    """Admin tuning: deactivate the prior active row for (kpi_key, tier) and
    insert a new active row with the new values. Returns new row id."""
    now = datetime.now(timezone.utc).isoformat()
    effective_from = effective_from or datetime.now(timezone.utc).date().isoformat()
    con = _con()
    con.execute(
        "UPDATE kpi_thresholds SET active=0, effective_until=? "
        "WHERE kpi_key=? AND tier=? AND active=1",
        (effective_from, kpi_key, tier),
    )
    cur = con.execute(
        "INSERT OR REPLACE INTO kpi_thresholds (kpi_key, tier, green_threshold, "
        "amber_band, red_floor, effective_from, active, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, 1, ?)",
        (kpi_key, tier, green, amber_band, red_floor, effective_from, now),
    )
    new_id = cur.lastrowid
    con.commit(); con.close()
    return new_id


def _chain_hash_kpi_score(prior_hash: str, row: dict) -> str:
    import hashlib, json as _j
    keys = ("tech_id", "period_key", "kpi_key", "raw_value", "sample_size",
            "band", "tier_at_computation", "computed_at")
    payload = {k: row.get(k) for k in keys}
    body = (prior_hash or "") + _j.dumps(payload, sort_keys=True, default=str)
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def _chain_hash_kpi_composite(prior_hash: str, row: dict) -> str:
    import hashlib, json as _j
    keys = ("tech_id", "period_key", "composite_pct", "band",
            "forced_red_reason", "tier_at_computation", "computed_at")
    payload = {k: row.get(k) for k in keys}
    body = (prior_hash or "") + _j.dumps(payload, sort_keys=True, default=str)
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def _chain_hash_kpi_flag(prior_hash: str, row: dict) -> str:
    import hashlib, json as _j
    keys = ("tech_id", "period_key", "kpi_key", "severity", "status",
            "manager_id", "created_at")
    payload = {k: row.get(k) for k in keys}
    body = (prior_hash or "") + _j.dumps(payload, sort_keys=True, default=str)
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def _last_kpi_score_chain(con=None) -> str:
    own = con is None
    if own: con = _con()
    r = con.execute("SELECT chain_hash FROM kpi_scores ORDER BY id DESC LIMIT 1").fetchone()
    if own: con.close()
    return (r["chain_hash"] if r else "") or ""


def _last_kpi_composite_chain(con=None) -> str:
    own = con is None
    if own: con = _con()
    r = con.execute("SELECT chain_hash FROM kpi_composite_scores ORDER BY id DESC LIMIT 1").fetchone()
    if own: con.close()
    return (r["chain_hash"] if r else "") or ""


def _last_kpi_flag_chain(con=None) -> str:
    own = con is None
    if own: con = _con()
    r = con.execute("SELECT chain_hash FROM kpi_flags ORDER BY id DESC LIMIT 1").fetchone()
    if own: con.close()
    return (r["chain_hash"] if r else "") or ""


# ════════════════════════════════════════════════════════════════════════════
# Employee KPI Tracking Module — compute engine
# Each helper returns (raw_value, sample_size, band_marker_or_None). The band
# is computed separately via score_to_band so threshold overrides flow through
# one path. Insufficient-data is propagated as raw_value=None with the
# threshold-specific minimum sample documented inline.
# ════════════════════════════════════════════════════════════════════════════

# Tier inference — technicians.role values map onto the tier table.
_KPI_TECH_ROLE_TO_TIER = {
    "tech":            "level_1",
    "tech_l1":         "level_1",
    "tech_level_1":    "level_1",
    "tech_l2":         "level_2",
    "tech_level_2":    "level_2",
    "tech_l3":         "level_3",
    "tech_level_3":    "level_3",
    "senior_tech":     "level_3",
    "lead_tech":       "level_3",
    "ops_manager":     "ops_manager",
}


def _kpi_tier_for_tech(tech_id: int) -> str:
    con = _con()
    r = con.execute("SELECT role FROM technicians WHERE id=?", (tech_id,)).fetchone()
    con.close()
    role = (r["role"] if r else "tech") or "tech"
    return _KPI_TECH_ROLE_TO_TIER.get(role, "level_1")


def _kpi_period_bounds_iso(period_key: str):
    """Return (start_iso_dt, end_iso_dt) datetime strings covering the full
    week — start is Monday 00:00 UTC, end is Sunday 23:59:59 UTC."""
    start, end = iso_week_bounds(period_key)
    return f"{start}T00:00:00+00:00", f"{end}T23:59:59+00:00"


def compute_callback_rate(tech_id: int, period_key: str) -> tuple:
    """callback_rate = (visits in period that are callbacks of THIS tech's
    prior work) / (visits this tech completed in period). Lower is better.
    Insufficient data if denominator < 3."""
    start, end = _kpi_period_bounds_iso(period_key)
    sd, ed = iso_week_bounds(period_key)
    con = _con()
    # Denominator: completed visits by this tech in the period (any type).
    denom = con.execute(
        "SELECT COUNT(*) FROM maintenance_visits "
        "WHERE assigned_tech_id=? AND completed_date IS NOT NULL "
        "AND completed_date BETWEEN ? AND ?",
        (tech_id, sd, ed),
    ).fetchone()[0]
    # Numerator: callbacks created in this period whose origin visit was done by this tech.
    num = con.execute(
        "SELECT COUNT(*) FROM maintenance_visits v "
        "JOIN maintenance_visits orig ON orig.id = v.callback_of_visit_id "
        "WHERE v.callback_of_visit_id IS NOT NULL "
        "AND orig.assigned_tech_id = ? "
        "AND v.created_at BETWEEN ? AND ?",
        (tech_id, start, end),
    ).fetchone()[0]
    con.close()
    if denom < 3:
        return (None, denom, "insufficient_data")
    pct = (num / denom) * 100.0
    return (round(pct, 2), denom, None)


def compute_documentation_quality(tech_id: int, period_key: str) -> tuple:
    """Per-visit score: 30 (base for being completed) + 30 (has readings) +
    20 (has photos) + 20 (has work_done_summary). Capped 100. Averaged
    across all completed visits in period. Insufficient if < 2 visits."""
    sd, ed = iso_week_bounds(period_key)
    con = _con()
    visits = con.execute(
        "SELECT v.id, v.work_done_summary, "
        "       EXISTS(SELECT 1 FROM visit_readings r WHERE r.visit_id=v.id) AS has_r, "
        "       EXISTS(SELECT 1 FROM visit_photos  p WHERE p.visit_id=v.id) AS has_p "
        "  FROM maintenance_visits v "
        " WHERE v.assigned_tech_id=? AND v.completed_date IS NOT NULL "
        "   AND v.completed_date BETWEEN ? AND ?",
        (tech_id, sd, ed),
    ).fetchall()
    con.close()
    n = len(visits)
    if n < 2:
        return (None, n, "insufficient_data")
    total = 0.0
    for v in visits:
        score = 30.0
        if v["has_r"]: score += 30.0
        if v["has_p"]: score += 20.0
        summ = (v["work_done_summary"] or "").strip()
        if summ: score += 20.0
        total += min(score, 100.0)
    return (round(total / n, 2), n, None)


def compute_pm_completion(tech_id: int, period_key: str) -> tuple:
    """PM visits completed on or before scheduled_date / PM visits scheduled
    in period. Insufficient if PM count < 2."""
    sd, ed = iso_week_bounds(period_key)
    con = _con()
    pm_visits = con.execute(
        "SELECT scheduled_date, completed_date "
        "  FROM maintenance_visits "
        " WHERE assigned_tech_id=? AND visit_type IN ('PM','pm','preventive') "
        "   AND scheduled_date BETWEEN ? AND ?",
        (tech_id, sd, ed),
    ).fetchall()
    con.close()
    n = len(pm_visits)
    if n < 2:
        return (None, n, "insufficient_data")
    on_time = 0
    for v in pm_visits:
        sched = v["scheduled_date"]; comp = v["completed_date"]
        if comp and sched and comp <= sched:
            on_time += 1
    pct = (on_time / n) * 100.0
    return (round(pct, 2), n, None)


def compute_utilization(tech_id: int, period_key: str) -> tuple:
    """billable_minutes / clocked_minutes.
    FIXME: no time-clock table exists yet. We can compute billable minutes from
    visit start_time/end_time but have no independent clocked_minutes signal.
    Until the time-clock table ships, this returns 100% with sample_size = visit
    count. Do NOT treat as authoritative; flagged as informational-grade only.
    Replace with real clock-in/out data when the time-clock table ships."""
    sd, ed = iso_week_bounds(period_key)
    con = _con()
    n = con.execute(
        "SELECT COUNT(*) FROM maintenance_visits "
        " WHERE assigned_tech_id=? AND completed_date IS NOT NULL "
        "   AND completed_date BETWEEN ? AND ? "
        "   AND start_time IS NOT NULL AND end_time IS NOT NULL",
        (tech_id, sd, ed),
    ).fetchone()[0]
    con.close()
    if n < 2:
        return (None, n, "insufficient_data")
    # FIXME: replace with real clock-in/out when time-clock table ships.
    return (100.0, n, None)


def compute_sla_adherence(tech_id: int, period_key: str) -> tuple:
    """CM (corrective maintenance) visits where the tech started within 24h
    of scheduled_date / total CM visits. Insufficient if no CM in period."""
    from datetime import datetime as _dt, timedelta as _td
    sd, ed = iso_week_bounds(period_key)
    con = _con()
    cms = con.execute(
        "SELECT scheduled_date, start_time "
        "  FROM maintenance_visits "
        " WHERE assigned_tech_id=? AND visit_type IN ('CM','cm','corrective','callback','repair') "
        "   AND scheduled_date BETWEEN ? AND ?",
        (tech_id, sd, ed),
    ).fetchall()
    con.close()
    n = len(cms)
    if n == 0:
        return (None, 0, "insufficient_data")
    SLA_HOURS = 24
    in_sla = 0
    for v in cms:
        sched = v["scheduled_date"]; st = v["start_time"]
        if not st or not sched:
            continue
        try:
            sched_dt = _dt.fromisoformat(sched)
            st_dt = _dt.fromisoformat(st.replace("Z", "+00:00"))
            # Strip tz on sched if naive
            if sched_dt.tzinfo is None and st_dt.tzinfo is not None:
                sched_dt = sched_dt.replace(tzinfo=st_dt.tzinfo)
            elif st_dt.tzinfo is None and sched_dt.tzinfo is not None:
                st_dt = st_dt.replace(tzinfo=sched_dt.tzinfo)
            if (st_dt - sched_dt) <= _td(hours=SLA_HOURS):
                in_sla += 1
        except Exception:
            continue
    pct = (in_sla / n) * 100.0
    return (round(pct, 2), n, None)


def compute_safety_compliance(tech_id: int, period_key: str) -> tuple:
    """100% minus (count of safety_loto fs_exceptions opened by this tech in
    period / total completed visits in period * 100), floored at 0. ANY
    safety_loto exception forces 0%. sample_size surfaces the # of LOTO events
    so the UI can show the underlying count."""
    start, end = _kpi_period_bounds_iso(period_key)
    sd, ed = iso_week_bounds(period_key)
    con = _con()
    loto_n = con.execute(
        "SELECT COUNT(*) FROM fs_exceptions "
        " WHERE severity='safety_loto' AND opened_by_id=? AND opened_at BETWEEN ? AND ?",
        (tech_id, start, end),
    ).fetchone()[0]
    visit_n = con.execute(
        "SELECT COUNT(*) FROM maintenance_visits "
        " WHERE assigned_tech_id=? AND completed_date IS NOT NULL "
        "   AND completed_date BETWEEN ? AND ?",
        (tech_id, sd, ed),
    ).fetchone()[0]
    con.close()
    if visit_n == 0 and loto_n == 0:
        return (None, 0, "insufficient_data")
    if loto_n > 0:
        # Any safety event is full RED — spec is unambiguous.
        return (0.0, loto_n, None)
    return (100.0, visit_n, None)


def compute_first_time_fix(tech_id: int, period_key: str) -> tuple:
    """CM visits NOT linked to a callback (i.e. not pointed at by a later
    callback row) / total CM visits. Informational only."""
    sd, ed = iso_week_bounds(period_key)
    con = _con()
    cms = con.execute(
        "SELECT v.id FROM maintenance_visits v "
        " WHERE v.assigned_tech_id=? AND v.visit_type IN ('CM','cm','corrective','repair') "
        "   AND v.completed_date IS NOT NULL "
        "   AND v.completed_date BETWEEN ? AND ?",
        (tech_id, sd, ed),
    ).fetchall()
    n = len(cms)
    if n < 2:
        con.close()
        return (None, n, "insufficient_data")
    ftf = 0
    for v in cms:
        had_callback = con.execute(
            "SELECT 1 FROM maintenance_visits WHERE callback_of_visit_id=? LIMIT 1",
            (v["id"],),
        ).fetchone()
        if not had_callback:
            ftf += 1
    con.close()
    pct = (ftf / n) * 100.0
    return (round(pct, 2), n, None)


def compute_revenue_per_tech(tech_id: int, period_key: str) -> tuple:
    """SUM(invoice_line_items.line_total) for line_type='labor' AND
    tech_id=this_tech AND invoice was created in period. Informational only."""
    start, end = _kpi_period_bounds_iso(period_key)
    con = _con()
    row = con.execute(
        "SELECT COALESCE(SUM(li.line_total), 0) AS rev, COUNT(*) AS n "
        "  FROM invoice_line_items li "
        "  JOIN invoices inv ON inv.id = li.invoice_id "
        " WHERE li.line_type='labor' AND li.tech_id=? "
        "   AND inv.created_at BETWEEN ? AND ?",
        (tech_id, start, end),
    ).fetchone()
    con.close()
    rev = float(row["rev"] or 0)
    n = int(row["n"] or 0)
    if n == 0:
        return (0.0, 0, None)
    return (round(rev, 2), n, None)


# ────────────────────────────────────────────────────────────────────────────
# Band logic
# ────────────────────────────────────────────────────────────────────────────

def _get_active_threshold(con, kpi_key: str, tier: str):
    r = con.execute(
        "SELECT * FROM kpi_thresholds WHERE kpi_key=? AND tier=? AND active=1 "
        "ORDER BY effective_from DESC LIMIT 1",
        (kpi_key, tier),
    ).fetchone()
    if r:
        return dict(r)
    # fall back to level_1 if tier-specific not configured
    r = con.execute(
        "SELECT * FROM kpi_thresholds WHERE kpi_key=? AND tier='level_1' AND active=1 "
        "ORDER BY effective_from DESC LIMIT 1",
        (kpi_key,),
    ).fetchone()
    return dict(r) if r else None


def score_to_band(kpi_key: str, tier: str, raw_value, sample_size: int = 0) -> str:
    """Translate a raw score into 'green'|'amber'|'red'|'insufficient_data'
    using the active threshold row for (kpi_key, tier). Honors direction
    (higher_better vs lower_better). Insufficient if raw_value is None."""
    if raw_value is None:
        return "insufficient_data"
    con = _con()
    defn = con.execute("SELECT direction FROM kpi_definitions WHERE kpi_key=?",
                       (kpi_key,)).fetchone()
    thr = _get_active_threshold(con, kpi_key, tier)
    con.close()
    if not thr or not defn:
        return "insufficient_data"
    direction = defn["direction"]
    green = thr["green_threshold"]
    amber = thr["amber_band"]
    red_floor = thr["red_floor"]
    val = float(raw_value)
    if direction == "higher_better":
        if val < red_floor: return "red"
        if val >= green:    return "green"
        if val >= green - amber: return "amber"
        return "red"
    else:  # lower_better
        if val > red_floor: return "red"
        if val <= green:    return "green"
        if val <= green + amber: return "amber"
        return "red"


# ────────────────────────────────────────────────────────────────────────────
# Score writers
# ────────────────────────────────────────────────────────────────────────────

def record_kpi_score(tech_id: int, period_key: str, kpi_key: str,
                      raw_value, sample_size: int, band: str, tier: str) -> int:
    """Upsert one (tech, period, kpi) row. Chain-hashed against the prior
    row. recomputed_count auto-increments on re-write."""
    now = datetime.now(timezone.utc).isoformat()
    con = _con()
    # Closed-period guard
    prow = con.execute("SELECT status FROM kpi_periods WHERE period_key=?",
                       (period_key,)).fetchone()
    if prow and prow["status"] == "closed":
        con.close()
        return 0
    existing = con.execute(
        "SELECT id, recomputed_count FROM kpi_scores "
        " WHERE tech_id=? AND period_key=? AND kpi_key=?",
        (tech_id, period_key, kpi_key),
    ).fetchone()
    prior = _last_kpi_score_chain(con)
    row_for_hash = {
        "tech_id": tech_id, "period_key": period_key, "kpi_key": kpi_key,
        "raw_value": raw_value, "sample_size": sample_size,
        "band": band, "tier_at_computation": tier, "computed_at": now,
    }
    chash = _chain_hash_kpi_score(prior, row_for_hash)
    if existing:
        new_count = (existing["recomputed_count"] or 0) + 1
        con.execute(
            "UPDATE kpi_scores SET raw_value=?, sample_size=?, band=?, "
            "tier_at_computation=?, computed_at=?, recomputed_count=?, "
            "prior_chain_hash=?, chain_hash=? WHERE id=?",
            (raw_value, sample_size, band, tier, now, new_count,
             prior, chash, existing["id"]),
        )
        rid = existing["id"]
    else:
        cur = con.execute(
            "INSERT INTO kpi_scores (tech_id, period_key, kpi_key, raw_value, "
            "sample_size, band, tier_at_computation, computed_at, "
            "recomputed_count, prior_chain_hash, chain_hash) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?)",
            (tech_id, period_key, kpi_key, raw_value, sample_size, band,
             tier, now, prior, chash),
        )
        rid = cur.lastrowid
    con.commit(); con.close()
    return rid


def record_composite_score(tech_id: int, period_key: str,
                            components: dict, tier: str) -> dict:
    """components: dict of kpi_key -> {'raw_value':..., 'band':...} for the
    in-composite KPIs only. Weighted average using kpi_definitions weights.
    Safety RED forces composite RED. Insufficient if any in-composite KPI
    lacks a usable value AND we have <4 valid signals.

    Returns the row written: {composite_pct, band, forced_red_reason}."""
    import logging as _lg
    _logger = _lg.getLogger("kpi")
    now = datetime.now(timezone.utc).isoformat()
    con = _con()
    prow = con.execute("SELECT status FROM kpi_periods WHERE period_key=?",
                       (period_key,)).fetchone()
    if prow and prow["status"] == "closed":
        con.close()
        return {"composite_pct": None, "band": None,
                "forced_red_reason": "period_closed"}

    defs = con.execute(
        "SELECT kpi_key, composite_weight_pct, safety_critical, direction "
        "  FROM kpi_definitions WHERE in_composite=1 AND active=1"
    ).fetchall()

    forced_red_reason = None
    weighted_sum = 0.0
    weight_used = 0.0
    valid_signals = 0
    safety_red_triggered = False
    for d in defs:
        k = d["kpi_key"]
        w = float(d["composite_weight_pct"] or 0)
        comp = components.get(k) or {}
        raw = comp.get("raw_value")
        band = comp.get("band")
        if d["safety_critical"] and band == "red":
            safety_red_triggered = True
        if raw is None or band == "insufficient_data":
            continue
        # Normalize lower-better to a higher-is-better contribution.
        # For callback_rate we invert: contribution = max(0, 100 - raw).
        if d["direction"] == "lower_better":
            contribution = max(0.0, 100.0 - float(raw))
        else:
            contribution = max(0.0, min(100.0, float(raw)))
        weighted_sum += contribution * w
        weight_used += w
        valid_signals += 1

    if weight_used <= 0 or valid_signals < 2:
        composite_pct = None
        band = "insufficient_data"
    else:
        composite_pct = round(weighted_sum / weight_used, 2)
        # Composite band: green if >=85, amber if >=70, red below.
        if composite_pct >= 85: band = "green"
        elif composite_pct >= 70: band = "amber"
        else: band = "red"

    if safety_red_triggered:
        # Locked decision: Safety RED forces composite RED regardless.
        _logger.warning(
            f"kpi.safety_red_force: tech_id={tech_id} period={period_key} "
            f"composite={composite_pct} -> forced RED"
        )
        band = "red"
        forced_red_reason = "safety_red"

    prior = _last_kpi_composite_chain(con)
    row_for_hash = {
        "tech_id": tech_id, "period_key": period_key,
        "composite_pct": composite_pct, "band": band,
        "forced_red_reason": forced_red_reason,
        "tier_at_computation": tier, "computed_at": now,
    }
    chash = _chain_hash_kpi_composite(prior, row_for_hash)
    existing = con.execute(
        "SELECT id FROM kpi_composite_scores WHERE tech_id=? AND period_key=?",
        (tech_id, period_key),
    ).fetchone()
    if existing:
        con.execute(
            "UPDATE kpi_composite_scores SET composite_pct=?, band=?, "
            "forced_red_reason=?, tier_at_computation=?, computed_at=?, "
            "prior_chain_hash=?, chain_hash=? WHERE id=?",
            (composite_pct, band, forced_red_reason, tier, now,
             prior, chash, existing["id"]),
        )
    else:
        con.execute(
            "INSERT INTO kpi_composite_scores (tech_id, period_key, "
            "composite_pct, band, forced_red_reason, tier_at_computation, "
            "computed_at, prior_chain_hash, chain_hash) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (tech_id, period_key, composite_pct, band, forced_red_reason,
             tier, now, prior, chash),
        )
    con.commit(); con.close()
    return {"composite_pct": composite_pct, "band": band,
            "forced_red_reason": forced_red_reason}


# ────────────────────────────────────────────────────────────────────────────
# Recompute orchestrator
# ────────────────────────────────────────────────────────────────────────────

_KPI_COMPUTE_FNS = {
    "callback_rate":         compute_callback_rate,
    "documentation_quality": compute_documentation_quality,
    "pm_completion":         compute_pm_completion,
    "utilization":           compute_utilization,
    "sla_adherence":         compute_sla_adherence,
    "safety_compliance":     compute_safety_compliance,
    "first_time_fix":        compute_first_time_fix,
    "revenue_per_tech":      compute_revenue_per_tech,
}


def recompute_kpi_scores(tech_id: int, period_key: str,
                          triggered_by: str = "manual",
                          triggered_by_id: int = None) -> dict:
    """Recompute all 8 KPI helpers + composite for one (tech, period).
    Logs to kpi_recompute_log. Returns a dict with each kpi result + composite."""
    ensure_period_exists(period_key)
    tier = _kpi_tier_for_tech(tech_id)
    started = datetime.now(timezone.utc).isoformat()
    con = _con()
    cur = con.execute(
        "INSERT INTO kpi_recompute_log (triggered_by, triggered_by_id, scope, "
        "tech_id, period_key, started_at) VALUES (?, ?, 'one_tech', ?, ?, ?)",
        (triggered_by, triggered_by_id, tech_id, period_key, started),
    )
    log_id = cur.lastrowid
    con.commit(); con.close()

    error = None
    out = {}
    components_for_composite = {}
    rows_affected = 0
    try:
        for kpi_key, fn in _KPI_COMPUTE_FNS.items():
            raw, sample, marker = fn(tech_id, period_key)
            if marker == "insufficient_data":
                band = "insufficient_data"
            else:
                band = score_to_band(kpi_key, tier, raw, sample)
            rid = record_kpi_score(tech_id, period_key, kpi_key,
                                    raw, sample, band, tier)
            if rid:
                rows_affected += 1
            out[kpi_key] = {"raw_value": raw, "sample_size": sample, "band": band}
            components_for_composite[kpi_key] = {"raw_value": raw, "band": band}
        # Phase 7: include any manual-entry KPIs that already have values for
        # this (tech, period). recompute MUST NOT overwrite them.
        try:
            con_m = _con()
            manual_rows = con_m.execute(
                "SELECT s.kpi_key, s.raw_value, s.sample_size, s.band "
                "FROM kpi_scores s JOIN kpi_definitions d ON d.kpi_key=s.kpi_key "
                "WHERE s.tech_id=? AND s.period_key=? AND d.compute_kind='manual' "
                "AND d.active=1",
                (tech_id, period_key),
            ).fetchall()
            con_m.close()
            for mr in manual_rows:
                k = mr["kpi_key"]
                if k not in components_for_composite:
                    components_for_composite[k] = {
                        "raw_value": mr["raw_value"], "band": mr["band"],
                    }
                    out[k] = {"raw_value": mr["raw_value"],
                              "sample_size": mr["sample_size"],
                              "band": mr["band"], "compute_kind": "manual"}
        except Exception:
            pass
        composite = record_composite_score(tech_id, period_key,
                                            components_for_composite, tier)
        out["composite"] = composite
        rows_affected += 1
        # ── Coaching trigger ────────────────────────────────────────────────
        # Phase 3 escalation engine: generate kpi_flags from the freshly
        # written scores. Idempotent — re-runs won't dup open flags.
        try:
            new_flag_ids = _generate_kpi_flags_for_tech(tech_id, period_key)
            out["new_flag_ids"] = new_flag_ids
        except Exception as _fe:
            import logging as _lg
            _lg.getLogger("kpi").warning(f"flag gen failed: {_fe}")
            out["new_flag_ids"] = []
    except Exception as e:
        error = str(e)[:500]
        out["error"] = error

    ended = datetime.now(timezone.utc).isoformat()
    con = _con()
    con.execute(
        "UPDATE kpi_recompute_log SET ended_at=?, rows_affected=?, error_text=? "
        "WHERE id=?", (ended, rows_affected, error, log_id),
    )
    con.commit(); con.close()
    return out


def recompute_all_open_periods(triggered_by: str = "cron",
                                triggered_by_id: int = None) -> dict:
    """For every open period × every active technician, recompute scores."""
    con = _con()
    periods = [r["period_key"] for r in con.execute(
        "SELECT period_key FROM kpi_periods WHERE status='open'"
    ).fetchall()]
    techs = [r["id"] for r in con.execute(
        "SELECT id FROM technicians WHERE active=1"
    ).fetchall()]
    con.close()
    total = 0
    for pk in periods:
        for tid in techs:
            try:
                recompute_kpi_scores(tid, pk, triggered_by=triggered_by,
                                      triggered_by_id=triggered_by_id)
                total += 1
            except Exception:
                pass
    return {"periods": len(periods), "techs": len(techs), "runs": total}


# ────────────────────────────────────────────────────────────────────────────
# Read helpers for scorecards
# ────────────────────────────────────────────────────────────────────────────

def get_kpi_scorecard(tech_id: int, period_key: str) -> dict:
    """Return all current scores + composite for (tech, period)."""
    con = _con()
    scores = con.execute(
        "SELECT kpi_key, raw_value, sample_size, band, tier_at_computation, "
        "computed_at, recomputed_count FROM kpi_scores "
        " WHERE tech_id=? AND period_key=? ORDER BY kpi_key",
        (tech_id, period_key),
    ).fetchall()
    comp = con.execute(
        "SELECT composite_pct, band, forced_red_reason, tier_at_computation, "
        "computed_at FROM kpi_composite_scores "
        " WHERE tech_id=? AND period_key=?",
        (tech_id, period_key),
    ).fetchone()
    con.close()
    return {
        "tech_id": tech_id,
        "period_key": period_key,
        "kpis": {r["kpi_key"]: dict(r) for r in scores},
        "composite": dict(comp) if comp else None,
    }


def get_kpi_trend(tech_id: int, windows: int = 4) -> list:
    """Return last `windows` periods of composite scores for a tech, newest first."""
    con = _con()
    rows = con.execute(
        "SELECT period_key, composite_pct, band, forced_red_reason, computed_at "
        "  FROM kpi_composite_scores WHERE tech_id=? "
        " ORDER BY period_key DESC LIMIT ?", (tech_id, windows),
    ).fetchall()
    con.close()
    return [dict(r) for r in rows]


def get_team_scoreboard(period_key: str, tier_filter: str = None,
                         hub_id: int = None) -> list:
    """Return per-tech composite + KPI band map for one period."""
    con = _con()
    sql = (
        "SELECT t.id AS tech_id, t.name, t.role, c.composite_pct, c.band, "
        "       c.forced_red_reason, c.tier_at_computation "
        "  FROM technicians t "
        "  LEFT JOIN kpi_composite_scores c "
        "    ON c.tech_id=t.id AND c.period_key=? "
        " WHERE t.active=1"
    )
    args = [period_key]
    rows = con.execute(sql, args).fetchall()
    out = []
    for r in rows:
        tier = r["tier_at_computation"] or _KPI_TECH_ROLE_TO_TIER.get(
            (r["role"] or "tech"), "level_1")
        if tier_filter and tier != tier_filter:
            continue
        # Pull per-KPI bands
        ks = con.execute(
            "SELECT kpi_key, raw_value, band FROM kpi_scores "
            " WHERE tech_id=? AND period_key=?", (r["tech_id"], period_key),
        ).fetchall()
        out.append({
            "tech_id": r["tech_id"],
            "name": r["name"],
            "role": r["role"],
            "tier": tier,
            "composite_band": r["band"],
            "composite_pct": r["composite_pct"],
            "forced_red_reason": r["forced_red_reason"],
            "kpis": {k["kpi_key"]: {"band": k["band"], "raw_value": k["raw_value"]} for k in ks},
        })
    con.close()
    # Per spec: exclude techs with insufficient_data composite
    return [o for o in out if o["composite_band"] not in (None, "insufficient_data")]


def list_kpi_flags_for_tech(tech_id: int, status: str = None, limit: int = 50) -> list:
    con = _con()
    if status:
        rows = con.execute(
            "SELECT * FROM kpi_flags WHERE tech_id=? AND status=? "
            "ORDER BY created_at DESC LIMIT ?", (tech_id, status, limit),
        ).fetchall()
    else:
        rows = con.execute(
            "SELECT * FROM kpi_flags WHERE tech_id=? "
            "ORDER BY created_at DESC LIMIT ?", (tech_id, limit),
        ).fetchall()
    con.close()
    return [_dec_row("kpi_flags", r) for r in rows]


# ════════════════════════════════════════════════════════════════════════════
# Employee KPI Tracking Module — Phase 3 escalation engine
# Coaching-first ladder:
#   - 2 consecutive AMBER on same kpi      -> coaching_suggested
#   - 1 RED on any composite KPI            -> coaching_required
#   - 2 consecutive RED on same composite   -> written_warning_recommended
#   - ANY Safety RED                        -> immediate_escalation (bypasses ladder)
# Lifecycle: open -> acknowledged -> in_progress -> resolved (or overridden, terminal)
# No payroll automation — coaching output only.
# ════════════════════════════════════════════════════════════════════════════

_KPI_FLAG_SEVERITIES = (
    "coaching_suggested",
    "coaching_required",
    "written_warning_recommended",
    "immediate_escalation",
)
_KPI_FLAG_LIFECYCLE = ("open", "acknowledged", "in_progress", "resolved", "overridden")


def _prior_period_key(period_key: str) -> str:
    """Return the previous ISO-week key for a 'YYYY-WNN' string."""
    from datetime import date, timedelta
    try:
        yr_s, wk_s = period_key.split("-W")
        yr, wk = int(yr_s), int(wk_s)
        monday = date.fromisocalendar(yr, wk, 1)
        prior_monday = monday - timedelta(days=7)
        py, pw, _ = prior_monday.isocalendar()
        return f"{py:04d}-W{pw:02d}"
    except Exception:
        return period_key


def _kpi_flag_exists_open(con, tech_id: int, kpi_key, severity: str) -> bool:
    """Idempotency check: return True if an OPEN (non-terminal) flag of the
    same (tech, kpi_key, severity) already exists. Terminal states
    (resolved/overridden) do not block creation of a new flag."""
    if kpi_key is None:
        r = con.execute(
            "SELECT 1 FROM kpi_flags WHERE tech_id=? AND kpi_key IS NULL "
            "AND severity=? AND status IN ('open','acknowledged','in_progress') "
            "LIMIT 1", (tech_id, severity),
        ).fetchone()
    else:
        r = con.execute(
            "SELECT 1 FROM kpi_flags WHERE tech_id=? AND kpi_key=? "
            "AND severity=? AND status IN ('open','acknowledged','in_progress') "
            "LIMIT 1", (tech_id, kpi_key, severity),
        ).fetchone()
    return bool(r)


def _insert_kpi_flag(con, tech_id: int, period_key: str, kpi_key,
                     severity: str, reason: str) -> int:
    """Low-level insert with chain hashing + audit. Caller owns the connection."""
    now = datetime.now(timezone.utc).isoformat()
    prior = _last_kpi_flag_chain(con)
    row_for_hash = {
        "tech_id": tech_id, "period_key": period_key, "kpi_key": kpi_key,
        "severity": severity, "status": "open",
        "manager_id": None, "created_at": now,
    }
    chash = _chain_hash_kpi_flag(prior, row_for_hash)
    enc = _enc_dict("kpi_flags", {"reason": reason})
    cur = con.execute(
        "INSERT INTO kpi_flags (tech_id, period_key, kpi_key, severity, "
        "status, reason, created_at, prior_chain_hash, chain_hash) "
        "VALUES (?, ?, ?, ?, 'open', ?, ?, ?, ?)",
        (tech_id, period_key, kpi_key, severity, enc.get("reason"),
         now, prior, chash),
    )
    return int(cur.lastrowid)


def _generate_kpi_flags_for_tech(tech_id: int, period_key: str) -> list:
    """Phase 3 coaching trigger — invoked AFTER record_composite_score writes.
    Generates kpi_flags for the (tech, period) per the escalation ladder.
    Idempotent: existing open flags of same (tech, kpi, severity) are skipped.
    Returns list of newly-created flag_ids."""
    import logging as _lg
    _logger = _lg.getLogger("kpi")
    prior_pk = _prior_period_key(period_key)
    con = _con()
    try:
        # Pull current + prior scores by kpi_key.
        cur_rows = con.execute(
            "SELECT kpi_key, band, raw_value FROM kpi_scores "
            "WHERE tech_id=? AND period_key=?", (tech_id, period_key),
        ).fetchall()
        prior_rows = con.execute(
            "SELECT kpi_key, band FROM kpi_scores "
            "WHERE tech_id=? AND period_key=?", (tech_id, prior_pk),
        ).fetchall()
        cur_band = {r["kpi_key"]: r["band"] for r in cur_rows}
        prior_band = {r["kpi_key"]: r["band"] for r in prior_rows}
        # Which KPIs roll into the composite?
        defs = con.execute(
            "SELECT kpi_key, in_composite, safety_critical, display_name "
            "  FROM kpi_definitions WHERE active=1"
        ).fetchall()
        composite_keys = {d["kpi_key"] for d in defs if d["in_composite"]}
        safety_keys    = {d["kpi_key"] for d in defs if d["safety_critical"]}
        display = {d["kpi_key"]: d["display_name"] for d in defs}

        new_flag_ids = []
        audit_payloads = []
        for kpi_key, band in cur_band.items():
            pband = prior_band.get(kpi_key)
            # 1) Safety RED → immediate_escalation (bypasses ladder)
            if kpi_key in safety_keys and band == "red":
                if not _kpi_flag_exists_open(con, tech_id, kpi_key,
                                              "immediate_escalation"):
                    reason = (f"Safety-critical KPI '{display.get(kpi_key, kpi_key)}' "
                              f"is RED for period {period_key}. Immediate review required.")
                    fid = _insert_kpi_flag(con, tech_id, period_key, kpi_key,
                                            "immediate_escalation", reason)
                    new_flag_ids.append(fid)
                    audit_payloads.append((fid, "immediate_escalation", kpi_key))
                # Do NOT also generate coaching_required for the same safety RED —
                # immediate_escalation supersedes.
                continue

            # 2) Two consecutive REDs on a composite KPI → written_warning_recommended
            if (kpi_key in composite_keys and band == "red" and pband == "red"):
                if not _kpi_flag_exists_open(con, tech_id, kpi_key,
                                              "written_warning_recommended"):
                    reason = (f"KPI '{display.get(kpi_key, kpi_key)}' has been "
                              f"RED for two consecutive periods ({prior_pk}, {period_key}).")
                    fid = _insert_kpi_flag(con, tech_id, period_key, kpi_key,
                                            "written_warning_recommended", reason)
                    new_flag_ids.append(fid)
                    audit_payloads.append((fid, "written_warning_recommended", kpi_key))
                    # Phase 6 hook: auto-create a DRAFT PIP. Never auto-activates.
                    try:
                        suggest_pip_for_flag(fid)
                    except Exception:
                        pass
                continue

            # 3) Current RED on a composite KPI → coaching_required
            if kpi_key in composite_keys and band == "red":
                if not _kpi_flag_exists_open(con, tech_id, kpi_key,
                                              "coaching_required"):
                    reason = (f"KPI '{display.get(kpi_key, kpi_key)}' is RED for "
                              f"period {period_key}. Coaching required.")
                    fid = _insert_kpi_flag(con, tech_id, period_key, kpi_key,
                                            "coaching_required", reason)
                    new_flag_ids.append(fid)
                    audit_payloads.append((fid, "coaching_required", kpi_key))
                continue

            # 4) Two consecutive AMBER → coaching_suggested
            if band == "amber" and pband == "amber":
                if not _kpi_flag_exists_open(con, tech_id, kpi_key,
                                              "coaching_suggested"):
                    reason = (f"KPI '{display.get(kpi_key, kpi_key)}' has been "
                              f"AMBER for two consecutive periods ({prior_pk}, {period_key}).")
                    fid = _insert_kpi_flag(con, tech_id, period_key, kpi_key,
                                            "coaching_suggested", reason)
                    new_flag_ids.append(fid)
                    audit_payloads.append((fid, "coaching_suggested", kpi_key))

        con.commit()
    finally:
        con.close()

    # Emit one audit row per new flag (out of band so the chain isn't held).
    for fid, severity, kpi_key in audit_payloads:
        try:
            log_audit(
                actor_type="system",
                actor_id=None,
                actor_label="kpi-engine",
                actor_role="system",
                action="kpi.flag_generated",
                target_type="kpi_flag",
                target_id=fid,
                target_label=f"{severity}/{kpi_key or '-'}",
                after_value={
                    "tech_id": tech_id, "period_key": period_key,
                    "kpi_key": kpi_key, "severity": severity,
                },
            )
        except Exception as _ae:
            _logger.warning(f"kpi.flag_generated audit failed: {_ae}")

    if new_flag_ids:
        _logger.info(
            f"kpi.flag_generated: tech_id={tech_id} period={period_key} "
            f"new_flags={new_flag_ids}"
        )
    return new_flag_ids


# ── Flag lifecycle transitions ──────────────────────────────────────────────

def _rehash_kpi_flag(con, flag_id: int):
    """Recompute chain_hash for a kpi_flags row after an UPDATE. The new
    prior_chain_hash points to the previous tail of the kpi_flags chain."""
    row = con.execute("SELECT * FROM kpi_flags WHERE id=?",
                      (flag_id,)).fetchone()
    if not row:
        return
    prior = _last_kpi_flag_chain(con)
    chash = _chain_hash_kpi_flag(prior, dict(row))
    con.execute(
        "UPDATE kpi_flags SET prior_chain_hash=?, chain_hash=? WHERE id=?",
        (prior, chash, flag_id),
    )


def _get_kpi_flag_or_404(flag_id: int) -> dict:
    con = _con()
    r = con.execute("SELECT * FROM kpi_flags WHERE id=?", (flag_id,)).fetchone()
    con.close()
    if not r:
        raise ValueError("flag_not_found")
    return _dec_row("kpi_flags", r)


def _append_encrypted_note(existing: str, new_note: str, manager_id: int) -> str:
    """Append a timestamped manager note to an existing notes blob (which may
    itself be ciphertext from a prior call). Decryption is best-effort; if the
    blob isn't decryptable, we treat it as opaque and concatenate."""
    ts = datetime.now(timezone.utc).isoformat()
    prefix = f"[{ts} mgr={manager_id}] "
    new_line = prefix + (new_note or "").strip()
    if not existing:
        return new_line
    try:
        existing_plain = _dec(existing)
    except Exception:
        existing_plain = ""
    return (existing_plain + "\n" + new_line).strip()


def acknowledge_kpi_flag(flag_id: int, manager_id: int) -> dict:
    """Move flag to 'acknowledged' state. Chain rebuild + audit."""
    flag = _get_kpi_flag_or_404(flag_id)
    if flag["status"] in ("resolved", "overridden"):
        raise ValueError("flag_already_terminal")
    now = datetime.now(timezone.utc).isoformat()
    con = _con()
    try:
        con.execute(
            "UPDATE kpi_flags SET status='acknowledged', acknowledged_at=?, "
            "manager_id=? WHERE id=?", (now, manager_id, flag_id),
        )
        _rehash_kpi_flag(con, flag_id)
        con.commit()
    finally:
        con.close()
    log_audit(actor_type="admin", actor_id=manager_id,
              actor_role="admin", action="kpi.flag_acknowledged",
              target_type="kpi_flag", target_id=flag_id,
              before_value={"status": flag["status"]},
              after_value={"status": "acknowledged"})
    return _get_kpi_flag_or_404(flag_id)


def start_kpi_flag_work(flag_id: int, manager_id: int, notes: str) -> dict:
    """Move flag to 'in_progress' state. Notes appended (encrypted)."""
    flag = _get_kpi_flag_or_404(flag_id)
    if flag["status"] in ("resolved", "overridden"):
        raise ValueError("flag_already_terminal")
    if not (notes or "").strip():
        raise ValueError("notes_required")
    if len(notes) > 2000:
        raise ValueError("notes_too_long")
    con = _con()
    try:
        row = con.execute("SELECT resolution_notes FROM kpi_flags WHERE id=?",
                          (flag_id,)).fetchone()
        existing = row["resolution_notes"] if row else None
        combined = _append_encrypted_note(existing, notes, manager_id)
        enc = _enc_dict("kpi_flags", {"resolution_notes": combined})
        ack = flag.get("acknowledged_at") or datetime.now(timezone.utc).isoformat()
        con.execute(
            "UPDATE kpi_flags SET status='in_progress', acknowledged_at=?, "
            "manager_id=?, resolution_notes=? WHERE id=?",
            (ack, manager_id, enc["resolution_notes"], flag_id),
        )
        _rehash_kpi_flag(con, flag_id)
        con.commit()
    finally:
        con.close()
    log_audit(actor_type="admin", actor_id=manager_id,
              actor_role="admin", action="kpi.flag_in_progress",
              target_type="kpi_flag", target_id=flag_id,
              before_value={"status": flag["status"]},
              after_value={"status": "in_progress",
                           "notes_len": len(notes)})
    return _get_kpi_flag_or_404(flag_id)


def resolve_kpi_flag(flag_id: int, manager_id: int,
                      resolution_notes: str) -> dict:
    """Resolve a flag. Resolution notes mandatory + encrypted + appended."""
    flag = _get_kpi_flag_or_404(flag_id)
    if flag["status"] in ("resolved", "overridden"):
        raise ValueError("flag_already_terminal")
    if not (resolution_notes or "").strip():
        raise ValueError("resolution_notes_required")
    if len(resolution_notes) > 2000:
        raise ValueError("resolution_notes_too_long")
    now = datetime.now(timezone.utc).isoformat()
    con = _con()
    try:
        row = con.execute("SELECT resolution_notes FROM kpi_flags WHERE id=?",
                          (flag_id,)).fetchone()
        existing = row["resolution_notes"] if row else None
        combined = _append_encrypted_note(existing, resolution_notes, manager_id)
        enc = _enc_dict("kpi_flags", {"resolution_notes": combined})
        con.execute(
            "UPDATE kpi_flags SET status='resolved', resolved_at=?, "
            "manager_id=?, resolution_notes=? WHERE id=?",
            (now, manager_id, enc["resolution_notes"], flag_id),
        )
        _rehash_kpi_flag(con, flag_id)
        con.commit()
    finally:
        con.close()
    log_audit(actor_type="admin", actor_id=manager_id,
              actor_role="admin", action="kpi.flag_resolved",
              target_type="kpi_flag", target_id=flag_id,
              before_value={"status": flag["status"]},
              after_value={"status": "resolved",
                           "notes_len": len(resolution_notes)})
    return _get_kpi_flag_or_404(flag_id)


def override_kpi_flag(flag_id: int, manager_id: int,
                       override_reason: str) -> dict:
    """Manager override — REQUIRES non-empty reason. Original flag is never
    deleted; only its status flips to 'overridden' with the encrypted reason
    persisted. Recipient (the tech) sees the flag was overridden but NOT the
    reason text (UI redacts to a fixed string)."""
    if not (override_reason or "").strip():
        raise ValueError("override_reason_required")
    if len(override_reason) > 1000:
        raise ValueError("override_reason_too_long")
    flag = _get_kpi_flag_or_404(flag_id)
    if flag["status"] == "overridden":
        raise ValueError("flag_already_overridden")
    if flag["status"] == "resolved":
        # Overriding a resolved flag would erase the resolution — disallow.
        raise ValueError("flag_already_resolved")
    now = datetime.now(timezone.utc).isoformat()
    enc = _enc_dict("kpi_flags",
                     {"override_reason": override_reason.strip()})
    con = _con()
    try:
        con.execute(
            "UPDATE kpi_flags SET status='overridden', override_reason=?, "
            "manager_id=?, resolved_at=? WHERE id=?",
            (enc["override_reason"], manager_id, now, flag_id),
        )
        _rehash_kpi_flag(con, flag_id)
        con.commit()
    finally:
        con.close()
    log_audit(actor_type="admin", actor_id=manager_id,
              actor_role="admin", action="kpi.flag_overridden",
              target_type="kpi_flag", target_id=flag_id,
              before_value={"status": flag["status"]},
              after_value={"status": "overridden",
                           "reason_len": len(override_reason)})
    return _get_kpi_flag_or_404(flag_id)


def list_kpi_flags(filters: dict = None) -> list:
    """List flags with optional filters. Filters keys: tech_id, severity,
    status, period_key, hub_id, date_from, date_to, limit (default 100),
    offset (default 0). Returns decrypted rows."""
    filters = filters or {}
    where = []
    args = []
    if filters.get("tech_id") is not None:
        where.append("f.tech_id=?"); args.append(int(filters["tech_id"]))
    if filters.get("severity"):
        where.append("f.severity=?"); args.append(filters["severity"])
    if filters.get("status"):
        where.append("f.status=?"); args.append(filters["status"])
    if filters.get("period_key"):
        where.append("f.period_key=?"); args.append(filters["period_key"])
    if filters.get("hub_id") is not None:
        where.append("t.hub_id=?"); args.append(int(filters["hub_id"]))
    if filters.get("date_from"):
        where.append("f.created_at >= ?"); args.append(filters["date_from"])
    if filters.get("date_to"):
        where.append("f.created_at <= ?"); args.append(filters["date_to"])
    sql = ("SELECT f.*, t.name AS tech_name, t.role AS tech_role "
           "  FROM kpi_flags f "
           "  LEFT JOIN technicians t ON t.id=f.tech_id")
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY f.created_at DESC LIMIT ? OFFSET ?"
    args.append(int(filters.get("limit") or 100))
    args.append(int(filters.get("offset") or 0))
    con = _con()
    rows = con.execute(sql, args).fetchall()
    con.close()
    out = []
    for r in rows:
        d = _dec_row("kpi_flags", r)
        d["tech_name"] = r["tech_name"]
        d["tech_role"] = r["tech_role"]
        out.append(d)
    return out


def count_open_flags_by_severity(hub_id: int = None) -> dict:
    """Return open-flag counts grouped by severity (Ops Manager dashboard
    tiles). 'Open' = status in (open, acknowledged, in_progress)."""
    sql = ("SELECT f.severity, COUNT(*) AS n FROM kpi_flags f "
           " LEFT JOIN technicians t ON t.id=f.tech_id "
           " WHERE f.status IN ('open','acknowledged','in_progress')")
    args = []
    if hub_id is not None:
        sql += " AND t.hub_id=?"; args.append(int(hub_id))
    sql += " GROUP BY f.severity"
    con = _con()
    rows = con.execute(sql, args).fetchall()
    con.close()
    out = {s: 0 for s in _KPI_FLAG_SEVERITIES}
    for r in rows:
        out[r["severity"]] = r["n"]
    return out


def get_kpi_flag_detail(flag_id: int) -> dict:
    """Return one flag with tech context + recent audit trail."""
    con = _con()
    r = con.execute(
        "SELECT f.*, t.name AS tech_name, t.role AS tech_role "
        "  FROM kpi_flags f LEFT JOIN technicians t ON t.id=f.tech_id "
        " WHERE f.id=?", (flag_id,),
    ).fetchone()
    if not r:
        con.close()
        return None
    d = _dec_row("kpi_flags", r)
    d["tech_name"] = r["tech_name"]
    d["tech_role"] = r["tech_role"]
    audit_rows = con.execute(
        "SELECT id, actor_label, actor_role, action, created_at "
        "  FROM audit_log WHERE target_type='kpi_flag' AND target_id=? "
        " ORDER BY id DESC LIMIT 50", (flag_id,),
    ).fetchall()
    con.close()
    d["audit"] = [dict(a) for a in audit_rows]
    return d


# ════════════════════════════════════════════════════════════════════════════
# KPI Notes Module (Phase 5)
# Five note kinds in one table, discriminated by note_kind.
# Bodies encrypted via _PII_RAND. Chain-hash on tech_response notes only.
# ════════════════════════════════════════════════════════════════════════════

_KPI_NOTE_KINDS = (
    "coaching", "tech_response", "recognition", "team_period", "score_annotation",
)


def _chain_hash_kpi_note(prior_hash: str, row: dict) -> str:
    import hashlib, json as _j
    keys = ("note_kind", "tech_id", "period_key", "flag_id", "score_id",
            "author_id", "author_kind", "visibility", "created_at")
    payload = {k: row.get(k) for k in keys}
    body = (prior_hash or "") + _j.dumps(payload, sort_keys=True, default=str)
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def _last_kpi_note_chain(con=None) -> str:
    own = con is None
    if own: con = _con()
    r = con.execute("SELECT chain_hash FROM kpi_notes "
                    "WHERE note_kind='tech_response' AND chain_hash IS NOT NULL "
                    "ORDER BY id DESC LIMIT 1").fetchone()
    if own: con.close()
    return (r["chain_hash"] if r else "") or ""


def _kpi_note_default_visibility(note_kind: str) -> str:
    return {
        "coaching":          "admins_and_subject_tech",
        "tech_response":     "admins_and_subject_tech",
        "recognition":       "admins_and_subject_tech",
        "team_period":       "admins_and_all_techs",
        "score_annotation":  "admins_and_subject_tech",
    }.get(note_kind, "admins_only")


def _kpi_note_default_lock_hours(note_kind: str):
    return {
        "coaching":          24,
        "score_annotation":  24,
    }.get(note_kind)


def create_kpi_note(note_kind: str, tech_id, period_key, flag_id, score_id,
                    author_id: int, author_kind: str, body: str,
                    visibility: str = None, lock_hours=None,
                    hub_id: int = 1) -> dict:
    if note_kind not in _KPI_NOTE_KINDS:
        raise ValueError("invalid_note_kind")
    if author_kind not in ("admin", "tech"):
        raise ValueError("invalid_author_kind")
    body = (body or "").strip()
    if not body:
        raise ValueError("body_required")
    if len(body) > 5000:
        raise ValueError("body_too_long")
    if note_kind in ("coaching", "recognition") and not tech_id:
        raise ValueError("tech_id_required")
    if note_kind == "tech_response":
        if not flag_id: raise ValueError("flag_id_required")
        if author_kind != "tech": raise ValueError("must_be_tech_author")
    if note_kind == "team_period" and not period_key:
        raise ValueError("period_key_required")
    if note_kind == "score_annotation" and not score_id:
        raise ValueError("score_id_required")

    visibility = visibility or _kpi_note_default_visibility(note_kind)
    if lock_hours is None:
        lock_hours = _kpi_note_default_lock_hours(note_kind)
    now_dt = datetime.now(timezone.utc)
    now = now_dt.isoformat()
    locked_after = None
    if lock_hours:
        locked_after = (now_dt + timedelta(hours=int(lock_hours))).isoformat()

    chain_hash = None
    prior = None
    if note_kind == "tech_response":
        con0 = _con()
        prior = _last_kpi_note_chain(con0)
        con0.close()
        row_for_hash = {
            "note_kind": note_kind, "tech_id": tech_id, "period_key": period_key,
            "flag_id": flag_id, "score_id": score_id, "author_id": author_id,
            "author_kind": author_kind, "visibility": visibility,
            "created_at": now,
        }
        chain_hash = _chain_hash_kpi_note(prior, row_for_hash)

    enc = _enc_dict("kpi_notes", {"body": body})
    con = _con()
    cur = con.execute(
        "INSERT INTO kpi_notes (note_kind, tech_id, period_key, flag_id, score_id, "
        "author_id, author_kind, body, visibility, status, created_at, "
        "locked_after, prior_chain_hash, chain_hash, hub_id) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?, ?, ?, ?)",
        (note_kind, tech_id, period_key, flag_id, score_id,
         author_id, author_kind, enc["body"], visibility, now,
         locked_after, prior, chain_hash, hub_id),
    )
    nid = cur.lastrowid
    con.commit(); con.close()
    return get_kpi_note(nid)


def get_kpi_note(note_id: int) -> dict:
    con = _con()
    r = con.execute("SELECT * FROM kpi_notes WHERE id=?", (note_id,)).fetchone()
    con.close()
    if not r: return None
    return _dec_row("kpi_notes", r)


def update_kpi_note(note_id: int, author_id: int, body: str,
                    mutability_check: bool = True) -> dict:
    body = (body or "").strip()
    if not body: raise ValueError("body_required")
    if len(body) > 5000: raise ValueError("body_too_long")
    con = _con()
    r = con.execute("SELECT * FROM kpi_notes WHERE id=?", (note_id,)).fetchone()
    if not r:
        con.close()
        raise ValueError("note_not_found")
    if r["status"] == "archived":
        con.close()
        raise ValueError("note_archived")
    if mutability_check:
        if r["note_kind"] == "recognition":
            con.close()
            raise ValueError("recognition_immutable")
        if r["locked_after"]:
            try:
                if datetime.now(timezone.utc) > datetime.fromisoformat(r["locked_after"]):
                    con.close()
                    raise ValueError("note_locked")
            except ValueError:
                raise
            except Exception:
                pass
        if r["note_kind"] == "tech_response" and r["flag_id"]:
            fr = con.execute("SELECT status FROM kpi_flags WHERE id=?",
                             (r["flag_id"],)).fetchone()
            if fr and fr["status"] in ("resolved", "overridden"):
                con.close()
                raise ValueError("parent_flag_closed")
    now = datetime.now(timezone.utc).isoformat()
    enc = _enc_dict("kpi_notes", {"body": body})
    con.execute("UPDATE kpi_notes SET body=?, updated_at=?, status='edited' WHERE id=?",
                (enc["body"], now, note_id))
    con.commit(); con.close()
    return get_kpi_note(note_id)


def archive_kpi_note(note_id: int, archiver_id: int) -> dict:
    con = _con()
    r = con.execute("SELECT id FROM kpi_notes WHERE id=?", (note_id,)).fetchone()
    if not r:
        con.close()
        raise ValueError("note_not_found")
    con.execute("UPDATE kpi_notes SET status='archived' WHERE id=?", (note_id,))
    con.commit(); con.close()
    return get_kpi_note(note_id)


def list_kpi_notes_for_tech(tech_id: int, note_kinds=None, period_key=None,
                            limit: int = 50) -> list:
    sql = "SELECT * FROM kpi_notes WHERE tech_id=? AND status!='archived'"
    args = [tech_id]
    if note_kinds:
        ph = ",".join(["?"] * len(note_kinds))
        sql += f" AND note_kind IN ({ph})"
        args.extend(note_kinds)
    if period_key:
        sql += " AND period_key=?"; args.append(period_key)
    sql += " ORDER BY created_at DESC LIMIT ?"
    args.append(int(limit))
    con = _con()
    rows = con.execute(sql, args).fetchall()
    con.close()
    return [_dec_row("kpi_notes", r) for r in rows]


def list_kpi_notes_for_flag(flag_id: int) -> list:
    con = _con()
    rows = con.execute(
        "SELECT * FROM kpi_notes WHERE flag_id=? AND status!='archived' "
        "ORDER BY created_at ASC", (flag_id,),
    ).fetchall()
    con.close()
    return [_dec_row("kpi_notes", r) for r in rows]


def list_kpi_notes_for_score(score_id: int) -> list:
    con = _con()
    rows = con.execute(
        "SELECT * FROM kpi_notes WHERE score_id=? AND status!='archived' "
        "ORDER BY created_at ASC", (score_id,),
    ).fetchall()
    con.close()
    return [_dec_row("kpi_notes", r) for r in rows]


def list_kpi_notes_for_period(period_key: str, note_kinds=None) -> list:
    if not note_kinds:
        note_kinds = ["team_period"]
    ph = ",".join(["?"] * len(note_kinds))
    sql = (f"SELECT * FROM kpi_notes WHERE period_key=? AND status!='archived' "
           f"AND note_kind IN ({ph}) ORDER BY created_at DESC")
    con = _con()
    rows = con.execute(sql, [period_key] + list(note_kinds)).fetchall()
    con.close()
    return [_dec_row("kpi_notes", r) for r in rows]


def count_open_tech_responses(tech_id: int) -> int:
    con = _con()
    r = con.execute(
        "SELECT COUNT(*) FROM kpi_notes WHERE tech_id=? "
        "AND note_kind='tech_response' AND status!='archived'", (tech_id,),
    ).fetchone()
    con.close()
    return int(r[0]) if r else 0


def list_kpi_notes_filtered(tech_id=None, note_kind=None, period_key=None,
                            flag_id=None, score_id=None,
                            page: int = 1, limit: int = 50) -> list:
    sql = "SELECT * FROM kpi_notes WHERE status!='archived'"
    args = []
    if tech_id:    sql += " AND tech_id=?";   args.append(tech_id)
    if note_kind:  sql += " AND note_kind=?"; args.append(note_kind)
    if period_key: sql += " AND period_key=?";args.append(period_key)
    if flag_id:    sql += " AND flag_id=?";   args.append(flag_id)
    if score_id:   sql += " AND score_id=?";  args.append(score_id)
    sql += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
    args.extend([int(limit), int(max(0, (page - 1) * limit))])
    con = _con()
    rows = con.execute(sql, args).fetchall()
    con.close()
    return [_dec_row("kpi_notes", r) for r in rows]


def _can_read_kpi_note(note: dict, viewer_id: int, viewer_kind: str,
                       viewer_role: str = None) -> bool:
    if not note: return False
    nk = note.get("note_kind")
    vis = note.get("visibility")
    if viewer_kind == "admin":
        if nk == "team_period":
            return True
        if nk == "coaching":
            if viewer_role in ("super_admin", "supervisor_admin"):
                return True
            if note.get("author_kind") == "admin" and note.get("author_id") == viewer_id:
                return True
            return False
        if nk == "tech_response":
            return viewer_role in ("super_admin", "supervisor_admin")
        if nk == "recognition":
            return viewer_role in ("super_admin", "supervisor_admin",
                                    "hr_admin", "system_admin")
        if nk == "score_annotation":
            return viewer_role in ("super_admin", "supervisor_admin",
                                    "hr_admin", "system_admin")
        return False
    if viewer_kind == "tech":
        if nk == "team_period":
            try:
                con = _con()
                r = con.execute(
                    "SELECT 1 FROM kpi_scores WHERE tech_id=? AND period_key=? LIMIT 1",
                    (viewer_id, note.get("period_key")),
                ).fetchone()
                con.close()
                return bool(r)
            except Exception:
                return False
        if nk == "tech_response":
            return note.get("author_id") == viewer_id and note.get("author_kind") == "tech"
        if note.get("tech_id") == viewer_id and vis in (
            "admins_and_subject_tech", "admins_and_all_techs",
        ):
            return True
        return False
    return False


# ════════════════════════════════════════════════════════════════════════════
# KPI Goals + PIPs (Phase 6)
# ════════════════════════════════════════════════════════════════════════════

def _chain_hash_kpi_goal(prior_hash: str, row: dict) -> str:
    import hashlib, json as _j
    keys = ("goal_kind", "tech_id", "status", "start_date", "target_date",
            "opened_by_id", "opened_at", "activated_at", "closed_at",
            "pip_severity", "hr_acknowledged_at")
    payload = {k: row.get(k) for k in keys}
    body = (prior_hash or "") + _j.dumps(payload, sort_keys=True, default=str)
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def _chain_hash_kpi_goal_checkin(prior_hash: str, row: dict) -> str:
    import hashlib, json as _j
    keys = ("goal_id", "checkin_date", "status", "author_id", "created_at")
    payload = {k: row.get(k) for k in keys}
    body = (prior_hash or "") + _j.dumps(payload, sort_keys=True, default=str)
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def _last_kpi_goal_chain(con=None) -> str:
    own = con is None
    if own: con = _con()
    r = con.execute("SELECT chain_hash FROM kpi_goals "
                    "WHERE chain_hash IS NOT NULL ORDER BY id DESC LIMIT 1").fetchone()
    if own: con.close()
    return (r["chain_hash"] if r else "") or ""


def _last_kpi_goal_checkin_chain(con=None) -> str:
    own = con is None
    if own: con = _con()
    r = con.execute("SELECT chain_hash FROM kpi_goal_checkins "
                    "WHERE chain_hash IS NOT NULL ORDER BY id DESC LIMIT 1").fetchone()
    if own: con.close()
    return (r["chain_hash"] if r else "") or ""


def create_kpi_goal(goal_kind: str, tech_id: int, title: str, description: str,
                    start_date: str, target_date: str, opened_by_id: int,
                    related_kpi_keys: str = None, action_items=None,
                    pip_severity=None, pip_review_dates=None,
                    triggering_flag_id=None, hub_id: int = 1) -> dict:
    import json as _j
    if goal_kind not in ("development_goal", "pip"):
        raise ValueError("invalid_goal_kind")
    if not (title or "").strip(): raise ValueError("title_required")
    if not (description or "").strip(): raise ValueError("description_required")
    if not start_date or not target_date: raise ValueError("dates_required")
    if goal_kind == "pip" and pip_severity not in ("standard", "final_warning"):
        raise ValueError("pip_severity_required")

    initial_status = "active" if goal_kind == "development_goal" else "draft"
    now = datetime.now(timezone.utc).isoformat()
    activated_at = now if initial_status == "active" else None

    action_items_json = None
    if action_items is not None:
        normalized = []
        for it in action_items:
            if isinstance(it, str):
                normalized.append({"text": it, "done": False, "completed_at": None})
            elif isinstance(it, dict):
                normalized.append({
                    "text": str(it.get("text", "")),
                    "done": bool(it.get("done", False)),
                    "completed_at": it.get("completed_at"),
                })
        action_items_json = _j.dumps(normalized)

    pip_review_dates_json = None
    if pip_review_dates:
        pip_review_dates_json = _j.dumps(list(pip_review_dates))

    chain_hash = None; prior = None
    if goal_kind == "pip":
        prior = _last_kpi_goal_chain()
        row_for_hash = {
            "goal_kind": goal_kind, "tech_id": tech_id, "status": initial_status,
            "start_date": start_date, "target_date": target_date,
            "opened_by_id": opened_by_id, "opened_at": now,
            "activated_at": activated_at, "closed_at": None,
            "pip_severity": pip_severity, "hr_acknowledged_at": None,
        }
        chain_hash = _chain_hash_kpi_goal(prior, row_for_hash)

    enc = _enc_dict("kpi_goals", {
        "title": title.strip(),
        "description": description.strip(),
        "action_items_json": action_items_json,
    })

    con = _con()
    cur = con.execute(
        "INSERT INTO kpi_goals (goal_kind, tech_id, title, description, "
        "start_date, target_date, status, action_items_json, related_kpi_keys, "
        "triggering_flag_id, opened_by_id, opened_at, activated_at, "
        "pip_review_dates, pip_severity, prior_chain_hash, chain_hash, hub_id) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (goal_kind, tech_id, enc["title"], enc["description"],
         start_date, target_date, initial_status, enc.get("action_items_json"),
         related_kpi_keys, triggering_flag_id, opened_by_id, now, activated_at,
         pip_review_dates_json, pip_severity, prior, chain_hash, hub_id),
    )
    gid = cur.lastrowid
    con.commit(); con.close()
    return get_kpi_goal(gid)


def get_kpi_goal(goal_id: int) -> dict:
    import json as _j
    con = _con()
    r = con.execute("SELECT * FROM kpi_goals WHERE id=?", (goal_id,)).fetchone()
    con.close()
    if not r: return None
    d = _dec_row("kpi_goals", r)
    if d.get("action_items_json"):
        try: d["action_items"] = _j.loads(d["action_items_json"])
        except Exception: d["action_items"] = []
    else:
        d["action_items"] = []
    if d.get("pip_review_dates"):
        try: d["pip_review_dates_list"] = _j.loads(d["pip_review_dates"])
        except Exception: d["pip_review_dates_list"] = []
    return d


def hr_acknowledge_pip(goal_id: int, hr_actor_id: int) -> dict:
    con = _con()
    r = con.execute("SELECT * FROM kpi_goals WHERE id=?", (goal_id,)).fetchone()
    if not r:
        con.close(); raise ValueError("goal_not_found")
    if r["goal_kind"] != "pip":
        con.close(); raise ValueError("not_a_pip")
    if r["hr_acknowledged_at"]:
        con.close(); raise ValueError("already_acknowledged")
    now = datetime.now(timezone.utc).isoformat()
    con.execute("UPDATE kpi_goals SET hr_acknowledged_at=? WHERE id=?",
                (now, goal_id))
    con.commit(); con.close()
    return get_kpi_goal(goal_id)


def activate_pip(goal_id: int, actor_id: int) -> dict:
    con = _con()
    r = con.execute("SELECT * FROM kpi_goals WHERE id=?", (goal_id,)).fetchone()
    if not r:
        con.close(); raise ValueError("goal_not_found")
    if r["goal_kind"] != "pip":
        con.close(); raise ValueError("not_a_pip")
    if r["status"] != "draft":
        con.close(); raise ValueError("not_draft")
    if not r["hr_acknowledged_at"]:
        con.close(); raise ValueError("hr_ack_required")
    now = datetime.now(timezone.utc).isoformat()
    prior = _last_kpi_goal_chain(con)
    row_for_hash = {
        "goal_kind": "pip", "tech_id": r["tech_id"], "status": "active",
        "start_date": r["start_date"], "target_date": r["target_date"],
        "opened_by_id": r["opened_by_id"], "opened_at": r["opened_at"],
        "activated_at": now, "closed_at": None,
        "pip_severity": r["pip_severity"],
        "hr_acknowledged_at": r["hr_acknowledged_at"],
    }
    chash = _chain_hash_kpi_goal(prior, row_for_hash)
    con.execute(
        "UPDATE kpi_goals SET status='active', activated_at=?, "
        "prior_chain_hash=?, chain_hash=? WHERE id=?",
        (now, prior, chash, goal_id),
    )
    con.commit(); con.close()
    return get_kpi_goal(goal_id)


def add_goal_checkin(goal_id: int, checkin_date: str, status: str,
                     notes: str, author_id: int) -> dict:
    if status not in ("on_track", "at_risk", "off_track", "met"):
        raise ValueError("invalid_status")
    if not (notes or "").strip():
        raise ValueError("notes_required")
    if len(notes) > 5000:
        raise ValueError("notes_too_long")
    con = _con()
    gr = con.execute("SELECT id, status FROM kpi_goals WHERE id=?",
                     (goal_id,)).fetchone()
    if not gr:
        con.close(); raise ValueError("goal_not_found")
    if gr["status"] in ("met", "not_met", "withdrawn"):
        con.close(); raise ValueError("goal_closed")
    now = datetime.now(timezone.utc).isoformat()
    prior = _last_kpi_goal_checkin_chain(con)
    row_for_hash = {"goal_id": goal_id, "checkin_date": checkin_date,
                    "status": status, "author_id": author_id, "created_at": now}
    chash = _chain_hash_kpi_goal_checkin(prior, row_for_hash)
    enc = _enc_dict("kpi_goal_checkins", {"notes": notes.strip()})
    cur = con.execute(
        "INSERT INTO kpi_goal_checkins (goal_id, checkin_date, status, notes, "
        "author_id, created_at, prior_chain_hash, chain_hash) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (goal_id, checkin_date, status, enc["notes"], author_id, now,
         prior, chash),
    )
    cid = cur.lastrowid
    if gr["status"] == "active":
        con.execute("UPDATE kpi_goals SET status='in_progress' WHERE id=?",
                    (goal_id,))
    con.commit(); con.close()
    return get_kpi_goal_checkin(cid)


def get_kpi_goal_checkin(cid: int) -> dict:
    con = _con()
    r = con.execute("SELECT * FROM kpi_goal_checkins WHERE id=?", (cid,)).fetchone()
    con.close()
    return _dec_row("kpi_goal_checkins", r) if r else None


def list_goal_checkins(goal_id: int) -> list:
    con = _con()
    rows = con.execute(
        "SELECT * FROM kpi_goal_checkins WHERE goal_id=? "
        "ORDER BY checkin_date DESC, id DESC", (goal_id,),
    ).fetchall()
    con.close()
    return [_dec_row("kpi_goal_checkins", r) for r in rows]


def close_goal(goal_id: int, outcome_status: str, outcome_summary: str,
               closer_id: int) -> dict:
    if outcome_status not in ("met", "not_met", "withdrawn"):
        raise ValueError("invalid_outcome_status")
    if not (outcome_summary or "").strip():
        raise ValueError("outcome_summary_required")
    con = _con()
    r = con.execute("SELECT * FROM kpi_goals WHERE id=?", (goal_id,)).fetchone()
    if not r:
        con.close(); raise ValueError("goal_not_found")
    if r["status"] in ("met", "not_met", "withdrawn"):
        con.close(); raise ValueError("already_closed")
    now = datetime.now(timezone.utc).isoformat()
    chash = None; prior = None
    if r["goal_kind"] == "pip":
        prior = _last_kpi_goal_chain(con)
        row_for_hash = {
            "goal_kind": "pip", "tech_id": r["tech_id"], "status": outcome_status,
            "start_date": r["start_date"], "target_date": r["target_date"],
            "opened_by_id": r["opened_by_id"], "opened_at": r["opened_at"],
            "activated_at": r["activated_at"], "closed_at": now,
            "pip_severity": r["pip_severity"],
            "hr_acknowledged_at": r["hr_acknowledged_at"],
        }
        chash = _chain_hash_kpi_goal(prior, row_for_hash)
    enc = _enc_dict("kpi_goals", {"outcome_summary": outcome_summary.strip()})
    if chash:
        con.execute(
            "UPDATE kpi_goals SET status=?, outcome_summary=?, closed_at=?, "
            "closed_by_id=?, prior_chain_hash=?, chain_hash=? WHERE id=?",
            (outcome_status, enc["outcome_summary"], now, closer_id,
             prior, chash, goal_id),
        )
    else:
        con.execute(
            "UPDATE kpi_goals SET status=?, outcome_summary=?, closed_at=?, "
            "closed_by_id=? WHERE id=?",
            (outcome_status, enc["outcome_summary"], now, closer_id, goal_id),
        )
    con.commit(); con.close()
    return get_kpi_goal(goal_id)


def list_goals_for_tech(tech_id: int, statuses=None, goal_kind=None) -> list:
    sql = "SELECT * FROM kpi_goals WHERE tech_id=?"
    args = [tech_id]
    if statuses:
        ph = ",".join(["?"] * len(statuses))
        sql += f" AND status IN ({ph})"
        args.extend(statuses)
    if goal_kind:
        sql += " AND goal_kind=?"; args.append(goal_kind)
    sql += " ORDER BY opened_at DESC"
    con = _con()
    rows = con.execute(sql, args).fetchall()
    con.close()
    import json as _j
    out = []
    for r in rows:
        d = _dec_row("kpi_goals", r)
        if d.get("action_items_json"):
            try: d["action_items"] = _j.loads(d["action_items_json"])
            except Exception: d["action_items"] = []
        else:
            d["action_items"] = []
        out.append(d)
    return out


def list_active_pips(hub_id: int = None) -> list:
    sql = ("SELECT g.*, t.name AS tech_name FROM kpi_goals g "
           "LEFT JOIN technicians t ON t.id=g.tech_id "
           "WHERE g.goal_kind='pip' AND g.status IN ('active','in_progress','draft')")
    args = []
    if hub_id is not None:
        sql += " AND g.hub_id=?"; args.append(int(hub_id))
    sql += " ORDER BY g.opened_at DESC"
    con = _con()
    rows = con.execute(sql, args).fetchall()
    con.close()
    out = []
    for r in rows:
        d = _dec_row("kpi_goals", r)
        d["tech_name"] = r["tech_name"]
        out.append(d)
    return out


def list_goals_filtered(tech_id=None, goal_kind=None, status=None,
                        page: int = 1, limit: int = 50) -> list:
    sql = ("SELECT g.*, t.name AS tech_name FROM kpi_goals g "
           "LEFT JOIN technicians t ON t.id=g.tech_id WHERE 1=1")
    args = []
    if tech_id:    sql += " AND g.tech_id=?";   args.append(tech_id)
    if goal_kind:  sql += " AND g.goal_kind=?"; args.append(goal_kind)
    if status:     sql += " AND g.status=?";    args.append(status)
    sql += " ORDER BY g.opened_at DESC LIMIT ? OFFSET ?"
    args.extend([int(limit), int(max(0, (page - 1) * limit))])
    con = _con()
    rows = con.execute(sql, args).fetchall()
    con.close()
    out = []
    for r in rows:
        d = _dec_row("kpi_goals", r)
        d["tech_name"] = r["tech_name"]
        out.append(d)
    return out


def list_open_goals_due_check_in(within_days: int = 7) -> list:
    cutoff = datetime.now(timezone.utc).date().isoformat()
    con = _con()
    rows = con.execute(
        "SELECT * FROM kpi_goals WHERE status IN ('active','in_progress') "
        "AND target_date <= date(?, '+' || ? || ' days') ORDER BY target_date ASC",
        (cutoff, within_days),
    ).fetchall()
    con.close()
    return [_dec_row("kpi_goals", r) for r in rows]


def suggest_pip_for_flag(flag_id: int) -> int:
    con = _con()
    f = con.execute("SELECT * FROM kpi_flags WHERE id=?", (flag_id,)).fetchone()
    if not f:
        con.close(); return 0
    if f["severity"] != "written_warning_recommended":
        con.close(); return 0
    existing = con.execute(
        "SELECT id FROM kpi_goals WHERE triggering_flag_id=? AND status='draft'",
        (flag_id,),
    ).fetchone()
    if existing:
        con.close(); return 0
    con.close()
    today = datetime.now(timezone.utc).date()
    target = (today + timedelta(days=90)).isoformat()
    try:
        goal = create_kpi_goal(
            goal_kind="pip", tech_id=f["tech_id"],
            title=f"Auto-suggested PIP for flag #{flag_id}",
            description=(f"Auto-suggested PIP based on written-warning flag #{flag_id}. "
                         "Manager and HR must review before activation."),
            start_date=today.isoformat(), target_date=target,
            opened_by_id=0,
            related_kpi_keys=(f["kpi_key"] or ""),
            pip_severity="standard",
            pip_review_dates=[(today + timedelta(days=30)).isoformat(),
                              (today + timedelta(days=60)).isoformat(),
                              (today + timedelta(days=90)).isoformat()],
            triggering_flag_id=flag_id,
        )
        try:
            log_audit(
                actor_type="system", actor_label="kpi-engine", actor_role="system",
                action="kpi.pip.draft_suggested",
                target_type="kpi_goal", target_id=goal.get("id"),
                target_label=f"flag={flag_id}",
            )
        except Exception:
            pass
        return int(goal.get("id") or 0)
    except Exception:
        return 0


def tech_set_action_item_done(goal_id: int, tech_id: int, idx: int,
                              done: bool = True) -> dict:
    import json as _j
    con = _con()
    r = con.execute("SELECT * FROM kpi_goals WHERE id=? AND tech_id=?",
                    (goal_id, tech_id)).fetchone()
    if not r:
        con.close(); raise ValueError("goal_not_found")
    if r["status"] in ("met", "not_met", "withdrawn"):
        con.close(); raise ValueError("goal_closed")
    aij = r["action_items_json"]
    try:
        aij_plain = _dec(aij) if aij else None
    except Exception:
        aij_plain = aij
    items = []
    if aij_plain:
        try: items = _j.loads(aij_plain)
        except Exception: items = []
    if idx < 0 or idx >= len(items):
        con.close(); raise ValueError("invalid_idx")
    items[idx]["done"] = bool(done)
    items[idx]["completed_at"] = (datetime.now(timezone.utc).isoformat()
                                  if done else None)
    new_json = _j.dumps(items)
    enc = _enc_dict("kpi_goals", {"action_items_json": new_json})
    con.execute("UPDATE kpi_goals SET action_items_json=? WHERE id=?",
                (enc["action_items_json"], goal_id))
    con.commit(); con.close()
    return get_kpi_goal(goal_id)


# ════════════════════════════════════════════════════════════════════════════
# Custom KPI definitions + manual values (Phase 7)
# ════════════════════════════════════════════════════════════════════════════

import re as _re_kpi

_KPI_KEY_RE = _re_kpi.compile(r"^[a-z][a-z0-9_]{2,40}$")


def create_custom_kpi(kpi_key: str, display_name: str, description: str,
                      direction: str, in_composite: int,
                      composite_weight_pct: float, safety_critical: int,
                      thresholds: list, creator_id: int) -> dict:
    if not _KPI_KEY_RE.match(kpi_key or ""):
        raise ValueError("invalid_kpi_key")
    if direction not in ("higher_better", "lower_better"):
        raise ValueError("invalid_direction")
    con = _con()
    existing = con.execute(
        "SELECT id FROM kpi_definitions WHERE kpi_key=?", (kpi_key,),
    ).fetchone()
    if existing:
        con.close(); raise ValueError("kpi_key_exists")
    now = datetime.now(timezone.utc).isoformat()
    today = datetime.now(timezone.utc).date().isoformat()
    rebalance_after = None
    if in_composite:
        cur_rows = con.execute(
            "SELECT kpi_key, composite_weight_pct FROM kpi_definitions "
            "WHERE active=1 AND in_composite=1"
        ).fetchall()
        cur_total = sum(float(r["composite_weight_pct"] or 0) for r in cur_rows)
        new_weight = float(composite_weight_pct or 0)
        target_existing = max(0.0, 100.0 - new_weight)
        if cur_total > 0:
            scale = target_existing / cur_total
            for r in cur_rows:
                new_val = round(float(r["composite_weight_pct"] or 0) * scale, 4)
                con.execute(
                    "UPDATE kpi_definitions SET composite_weight_pct=?, "
                    "updated_at=? WHERE kpi_key=?",
                    (new_val, now, r["kpi_key"]),
                )
            rebalance_after = {r["kpi_key"]: round(
                float(r["composite_weight_pct"] or 0) * scale, 4
            ) for r in cur_rows}
    con.execute(
        "INSERT INTO kpi_definitions (kpi_key, display_name, description, "
        "direction, in_composite, composite_weight_pct, safety_critical, "
        "active, created_at, updated_at, compute_kind, created_by_id, created_at_ext) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?, 'manual', ?, ?)",
        (kpi_key, display_name, description or "", direction,
         int(bool(in_composite)), float(composite_weight_pct or 0),
         int(bool(safety_critical)), now, now, creator_id, now),
    )
    tiers = ("level_1", "level_2", "level_3", "ops_manager")
    by_tier = {}
    for t in (thresholds or []):
        if t.get("tier") in tiers:
            by_tier[t["tier"]] = t
    for tier in tiers:
        t = by_tier.get(tier) or by_tier.get("level_3") or {
            "green": 0, "amber_band": 0, "red_floor": 0,
        }
        con.execute(
            "INSERT OR IGNORE INTO kpi_thresholds (kpi_key, tier, green_threshold, "
            "amber_band, red_floor, effective_from, active, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, 1, ?)",
            (kpi_key, tier, float(t.get("green") or 0),
             float(t.get("amber_band") or 0), float(t.get("red_floor") or 0),
             today, now),
        )
    con.commit(); con.close()
    return {"kpi_key": kpi_key, "rebalanced": rebalance_after}


def archive_custom_kpi(kpi_key: str) -> bool:
    con = _con()
    r = con.execute("SELECT compute_kind FROM kpi_definitions WHERE kpi_key=?",
                    (kpi_key,)).fetchone()
    if not r:
        con.close(); raise ValueError("kpi_not_found")
    if r["compute_kind"] != "manual":
        con.close(); raise ValueError("not_a_custom_kpi")
    con.execute("UPDATE kpi_definitions SET active=0, updated_at=? WHERE kpi_key=?",
                (datetime.now(timezone.utc).isoformat(), kpi_key))
    con.commit(); con.close()
    return True


def set_manual_kpi_value(tech_id: int, period_key: str, kpi_key: str,
                         raw_value: float, sample_size: int,
                         author_id: int) -> dict:
    con = _con()
    d = con.execute(
        "SELECT compute_kind FROM kpi_definitions WHERE kpi_key=? AND active=1",
        (kpi_key,),
    ).fetchone()
    con.close()
    if not d:
        raise ValueError("kpi_not_found")
    if d["compute_kind"] != "manual":
        raise ValueError("kpi_not_manual")
    ensure_period_exists(period_key)
    tier = _kpi_tier_for_tech(tech_id)
    band = score_to_band(kpi_key, tier, raw_value, sample_size)
    rid = record_kpi_score(tech_id, period_key, kpi_key,
                            raw_value, sample_size, band, tier)
    return {"score_id": rid, "band": band, "raw_value": raw_value,
            "sample_size": sample_size, "tier": tier}


def list_manual_kpi_history(kpi_key: str, period_key: str = None,
                            limit: int = 100) -> list:
    sql = ("SELECT s.*, t.name AS tech_name FROM kpi_scores s "
           "LEFT JOIN technicians t ON t.id=s.tech_id "
           "WHERE s.kpi_key=?")
    args = [kpi_key]
    if period_key:
        sql += " AND s.period_key=?"; args.append(period_key)
    sql += " ORDER BY s.computed_at DESC LIMIT ?"
    args.append(int(limit))
    con = _con()
    rows = con.execute(sql, args).fetchall()
    con.close()
    return [dict(r) for r in rows]


# ── Visible-count helper for access-gated dashboards ──────────────────────────
# Per universal access-gate spec (decision C): counts returned to the SPA
# must match what the viewer can actually read. For super_admin / supervisor
# we return the global count; for delegated admins we restrict to their
# scope; for everyone else we default to zero rather than leaking a tile
# that says "12" when the user can open none of them.

def count_visible_for(viewer_id: int, viewer_kind: str, viewer_role: str,
                      count_target: str):
    """Returns the actual count the viewer would see if they queried the
    target. count_target is one of:
      'invoices_outstanding', 'invoices_overdue',
      'visits_open', 'visits_today',
      'inventory_low_stock',
      'kpi_flags_open_by_severity' (returns dict),
      'reviews_pending',
      'fs_exceptions_open',
      'audit_log_recent_24h'.
    """
    global_roles = {"super_admin", "supervisor_admin"}
    is_global = (viewer_kind == "admin" and viewer_role in global_roles)

    con = _con()
    try:
        if count_target == "invoices_outstanding":
            if not is_global:
                return 0
            row = con.execute(
                "SELECT COUNT(*) c FROM invoices "
                "WHERE status='sent' AND (total - amount_paid) > 0.01"
            ).fetchone()
            return int(row["c"] or 0)

        if count_target == "invoices_overdue":
            if not is_global:
                return 0
            today = datetime.now(timezone.utc).date().isoformat()
            row = con.execute(
                "SELECT COUNT(*) c FROM invoices "
                "WHERE status='sent' AND due_date < ? "
                "AND (total - amount_paid) > 0.01", (today,),
            ).fetchone()
            return int(row["c"] or 0)

        if count_target == "visits_open":
            if not is_global:
                return 0
            row = con.execute(
                "SELECT COUNT(*) c FROM visits "
                "WHERE status NOT IN ('completed','cancelled','canceled')"
            ).fetchone()
            return int(row["c"] or 0)

        if count_target == "visits_today":
            if not is_global:
                return 0
            today = datetime.now(timezone.utc).date().isoformat()
            row = con.execute(
                "SELECT COUNT(*) c FROM visits WHERE scheduled_date = ?",
                (today,),
            ).fetchone()
            return int(row["c"] or 0)

        if count_target == "inventory_low_stock":
            if not is_global and viewer_role not in (
                "system_admin", "inventory_manager"
            ):
                return 0
            row = con.execute(
                "SELECT COUNT(*) c FROM parts "
                "WHERE active=1 AND quantity <= COALESCE(reorder_point,0)"
            ).fetchone()
            return int(row["c"] or 0)

        if count_target == "reviews_pending":
            if not is_global:
                return 0
            row = con.execute(
                "SELECT COUNT(*) c FROM reviews WHERE status='pending'"
            ).fetchone()
            return int(row["c"] or 0)

        if count_target == "fs_exceptions_open":
            if not is_global and viewer_role not in (
                "system_admin", "hr_admin", "ceo_assistant"
            ):
                return 0
            try:
                row = con.execute(
                    "SELECT COUNT(*) c FROM fs_exceptions WHERE status='open'"
                ).fetchone()
                return int(row["c"] or 0)
            except Exception:
                return 0

        if count_target == "audit_log_recent_24h":
            if viewer_kind != "admin":
                return 0
            if is_global:
                row = con.execute(
                    "SELECT COUNT(*) c FROM audit_log "
                    "WHERE created_at >= datetime('now','-1 day')"
                ).fetchone()
                return int(row["c"] or 0)
            # view_self only: only own rows
            row = con.execute(
                "SELECT COUNT(*) c FROM audit_log "
                "WHERE created_at >= datetime('now','-1 day') "
                "AND actor_type='admin' AND actor_id=?",
                (viewer_id,),
            ).fetchone()
            return int(row["c"] or 0)

        if count_target == "kpi_flags_open_by_severity":
            # Return a dict {severity: count}.
            if not is_global and viewer_role not in (
                "system_admin", "hr_admin"
            ):
                return {}
            try:
                rows = con.execute(
                    "SELECT severity, COUNT(*) c FROM kpi_flags "
                    "WHERE status='open' GROUP BY severity"
                ).fetchall()
                return {r["severity"]: int(r["c"] or 0) for r in rows}
            except Exception:
                return {}

        return 0
    finally:
        try: con.close()
        except Exception: pass
