import hashlib
import os
import secrets
import sqlite3
from datetime import datetime, timezone

DB_PATH = "submissions.db"


def _hash_pin(pin: str, salt: str = None) -> str:
    """Returns 'salt$hash'. Generates a new salt if none provided."""
    if salt is None:
        salt = secrets.token_hex(8)
    digest = hashlib.pbkdf2_hmac("sha256", pin.encode(), salt.encode(), 50_000).hex()
    return f"{salt}${digest}"


def _verify_pin(pin: str, stored: str) -> bool:
    if not stored or "$" not in stored:
        return False
    salt, _ = stored.split("$", 1)
    return secrets.compare_digest(_hash_pin(pin, salt), stored)


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


def _con():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
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
    if "pin_hash" not in cust_cols:
        try: con.execute("ALTER TABLE customers ADD COLUMN pin_hash TEXT")
        except sqlite3.OperationalError: pass

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
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            tech_code  TEXT NOT NULL UNIQUE,
            pin_hash   TEXT NOT NULL,
            name       TEXT NOT NULL,
            phone      TEXT,
            email      TEXT,
            role       TEXT NOT NULL DEFAULT 'tech',
            prid       TEXT UNIQUE,
            active     INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL
        )
    """)
    # Idempotent column additions for existing tech DBs
    tech_cols = {row[1] for row in con.execute("PRAGMA table_info(technicians)")}
    for name, sql in (
        ("role",      "ALTER TABLE technicians ADD COLUMN role TEXT NOT NULL DEFAULT 'tech'"),
        ("prid",      "ALTER TABLE technicians ADD COLUMN prid TEXT"),
        ("hire_date", "ALTER TABLE technicians ADD COLUMN hire_date TEXT"),
    ):
        if name not in tech_cols:
            try: con.execute(sql)
            except sqlite3.OperationalError: pass

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
            active        INTEGER NOT NULL DEFAULT 1,
            created_by    INTEGER REFERENCES admin_users(id),
            created_at    TEXT NOT NULL
        )
    """)
    # Idempotent column addition for existing admin DBs
    admin_cols = {row[1] for row in con.execute("PRAGMA table_info(admin_users)")}
    if "hire_date" not in admin_cols:
        try: con.execute("ALTER TABLE admin_users ADD COLUMN hire_date TEXT")
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
            created_at   TEXT NOT NULL
        )
    """)
    con.execute("CREATE INDEX IF NOT EXISTS idx_audit_actor   ON audit_log(actor_id, created_at)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_audit_action  ON audit_log(action, created_at)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_audit_target  ON audit_log(target_type, target_id)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log(created_at)")
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
        ("assigned_tech_id", "ALTER TABLE maintenance_visits ADD COLUMN assigned_tech_id INTEGER REFERENCES technicians(id)"),
        ("start_time",       "ALTER TABLE maintenance_visits ADD COLUMN start_time TEXT"),
        ("end_time",         "ALTER TABLE maintenance_visits ADD COLUMN end_time TEXT"),
        ("scheduled_time",   "ALTER TABLE maintenance_visits ADD COLUMN scheduled_time TEXT"),
    ):
        if col_sql[0] not in existing_cols:
            try: con.execute(col_sql[1])
            except sqlite3.OperationalError: pass

    con.commit()
    con.close()
    _backfill_prids()


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
    return dict(row) if row else None


def get_customer_by_id(customer_id: int):
    con = _con()
    row = con.execute("SELECT * FROM customers WHERE id = ?", (customer_id,)).fetchone()
    con.close()
    return dict(row) if row else None


def get_all_customers():
    con = _con()
    rows = con.execute(
        "SELECT id, customer_code, name, company, email, phone, address, notes, "
        "(pin_hash IS NOT NULL) AS has_pin, created_at FROM customers ORDER BY name"
    ).fetchall()
    con.close()
    return [dict(r) for r in rows]


def create_customer(data: dict) -> int:
    pin = data.get("pin", "").strip()
    pin_hash = _hash_pin(pin) if pin else None
    con = _con()
    cur = con.execute(
        """
        INSERT INTO customers (customer_code, name, company, email, phone, address, notes, pin_hash, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            data["customer_code"].strip().upper(),
            data["name"],
            data.get("company", ""),
            data.get("email", ""),
            data.get("phone", ""),
            data.get("address", ""),
            data.get("notes", ""),
            pin_hash,
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
    return cust


def set_customer_pin(customer_id: int, pin: str):
    con = _con()
    con.execute("UPDATE customers SET pin_hash = ? WHERE id = ?", (_hash_pin(pin), customer_id))
    con.commit()
    con.close()


def get_customer_by_code_and_email(code: str, email: str):
    con = _con()
    row = con.execute(
        "SELECT * FROM customers WHERE customer_code = ? AND LOWER(email) = LOWER(?)",
        (code.strip().upper(), email.strip()),
    ).fetchone()
    con.close()
    return dict(row) if row else None


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


def delete_customer(customer_id: int):
    con = _con()
    con.execute("DELETE FROM maintenance_visits WHERE customer_id = ?", (customer_id,))
    con.execute("DELETE FROM equipment WHERE customer_id = ?", (customer_id,))
    con.execute("DELETE FROM customers WHERE id = ?", (customer_id,))
    con.commit()
    con.close()


# ── Equipment ─────────────────────────────────────────────────────────────────

def get_customer_equipment(customer_id: int):
    con = _con()
    rows = con.execute(
        "SELECT * FROM equipment WHERE customer_id = ? ORDER BY name", (customer_id,)
    ).fetchall()
    con.close()
    return [dict(r) for r in rows]


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
            data.get("serial_number", ""),
            data.get("location", ""),
            data.get("notes", ""),
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
    return [dict(r) for r in rows]


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
    return [dict(r) for r in rows]


def create_visit(data: dict) -> int:
    con = _con()
    cur = con.execute(
        """
        INSERT INTO maintenance_visits
            (customer_id, equipment_id, visit_type, status, scheduled_date,
             scheduled_time, completed_date, technician, work_done, parts_replaced,
             notes, assigned_tech_id, start_time, end_time, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
            data.get("work_done", ""),
            data.get("parts_replaced", ""),
            data.get("notes", ""),
            data.get("assigned_tech_id") or None,
            data.get("start_time") or None,
            data.get("end_time") or None,
            datetime.now(timezone.utc).isoformat(),
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
            equipment_id     = ?,
            visit_type       = ?,
            status           = ?,
            scheduled_date   = ?,
            scheduled_time   = ?,
            completed_date   = ?,
            technician       = ?,
            work_done        = ?,
            parts_replaced   = ?,
            notes            = ?,
            assigned_tech_id = ?
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
            data.get("work_done", ""),
            data.get("parts_replaced", ""),
            data.get("notes", ""),
            data.get("assigned_tech_id") or None,
            visit_id,
        ),
    )
    con.commit()
    con.close()


def get_visit_by_id(visit_id: int):
    con = _con()
    row = con.execute(
        """
        SELECT v.*, c.name AS customer_name, c.company AS customer_company,
               c.phone AS customer_phone, c.address AS customer_address,
               c.customer_code, e.name AS equipment_name, e.type AS equipment_type,
               e.model AS equipment_model, e.location AS equipment_location,
               t.name AS tech_name
        FROM maintenance_visits v
        JOIN customers c ON v.customer_id = c.id
        LEFT JOIN equipment   e ON v.equipment_id     = e.id
        LEFT JOIN technicians t ON v.assigned_tech_id = t.id
        WHERE v.id = ?
        """,
        (visit_id,),
    ).fetchone()
    con.close()
    return dict(row) if row else None


def update_visit_time(visit_id: int, field: str, value: str):
    """field: 'start_time' or 'end_time'"""
    if field not in ("start_time", "end_time"):
        raise ValueError("invalid field")
    con = _con()
    con.execute(f"UPDATE maintenance_visits SET {field} = ? WHERE id = ?", (value, visit_id))
    con.commit()
    con.close()


def tech_complete_visit(visit_id: int, work_done: str, parts: str, notes: str, end_time: str, completed_date: str):
    con = _con()
    con.execute(
        """
        UPDATE maintenance_visits SET
            status         = 'completed',
            work_done      = ?,
            parts_replaced = ?,
            notes          = ?,
            end_time       = ?,
            completed_date = ?
        WHERE id = ?
        """,
        (work_done, parts, notes, end_time, completed_date, visit_id),
    )
    con.commit()
    con.close()


def get_tech_jobs(tech_id: int):
    con = _con()
    rows = con.execute(
        """
        SELECT v.*, c.name AS customer_name, c.company AS customer_company,
               c.phone AS customer_phone, c.address AS customer_address,
               c.customer_code, e.name AS equipment_name
        FROM maintenance_visits v
        JOIN customers c ON v.customer_id = c.id
        LEFT JOIN equipment e ON v.equipment_id = e.id
        WHERE v.assigned_tech_id = ?
        ORDER BY COALESCE(v.scheduled_date, v.created_at) ASC
        """,
        (tech_id,),
    ).fetchall()
    con.close()
    return [dict(r) for r in rows]


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
    return dict(row) if row else None


def get_tech_by_id(tech_id: int):
    con = _con()
    row = con.execute("SELECT * FROM technicians WHERE id = ?", (tech_id,)).fetchone()
    con.close()
    return dict(row) if row else None


def verify_tech(code: str, pin: str):
    tech = get_tech_by_code(code)
    if not tech or not _verify_pin(pin, tech["pin_hash"]):
        return None
    return tech


def get_all_techs():
    con = _con()
    rows = con.execute(
        """
        SELECT t.id, t.tech_code, t.name, t.phone, t.email, t.role, t.prid, t.active, t.created_at,
               (SELECT COUNT(*) FROM maintenance_visits v
                WHERE v.assigned_tech_id = t.id AND v.status != 'completed') AS active_jobs
        FROM technicians t
        ORDER BY t.active DESC, t.name
        """
    ).fetchall()
    con.close()
    return [dict(r) for r in rows]


def create_tech(data: dict) -> tuple:
    """Returns (tech_id, prid). If `tech_code` not provided, PRID is used as the tech_code."""
    hire_date = (data.get("hire_date") or "").strip() or None
    prid      = generate_prid(name=data["name"], hire_date=hire_date)
    raw_code  = (data.get("tech_code") or "").strip().upper()
    tech_code = raw_code if raw_code else prid
    con = _con()
    cur = con.execute(
        """
        INSERT INTO technicians (tech_code, pin_hash, name, phone, email, role, prid, hire_date, active, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?)
        """,
        (
            tech_code,
            _hash_pin(data["pin"]),
            data["name"],
            data.get("phone", ""),
            data.get("email", ""),
            data.get("role", "tech"),
            prid,
            hire_date,
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
        "UPDATE technicians SET name = ?, phone = ?, email = ?, role = ?, active = ? WHERE id = ?",
        (
            data.get("name", ""),
            data.get("phone", ""),
            data.get("email", ""),
            data.get("role", "tech"),
            1 if data.get("active", True) else 0,
            tech_id,
        ),
    )
    con.commit()
    con.close()


def get_tech_by_code_and_email(code: str, email: str):
    con = _con()
    row = con.execute(
        "SELECT * FROM technicians WHERE tech_code = ? AND LOWER(email) = LOWER(?) AND active = 1",
        (code.strip().upper(), email.strip()),
    ).fetchone()
    con.close()
    return dict(row) if row else None


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

def create_photo(visit_id: int, category: str, filename: str, tech_id: int = None) -> int:
    con = _con()
    cur = con.execute(
        """
        INSERT INTO visit_photos (visit_id, category, filename, uploaded_by, uploaded_at)
        VALUES (?, ?, ?, ?, ?)
        """,
        (visit_id, category, filename, tech_id, datetime.now(timezone.utc).isoformat()),
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
    return [dict(r) for r in rows]


def get_photo_by_id(photo_id: int):
    con = _con()
    row = con.execute("SELECT * FROM visit_photos WHERE id = ?", (photo_id,)).fetchone()
    con.close()
    return dict(row) if row else None


def delete_photo(photo_id: int):
    con = _con()
    con.execute("DELETE FROM visit_photos WHERE id = ?", (photo_id,))
    con.commit()
    con.close()


# ── Admin Users ───────────────────────────────────────────────────────────────

def _hash_password(pw: str, salt: str = None) -> str:
    if salt is None:
        salt = secrets.token_hex(12)
    digest = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt.encode(), 100_000).hex()
    return f"{salt}${digest}"


def _verify_password(pw: str, stored: str) -> bool:
    if not stored or "$" not in stored:
        return False
    salt, _ = stored.split("$", 1)
    return secrets.compare_digest(_hash_password(pw, salt), stored)


def get_admin_user_by_username(username: str):
    con = _con()
    row = con.execute(
        "SELECT * FROM admin_users WHERE LOWER(username) = LOWER(?) AND active = 1",
        (username.strip(),),
    ).fetchone()
    con.close()
    return dict(row) if row else None


def get_admin_user_by_id(admin_id: int):
    con = _con()
    row = con.execute("SELECT * FROM admin_users WHERE id = ?", (admin_id,)).fetchone()
    con.close()
    return dict(row) if row else None


def verify_admin_user(username: str, password: str):
    admin = get_admin_user_by_username(username)
    if not admin or not _verify_password(password, admin["password_hash"]):
        return None
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
    return [dict(r) for r in rows]


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
            (username, password_hash, name, email, phone, role, prid, hire_date, active, created_by, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
        """,
        (
            username,
            _hash_password(data["password"]),
            data["name"].strip(),
            data["email"].strip().lower(),
            data.get("phone", "").strip(),
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
        "UPDATE admin_users SET name = ?, email = ?, phone = ? WHERE id = ?",
        (
            data["name"].strip(),
            data["email"].strip().lower(),
            data.get("phone", "").strip(),
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


def get_admin_by_email(email: str):
    con = _con()
    row = con.execute(
        "SELECT * FROM admin_users WHERE LOWER(email) = LOWER(?) AND active = 1",
        (email.strip(),),
    ).fetchone()
    con.close()
    return dict(row) if row else None


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
    import json as _json
    con = _con()
    con.execute(
        """
        INSERT INTO audit_log
            (actor_type, actor_id, actor_prid, actor_label, actor_role,
             action, target_type, target_id, target_label,
             before_value, after_value, ip_address, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            actor_type, actor_id, actor_prid, actor_label, actor_role,
            action, target_type, target_id, target_label,
            _json.dumps(before_value) if before_value is not None else None,
            _json.dumps(after_value)  if after_value  is not None else None,
            ip_address,
            datetime.now(timezone.utc).isoformat(),
        ),
    )
    con.commit()
    con.close()


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
             reorder_point, supplier, active, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
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
            unit_cost = ?, reorder_point = ?, supplier = ?,
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
