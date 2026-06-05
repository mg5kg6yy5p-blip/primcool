#!/usr/bin/env python3
"""Seed the database to the target operating scale:

    30 staff: 1 super_admin + 4 admins (HR/CEO/Sys/Inventory)
              + 3 dispatchers (seeded as supervisor_admin until R5
                upgrades the role matrix to add a true dispatcher role)
              + 18 techs (3 lead + 12 tech + 3 apprentice)
              + 4 warehouse (1 manager + 2 floor + 1 parts runner)

    200 customers: 140 residential + 60 commercial

Plus realistic linked data so the optimization batches (R2-R6) have
something to measure against:
    ~400 equipment units (1-3 per customer)
    ~2,400 maintenance visits over the last 6 months
    ~800 invoices (one per ~3 visits, mixed paid/sent/overdue)
    ~600 invoice payments

USAGE
    python3 scripts/seed_30_200.py            # dry run
    python3 scripts/seed_30_200.py --apply    # writes to the DB

The script is idempotent for staff (skips existing usernames /
tech_codes) but TRUNCATES customers + their linked tables every run
so re-running gives a consistent dataset. Staff credentials are
written to /tmp/pc_creds_30_200.tsv on apply.
"""
from __future__ import annotations
import argparse, os, random, secrets, string, sys
from datetime import datetime, date, timedelta, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

# Field encryption keys must be in env BEFORE crypto/database import so
# `create_customer` (which encrypts PII) doesn't raise "key not configured".
if not os.environ.get("FIELD_ENCRYPTION_KEY"):
    try:
        with open(os.path.join(ROOT, ".dev.env")) as _f:
            for _line in _f:
                if _line.startswith("export "):
                    _k, _v = _line[7:].strip().split("=", 1)
                    os.environ.setdefault(_k, _v.strip('"'))
    except FileNotFoundError:
        pass

from database import (  # type: ignore
    _con, _hash_pin, _hash_password,
    create_admin_user, create_tech, create_customer, create_equipment,
    create_visit, create_invoice_with_lines, record_invoice_payment_v2,
    create_part, create_pay_period, upsert_payslip,
    create_purchase_order,
)

random.seed(20260524)

# ── Roster definitions ────────────────────────────────────────────────────
ADMIN_ROSTER = [
    # (name, role, email)
    ("Ray Juggar",       "super_admin",      "ray@primecool.example.jm"),
    ("Andre Walker",     "supervisor_admin", "andre.w@primecool.example.jm"),
    ("Damion Reid",      "system_admin",     "damion.r@primecool.example.jm"),
    ("Camille Bennett",  "hr_admin",         "camille.b@primecool.example.jm"),
    ("Latoya Thompson",  "ceo_assistant",    "latoya.t@primecool.example.jm"),
    ("Trevor Edwards",   "inventory_manager","trevor.e@primecool.example.jm"),
    # 3 dispatchers — temporarily supervisor_admin until R5 lands the
    # dedicated dispatcher role.
    ("Karen Powell",     "supervisor_admin", "karen.p@primecool.example.jm"),
    ("Jermaine Foster",  "supervisor_admin", "jermaine.f@primecool.example.jm"),
    ("Shauna McKenzie",  "supervisor_admin", "shauna.m@primecool.example.jm"),
]

# 18 field techs — 3 lead, 12 mid, 3 apprentice
TECH_ROSTER = [
    # (name, role, hourly_rate)
    ("Marcus Brown",    "lead_tech",  3500),
    ("Devon Wright",    "lead_tech",  3500),
    ("Renaldo Clarke",  "lead_tech",  3500),
    ("Jermaine Lyn",    "tech",       2800),
    ("Tomoya Reid",     "tech",       2800),
    ("Damion Foster",   "tech",       2800),
    ("Andre Campbell",  "tech",       2800),
    ("Kemar Wright",    "tech",       2800),
    ("Sherwin Palmer",  "tech",       2800),
    ("Owen Thompson",   "tech",       2800),
    ("Tameka Williams", "tech",       2800),
    ("Garnet Clarke",   "tech",       2800),
    ("Patricia Bailey", "tech",       2800),
    ("Donovan Beckford","tech",       2800),
    ("Norval Clarke",   "tech",       2800),
    ("Shanique Lyn",    "apprentice", 1800),
    ("Junior Powell",   "apprentice", 1800),
    ("Anya Thompson",   "apprentice", 1800),
]

WAREHOUSE_ROSTER = [
    ("Donovan Bennett", "warehouse_manager", "tech"),
    ("Renata Reid",     "warehouse_floor",   "tech"),
    ("Maurice Chin",    "warehouse_floor",   "tech"),
    ("Cherise Cooper",  "parts_runner",      "tech"),
]

# Customer name pool (recycled with a counter for the 200-row target)
FIRST_NAMES = [
    "Andre","Anya","Camille","Carlton","Cherise","Christine","Damion","Devon",
    "Donovan","Garnet","Howard","Jermaine","Junior","Karen","Kemar","Kevon",
    "Latoya","Marcus","Maurice","Norval","Owen","Patricia","Renaldo","Renata",
    "Sasha","Shanice","Sherwin","Suzette","Tameka","Tanya","Tomoya","Tasha",
    "Alicia","Cherise","Maxine","Latrice","Donna","Roxanne","Kemar","Trevor",
]
LAST_NAMES = [
    "Brown","Clarke","Wright","Reid","Thompson","Williams","Bennett",
    "Foster","Campbell","Beckford","Bailey","Palmer","Edwards","Powell",
    "Henry","Robinson","Bryan","McKenzie","Lyn","Cooper","Chin","Lewis",
    "Cooke","Grant","Spence","Reynolds","Walters","Salmon","Patterson",
]
COMPANY_SUFFIX = ["Ltd","Holdings","Group","Services","Co","Enterprises"]
COMPANY_PREFIX = [
    "Constant Spring","Liguanea","Half Way Tree","Portmore","New Kingston",
    "Spanish Town","Mandeville","Ocho Rios","Mobay","Negril","Linstead",
    "May Pen","Old Harbour","Annotto Bay","Falmouth","Browns Town","Yallahs",
]

EQUIP_TYPES = [
    ("Lobby Split",     "Daikin",    "FTKM50R"),
    ("Open Plan Central","Carrier",  "38UVH-024"),
    ("Lab Water Cooler","Trane",     "WSC036"),
    ("Den Central",     "LG",        "LSU240HEV"),
    ("Guest Bedroom Split","Mitsubishi","MSZ-GL18"),
    ("Server Room",     "Daikin",    "FFA50RVMA"),
    ("Warehouse Spot",  "Carrier",   "40MAH"),
    ("Living Room Central","Trane",  "XV20i"),
]

VISIT_TYPES = ["PM","CM","PM","PM","CM"]  # 60% PM, 40% CM

# ── Helpers ──────────────────────────────────────────────────────────────
def _pin():
    return f"{secrets.randbelow(900_000) + 100_000}"

def _pw():
    alphabet = string.ascii_letters + string.digits
    while True:
        pw = "".join(secrets.choice(alphabet) for _ in range(12))
        if any(c.isdigit() for c in pw) and any(c.isupper() for c in pw) and any(c.islower() for c in pw):
            return pw

def _phone():
    return f"+1876{random.randint(2000000, 9999999)}"

def _kingston_address():
    n = random.randint(1, 199)
    street = random.choice([
        "Old Hope Rd","Constant Spring Rd","Hagley Park Rd","Half Way Tree Rd",
        "Lady Musgrave Rd","Mountain View Ave","Trafalgar Rd","Knutsford Blvd",
        "Waterloo Rd","South Camp Rd","Mobay Hip Strip","Negril Ave",
    ])
    kingston = random.choice([
        "Kingston 5","Kingston 6","Kingston 8","Kingston 10","Kingston 11",
        "Spanish Town","Portmore","Mandeville","Ocho Rios","Montego Bay",
    ])
    return f"{n} {street}, {kingston}"

def _existing_codes(con, table, col):
    rows = con.execute(f"SELECT {col} AS c FROM {table}").fetchall()
    return {r["c"] for r in rows}

# ── Step 1: wipe customer-side data ──────────────────────────────────────
def wipe_customers(con):
    print("Wiping customer-side tables (children → parents)...")
    plan = [
        ("DELETE FROM visit_photos     WHERE visit_id IN (SELECT id FROM maintenance_visits)",     "visit_photos"),
        ("DELETE FROM visit_parts      WHERE visit_id IN (SELECT id FROM maintenance_visits)",     "visit_parts"),
        ("DELETE FROM visit_readings   WHERE visit_id IN (SELECT id FROM maintenance_visits)",     "visit_readings"),
        ("DELETE FROM visit_signatures WHERE visit_id IN (SELECT id FROM maintenance_visits)",     "visit_signatures"),
        ("DELETE FROM invoice_line_items WHERE invoice_id IN (SELECT id FROM invoices)",            "invoice_line_items"),
        ("DELETE FROM invoice_payments   WHERE invoice_id IN (SELECT id FROM invoices)",            "invoice_payments"),
        ("DELETE FROM customer_credit_movements",                                                   "customer_credit_movements"),
        ("DELETE FROM customer_pin_resets",                                                         "customer_pin_resets"),
        ("DELETE FROM service_requests   WHERE customer_id IS NOT NULL",                            "service_requests"),
        ("DELETE FROM reviews            WHERE customer_id IS NOT NULL",                            "reviews"),
        ("DELETE FROM invoices",                                                                    "invoices"),
        ("DELETE FROM maintenance_visits",                                                          "maintenance_visits"),
        ("DELETE FROM equipment",                                                                   "equipment"),
        ("DELETE FROM sessions WHERE subject_type='customer'",                                      "customer sessions"),
        ("DELETE FROM customers",                                                                   "customers"),
        # Payroll wipe — periodic reseeds rebuild the full payslip stream.
        ("DELETE FROM payslips",                                                                    "payslips"),
        ("DELETE FROM pay_periods",                                                                 "pay_periods"),
        # Inventory wipe — keeps the catalog fresh; PO history rebuilt below.
        ("DELETE FROM purchase_order_lines",                                                        "po_lines"),
        ("DELETE FROM purchase_orders",                                                             "purchase_orders"),
        ("DELETE FROM part_movements",                                                              "part_movements"),
        ("DELETE FROM parts",                                                                       "parts"),
    ]
    con.execute("PRAGMA defer_foreign_keys = ON")
    for sql, label in plan:
        try:
            n = con.execute(sql).rowcount
            print(f"  {label:<30} → {n}")
        except Exception as e:
            print(f"  {label:<30} → SKIPPED ({e})")

# ── Step 2: staff (idempotent) ───────────────────────────────────────────
def seed_admins(con, creds):
    print(f"\nSeeding {len(ADMIN_ROSTER)} admins...")
    existing = _existing_codes(con, "admin_users", "username")
    for name, role, email in ADMIN_ROSTER:
        # Re-use the post-reset username convention: pc_<prid_lowercase>.
        if any(name.lower().replace(" ","") in u for u in existing):
            print(f"  SKIP (already exists) {name}")
            continue
        pw = _pw()
        try:
            admin_id, prid = create_admin_user({
                "name": name, "email": email, "phone": _phone(),
                "role": role, "password": pw, "hire_date": "2024-01-01",
            })
            uname = f"pc_{prid.lower()}"
            con.execute("UPDATE admin_users SET username = ? WHERE id = ?", (uname, admin_id))
            con.commit()  # release the write lock so the next create_*() (own connection) isn't blocked
            creds.append(("ADMIN", prid, name, role, uname, pw))
            print(f"  + {name:<22} {role:<22} {uname:<24} {pw}")
        except Exception as e:
            print(f"  ! {name}: {e}")

def seed_techs(con, creds):
    print(f"\nSeeding {len(TECH_ROSTER)} field techs...")
    existing = _existing_codes(con, "technicians", "name")
    for name, role, rate in TECH_ROSTER:
        if name in existing:
            print(f"  SKIP (already exists) {name}")
            continue
        pin = _pin()
        try:
            tech_id, prid = create_tech({
                "name": name,
                "pin": pin,
                "phone": _phone(),
                "email": f"{name.lower().replace(' ','.')}@primecool.example.jm",
                "role": role,
                "hire_date": "2024-06-01",
                "hourly_rate": rate,
                "staff_type": "tech",
                "department": "field",
                "hub_id": 1,
            })
            creds.append(("STAFF", prid, name, f"tech/{role}", prid, pin))
            print(f"  + {name:<22} {role:<12} {prid:<20} {pin}")
        except Exception as e:
            print(f"  ! {name}: {e}")

def seed_warehouse(con, creds):
    print(f"\nSeeding {len(WAREHOUSE_ROSTER)} warehouse staff...")
    existing = _existing_codes(con, "technicians", "name")
    for name, staff_type, role in WAREHOUSE_ROSTER:
        if name in existing:
            print(f"  SKIP (already exists) {name}")
            continue
        pin = _pin()
        try:
            tech_id, prid = create_tech({
                "name": name,
                "pin": pin,
                "phone": _phone(),
                "email": f"{name.lower().replace(' ','.')}@primecool.example.jm",
                "role": role,
                "hire_date": "2024-09-01",
                "hourly_rate": 1900,
                "staff_type": staff_type,
                "department": "warehouse",
                "hub_id": 1,
            })
            creds.append(("STAFF", prid, name, f"{staff_type}/{role}", prid, pin))
            print(f"  + {name:<22} {staff_type:<22} {prid:<20} {pin}")
        except Exception as e:
            print(f"  ! {name}: {e}")

# ── Step 3: customers ────────────────────────────────────────────────────
def seed_customers(con, creds, n_residential=140, n_commercial=60):
    print(f"\nSeeding {n_residential} residential + {n_commercial} commercial customers...")
    out = []
    for i in range(1, n_residential + 1):
        name = f"{random.choice(FIRST_NAMES)} {random.choice(LAST_NAMES)}"
        pin = _pin()
        code = f"RES-{i:03d}"
        try:
            cid = create_customer({
                "customer_code": code,
                "name": name,
                "pin": pin,
                "phone": _phone(),
                "email": f"{name.lower().replace(' ','.')}{i}@example.jm",
                "address": _kingston_address(),
                "customer_type": "residential",
                "notes": "",
            })
            out.append((cid, code, name, "residential"))
            creds.append(("CUSTOMER", code, name, "residential", code, pin))
        except Exception as e:
            print(f"  ! {code}: {e}")
    for i in range(1, n_commercial + 1):
        company = f"{random.choice(COMPANY_PREFIX)} {random.choice(COMPANY_SUFFIX)}"
        contact = f"{random.choice(FIRST_NAMES)} {random.choice(LAST_NAMES)}"
        pin = _pin()
        code = f"COM-{i:03d}"
        try:
            cid = create_customer({
                "customer_code": code,
                "name": contact,
                "pin": pin,
                "phone": _phone(),
                "email": f"ap@{company.lower().replace(' ','')}.example.jm",
                "address": _kingston_address(),
                "company": company,
                "customer_type": "commercial",
                "notes": "",
            })
            out.append((cid, code, contact, "commercial"))
            creds.append(("CUSTOMER", code, f"{contact} ({company})", "commercial", code, pin))
        except Exception as e:
            print(f"  ! {code}: {e}")
    print(f"  + {len(out)} customers created")
    return out

# ── Step 4: equipment (1–3 per customer) ─────────────────────────────────
def seed_equipment(con, customers):
    print(f"\nSeeding equipment...")
    eq = []
    for (cid, code, name, ctype) in customers:
        count = random.choices([1,2,3], weights=[55,30,15])[0] if ctype == "residential" else random.choices([2,3,4,5], weights=[30,40,20,10])[0]
        for k in range(count):
            etype, brand, model = random.choice(EQUIP_TYPES)
            try:
                eid = create_equipment({
                    "customer_id": cid,
                    "name":  f"{etype} #{k+1}",
                    "type":  etype,
                    "model": f"{brand} {model}",
                    "serial_number": f"SN-{random.randint(10000, 999999)}",
                    "location": etype,
                    "notes": f"Installed ~{random.randint(2, 5)} years ago, refrigerant {random.choice(['R-410A','R-32','R-22'])}",
                })
                eq.append((eid, cid))
            except Exception as e:
                if "locked" not in str(e):
                    print(f"  ! equipment for customer {cid}: {e}")
    print(f"  + {len(eq)} equipment units created")
    return eq

# ── Step 5: visits ───────────────────────────────────────────────────────
def seed_visits(con, customers, equipment, techs, days_back=180):
    print(f"\nSeeding visits over the last {days_back} days...")
    eq_by_cust = {}
    for eid, cid in equipment:
        eq_by_cust.setdefault(cid, []).append(eid)
    today = date.today()
    visits = []
    # Scale visit volume with horizon: original (~12 res / ~16 com per 180d)
    # works out to roughly one residential visit every 15 days and one
    # commercial visit every 11 days. Keep that cadence so a 365-day run
    # produces a proportionally bigger workload (~24 / ~33 per customer).
    scale = max(1.0, days_back / 180.0)
    target_per_customer = {
        "residential": max(1, int(round(12 * scale))),
        "commercial":  max(1, int(round(16 * scale))),
    }
    statuses = ["completed"] * 8 + ["in_progress"] * 1 + ["scheduled"] * 1
    for (cid, code, name, ctype) in customers:
        n = target_per_customer.get(ctype, 12)
        for _ in range(n):
            d = today - timedelta(days=random.randint(0, days_back))
            tech = random.choice(techs)
            vtype = random.choice(VISIT_TYPES)
            status = random.choice(statuses)
            eq_id = random.choice(eq_by_cust.get(cid, [None])) if eq_by_cust.get(cid) else None
            try:
                vid = create_visit({
                    "customer_id": cid,
                    "equipment_id": eq_id,
                    "visit_type": vtype,
                    "scheduled_date": d.isoformat(),
                    "scheduled_time": f"{random.randint(8,15):02d}:{random.choice(['00','15','30','45'])}",
                    "assigned_tech_id": tech,
                    "status": status,
                    "notes": "",
                    "scope_of_work": "Routine PM" if vtype == "PM" else "Service call",
                })
                visits.append((vid, cid, status))
            except Exception as e:
                pass
    print(f"  + {len(visits)} visits created")
    return visits

# ── Step 6: invoices ─────────────────────────────────────────────────────
def seed_invoices(con, customers, visits, days_back=180):
    print(f"\nSeeding invoices (one per ~3 completed visits)...")
    # Group completed visits by customer.
    by_cust = {}
    for vid, cid, status in visits:
        if status == "completed":
            by_cust.setdefault(cid, []).append(vid)
    today = date.today()
    invoices = []
    # Spread issue dates across the same horizon as the visits.
    issue_window = max(30, int(days_back * 0.85))
    for cid, vlist in by_cust.items():
        # ~1 invoice per 3 visits.
        n_inv = max(1, len(vlist) // 3)
        for i in range(n_inv):
            issued = today - timedelta(days=random.randint(0, issue_window))
            due    = issued + timedelta(days=30)
            line_count = random.randint(1, 4)
            lines = []
            for _ in range(line_count):
                qty = random.randint(1, 3)
                unit = round(random.uniform(2500, 28000), 2)
                lines.append({
                    "description": random.choice([
                        "PM service — system inspection + filter",
                        "Refrigerant top-up R-410A",
                        "Capacitor replacement",
                        "Drain line clean-out",
                        "Compressor diagnostic",
                        "Service call after-hours",
                    ]),
                    "quantity": qty,
                    "unit_price": unit,
                    "tax_rate": 0.15,
                })
            try:
                inv_id = create_invoice_with_lines({
                    "customer_id": cid,
                    "issue_date": issued.isoformat(),
                    "due_date":   due.isoformat(),
                    "currency":   "JMD",
                    "line_items": lines,
                    "notes": "",
                })
                # create_invoice() always persists status='draft' (the real
                # lifecycle promotes via a separate "send" action). Simulate that
                # here so AR aging + the payments pass have realistic data. Commit
                # each iteration so the next create_*() (own connection) isn't
                # lock-blocked. seed_payments() then marks ~75% of 'sent' as paid.
                if random.choices(["sent", "draft"], weights=[90, 10])[0] == "sent":
                    con.execute("UPDATE invoices SET status='sent' WHERE id=?", (inv_id,))
                    con.commit()
                invoices.append(inv_id)
            except Exception as e:
                pass
    print(f"  + {len(invoices)} invoices created")
    return invoices

# ── Step 7: invoice payments (cover ~75% of sent/paid) ───────────────────
def seed_payments(con):
    print(f"\nRecording payments for ~75% of invoices ≥1 day old...")
    today = date.today().isoformat()
    rows = con.execute(
        "SELECT id, customer_id, total, issue_date, status FROM invoices "
        "WHERE status IN ('sent','paid') AND issue_date < ? "
        "ORDER BY id", (today,)
    ).fetchall()
    today_d = date.today()
    n_paid = 0
    n_err = 0
    for r in rows:
        # Mark ~75% as paid in full.
        if random.random() > 0.75:
            continue
        # Pay 3-28 days after issue, but never in the future.
        pay_d = date.fromisoformat(r["issue_date"]) + timedelta(days=random.randint(3, 28))
        if pay_d > today_d:
            pay_d = today_d
        try:
            # record_invoice_payment_v2 manages its own connection, computes the
            # chain_hash, recomputes invoice totals, and auto-flips to 'paid'.
            record_invoice_payment_v2(
                r["id"],
                {
                    "amount":       r["total"],
                    "payment_date": pay_d.isoformat(),
                    "method":       "bank_transfer",
                    "reference":    f"REF-{random.randint(100000, 999999)}",
                },
                recorded_by_label="seed",
            )
            n_paid += 1
        except Exception as e:
            n_err += 1
            print(f"  ! payment for invoice {r['id']} failed: {e}")
    print(f"  + {n_paid} payments recorded" + (f" ({n_err} errors)" if n_err else ""))

# ── Step 8: inventory (parts catalog + initial stock + a few POs) ────────
PARTS_CATALOG = [
    # (sku, name, category, unit, cost, reorder, supplier)
    ("REF-R410A-10",  "Refrigerant R-410A 10lb cylinder", "Refrigerant",  "cylinder", 18500, 8,  "Cool Supply Co"),
    ("REF-R32-10",    "Refrigerant R-32 10lb cylinder",   "Refrigerant",  "cylinder", 16800, 6,  "Cool Supply Co"),
    ("REF-R22-10",    "Refrigerant R-22 10lb cylinder",   "Refrigerant",  "cylinder", 32000, 3,  "Heritage Refrigerants"),
    ("CAP-35-370",    "Run capacitor 35µF 370V",          "Capacitor",    "each",       1850, 20, "Caribbean HVAC Parts"),
    ("CAP-45-440",    "Dual run capacitor 45/5µF 440V",   "Capacitor",    "each",       2250, 20, "Caribbean HVAC Parts"),
    ("CAP-55-440",    "Dual run capacitor 55/5µF 440V",   "Capacitor",    "each",       2450, 15, "Caribbean HVAC Parts"),
    ("CON-30A-2P",    "Contactor 30A 2-pole 24V coil",    "Contactor",    "each",       3200, 12, "Caribbean HVAC Parts"),
    ("CON-40A-2P",    "Contactor 40A 2-pole 24V coil",    "Contactor",    "each",       3800, 10, "Caribbean HVAC Parts"),
    ("MTR-FAN-1/4",   "Condenser fan motor 1/4 HP",       "Motor",        "each",      18500, 5,  "Caribbean HVAC Parts"),
    ("MTR-FAN-1/3",   "Condenser fan motor 1/3 HP",       "Motor",        "each",      21200, 5,  "Caribbean HVAC Parts"),
    ("MTR-BLW-1/2",   "Blower motor 1/2 HP",              "Motor",        "each",      27500, 4,  "Caribbean HVAC Parts"),
    ("TUB-CU-3/8-50", "Copper tubing 3/8\" x 50ft roll",  "Tubing",       "roll",      14500, 6,  "Pan Carib Metals"),
    ("TUB-CU-1/2-50", "Copper tubing 1/2\" x 50ft roll",  "Tubing",       "roll",      17500, 6,  "Pan Carib Metals"),
    ("TUB-CU-5/8-50", "Copper tubing 5/8\" x 50ft roll",  "Tubing",       "roll",      21500, 4,  "Pan Carib Metals"),
    ("INS-3/8-AC",    "Armaflex insulation 3/8\" x 6ft",  "Insulation",   "stick",      1200, 30, "Pan Carib Metals"),
    ("INS-1/2-AC",    "Armaflex insulation 1/2\" x 6ft",  "Insulation",   "stick",      1450, 30, "Pan Carib Metals"),
    ("FLT-16x20",     "Pleated filter 16x20x1",           "Filter",       "each",        450, 50, "Cool Supply Co"),
    ("FLT-20x25",     "Pleated filter 20x25x1",           "Filter",       "each",        550, 50, "Cool Supply Co"),
    ("FLT-16x25",     "Pleated filter 16x25x1",           "Filter",       "each",        500, 50, "Cool Supply Co"),
    ("DRN-CLN-32",    "Drain line cleaner 32oz",          "Chemical",     "bottle",     1100, 18, "Cool Supply Co"),
    ("COIL-CLN-1G",   "Evap/condenser coil cleaner 1gal", "Chemical",     "gallon",     2950, 12, "Cool Supply Co"),
    ("LEAK-DET-8",    "UV leak detection dye 8oz",        "Chemical",     "bottle",     3200, 6,  "Heritage Refrigerants"),
    ("DUC-TAPE-AL",   "Foil duct tape 2\" x 60yd",         "Tape",         "roll",        950, 20, "Pan Carib Metals"),
    ("WIR-THM-18-5",  "Thermostat wire 18/5 x 250ft",     "Wiring",       "roll",       8500, 6,  "Caribbean HVAC Parts"),
    ("WIR-THM-18-8",  "Thermostat wire 18/8 x 250ft",     "Wiring",       "roll",      11500, 4,  "Caribbean HVAC Parts"),
    ("THM-DIG-PRG",   "Digital programmable thermostat",  "Thermostat",   "each",       5500, 10, "Caribbean HVAC Parts"),
    ("THM-WIFI",      "WiFi smart thermostat",            "Thermostat",   "each",      14500, 5,  "Caribbean HVAC Parts"),
    ("SEN-PRE-LOW",   "Low pressure sensor",              "Sensor",       "each",       4200, 4,  "Heritage Refrigerants"),
    ("SEN-PRE-HI",    "High pressure sensor",             "Sensor",       "each",       4500, 4,  "Heritage Refrigerants"),
    ("GAU-MANIFOLD",  "Manifold gauge set R-410A/R-32",   "Tool",         "set",       18500, 2,  "Heritage Refrigerants"),
    ("VAC-PUMP-3CFM", "Vacuum pump 3 CFM",                "Tool",         "each",      28500, 1,  "Heritage Refrigerants"),
    ("BLT-V-A38",     "V-belt A38",                       "Belt",         "each",        650, 15, "Pan Carib Metals"),
    ("BLT-V-A42",     "V-belt A42",                       "Belt",         "each",        720, 15, "Pan Carib Metals"),
    ("BLT-V-A46",     "V-belt A46",                       "Belt",         "each",        780, 12, "Pan Carib Metals"),
    ("PAN-DRAIN-PVC", "PVC condensate drain pan 24\"",    "Drain",        "each",       3200, 6,  "Pan Carib Metals"),
    ("PMP-CON-AUTO",  "Condensate pump auto-shutoff",     "Pump",         "each",       8900, 4,  "Caribbean HVAC Parts"),
    ("SOL-VAL-1/4",   "Solenoid valve 1/4\" R-410A",      "Valve",        "each",       6200, 4,  "Heritage Refrigerants"),
    ("TXV-2T-R410",   "TXV 2-ton R-410A",                 "Valve",        "each",      14500, 3,  "Heritage Refrigerants"),
    ("TXV-3T-R410",   "TXV 3-ton R-410A",                 "Valve",        "each",      16500, 3,  "Heritage Refrigerants"),
    ("FLR-DRYER",     "Filter dryer 1/4\" SAE",           "Filter",       "each",       2400, 10, "Heritage Refrigerants"),
    ("REL-START-RB",  "Hard start kit / relay+capacitor", "Capacitor",    "kit",        4200, 8,  "Caribbean HVAC Parts"),
    ("UV-LAMP-24V",   "UV germicidal lamp 24V",           "Air Quality",  "each",       6900, 4,  "Cool Supply Co"),
    ("ION-AIR-CELL",  "Bipolar ionization air cell",      "Air Quality",  "each",      18500, 2,  "Cool Supply Co"),
    ("NUT-FLR-1/4",   "Flare nut 1/4\" (pack of 10)",     "Fittings",     "pack",        450, 25, "Pan Carib Metals"),
    ("NUT-FLR-3/8",   "Flare nut 3/8\" (pack of 10)",     "Fittings",     "pack",        550, 25, "Pan Carib Metals"),
    ("BRZ-ROD-15",    "Brazing rod 15% silver 1lb",       "Consumable",   "lb",        12500, 4,  "Pan Carib Metals"),
    ("NIT-CYL-80",    "Nitrogen cylinder 80 cu ft",       "Consumable",   "cylinder",   8500, 3,  "Heritage Refrigerants"),
    ("CLN-RAG-25",    "Microfiber cleaning rags (25pk)",  "Consumable",   "pack",       1200, 20, "Cool Supply Co"),
    ("PPE-GLV-NIT",   "Nitrile gloves (100 box)",         "PPE",          "box",        1800, 15, "Cool Supply Co"),
    ("PPE-GLS-SFT",   "Safety glasses ANSI Z87",          "PPE",          "each",        650, 25, "Cool Supply Co"),
    ("PPE-MSK-N95",   "N95 respirator (20 pack)",         "PPE",          "pack",       2400, 12, "Cool Supply Co"),
    ("BOLT-LAG-3",    "Lag bolt 1/4\" x 3\" (50pk)",      "Fasteners",    "pack",       1100, 12, "Pan Carib Metals"),
    ("PAD-NEO-18",    "Neoprene vibration pad 18\"x18\"", "Mount",        "each",       2200, 10, "Pan Carib Metals"),
    ("BRK-WALL-AC",   "Wall bracket 18-24K BTU",          "Mount",        "each",       4800, 8,  "Caribbean HVAC Parts"),
    ("BRK-WALL-AC-L", "Wall bracket 30-36K BTU",          "Mount",        "each",       6500, 6,  "Caribbean HVAC Parts"),
    ("FUSE-30A",      "Disconnect fuse 30A (3pk)",        "Electrical",   "pack",       1450, 10, "Caribbean HVAC Parts"),
    ("FUSE-60A",      "Disconnect fuse 60A (3pk)",        "Electrical",   "pack",       1850, 8,  "Caribbean HVAC Parts"),
    ("WHL-CSTR-3",    "Caster wheel 3\" swivel",          "Hardware",     "each",        850, 12, "Pan Carib Metals"),
    ("LBL-WARN-HV",   "Warning label HV (50pk)",          "Labels",       "pack",        650, 15, "Cool Supply Co"),
]

def seed_inventory(con, super_admin_id):
    print(f"\nSeeding inventory ({len(PARTS_CATALOG)} parts)...")
    existing_skus = _existing_codes(con, "parts", "sku")
    n_created = 0
    part_ids = []
    for (sku, name, cat, unit, cost, reorder, supplier) in PARTS_CATALOG:
        if sku in existing_skus:
            r = con.execute("SELECT id FROM parts WHERE sku = ?", (sku,)).fetchone()
            if r: part_ids.append((r["id"], cost))
            continue
        try:
            # Initial on-hand: 1.5x to 4x reorder point so most parts are above
            # threshold but a handful land low (creates reorder pressure).
            qty = max(0, int(reorder * random.uniform(0.6, 3.5)))
            pid = create_part({
                "sku": sku, "name": name, "category": cat,
                "unit": unit, "unit_cost": cost,
                "quantity": qty, "reorder_point": reorder,
                "supplier": supplier, "location": "Main Warehouse",
            })
            part_ids.append((pid, cost))
            n_created += 1
        except Exception as e:
            print(f"  ! {sku}: {e}")
    print(f"  + {n_created} new parts (total catalog: {len(part_ids)})")
    # A handful of purchase orders for restock pressure.
    n_po = 0
    suppliers = list({p[6] for p in PARTS_CATALOG})
    for sup in suppliers:
        sup_parts = [p for p in PARTS_CATALOG if p[6] == sup]
        if not sup_parts: continue
        # Build 1-2 POs per supplier.
        for _ in range(random.randint(1, 2)):
            chosen = random.sample(sup_parts, min(len(sup_parts), random.randint(3, 6)))
            lines = []
            for (sku, _n, _c, _u, cost, reorder, _s) in chosen:
                r = con.execute("SELECT id FROM parts WHERE sku = ?", (sku,)).fetchone()
                if not r: continue
                lines.append({"part_id": r["id"],
                              "quantity": int(reorder * random.uniform(1.5, 3.0)),
                              "expected_unit_cost": cost * random.uniform(0.95, 1.05)})
            if not lines: continue
            try:
                create_purchase_order(sup, lines, super_admin_id)
                n_po += 1
            except Exception as e:
                print(f"  ! PO {sup}: {e}")
    print(f"  + {n_po} purchase orders drafted")


# ── Step 9: payroll (fortnightly payslips across the horizon) ────────────
def seed_payroll(con, days_back, generated_by):
    """Generate fortnightly pay periods + payslips for every active staff
    member across the operational horizon. Techs get hourly pay; admins get
    fixed-salary pay; warehouse staff get hourly. All amounts in JMD."""
    print(f"\nSeeding payroll over the last {days_back} days...")
    # Build 14-day periods walking BACK from today.
    today = date.today()
    n_periods = max(1, days_back // 14)
    periods = []
    for i in range(n_periods):
        end   = today - timedelta(days=i * 14)
        start = end - timedelta(days=13)
        label = f"PP {start.isoformat()} – {end.isoformat()}"
        try:
            pid = create_pay_period(start.isoformat(), end.isoformat(),
                                    label, generated_by, "JMD")
            periods.append(pid)
        except Exception as e:
            pass
    print(f"  + {len(periods)} pay periods created")

    # Admin salary table (per fortnight, JMD).
    admin_salary = {
        "super_admin":       180_000,
        "supervisor_admin":  130_000,
        "system_admin":      120_000,
        "hr_admin":          120_000,
        "ceo_assistant":     115_000,
        "inventory_manager": 120_000,
        "dispatcher":         85_000,
        "warehouse_supervisor": 110_000,
    }
    admins = con.execute(
        "SELECT id, name, prid, role FROM admin_users WHERE active = 1"
    ).fetchall()
    techs = con.execute(
        "SELECT id, name, prid, role, hourly_rate, staff_type FROM technicians WHERE active = 1"
    ).fetchall()

    n_slips = 0
    for pid in periods:
        for a in admins:
            salary = admin_salary.get(a["role"], 100_000)
            bonus  = round(salary * random.uniform(0.0, 0.04), 2)
            try:
                upsert_payslip(pid, "admin", a["id"], a["name"], a["prid"],
                               {"fixed_salary": salary, "bonus": bonus,
                                "hours_regular": 0, "hours_overtime": 0,
                                "hourly_rate": 0, "overtime_rate": 0,
                                "other_deductions": 0,
                                "pay_periods_per_year": 26}, generated_by)
                n_slips += 1
            except Exception as e:
                pass
        for t in techs:
            rate = float(t["hourly_rate"] or 0)
            ot_rate = rate * 1.5
            # 80h base over 14 days + 0–18h overtime; apprentices fewer hours.
            base_h = random.uniform(72, 88) if t["role"] != "apprentice" else random.uniform(60, 80)
            ot_h   = random.uniform(0, 12) if t["role"] != "apprentice" else random.uniform(0, 4)
            try:
                upsert_payslip(pid, "tech", t["id"], t["name"], t["prid"],
                               {"hours_regular": round(base_h, 2),
                                "hours_overtime": round(ot_h, 2),
                                "hourly_rate": rate, "overtime_rate": ot_rate,
                                "fixed_salary": 0, "bonus": 0,
                                "other_deductions": 0,
                                "pay_periods_per_year": 26}, generated_by)
                n_slips += 1
            except Exception as e:
                pass
    print(f"  + {n_slips} payslips generated")


# ── Main ─────────────────────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--apply", action="store_true",
                    help="Commit writes (without this, exits before any change).")
    ap.add_argument("--residential", type=int, default=140,
                    help="Number of residential customers (default 140).")
    ap.add_argument("--commercial",  type=int, default=60,
                    help="Number of commercial customers (default 60).")
    ap.add_argument("--days", type=int, default=180,
                    help="Operational horizon in days to backfill (default 180).")
    args = ap.parse_args()

    total_customers = args.residential + args.commercial
    # Rough estimates so the dry-run message stays accurate.
    scale = max(1.0, args.days / 180.0)
    est_visits   = int(args.residential * 12 * scale + args.commercial * 16 * scale)
    est_invoices = est_visits // 3
    if not args.apply:
        print("DRY RUN — no writes. Re-run with --apply to commit.")
        print(f"Will create: {len(ADMIN_ROSTER)} admins, {len(TECH_ROSTER)} field techs,")
        print(f"             {len(WAREHOUSE_ROSTER)} warehouse staff, {total_customers} customers")
        print(f"             ({args.residential} residential + {args.commercial} commercial),")
        print(f"             ~{int(total_customers * 2.0)} equipment, ~{est_visits:,} visits "
              f"over {args.days} days, ~{est_invoices:,} invoices.")
        return

    creds = []
    con = _con()
    try:
        wipe_customers(con)
        con.commit()

        seed_admins(con, creds)
        seed_techs(con, creds)
        seed_warehouse(con, creds)

        # Collect tech ids for visit assignment.
        techs = [r["id"] for r in con.execute(
            "SELECT id FROM technicians WHERE active=1 AND staff_type='tech' AND role IN ('lead_tech','tech','apprentice')"
        ).fetchall()]

        customers = seed_customers(con, creds,
                                   n_residential=args.residential,
                                   n_commercial=args.commercial)
        con.commit()

        equipment = seed_equipment(con, customers)
        con.commit()

        visits = seed_visits(con, customers, equipment, techs, days_back=args.days)
        con.commit()

        seed_invoices(con, customers, visits, days_back=args.days)
        con.commit()

        seed_payments(con)
        con.commit()

        # Use the first super_admin as the "generated_by" actor for
        # inventory + payroll bootstrap rows.
        sa = con.execute(
            "SELECT id FROM admin_users WHERE role = 'super_admin' AND active = 1 "
            "ORDER BY id LIMIT 1"
        ).fetchone()
        sa_id = sa["id"] if sa else 1
        seed_inventory(con, sa_id)
        con.commit()
        seed_payroll(con, days_back=args.days, generated_by=sa_id)
        con.commit()
    finally:
        con.close()

    out_path = "/tmp/pc_creds_30_200.tsv"
    with open(out_path, "w") as f:
        f.write(f"# PrimeCool seed_30_200 — {datetime.now(timezone.utc).isoformat()}\n")
        f.write("# columns: kind\tcode\tname\trole\tlogin_id\tsecret\n\n")
        for row in creds:
            f.write("\t".join(str(x) for x in row) + "\n")
    print(f"\nDone. {len(creds)} credentials written to {out_path}")


if __name__ == "__main__":
    main()
