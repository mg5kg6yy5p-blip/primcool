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

from database import (  # type: ignore
    _con, _hash_pin, _hash_password,
    create_admin_user, create_tech, create_customer, create_equipment,
    create_visit, create_invoice_with_lines,
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
    # Average ~12 visits per customer over 180 days for residential,
    # ~16 for commercial.
    target_per_customer = {"residential": 12, "commercial": 16}
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
def seed_invoices(con, customers, visits):
    print(f"\nSeeding invoices (one per ~3 completed visits)...")
    # Group completed visits by customer.
    by_cust = {}
    for vid, cid, status in visits:
        if status == "completed":
            by_cust.setdefault(cid, []).append(vid)
    today = date.today()
    invoices = []
    for cid, vlist in by_cust.items():
        # ~1 invoice per 3 visits.
        n_inv = max(1, len(vlist) // 3)
        for i in range(n_inv):
            issued = today - timedelta(days=random.randint(0, 150))
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
                    "status":     random.choices(["sent","paid","draft"], weights=[40,55,5])[0],
                    "line_items": lines,
                    "notes": "",
                })
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
    n_paid = 0
    for r in rows:
        # Mark ~75% as paid in full.
        if random.random() > 0.75:
            continue
        try:
            con.execute(
                "INSERT INTO invoice_payments "
                "(invoice_id, paid_at, amount, method, reference, recorded_by) "
                "VALUES (?, ?, ?, 'bank_transfer', ?, NULL)",
                (r["id"], (date.fromisoformat(r["issue_date"]) + timedelta(days=random.randint(3, 28))).isoformat(),
                 r["total"], f"REF-{random.randint(100000, 999999)}"),
            )
            con.execute("UPDATE invoices SET status='paid' WHERE id = ?", (r["id"],))
            n_paid += 1
        except Exception as e:
            pass
    print(f"  + {n_paid} payments recorded")

# ── Main ─────────────────────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--apply", action="store_true",
                    help="Commit writes (without this, exits before any change).")
    args = ap.parse_args()

    if not args.apply:
        print("DRY RUN — no writes. Re-run with --apply to commit.")
        print(f"Will create: {len(ADMIN_ROSTER)} admins, {len(TECH_ROSTER)} field techs,")
        print(f"             {len(WAREHOUSE_ROSTER)} warehouse staff, 200 customers,")
        print(f"             ~400 equipment, ~2,400 visits, ~800 invoices.")
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

        customers = seed_customers(con, creds)
        con.commit()

        equipment = seed_equipment(con, customers)
        con.commit()

        visits = seed_visits(con, customers, equipment, techs)
        con.commit()

        seed_invoices(con, customers, visits)
        con.commit()

        seed_payments(con)
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
