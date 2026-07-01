#!/usr/bin/env python3
"""Single-connection bulk customer seeder.

Reuses one SQLite connection across all 200 customer/equipment/visit/
invoice writes so we don't trip over WAL journal-mode handshake locks
that the regular per-call _con() pattern hits at this scale. Wraps
all writes in one transaction; one COMMIT at the end.

Run this AFTER scripts/seed_30_200.py has seeded admins + techs (the
target 30-staff roster). Customer-side rows wiped on entry.
"""
from __future__ import annotations
import os, random, secrets, sys
from datetime import datetime, date, timedelta, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

from database import _con, _hash_pin, _enc, _enc_dict, _email_hash  # type: ignore

random.seed(42)

FIRST_NAMES = ["Andre","Anya","Camille","Carlton","Cherise","Christine","Damion","Devon","Donovan","Garnet","Howard","Jermaine","Junior","Karen","Kemar","Kevon","Latoya","Marcus","Maurice","Norval","Owen","Patricia","Renaldo","Renata","Sasha","Shanice","Sherwin","Suzette","Tameka","Tanya","Tomoya","Tasha","Alicia","Maxine","Latrice","Donna","Roxanne","Trevor"]
LAST_NAMES = ["Brown","Clarke","Wright","Reid","Thompson","Williams","Bennett","Foster","Campbell","Beckford","Bailey","Palmer","Edwards","Powell","Henry","Robinson","Bryan","McKenzie","Lyn","Cooper","Chin","Lewis","Cooke","Grant","Spence","Reynolds","Walters","Salmon","Patterson"]
COMPANY_PREFIX = ["Constant Spring","Liguanea","Half Way Tree","Portmore","New Kingston","Spanish Town","Mandeville","Ocho Rios","Mobay","Negril","Linstead","May Pen","Old Harbour","Annotto Bay","Falmouth","Browns Town","Yallahs"]
COMPANY_SUFFIX = ["Ltd","Holdings","Group","Services","Co","Enterprises"]
STREETS = ["Old Hope Rd","Constant Spring Rd","Hagley Park Rd","Half Way Tree Rd","Lady Musgrave Rd","Mountain View Ave","Trafalgar Rd","Knutsford Blvd","Waterloo Rd","South Camp Rd"]
PARISHES = ["Kingston 5","Kingston 6","Kingston 8","Kingston 10","Spanish Town","Portmore","Mandeville","Ocho Rios","Montego Bay"]
EQUIP_TYPES = [("Lobby Split","Daikin","FTKM50R"),("Open Plan Central","Carrier","38UVH-024"),("Lab Water Cooler","Trane","WSC036"),("Den Central","LG","LSU240HEV"),("Guest Bedroom Split","Mitsubishi","MSZ-GL18"),("Server Room","Daikin","FFA50RVMA"),("Warehouse Spot","Carrier","40MAH"),("Living Room Central","Trane","XV20i")]

def _pin():
    return f"{secrets.randbelow(900_000) + 100_000}"

def _phone():
    return f"+1876{random.randint(2000000, 9999999)}"

def _addr():
    return f"{random.randint(1,199)} {random.choice(STREETS)}, {random.choice(PARISHES)}"

def main():
    now = datetime.now(timezone.utc).isoformat()
    today = date.today()
    con = _con()
    # SQLite optimization for bulk: WAL is already on, but bump
    # cache_size and turn off synchronous JUST for this script's
    # write-heavy phase. Reset before close.
    con.execute("PRAGMA synchronous=OFF")
    con.execute("PRAGMA cache_size=-10000")  # 10MB page cache
    con.execute("PRAGMA temp_store=MEMORY")

    print("Wiping customer-side tables...")
    con.execute("PRAGMA defer_foreign_keys=ON")
    con.execute("BEGIN")
    for sql in [
        "DELETE FROM visit_photos WHERE visit_id IN (SELECT id FROM maintenance_visits)",
        "DELETE FROM visit_parts WHERE visit_id IN (SELECT id FROM maintenance_visits)",
        "DELETE FROM visit_readings WHERE visit_id IN (SELECT id FROM maintenance_visits)",
        "DELETE FROM visit_signatures WHERE visit_id IN (SELECT id FROM maintenance_visits)",
        "DELETE FROM invoice_line_items WHERE invoice_id IN (SELECT id FROM invoices)",
        "DELETE FROM invoice_payments WHERE invoice_id IN (SELECT id FROM invoices)",
        "DELETE FROM customer_credit_movements",
        "DELETE FROM customer_pin_resets",
        "DELETE FROM service_requests WHERE customer_id IS NOT NULL",
        "DELETE FROM reviews WHERE customer_id IS NOT NULL",
        "DELETE FROM invoices",
        "DELETE FROM maintenance_visits",
        "DELETE FROM equipment",
        "DELETE FROM sessions WHERE subject_type='customer'",
        "DELETE FROM customers",
    ]:
        try: con.execute(sql)
        except Exception as e: print(f"  skip: {sql[:50]}... ({e})")
    con.commit()

    # ── Customers ────────────────────────────────────────────────────────
    print("Inserting 200 customers...")
    creds = []
    customer_ids = []
    con.execute("BEGIN")
    for i in range(1, 141):
        name = f"{random.choice(FIRST_NAMES)} {random.choice(LAST_NAMES)}"
        pin = _pin()
        code = f"RES-{i:03d}"
        enc = _enc_dict("customers", {
            "email":   f"{name.lower().replace(' ','.')}{i}@example.jm",
            "phone":   _phone(),
            "address": _addr(),
            "notes":   "",
        })
        cur = con.execute(
            "INSERT INTO customers (customer_code, name, company, email, email_hash, phone, address, notes, pin_hash, customer_type, created_at) "
            "VALUES (?, ?, '', ?, ?, ?, ?, ?, ?, 'residential', ?)",
            (code, name, enc["email"], enc["email_hash"], enc["phone"], enc["address"], enc["notes"], _hash_pin(pin), now),
        )
        customer_ids.append((cur.lastrowid, code, "residential"))
        creds.append(("CUSTOMER", code, name, "residential", code, pin))
    for i in range(1, 61):
        company = f"{random.choice(COMPANY_PREFIX)} {random.choice(COMPANY_SUFFIX)}"
        contact = f"{random.choice(FIRST_NAMES)} {random.choice(LAST_NAMES)}"
        pin = _pin()
        code = f"COM-{i:03d}"
        email = f"ap@{company.lower().replace(' ','')}.example.jm"
        enc = _enc_dict("customers", {
            "email": email, "phone": _phone(), "address": _addr(), "notes": "",
        })
        cur = con.execute(
            "INSERT INTO customers (customer_code, name, company, email, email_hash, phone, address, notes, pin_hash, customer_type, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'commercial', ?)",
            (code, contact, company, enc["email"], enc["email_hash"], enc["phone"], enc["address"], enc["notes"], _hash_pin(pin), now),
        )
        customer_ids.append((cur.lastrowid, code, "commercial"))
        creds.append(("CUSTOMER", code, f"{contact} ({company})", "commercial", code, pin))
    con.commit()
    print(f"  + {len(customer_ids)} customers")

    # ── Equipment ────────────────────────────────────────────────────────
    print("Inserting equipment (1-3 per residential, 2-5 per commercial)...")
    equipment = []
    con.execute("BEGIN")
    for cid, code, ctype in customer_ids:
        n = random.choices([1,2,3], weights=[55,30,15])[0] if ctype == "residential" else random.choices([2,3,4,5], weights=[30,40,20,10])[0]
        for k in range(n):
            etype, brand, model = random.choice(EQUIP_TYPES)
            cur = con.execute(
                "INSERT INTO equipment (customer_id, name, type, model, serial_number, location, notes, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (cid, f"{etype} #{k+1}", etype, f"{brand} {model}",
                 _enc(f"SN-{random.randint(10000,999999)}"),
                 _enc(etype),
                 _enc(f"R-{random.choice(['410A','32','22'])}"),
                 now),
            )
            equipment.append((cur.lastrowid, cid))
    con.commit()
    print(f"  + {len(equipment)} equipment units")

    # ── Visits ──────────────────────────────────────────────────────────
    print("Inserting visits (~12-16 per customer, last 180 days)...")
    techs = [r["id"] for r in con.execute(
        "SELECT id FROM technicians WHERE active=1 AND staff_type='tech'"
    ).fetchall()]
    if not techs:
        techs = [r["id"] for r in con.execute("SELECT id FROM technicians WHERE active=1").fetchall()]
    eq_by_cust = {}
    for eid, cid in equipment:
        eq_by_cust.setdefault(cid, []).append(eid)
    visits = []
    con.execute("BEGIN")
    for cid, code, ctype in customer_ids:
        n = 12 if ctype == "residential" else 16
        for _ in range(n):
            d = today - timedelta(days=random.randint(0, 180))
            vtype = random.choice(["PM","PM","PM","CM","CM"])
            status = random.choices(["completed","in_progress","scheduled"], weights=[80,10,10])[0]
            eq_id = random.choice(eq_by_cust.get(cid, [None])) if eq_by_cust.get(cid) else None
            tech_id = random.choice(techs) if techs else None
            cur = con.execute(
                "INSERT INTO maintenance_visits (customer_id, equipment_id, visit_type, scheduled_date, scheduled_time, assigned_tech_id, status, scope_of_work, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (cid, eq_id, vtype, d.isoformat(),
                 f"{random.randint(8,15):02d}:{random.choice(['00','15','30','45'])}",
                 tech_id, status,
                 "Routine PM" if vtype == "PM" else "Service call",
                 now),
            )
            visits.append((cur.lastrowid, cid, status))
    con.commit()
    print(f"  + {len(visits)} visits")

    # ── Invoices ────────────────────────────────────────────────────────
    print("Inserting invoices (one per ~3 completed visits)...")
    completed_by_cust = {}
    for vid, cid, status in visits:
        if status == "completed":
            completed_by_cust.setdefault(cid, []).append(vid)
    n_inv = 0
    con.execute("BEGIN")
    for cid, vlist in completed_by_cust.items():
        for i in range(max(1, len(vlist)//3)):
            issued = today - timedelta(days=random.randint(0, 150))
            due    = issued + timedelta(days=30)
            line_count = random.randint(1, 4)
            subtotal = 0.0
            invoice_status = random.choices(["sent","paid","draft"], weights=[40,55,5])[0]
            inv_cur = con.execute(
                "INSERT INTO invoices (customer_id, invoice_number, issue_date, due_date, currency, status, subtotal, tax_rate, tax_amount, total, amount_paid, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, 'JMD', ?, 0, 0.15, 0, 0, 0, ?, ?)",
                (cid, f"INV-2026-{n_inv+10000:05d}", issued.isoformat(), due.isoformat(), invoice_status, now, now),
            )
            inv_id = inv_cur.lastrowid
            for k in range(line_count):
                qty = random.randint(1, 3)
                unit = round(random.uniform(2500, 28000), 2)
                line_total = qty * unit
                subtotal += line_total
                con.execute(
                    "INSERT INTO invoice_line_items (invoice_id, line_type, sort_order, description, quantity, unit_price, line_total) "
                    "VALUES (?, 'service', ?, ?, ?, ?, ?)",
                    (inv_id, k,
                     random.choice(["PM service — inspection","Refrigerant R-410A top-up","Capacitor replacement","Drain line clean-out","Compressor diagnostic","Service call after-hours"]),
                     qty, unit, line_total),
                )
            tax = round(subtotal * 0.15, 2)
            total = round(subtotal + tax, 2)
            paid = total if invoice_status == "paid" else 0.0
            con.execute("UPDATE invoices SET subtotal=?, tax_amount=?, total=?, amount_paid=? WHERE id=?",
                        (subtotal, tax, total, paid, inv_id))
            if invoice_status == "paid":
                con.execute(
                    "INSERT INTO invoice_payments (invoice_id, payment_date, amount, method, reference, created_at) "
                    "VALUES (?, ?, ?, 'bank_transfer', ?, ?)",
                    (inv_id, (issued + timedelta(days=random.randint(3,28))).isoformat(),
                     total, f"REF-{random.randint(100000,999999)}", now),
                )
            n_inv += 1
    con.commit()
    print(f"  + {n_inv} invoices")

    # Restore synchronous=FULL.
    con.execute("PRAGMA synchronous=FULL")
    con.close()

    # Credentials file
    out = "/tmp/pc_creds_30_200.tsv"
    # Preserve existing admin+staff creds; append customers.
    existing = []
    if os.path.exists(out):
        with open(out) as f:
            for line in f:
                if line.startswith(("ADMIN", "STAFF")):
                    existing.append(line.rstrip("\n"))
    with open(out, "w") as f:
        f.write(f"# PrimeCool seed_customers_fast — {now}\n")
        f.write("# columns: kind\tcode\tname\trole\tlogin_id\tsecret\n\n")
        for line in existing:
            f.write(line + "\n")
        for row in creds:
            f.write("\t".join(str(x) for x in row) + "\n")

    print(f"\nDone. {len(creds)} customer creds appended to {out}")


if __name__ == "__main__":
    main()
