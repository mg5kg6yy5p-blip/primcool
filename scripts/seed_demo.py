"""Seed demo data for walkthroughs. Idempotent on re-run (skips if customers exist)."""
import os, sys, sqlite3
from datetime import datetime, timezone, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Ensure crypto key is loaded (read from .dev.env if present)
if not os.environ.get("FIELD_ENCRYPTION_KEY"):
    try:
        with open(".dev.env") as f:
            for line in f:
                if line.startswith("export "):
                    k, v = line[7:].strip().split("=", 1)
                    os.environ.setdefault(k, v.strip('"'))
    except FileNotFoundError:
        pass

from crypto import encrypt, det_encrypt, email_hash
from database import _hash_pin

DB = "submissions.db"
now_iso = datetime.now(timezone.utc).isoformat()

c = sqlite3.connect(DB)
c.row_factory = sqlite3.Row

# Skip if demo customers already present
existing = c.execute("SELECT COUNT(*) FROM customers WHERE customer_code LIKE 'DEMO-%'").fetchone()[0]
if existing >= 2:
    print(f"demo data already present ({existing} demo customers). skipping.")
    print("--- existing ---")
    for r in c.execute("SELECT id, customer_code, name FROM customers WHERE customer_code LIKE 'DEMO-%'"):
        print(" ", dict(r))
    sys.exit(0)

# ─── Customers ──────────────────────────────────────────────────
def add_customer(code, name, ctype, company, email, phone, address, notes, pin_plain):
    row = (
        code, name, company,
        det_encrypt(email),
        encrypt(phone),
        encrypt(address),
        encrypt(notes),
        _hash_pin(pin_plain),
        now_iso, "pin", None, ctype, None, 0, None, None, 1, None, None,
        email_hash(email), 0, None, 1,
    )
    cur = c.execute("""
        INSERT INTO customers
        (customer_code,name,company,email,phone,address,notes,pin_hash,
         created_at,auth_mode,password_hash,customer_type,mfa_secret,mfa_enabled,
         backup_codes,deletion_requested_at,active,terminated_at,last_login_at,
         email_hash,pin_failed_count,pin_locked_until,hub_id)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    """, row)
    return cur.lastrowid

c1 = add_customer(
    "DEMO-RES-001", "Jane Brown", "residential",
    None, "jane.brown@example.jm", "+18761112222",
    "12 Hope Road, Kingston 10\nApt 4B", "Prefers morning service. Two AC units.",
    "1234"
)
c2 = add_customer(
    "DEMO-COM-001", "Acme Commercial Ltd.", "commercial",
    "Acme Commercial Ltd.", "facilities@acme.example.jm", "+18764445555",
    "23 Knutsford Boulevard, Kingston 5\nFloor 3", "After-hours service only. Manager: John Smith.",
    "5678"
)
print(f"customers seeded: c1={c1} c2={c2}")

# ─── Equipment ──────────────────────────────────────────────────
def add_equipment(customer_id, name, etype, model, serial, location, notes):
    cur = c.execute("""
        INSERT INTO equipment (customer_id,name,type,model,serial_number,location,notes,created_at)
        VALUES (?,?,?,?,?,?,?,?)
    """, (customer_id, name, etype, model,
          encrypt(serial), encrypt(location), encrypt(notes), now_iso))
    return cur.lastrowid

e1 = add_equipment(c1, "Living Room Split AC", "split", "LG-LS122HEV1",
                   "SN-2024-9981", "Living room, east wall, 2.4m height",
                   "Last filter swap Jan 2026. Owner notes mild hum at startup.")
e2 = add_equipment(c1, "Bedroom Split AC", "split", "Samsung-AR12TXFZ",
                   "SN-2024-9982", "Master bedroom, north wall",
                   "Installed 2023. Drainage line periodically clogs.")
e3 = add_equipment(c2, "Conference Room AC #2", "central", "Trane-XR16",
                   "SN-COM-44120", "Roof, north side, near exhaust stack",
                   "Commercial unit. Service contract active. PM every 90 days.")
e4 = add_equipment(c2, "Server Room Precision Unit", "split", "Liebert-DSE060",
                   "SN-COM-44121", "Floor 3, server room, dedicated breaker",
                   "Critical load. Backup unit required during maintenance.")
print(f"equipment seeded: e1..e4 = {[e1,e2,e3,e4]}")

# ─── Visits ─────────────────────────────────────────────────────
def add_visit(customer_id, equip_id, vtype, status, sched_date, sched_time,
              completed_date, work_done, work_summary, scope, notes,
              tech_id, start_time=None, end_time=None):
    cur = c.execute("""
        INSERT INTO maintenance_visits
        (customer_id,equipment_id,visit_type,status,scheduled_date,scheduled_time,
         completed_date,technician,work_done,parts_replaced,notes,assigned_tech_id,
         start_time,end_time,created_at,submitted_at,scope_of_work,estimated_duration_min,
         work_done_summary,hub_id)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    """, (
        customer_id, equip_id, vtype, status, sched_date, sched_time,
        completed_date, "Test Technician",
        encrypt(work_done), encrypt(""), encrypt(notes), tech_id,
        start_time, end_time, now_iso, completed_date,
        encrypt(scope), 90, encrypt(work_summary), 1,
    ))
    return cur.lastrowid

tech_id = c.execute("SELECT id FROM technicians ORDER BY id LIMIT 1").fetchone()[0]
today = datetime.now(timezone.utc).date()

v1 = add_visit(c1, e1, "PM", "completed",
               (today - timedelta(days=30)).isoformat(), "09:00",
               (today - timedelta(days=30)).isoformat() + "T10:30:00",
               "Quarterly preventive maintenance completed. Cleaned coils, replaced air filter, verified refrigerant pressures within spec.",
               "PM complete — all readings nominal.",
               "Quarterly PM on living-room split. Inspect filter, evap/condenser coils, drain line, refrigerant charge, electrical connections.",
               "Customer mentioned mild hum on startup — verified normal compressor inrush, no fault.",
               tech_id,
               (today - timedelta(days=30)).isoformat() + "T09:05:00",
               (today - timedelta(days=30)).isoformat() + "T10:30:00")

v2 = add_visit(c1, e2, "CM", "completed",
               (today - timedelta(days=15)).isoformat(), "14:00",
               (today - timedelta(days=15)).isoformat() + "T15:45:00",
               "Drain line cleared. Replaced anti-microbial pan tablet. Tested cooling cycle.",
               "Drain blockage resolved — biofilm buildup at trap.",
               "Customer reported water dripping from indoor unit. Diagnose and resolve drainage issue.",
               "Recommended quarterly drain flush going forward.",
               tech_id,
               (today - timedelta(days=15)).isoformat() + "T14:10:00",
               (today - timedelta(days=15)).isoformat() + "T15:45:00")

v3 = add_visit(c2, e3, "PM", "completed",
               (today - timedelta(days=7)).isoformat(), "18:00",
               (today - timedelta(days=7)).isoformat() + "T20:30:00",
               "90-day PM on conference room unit. Full coil clean, blower inspection, condensate line clear, refrigerant verified.",
               "PM complete — supply air 52F at panel, no faults logged.",
               "Standard 90-day PM per service contract. Includes coil clean, blower inspection, drain check, electrical check, refrigerant verification.",
               "After-hours per commercial agreement. No occupant impact.",
               tech_id,
               (today - timedelta(days=7)).isoformat() + "T18:00:00",
               (today - timedelta(days=7)).isoformat() + "T20:30:00")

v4 = add_visit(c2, e4, "CM", "in_progress",
               today.isoformat(), "22:00",
               None,
               "Diagnosing intermittent high-pressure trip on server-room precision unit.",
               "",
               "Server-room unit faulting on high pressure roughly every 4 hours. Need to isolate cause — condenser, charge, or sensor.",
               "Critical load — coordinate with IT for backup unit before any service interruption.",
               tech_id,
               today.isoformat() + "T22:00:00",
               None)

v5 = add_visit(c1, e1, "PM", "scheduled",
               (today + timedelta(days=60)).isoformat(), "09:00",
               None,
               "",
               "",
               "Next quarterly PM on living-room split AC.",
               "",
               tech_id)

print(f"visits seeded: v1..v5 = {[v1,v2,v3,v4,v5]}")

# ─── Visit readings (Section 6 of detail view) ──────────────────
for vid in (v1, v3):
    c.execute("""INSERT INTO visit_readings
        (visit_id,pressure_high,pressure_low,temp_supply,temp_return,delta_t,
         superheat,subcool,approach_temp,notes,recorded_by,recorded_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
    """, (vid, 389.0, 118.0, 52.0, 72.0, 20.0, 15.0, 8.0, 2.4,
          encrypt("Within manufacturer spec."), tech_id, now_iso))
print("readings seeded for v1, v3")

# ─── Invoices ───────────────────────────────────────────────────
def add_invoice(visit_id, customer_id, sub, tax_rate, status, amount_paid, paid_at=None):
    tax = round(sub * tax_rate / 100.0, 2)
    total = sub + tax
    inv_num = f"INV-2026-{visit_id:05d}"
    cur = c.execute("""
        INSERT INTO invoices
        (invoice_number,customer_id,visit_id,issue_date,due_date,status,
         subtotal,tax_rate,tax_amount,total,amount_paid,currency,notes,sent_at,
         paid_at,created_by,created_at,updated_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    """, (inv_num, customer_id, visit_id, today.isoformat(),
          (today + timedelta(days=30)).isoformat(), status,
          sub, tax_rate, tax, total, amount_paid, "JMD",
          encrypt("Demo invoice for walkthrough."), now_iso, paid_at, 1, now_iso, now_iso))
    return cur.lastrowid, inv_num, total

i1 = add_invoice(v1, c1, 12000.0, 0.0, "sent", 0.0)
i2 = add_invoice(v2, c1, 8500.0, 0.0, "paid", 8500.0, now_iso)
i3 = add_invoice(v3, c2, 45000.0, 15.0, "sent", 0.0)
print(f"invoices seeded: {i1[1]}={i1[2]}  {i2[1]}={i2[2]}  {i3[1]}={i3[2]}")

c.commit()

# ─── Assign tech to seeded 5S assets so audits work ────────────
c.execute("UPDATE fs_assets SET assigned_tech_id=? WHERE assigned_tech_id IS NULL AND asset_code IN ('VAN-KIN-01','TKIT-KIN-01')", (tech_id,))
c.commit()
print("5S assets assigned to tech_id =", tech_id)

print()
print("=" * 60)
print("DEMO SEED COMPLETE")
print("=" * 60)
print(f"  Residential customer:  id={c1}  code=DEMO-RES-001  Jane Brown (PIN 1234)")
print(f"  Commercial  customer:  id={c2}  code=DEMO-COM-001  Acme Commercial Ltd. (PIN 5678)")
print(f"  Equipment:             ids={[e1,e2,e3,e4]}")
print(f"  Visits (PM/CM mix):    ids={[v1,v2,v3,v4,v5]}")
print(f"  Invoices:              {i1[1]} (unpaid)  {i2[1]} (paid)  {i3[1]} (unpaid + GCT)")
