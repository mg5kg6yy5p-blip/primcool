"""Full-staffed "upside of operations" demo seed for PrimeCool dev DB.

Treats 2026-05-21 as the present (month 5 of year 6 of the company).
Idempotent: skips if RES-001 customer exists.

Run:
  source .dev.env && python3 scripts/seed_full_demo.py
"""
from __future__ import annotations

import os
import sys
import random
import sqlite3
import hashlib
from datetime import datetime, timezone, timedelta, date

# ── env wiring (must happen before importing crypto/database) ─────────────
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if not os.environ.get("FIELD_ENCRYPTION_KEY"):
    try:
        with open(".dev.env") as f:
            for line in f:
                if line.startswith("export "):
                    k, v = line[7:].strip().split("=", 1)
                    os.environ.setdefault(k, v.strip('"'))
    except FileNotFoundError:
        pass

from crypto import encrypt, det_encrypt, email_hash  # noqa: E402
from database import (  # noqa: E402
    _hash_pin, _hash_password,
    bootstrap_super_admin, init_db,
    compute_payslip_amounts,
)

DB = "submissions.db"
TODAY = date(2026, 5, 21)
NOW_DT = datetime(2026, 5, 21, 12, 0, 0, tzinfo=timezone.utc)
NOW_ISO = NOW_DT.isoformat()

random.seed(20260521)

# Ensure schema is up.
init_db()

con = sqlite3.connect(DB)
con.row_factory = sqlite3.Row

# Idempotency guard
existing = con.execute(
    "SELECT COUNT(*) FROM customers WHERE customer_code LIKE 'RES-%'"
).fetchone()[0]
if existing >= 5:
    print(f"demo data already seeded ({existing} RES-* customers); skipping.")
    sys.exit(0)


def iso(dt: datetime) -> str:
    return dt.isoformat()


def rand_phone() -> str:
    return f"+1876-{random.randint(200,899)}-{random.randint(1000,9999)}"


def rand_date_between(d_start: date, d_end: date) -> date:
    delta = (d_end - d_start).days
    return d_start + timedelta(days=random.randint(0, max(0, delta)))


# ────────────────────────────────────────────────────────────────────────
# 1. ADMINS
# ────────────────────────────────────────────────────────────────────────
print("seeding admins …")

# director — use existing bootstrap helper (idempotent)
bs_user = os.environ.get("BOOTSTRAP_ADMIN_USERNAME", "director")
bs_pw = os.environ.get("BOOTSTRAP_ADMIN_PASSWORD", "PrimeCool!Dev2026")
bs_email = os.environ.get("BOOTSTRAP_ADMIN_EMAIL", "rjuggar@aol.com")
bs_name = os.environ.get("BOOTSTRAP_ADMIN_NAME", "Ray Juggar")
bootstrap_super_admin(bs_user, bs_pw, bs_name, bs_email)

director_id = con.execute(
    "SELECT id FROM admin_users WHERE username=?", (bs_user,)
).fetchone()[0]


def insert_admin(username, name, email, role, hire_date):
    pw_hash = _hash_password("PrimeCool!Dev2026")
    # PRID generation: use the existing one only via create_admin_user; for
    # idempotent direct INSERT we craft a deterministic-ish PRID.
    initials = "".join(p[0].upper() for p in name.split()[:2])
    yyyymm = hire_date.replace("-", "")[:6]
    # find a free suffix
    suffix = 1
    while True:
        prid = f"PC{initials}{yyyymm}{suffix:02d}"
        if not con.execute("SELECT 1 FROM admin_users WHERE prid=?", (prid,)).fetchone():
            break
        suffix += 1
    con.execute(
        """INSERT INTO admin_users
           (username, password_hash, name, email, email_hash, phone,
            role, prid, hire_date, active, created_by, created_at)
           VALUES (?,?,?,?,?,?,?,?,?,1,?,?)""",
        (username, pw_hash, name,
         det_encrypt(email), email_hash(email),
         encrypt(rand_phone()),
         role, prid, hire_date, director_id, NOW_ISO),
    )
    return con.execute("SELECT id FROM admin_users WHERE username=?", (username,)).fetchone()[0]


admin_specs = [
    ("supervisor", "Andre Walker",    "andre.walker@primecool.example.jm",   "supervisor_admin",  "2025-01-10"),
    ("sysadmin",   "Damion Reid",     "damion.reid@primecool.example.jm",    "system_admin",      "2024-08-15"),
    ("hr",         "Camille Bennett", "camille.bennett@primecool.example.jm","hr_admin",          "2024-09-01"),
    ("ceoasst",    "Latoya Thompson", "latoya.thompson@primecool.example.jm","ceo_assistant",     "2025-02-01"),
    ("invmgr",     "Trevor Edwards",  "trevor.edwards@primecool.example.jm", "inventory_manager", "2024-11-01"),
]
admin_ids = {"director": director_id}
for u, n, e, r, h in admin_specs:
    row = con.execute("SELECT id FROM admin_users WHERE username=?", (u,)).fetchone()
    if row:
        admin_ids[u] = row[0]
    else:
        admin_ids[u] = insert_admin(u, n, e, r, h)
con.commit()
print(f"  admins: {admin_ids}")

# ────────────────────────────────────────────────────────────────────────
# 2. TECHNICIANS
# ────────────────────────────────────────────────────────────────────────
print("seeding technicians …")

TECH_SPECS = [
    ("T01", "Marcus Brown",      "lead_tech",  "2024-02-15", 3500),
    ("T02", "Andre Williams",    "tech",       "2024-04-01", 2800),
    ("T03", "Damion Bryan",      "tech",       "2024-06-10", 2800),
    ("T04", "Jermaine Clarke",   "tech",       "2024-09-01", 2200),
    ("T05", "Kevon Anderson",    "tech",       "2024-11-20", 2200),
    ("T06", "Tasha Henry",       "tech",       "2025-01-15", 2200),
    ("T07", "Devon Reid",        "tech",       "2025-04-01", 2000),
    ("T08", "Shanique Powell",   "apprentice", "2025-08-10", 1800),
    ("T09", "Romario Cooper",    "apprentice", "2025-11-05", 1800),
    ("T10", "Renee Palmer",      "apprentice", "2026-02-15", 1800),
    ("T11", "Junior McKenzie",   "apprentice", "2026-03-10", 1800),
    ("T12", "Alicia Bailey",     "apprentice", "2026-04-20", 1800),
]


def insert_tech(code, name, role, hire_date, rate):
    em = f"{name.lower().replace(' ', '.')}@primecool.example.jm"
    initials = "".join(p[0].upper() for p in name.split()[:2])
    yyyymm = hire_date.replace("-", "")[:6]
    suffix = 1
    while True:
        prid = f"PC{initials}{yyyymm}{suffix:02d}"
        if not con.execute("SELECT 1 FROM technicians WHERE prid=?", (prid,)).fetchone():
            break
        suffix += 1
    con.execute(
        """INSERT INTO technicians
           (tech_code, pin_hash, name, phone, email, email_hash,
            role, prid, hire_date, hourly_rate, active, employment_status, created_at)
           VALUES (?,?,?,?,?,?,?,?,?,?,1,'active',?)""",
        (code, _hash_pin("123456"), name,
         encrypt(rand_phone()), det_encrypt(em), email_hash(em),
         role, prid, hire_date, rate, NOW_ISO),
    )
    return con.execute("SELECT id FROM technicians WHERE tech_code=?", (code,)).fetchone()[0]


tech_ids = {}  # code -> id
tech_info = {}  # id -> {hire_date, rate, role, name}
for code, name, role, hd, rate in TECH_SPECS:
    row = con.execute("SELECT id FROM technicians WHERE tech_code=?", (code,)).fetchone()
    tid = row[0] if row else insert_tech(code, name, role, hd, rate)
    tech_ids[code] = tid
    tech_info[tid] = {"hire_date": hd, "rate": rate, "role": role, "name": name, "code": code}
con.commit()
print(f"  techs: {len(tech_ids)} created")

# ────────────────────────────────────────────────────────────────────────
# 3. 5S ASSETS — assign per-tech vans and toolkits
# ────────────────────────────────────────────────────────────────────────
print("seeding 5S assets …")
# Existing VAN-KIN-01 & TKIT-KIN-01 — link to T01 if unassigned
con.execute(
    "UPDATE fs_assets SET assigned_tech_id=? WHERE asset_code='VAN-KIN-01' AND (assigned_tech_id IS NULL OR assigned_tech_id=0)",
    (tech_ids["T01"],),
)
con.execute(
    "UPDATE fs_assets SET assigned_tech_id=? WHERE asset_code='TKIT-KIN-01' AND (assigned_tech_id IS NULL OR assigned_tech_id=0)",
    (tech_ids["T01"],),
)

# Add VAN-KIN-02..12 and TKIT-KIN-02..12
for i in range(2, 13):
    code_v = f"VAN-KIN-{i:02d}"
    code_t = f"TKIT-KIN-{i:02d}"
    tcode = f"T{i:02d}"
    tid = tech_ids[tcode]
    if not con.execute("SELECT 1 FROM fs_assets WHERE asset_code=?", (code_v,)).fetchone():
        con.execute(
            "INSERT INTO fs_assets (asset_code, asset_type, label, hub_id, assigned_tech_id, active, created_at) "
            "VALUES (?, 'vehicle', ?, 1, ?, 1, ?)",
            (code_v, f"Kingston Service Van {i:02d}", tid, NOW_ISO),
        )
    if not con.execute("SELECT 1 FROM fs_assets WHERE asset_code=?", (code_t,)).fetchone():
        con.execute(
            "INSERT INTO fs_assets (asset_code, asset_type, label, hub_id, assigned_tech_id, active, created_at) "
            "VALUES (?, 'toolkit', ?, 1, ?, 1, ?)",
            (code_t, f"Kingston Toolkit {i:02d}", tid, NOW_ISO),
        )
con.commit()

# Build tech_id → (van_id, toolkit_id)
tech_assets = {}
for code, tid in tech_ids.items():
    n = code[1:]  # '01'..'12'
    van_row = con.execute("SELECT id FROM fs_assets WHERE asset_code=?", (f"VAN-KIN-{n}",)).fetchone()
    tk_row  = con.execute("SELECT id FROM fs_assets WHERE asset_code=?", (f"TKIT-KIN-{n}",)).fetchone()
    tech_assets[tid] = (van_row[0] if van_row else None, tk_row[0] if tk_row else None)
print(f"  fs_assets total: {con.execute('SELECT COUNT(*) FROM fs_assets').fetchone()[0]}")

# ────────────────────────────────────────────────────────────────────────
# 4. PARTS CATALOG
# ────────────────────────────────────────────────────────────────────────
print("seeding parts catalog …")

PARTS_PLAN = [
    # (prefix, category, count, base_cost, name_template)
    ("CAP",  "capacitors",          10, 2400,  "Run Capacitor {n} (35µF/440V)"),
    ("FILT", "filters",             15, 1100,  "Air Filter {n} (MERV-{merv})"),
    ("REFR", "refrigerant",          4, 8500,  "Refrigerant {gas} 1lb #{n}"),
    ("CONT", "contactors",           8, 4200,  "Contactor 30A 2-pole #{n}"),
    ("CTRL", "control_boards",      12, 18500, "Control Board {n}"),
    ("FAN",  "fan_motors",           8, 9800,  "Condenser Fan Motor {n}"),
    ("DRAIN","drain_treatments",     4, 950,   "Drain Treatment Tablet {n}"),
    ("CU",   "copper_line_set",     10, 6500,  "Copper Line Set 1/4\"x3/8\" #{n}"),
    ("ELEC", "electrical",          20, 1300,  "Electrical Component {n}"),
    ("CONS", "consumables",         15, 480,   "Consumable Pack {n}"),
    ("TOOL", "tools",               12, 7200,  "Hand Tool {n}"),
    ("SPEC", "specialty",           12, 14500, "Specialty Part {n}"),
]

REFR_GASES = ["R-410A", "R-32", "R-410A", "R-32"]


def insert_part(sku, name, cat, unit_cost, qty):
    selling = round(unit_cost * 1.45, 2)
    con.execute(
        """INSERT INTO parts (sku, name, description, category, unit, unit_cost,
            quantity, reorder_point, supplier, active, created_at, updated_at, hub_id)
           VALUES (?,?,?,?,?,?,?,?,?,1,?,?,1)""",
        (sku, name, f"{cat} — auto-seeded for demo", cat, "each",
         unit_cost, qty, max(5, qty // 4),
         random.choice(["Caribbean HVAC Supply", "Island Parts Ltd.", "Kingston Wholesale"]),
         NOW_ISO, NOW_ISO),
    )
    # selling_price col doesn't exist on parts table — markup is implicit.
    return con.execute("SELECT id FROM parts WHERE sku=?", (sku,)).fetchone()[0]


part_ids = []
for prefix, cat, cnt, base, tmpl in PARTS_PLAN:
    for i in range(1, cnt + 1):
        sku = f"{prefix}-{i:03d}"
        if con.execute("SELECT 1 FROM parts WHERE sku=?", (sku,)).fetchone():
            pid = con.execute("SELECT id FROM parts WHERE sku=?", (sku,)).fetchone()[0]
            part_ids.append(pid)
            continue
        kwargs = {"n": i}
        if "{merv}" in tmpl:
            kwargs["merv"] = random.choice([8, 11, 13])
        if "{gas}" in tmpl:
            kwargs["gas"] = REFR_GASES[(i - 1) % len(REFR_GASES)]
        nm = tmpl.format(**kwargs)
        cost = base * random.uniform(0.85, 1.25)
        qty = random.randint(5, 200)
        part_ids.append(insert_part(sku, nm, cat, round(cost, 2), qty))
con.commit()
print(f"  parts: {len(part_ids)} total ({con.execute('SELECT COUNT(*) FROM parts').fetchone()[0]} in db)")

# ────────────────────────────────────────────────────────────────────────
# 5. CUSTOMERS
# ────────────────────────────────────────────────────────────────────────
print("seeding customers …")

JM_FIRST = ["Andre", "Camille", "Damion", "Latoya", "Trevor", "Marcia", "Jermaine",
            "Shanique", "Renee", "Kevon", "Tasha", "Devon", "Romario", "Junior",
            "Alicia", "Carlton", "Suzette", "Roxanne", "Owen", "Patricia",
            "Sherwin", "Karen", "Norval", "Anya", "Garnet", "Pauline",
            "Maurice", "Tanya", "Donovan", "Cherise", "Wayne", "Janelle",
            "Linton", "Renata", "Garth", "Sasha", "Phillipa", "Kemar",
            "Tameka", "Howard", "Latrice", "Christine", "Roxroy"]
JM_LAST = ["Brown", "Williams", "Clarke", "Henry", "Reid", "Palmer", "McKenzie",
           "Thompson", "Edwards", "Bennett", "Walker", "Bryan", "Anderson",
           "Powell", "Cooper", "Bailey", "Campbell", "Grant", "Lewis",
           "Robinson", "Foster", "Lyn", "Chin", "Beckford", "Wright"]

JM_STREETS = ["Hope Road", "Knutsford Boulevard", "Constant Spring Road",
              "Old Hope Road", "Trafalgar Road", "Holborn Road",
              "Lady Musgrave Road", "Eastwood Park Road", "Half-Way Tree Road",
              "Mountain View Avenue", "Red Hills Road", "Washington Boulevard",
              "Marcus Garvey Drive", "Spanish Town Road", "Manor Park Plaza"]

COM_NAMES = [
    "Kingston Tech Hub", "Half-Way Tree Pharmacy", "Liguanea Dental Clinic",
    "Cross Roads Auto Parts", "Portmore Print Co.", "New Kingston Law Group",
    "Manor Park Wellness Centre", "Spanish Town Logistics", "Mona Heights Cafe",
    "Norbrook Realty", "Constant Spring Insurance", "Stony Hill Computers",
    "Hope Road Bakery", "Liguanea IT Solutions", "Tropic Cold Storage Ltd.",
    "Eastwood Park Veterinary", "Mountain View Hardware", "Half-Way Tree Optical",
    "Kingston Lab Services", "Beverly Hills Spa", "Knutsford Express Office",
    "Manor Park Foods Ltd.", "Mona Real Estate", "Cross Roads Eye Clinic",
    "Hope Gardens Florist", "Liguanea Plaza Cinema", "Stony Hill Coffee Roasters",
    "Norbrook Tax Advisory", "Constant Spring Tyre Centre", "Spanish Town Beverage Co.",
    "New Kingston Trading", "Half-Way Tree Music Co.", "Portmore Marine Supply",
    "Tropic Tours Jamaica", "Beverly Hills Architects",
]

NOTES_POOL = ["Prefers morning service", "Service contract active, PM every 90 days",
              "Pet on premises", "After-hours only", "Gate code provided to supervisor",
              "Allergic to fragrances", "Loud dog — call before arriving",
              "Building has 24h security desk", "PM due quarterly per contract",
              "Critical-load site — coordinate with IT"]

CUST_START = date(2024, 1, 1)
CUST_END = date(2026, 4, 30)

customer_ids = []  # list of (cust_id, ctype, created_at, code)


def insert_customer(code, name, ctype, company, email, phone, address, notes, created_at_iso, cid_pin):
    pin = str(1000 + cid_pin)  # we use a placeholder; final pin uses real id below
    con.execute(
        """INSERT INTO customers
            (customer_code, name, company, email, phone, address, notes,
             pin_hash, created_at, auth_mode, customer_type, active, hub_id,
             email_hash, mfa_enabled, pin_failed_count)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,1,1,?,0,0)""",
        (code, name, company,
         det_encrypt(email), encrypt(phone), encrypt(address), encrypt(notes),
         _hash_pin(pin), created_at_iso, "pin", ctype,
         email_hash(email)),
    )
    return con.execute("SELECT id FROM customers WHERE customer_code=?", (code,)).fetchone()[0]


# 55 residential
for i in range(1, 56):
    code = f"RES-{i:03d}"
    first = random.choice(JM_FIRST)
    last = random.choice(JM_LAST)
    name = f"{first} {last}"
    email = f"{first.lower()}.{last.lower()}{i}@example.jm"
    phone = rand_phone()
    addr = f"{random.randint(2, 188)} {random.choice(JM_STREETS)}, Kingston {random.choice([5,6,7,8,10,19,20])}"
    if random.random() < 0.4:
        addr += f"\nApt {random.randint(1,12)}{random.choice('ABCD')}"
    notes = random.choice(NOTES_POOL)
    ca = datetime.combine(rand_date_between(CUST_START, CUST_END),
                           datetime.min.time(), tzinfo=timezone.utc).isoformat()
    cid = insert_customer(code, name, "residential", None, email, phone, addr, notes, ca, i)
    customer_ids.append((cid, "residential", ca, code))

# 35 commercial
for i in range(1, 36):
    code = f"COM-{i:03d}"
    company = COM_NAMES[(i - 1) % len(COM_NAMES)]
    contact_first = random.choice(JM_FIRST)
    contact_last = random.choice(JM_LAST)
    name = f"{contact_first} {contact_last}"  # contact person
    email = f"info{i}@{company.lower().replace(' ', '').replace('.', '').replace(',','')[:18]}.example.jm"
    phone = rand_phone()
    addr = f"{random.randint(2, 188)} {random.choice(JM_STREETS)}, Kingston {random.choice([5,6,10])}\nFloor {random.randint(1,5)}"
    notes = random.choice(NOTES_POOL)
    ca = datetime.combine(rand_date_between(CUST_START, CUST_END),
                           datetime.min.time(), tzinfo=timezone.utc).isoformat()
    cid = insert_customer(code, name, "commercial", company, email, phone, addr, notes, ca, 55 + i)
    customer_ids.append((cid, "commercial", ca, code))

# Re-set PINs so they match real DB id (PIN = 1000 + id)
for cid, *_ in customer_ids:
    pin = str(1000 + cid)
    con.execute("UPDATE customers SET pin_hash=? WHERE id=?", (_hash_pin(pin), cid))
con.commit()
print(f"  customers: {len(customer_ids)} (55 res + 35 com)")

# ────────────────────────────────────────────────────────────────────────
# 6. EQUIPMENT
# ────────────────────────────────────────────────────────────────────────
print("seeding equipment …")

EQ_TYPES = [("split", 55), ("central", 25), ("vrf", 10), ("precision", 5), ("water_cooler", 5)]
EQ_TYPE_POOL = []
for t, w in EQ_TYPES:
    EQ_TYPE_POOL.extend([t] * w)

ROOMS_RES = ["Living Room", "Master Bedroom", "Guest Bedroom", "Kitchen", "Den", "Office"]
ROOMS_COM = ["Conference Room", "Reception", "Server Room", "Open Plan", "Manager Office",
             "Lobby", "Storage", "Lab"]

MODELS_BY_TYPE = {
    "split":        ["LG-LS122HEV1", "Samsung-AR12TXFZ", "Daikin-FTKS", "Mitsubishi-MSZ-GE", "Carrier-42KHN"],
    "central":      ["Carrier-38KCS", "Trane-XR16", "York-YHJF", "Lennox-XC25", "Goodman-GSX16"],
    "vrf":          ["Daikin-VRV-IV", "Mitsubishi-CITY-MULTI", "LG-Multi-V", "Samsung-DVM-S"],
    "precision":    ["Liebert-DSE060", "Stulz-CW", "Vertiv-CRV"],
    "water_cooler": ["Avalon-A1WATERCOOLER", "Primo-601089", "Aquverse-A1H"],
}

equipment_ids = []  # list of (eq_id, customer_id, customer_ctype, customer_created_at)
EQ_TOTAL_TARGET = 190
res_avg = 1.5
com_avg = 3.5
res_target = round(res_avg * 55)  # ~82
com_target = round(com_avg * 35)  # ~123
# scale ratio
ratio = EQ_TOTAL_TARGET / (res_target + com_target)
res_target = int(res_target * ratio)
com_target = EQ_TOTAL_TARGET - res_target

def make_equipment_for(cid, ctype, ca_iso, target):
    rooms = ROOMS_RES if ctype == "residential" else ROOMS_COM
    placed = 0
    cnt = max(1, min(target, random.randint(1, 4 if ctype == "commercial" else 2)))
    for j in range(cnt):
        etype = random.choice(EQ_TYPE_POOL)
        model = random.choice(MODELS_BY_TYPE[etype])
        room = random.choice(rooms)
        idx = j + 1
        name = f"{room} {etype.title().replace('_',' ')} #{idx}"
        serial = f"SN-{random.choice([2023,2024,2025])}-{random.randint(1000,9999)}"
        location = f"{room}, {random.choice(['east','west','north','south'])} wall"
        notes = random.choice(["Installed during fit-out.",
                               "Last filter swap recent.",
                               "Mild noise reported once — verified normal.",
                               "Service tag attached.",
                               ""])
        # equipment created_at slightly after customer created_at
        ca_dt = datetime.fromisoformat(ca_iso)
        eq_ca = ca_dt + timedelta(days=random.randint(0, 60))
        con.execute(
            """INSERT INTO equipment
                (customer_id, name, type, model, serial_number, location, notes, created_at)
               VALUES (?,?,?,?,?,?,?,?)""",
            (cid, name, etype, model,
             encrypt(serial), encrypt(location), encrypt(notes),
             eq_ca.isoformat()),
        )
        equipment_ids.append((con.execute("SELECT last_insert_rowid()").fetchone()[0],
                              cid, ctype, ca_iso))
        placed += 1
    return placed


res_placed = 0
com_placed = 0
for cid, ctype, ca, _code in customer_ids:
    if ctype == "residential" and res_placed >= res_target:
        # still create at least 1
        make_equipment_for(cid, ctype, ca, 1)
        res_placed += 1
        continue
    n = make_equipment_for(cid, ctype, ca, 99)
    if ctype == "residential":
        res_placed += n
    else:
        com_placed += n
con.commit()
print(f"  equipment: {len(equipment_ids)}")

# ────────────────────────────────────────────────────────────────────────
# 7. VISITS
# ────────────────────────────────────────────────────────────────────────
print("seeding visits …")

VISIT_START = date(2024, 1, 15)
VISIT_END   = date(2026, 5, 20)
N_VISITS = 650

# Visits constrained: visit date >= max(tech.hire_date, equipment.created_at).
tech_id_list = list(tech_ids.values())
tech_hire = {tid: datetime.fromisoformat(tech_info[tid]["hire_date"] + "T00:00:00+00:00").date()
             for tid in tech_id_list}

visit_rows = []  # (visit_id, customer_id, equipment_id, status, completed_dt, tech_id, vtype)


def random_tech_active_on(d: date):
    eligible = [tid for tid in tech_id_list if tech_hire[tid] <= d]
    return random.choice(eligible) if eligible else None


for i in range(N_VISITS):
    # Pick equipment
    eq_id, cust_id, ctype, ca = random.choice(equipment_ids)
    # Date
    ca_d = datetime.fromisoformat(ca).date()
    start = max(VISIT_START, ca_d)
    if start > VISIT_END:
        continue
    vdate = rand_date_between(start, VISIT_END)
    tech_id = random_tech_active_on(vdate)
    if not tech_id:
        continue
    vtype = "PM" if random.random() < 0.70 else "CM"
    # status mix
    r = random.random()
    if vdate >= TODAY:
        status = "scheduled"
    elif (TODAY - vdate).days <= 2 and r < 0.50:
        status = "in_progress"
    else:
        if r < 0.88:
            status = "completed"
        elif r < 0.94:
            # recent few in_progress, else canceled
            if (TODAY - vdate).days <= 7:
                status = "in_progress"
            else:
                status = "completed"
        elif r < 0.98:
            status = "completed"
        else:
            status = "canceled"

    sched_time = f"{random.randint(7,18):02d}:{random.choice(['00','15','30','45'])}"
    start_dt = datetime.combine(vdate, datetime.min.time(), tzinfo=timezone.utc) + \
               timedelta(hours=int(sched_time[:2]), minutes=int(sched_time[3:]))
    duration_min = random.randint(45, 240)
    end_dt = start_dt + timedelta(minutes=duration_min)

    completed_dt_iso = None
    start_iso = None
    end_iso = None
    if status == "completed":
        completed_dt_iso = end_dt.isoformat()
        start_iso = start_dt.isoformat()
        end_iso = end_dt.isoformat()
    elif status == "in_progress":
        start_iso = start_dt.isoformat()

    work_done = ("Completed scheduled PM: cleaned coils, checked refrigerant, verified electrical."
                 if vtype == "PM" else
                 "Diagnosed reported fault, replaced affected components, verified operation.")
    notes_text = random.choice(["Customer present.", "After-hours service.",
                                "Follow-up may be needed.", "All readings nominal.",
                                "Recommended quarterly drain flush."])
    scope = ("Standard PM per service plan." if vtype == "PM"
             else "Customer-reported issue — diagnose and resolve.")

    callback_of = None
    if random.random() < 0.03 and visit_rows:
        # find a prior completed visit on same equipment
        candidates = [v for v in visit_rows if v[2] == eq_id and v[3] == "completed"]
        if candidates:
            callback_of = candidates[-1][0]

    con.execute(
        """INSERT INTO maintenance_visits
            (customer_id, equipment_id, visit_type, status, scheduled_date,
             scheduled_time, completed_date, technician, work_done,
             parts_replaced, notes, assigned_tech_id, start_time, end_time,
             created_at, submitted_at, scope_of_work, estimated_duration_min,
             work_done_summary, hub_id, callback_of_visit_id)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,1,?)""",
        (cust_id, eq_id, vtype, status, vdate.isoformat(), sched_time,
         vdate.isoformat() if status == "completed" else None,
         tech_info[tech_id]["name"],
         encrypt(work_done if status != "scheduled" else ""),
         encrypt(""),
         encrypt(notes_text),
         tech_id, start_iso, end_iso,
         start_dt.isoformat(), completed_dt_iso,
         scope, duration_min,
         work_done if status == "completed" else "",
         callback_of),
    )
    vid = con.execute("SELECT last_insert_rowid()").fetchone()[0]
    visit_rows.append((vid, cust_id, eq_id, status, completed_dt_iso, tech_id, vtype, duration_min, start_dt, end_dt))

con.commit()
print(f"  visits: {len(visit_rows)}")

# Visit readings — 30% of completed
completed_visits = [v for v in visit_rows if v[3] == "completed"]
for v in random.sample(completed_visits, k=int(len(completed_visits) * 0.30)):
    vid, _cid, _eid, _st, comp_iso, tid, _vt, *_ = v
    n_readings = random.randint(1, 3)
    for _ in range(n_readings):
        con.execute(
            """INSERT INTO visit_readings
                (visit_id, pressure_high, pressure_low, temp_supply, temp_return,
                 delta_t, superheat, subcool, approach_temp, notes, recorded_by, recorded_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
            (vid,
             round(random.uniform(330, 420), 1),
             round(random.uniform(95, 135), 1),
             round(random.uniform(48, 58), 1),
             round(random.uniform(68, 78), 1),
             round(random.uniform(15, 22), 1),
             round(random.uniform(8, 18), 1),
             round(random.uniform(5, 12), 1),
             round(random.uniform(1.5, 4.0), 1),
             encrypt("Within manufacturer spec."),
             tid, comp_iso or NOW_ISO),
        )
con.commit()
print(f"  visit_readings seeded")

# Visit parts — 25% of completed
for v in random.sample(completed_visits, k=int(len(completed_visits) * 0.25)):
    vid, _cid, _eid, _st, comp_iso, tid, *_ = v
    n_parts = random.randint(1, 3)
    used_pids = random.sample(part_ids, k=n_parts)
    for pid in used_pids:
        qty = random.choice([1, 1, 1, 2, 2, 3])
        # snapshot unit_cost
        unit_cost = con.execute("SELECT unit_cost FROM parts WHERE id=?", (pid,)).fetchone()[0]
        con.execute(
            """INSERT INTO visit_parts (visit_id, part_id, quantity, unit_price, notes, added_by_tech_id, created_at)
               VALUES (?,?,?,?,?,?,?)""",
            (vid, pid, qty, unit_cost, "", tid, comp_iso or NOW_ISO),
        )
        # Also decrement parts on hand (best-effort)
        con.execute("UPDATE parts SET quantity = MAX(quantity - ?, 0) WHERE id=?", (qty, pid))
con.commit()
print(f"  visit_parts seeded")

# Visit photos — 12% stubs
for v in random.sample(completed_visits, k=int(len(completed_visits) * 0.12)):
    vid, _cid, _eid, _st, comp_iso, tid, *_ = v
    con.execute(
        """INSERT INTO visit_photos (visit_id, category, filename, uploaded_by, uploaded_at)
           VALUES (?,?,?,?,?)""",
        (vid, random.choice(["before", "after", "during"]),
         f"demo-photo-{vid}.jpg", tid, comp_iso or NOW_ISO),
    )
con.commit()
print(f"  visit_photos seeded")

# ────────────────────────────────────────────────────────────────────────
# 8. FX rates
# ────────────────────────────────────────────────────────────────────────
print("seeding fx_rates …")
for cur, rate in (("USD", 155.0), ("GBP", 195.0)):
    if not con.execute("SELECT 1 FROM fx_rates WHERE from_currency=? AND active=1", (cur,)).fetchone():
        con.execute(
            """INSERT INTO fx_rates (from_currency, to_currency, buy_rate, source,
                fetched_at, effective_date, entered_by, notes, active)
               VALUES (?, 'JMD', ?, 'manual', ?, ?, ?, ?, 1)""",
            (cur, rate, NOW_ISO, TODAY.isoformat(), director_id,
             encrypt(f"Demo FX rate {cur}->JMD")),
        )
con.commit()

# ────────────────────────────────────────────────────────────────────────
# 9. INVOICES + LINES + PAYMENTS
# ────────────────────────────────────────────────────────────────────────
print("seeding invoices …")

# Pool: completed visits (have tech/duration for labor line)
invoice_visit_pool = completed_visits[:]
random.shuffle(invoice_visit_pool)

# Target 550 invoices. We have ~88% of 650 completed ≈ ~570 — plenty.
N_INVOICES = 550
invoice_visit_pool = invoice_visit_pool[:N_INVOICES]


def next_inv_number(seq):
    return f"INV-2026-{seq:05d}"


inv_seq = 1
invoice_ids = []
for v in invoice_visit_pool:
    vid, cust_id, _eid, _st, comp_iso, tid, vtype, dur_min, start_dt, end_dt = v
    ctype = con.execute("SELECT customer_type FROM customers WHERE id=?", (cust_id,)).fetchone()[0]
    tax_rate_frac = 0.15 if ctype == "commercial" else 0.0

    # status mix
    r = random.random()
    if r < 0.88:
        status = "paid"
    elif r < 0.95:
        status = "sent"
    elif r < 0.99:
        status = "sent"  # potentially overdue
    else:
        status = "canceled"

    issue_d = datetime.fromisoformat(comp_iso).date() if comp_iso else TODAY
    # 4% should be overdue (due_date < today, sent, unpaid)
    if status == "sent" and random.random() < 0.45:
        # overdue
        issue_d = TODAY - timedelta(days=random.randint(45, 120))
        due_d = issue_d + timedelta(days=30)
    else:
        due_d = issue_d + timedelta(days=30)

    # Foreign currency mix: top of pool only
    display_currency = "JMD"
    fx_rate_used = None
    fx_fee_pct = 2.0
    if inv_seq > N_INVOICES - 30 and random.random() < 0.20:
        display_currency = random.choice(["USD", "GBP"])
        fx_rate_used = 155.0 if display_currency == "USD" else 195.0

    inv_no = next_inv_number(inv_seq)
    while con.execute("SELECT 1 FROM invoices WHERE invoice_number=?", (inv_no,)).fetchone():
        inv_seq += 1
        inv_no = next_inv_number(inv_seq)

    canceled_at = None
    canceled_by = None
    canceled_reason = None
    if status == "canceled":
        canceled_at = NOW_ISO
        canceled_by = admin_ids["supervisor"]
        canceled_reason = encrypt(random.choice([
            "Customer disputed the work scope.",
            "Service was rescheduled, original invoice voided.",
            "Duplicate of a prior invoice."]))

    con.execute(
        """INSERT INTO invoices
            (invoice_number, customer_id, visit_id, issue_date, due_date, status,
             subtotal, tax_rate, tax_amount, total, amount_paid, currency,
             notes, sent_at, paid_at, created_by, created_at, updated_at,
             fx_fee_pct, fx_rate_used, display_currency,
             canceled_at, canceled_by, canceled_reason)
           VALUES (?,?,?,?,?,?,0,?,0,0,0,'JMD',?,?,NULL,?,?,?,?,?,?,?,?,?)""",
        (inv_no, cust_id, vid, issue_d.isoformat(), due_d.isoformat(), status,
         tax_rate_frac,
         encrypt("Auto-seeded demo invoice."),
         issue_d.isoformat() + "T08:00:00+00:00" if status != "draft" else None,
         director_id,
         issue_d.isoformat() + "T08:00:00+00:00",
         NOW_ISO,
         fx_fee_pct, fx_rate_used, display_currency,
         canceled_at, canceled_by, canceled_reason),
    )
    invoice_id = con.execute("SELECT last_insert_rowid()").fetchone()[0]

    # Lines: labor + 1-3 parts + maybe 1 other
    tech_rate = tech_info[tid]["rate"]
    hours = round(dur_min / 60.0, 2)
    labor_total = round(hours * tech_rate, 2)
    con.execute(
        """INSERT INTO invoice_line_items
            (invoice_id, line_type, part_id, description, quantity, unit_price,
             line_total, sort_order, tech_id, hours, hourly_rate, created_at, updated_at)
           VALUES (?, 'labor', NULL, ?, ?, ?, ?, 0, ?, ?, ?, ?, ?)""",
        (invoice_id, f"Labor — {tech_info[tid]['name']} ({vtype})",
         hours, tech_rate, labor_total, tid, hours, tech_rate, NOW_ISO, NOW_ISO),
    )
    subtotal = labor_total

    # Parts (1–3)
    n_parts = random.randint(1, 3)
    used_pids = random.sample(part_ids, k=n_parts)
    sort_n = 1
    for pid in used_pids:
        row = con.execute("SELECT sku, name, unit_cost FROM parts WHERE id=?", (pid,)).fetchone()
        sku, pname, ucost = row[0], row[1], float(row[2])
        qty = random.choice([1, 1, 2])
        price = round(ucost * 1.45, 2)
        line_total = round(qty * price, 2)
        con.execute(
            """INSERT INTO invoice_line_items
                (invoice_id, line_type, part_id, part_sku, description, quantity,
                 unit_price, line_total, sort_order, created_at, updated_at)
               VALUES (?, 'part', ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (invoice_id, pid, sku, f"{pname}", qty, price, line_total, sort_n,
             NOW_ISO, NOW_ISO),
        )
        subtotal += line_total
        sort_n += 1

    # Other line — 30%
    if random.random() < 0.30:
        other_amt = round(random.choice([1500.0, 2500.0, 3500.0, 5000.0]), 2)
        con.execute(
            """INSERT INTO invoice_line_items
                (invoice_id, line_type, description, quantity, unit_price,
                 line_total, sort_order, created_at, updated_at)
               VALUES (?, 'other', ?, 1, ?, ?, ?, ?, ?)""",
            (invoice_id,
             random.choice(["Travel/disposal surcharge", "Refrigerant disposal fee",
                             "After-hours surcharge"]),
             other_amt, other_amt, sort_n, NOW_ISO, NOW_ISO),
        )
        subtotal += other_amt

    tax_amount = round(subtotal * tax_rate_frac, 2)
    total = round(subtotal + tax_amount, 2)
    con.execute(
        "UPDATE invoices SET subtotal=?, tax_amount=?, gct_amount=?, total=? WHERE id=?",
        (subtotal, tax_amount, tax_amount, total, invoice_id),
    )

    # Payments for paid invoices
    if status == "paid":
        pay_method = random.choices(
            ["cash", "bank_transfer", "cheque", "card", "other"],
            weights=[40, 35, 15, 8, 2], k=1,
        )[0]
        # Chain hash
        prior = con.execute(
            "SELECT chain_hash FROM invoice_payments ORDER BY id DESC LIMIT 1"
        ).fetchone()
        prior_hash = (prior[0] if prior else "") or ""
        payment_date = (issue_d + timedelta(days=random.randint(0, 25))).isoformat()
        pay_payload = {
            "invoice_id": invoice_id, "amount": total,
            "payment_date": payment_date, "method": pay_method,
            "foreign_amount": None, "foreign_currency": None,
            "fx_rate_used": None, "recorded_by": admin_ids["ceoasst"],
            "created_at": NOW_ISO,
        }
        # For foreign-currency invoices, simulate a foreign payment for ~half
        foreign_amount = None
        foreign_currency = None
        fx_used = None
        effective_rate = None
        if display_currency in ("USD", "GBP") and random.random() < 0.5:
            foreign_currency = display_currency
            foreign_amount = round(total / fx_rate_used, 2)
            fx_used = fx_rate_used
            effective_rate = round(fx_rate_used * (1 - fx_fee_pct / 100.0), 4)
            pay_payload["foreign_amount"] = foreign_amount
            pay_payload["foreign_currency"] = foreign_currency
            pay_payload["fx_rate_used"] = fx_used

        import json as _json
        canonical = _json.dumps(pay_payload, sort_keys=True, separators=(",", ":"))
        chain_hash = hashlib.sha256((prior_hash + "\n" + canonical).encode()).hexdigest()
        con.execute(
            """INSERT INTO invoice_payments
                (invoice_id, payment_date, amount, method, reference, notes,
                 recorded_by, recorded_by_label, recorded_by_prid, created_at,
                 foreign_amount, foreign_currency, fx_rate_used, fx_fee_pct_used,
                 effective_rate_used, hub_id, prior_chain_hash, chain_hash)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,1,?,?)""",
            (invoice_id, payment_date, total, pay_method, "",
             encrypt(""), admin_ids["ceoasst"], "Latoya Thompson", None, NOW_ISO,
             foreign_amount, foreign_currency, fx_used,
             fx_fee_pct if foreign_currency else None,
             effective_rate, prior_hash, chain_hash),
        )
        con.execute(
            "UPDATE invoices SET amount_paid=?, paid_at=? WHERE id=?",
            (total, NOW_ISO, invoice_id),
        )

    invoice_ids.append(invoice_id)
    inv_seq += 1

con.commit()
print(f"  invoices: {len(invoice_ids)}")

# ────────────────────────────────────────────────────────────────────────
# 10. 5S AUDITS (last 60 days, per-tech ~2/day)
# ────────────────────────────────────────────────────────────────────────
print("seeding 5S audits + items + exceptions …")

CHECKLISTS = {
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
}
SAFETY_KEYS = {
    "safety_gear_present", "lights_working", "tires_visual_ok",
    "fluids_checked", "tools_no_damage", "any_damage_logged",
}

AUDIT_GENESIS = "GENESIS"


def fs_canonical(row, fields):
    import json as _json
    return _json.dumps({f: row.get(f) for f in fields}, sort_keys=True, separators=(",", ":"))


def fs_compute(prev, row, fields):
    payload = (prev or AUDIT_GENESIS) + "\n" + fs_canonical(row, fields)
    return hashlib.sha256(payload.encode()).hexdigest()


FS_AUDIT_FIELDS = ("asset_id", "auditor_id", "auditor_kind", "phase",
                   "audit_ts", "overall_pass", "hub_id")
FS_EXC_FIELDS = ("asset_id", "audit_id", "opened_by_id", "opened_by_kind",
                 "opened_at", "severity", "category", "status",
                 "resolved_by_id", "resolved_at", "escalated_at",
                 "escalated_to_id", "hub_id")

audit_start = TODAY - timedelta(days=60)
audit_count = 0
item_count = 0
exc_count = 0
exc_status_chosen = []

prior_audit_hash = ""
prior_exc_hash = ""

for tid in tech_id_list:
    van_id, tk_id = tech_assets[tid]
    if not van_id or not tk_id:
        continue
    tech_hd = tech_hire[tid]
    d = audit_start
    while d <= TODAY:
        # skip weekends ~60% of time, allow some weekend ones
        if d.weekday() >= 5 and random.random() < 0.85:
            d += timedelta(days=1)
            continue
        if d < tech_hd:
            d += timedelta(days=1)
            continue
        # ~10% absent (sick / vacation)
        if random.random() < 0.10:
            d += timedelta(days=1)
            continue

        for phase, asset_id, asset_type in (
            ("start_shift", van_id, "vehicle"),
            ("end_shift",   van_id, "vehicle"),
        ):
            tmpl = CHECKLISTS[(asset_type, phase)]
            # 92% pass overall
            has_fail = random.random() > 0.92
            now_ts = datetime.combine(d, datetime.min.time(),
                                      tzinfo=timezone.utc) + timedelta(
                hours=(7 if phase == "start_shift" else 17),
                minutes=random.randint(0, 59),
            )
            now_iso_ts = now_ts.isoformat()

            # decide overall pass
            all_items = [(s, k) for s, keys in tmpl.items() for k in keys]
            failed_idx = None
            if has_fail:
                failed_idx = random.randint(0, len(all_items) - 1)

            overall_pass = 0 if has_fail else 1
            header = {"asset_id": asset_id, "auditor_id": tid,
                      "auditor_kind": "tech", "phase": phase,
                      "audit_ts": now_iso_ts, "overall_pass": overall_pass,
                      "hub_id": 1}
            chash = fs_compute(prior_audit_hash, header, FS_AUDIT_FIELDS)
            cur = con.execute(
                """INSERT INTO fs_audits
                    (asset_id, auditor_id, auditor_kind, phase, audit_ts,
                     overall_pass, hub_id, prior_chain_hash, chain_hash)
                   VALUES (?, ?, 'tech', ?, ?, ?, 1, ?, ?)""",
                (asset_id, tid, phase, now_iso_ts, overall_pass,
                 prior_audit_hash, chash),
            )
            audit_id = cur.lastrowid
            prior_audit_hash = chash
            audit_count += 1

            for idx, (section, key) in enumerate(all_items):
                status = "pass"
                if idx == failed_idx:
                    status = "fail"
                con.execute(
                    """INSERT INTO fs_audit_items
                        (audit_id, section, item_key, item_label, status, note)
                       VALUES (?,?,?,?,?,?)""",
                    (audit_id, section, key, key.replace("_", " ").capitalize(),
                     status, None),
                )
                item_count += 1
                if status == "fail":
                    severity = "safety_loto" if (key in SAFETY_KEYS or random.random() < 0.20) else "normal"
                    # status distribution
                    r = random.random()
                    if r < 0.80:
                        exc_st = "resolved"
                    elif r < 0.92:
                        exc_st = "open"
                    elif r < 0.98:
                        exc_st = "escalated"
                    else:
                        exc_st = "escalated_director"
                    resolved_by_id = tid if exc_st == "resolved" else None
                    resolved_at = now_iso_ts if exc_st == "resolved" else None
                    escalated_at = now_iso_ts if exc_st in ("escalated", "escalated_director") else None
                    escalated_to_id = admin_ids["supervisor"] if exc_st == "escalated" else (
                        director_id if exc_st == "escalated_director" else None)
                    erow = {
                        "asset_id": asset_id, "audit_id": audit_id,
                        "opened_by_id": tid, "opened_by_kind": "tech",
                        "opened_at": now_iso_ts, "severity": severity,
                        "category": key, "status": exc_st,
                        "resolved_by_id": resolved_by_id, "resolved_at": resolved_at,
                        "escalated_at": escalated_at, "escalated_to_id": escalated_to_id,
                        "hub_id": 1,
                    }
                    ech = fs_compute(prior_exc_hash, erow, FS_EXC_FIELDS)
                    resolution_note_enc = encrypt(
                        random.choice(["Cleaned on-site immediately.",
                                       "Resolved by EOD.",
                                       "Tool replaced from stock."])
                    ) if exc_st == "resolved" else None
                    desc_enc = encrypt(f"Auto-opened from failed checklist item: {key}")
                    cur2 = con.execute(
                        """INSERT INTO fs_exceptions
                            (audit_id, asset_id, opened_by_id, opened_by_kind,
                             opened_at, severity, category, description, status,
                             resolved_by_id, resolved_by_kind, resolved_at, resolution_note,
                             escalated_at, escalated_to_id, hub_id,
                             prior_chain_hash, chain_hash)
                           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,1,?,?)""",
                        (audit_id, asset_id, tid, "tech",
                         now_iso_ts, severity, key, desc_enc, exc_st,
                         resolved_by_id, "tech" if exc_st == "resolved" else None,
                         resolved_at, resolution_note_enc,
                         escalated_at, escalated_to_id,
                         prior_exc_hash, ech),
                    )
                    eid = cur2.lastrowid
                    prior_exc_hash = ech
                    exc_count += 1
                    exc_status_chosen.append((eid, exc_st))

                    # Insert opened event
                    con.execute(
                        """INSERT INTO fs_exception_events
                            (exception_id, event_type, actor_id, actor_kind,
                             occurred_at, from_status, to_status, note)
                           VALUES (?, 'opened', ?, 'tech', ?, NULL, 'open', NULL)""",
                        (eid, tid, now_iso_ts),
                    )
                    if exc_st != "open":
                        con.execute(
                            """INSERT INTO fs_exception_events
                                (exception_id, event_type, actor_id, actor_kind,
                                 occurred_at, from_status, to_status, note)
                               VALUES (?, ?, ?, ?, ?, 'open', ?, NULL)""",
                            (eid,
                             exc_st if exc_st != "resolved" else "resolved",
                             resolved_by_id or escalated_to_id or director_id,
                             "tech" if exc_st == "resolved" else "admin",
                             now_iso_ts, exc_st),
                        )

        # commit per-day to keep transaction small
        d += timedelta(days=1)
    con.commit()

print(f"  audits: {audit_count} | items: {item_count} | exceptions: {exc_count}")

# ────────────────────────────────────────────────────────────────────────
# 11. PERFORMANCE REVIEWS
# ────────────────────────────────────────────────────────────────────────
print("seeding technician_reviews …")
_TECH_REVIEW_FIELDS = ("tech_id", "review_type", "status", "reviewer_id",
                       "created_at", "updated_at", "followup_date", "hub_id")

review_summaries = {
    "coaching": [
        "Discussed PM completion pace. Set target of 3 PMs/day for next 4 weeks.",
        "Reviewed callback on Henry residence — recommend deeper diagnostic checklist.",
        "Coached on customer communication during after-hours visits.",
    ],
    "positive_feedback": [
        "Excellent work resolving the Kingston Tech Hub server-room incident.",
        "Customer specifically commended professionalism and clean workmanship.",
        "On-time completion rate top of cohort this quarter.",
    ],
    "written_warning": [
        "Second missed safety LOTO check this month. Formal warning issued.",
        "Refrigerant log entries missing two weeks running — corrective action.",
    ],
    "other": [
        "Annual check-in. Goals set for next half.",
        "Cross-training plan discussed.",
        "Tools inventory review.",
    ],
}

prior_review_hash = ""
review_count = 0
for tid in tech_id_list:
    n = random.randint(1, 3)
    for _ in range(n):
        r = random.random()
        rt = ("coaching" if r < 0.60 else
              "positive_feedback" if r < 0.85 else
              "written_warning" if r < 0.90 else "other")
        sr = random.random()
        st = "resolved" if sr < 0.70 else "open" if sr < 0.90 else "archived"
        followup = (TODAY + timedelta(days=random.randint(7, 60))).isoformat() if random.random() < 0.30 else None
        action_items = random.choice([None, None,
                                       "Schedule re-training",
                                       "Pair with T01 on next 5 jobs"])
        summary = random.choice(review_summaries[rt])
        created_at_dt = datetime.combine(
            TODAY - timedelta(days=random.randint(5, 180)),
            datetime.min.time(), tzinfo=timezone.utc,
        )
        created_at = created_at_dt.isoformat()
        canonical = {"tech_id": tid, "review_type": rt, "status": st,
                     "reviewer_id": director_id, "created_at": created_at,
                     "updated_at": None, "followup_date": followup, "hub_id": 1}
        ch = fs_compute(prior_review_hash, canonical, _TECH_REVIEW_FIELDS)
        con.execute(
            """INSERT INTO technician_reviews
                (tech_id, review_type, summary, status, action_items,
                 followup_date, reviewer_id, created_at, hub_id,
                 prior_chain_hash, chain_hash)
               VALUES (?,?,?,?,?,?,?,?,1,?,?)""",
            (tid, rt, encrypt(summary), st,
             encrypt(action_items) if action_items else None,
             followup, director_id, created_at, prior_review_hash, ch),
        )
        prior_review_hash = ch
        review_count += 1
con.commit()
print(f"  technician_reviews: {review_count}")

# ────────────────────────────────────────────────────────────────────────
# 12. KPI THRESHOLD OVERRIDES (T08–T12)
# ────────────────────────────────────────────────────────────────────────
print("seeding technician_kpi_overrides …")
_KPI_FIELDS = ("tech_id", "kpi_key", "green_threshold", "amber_threshold",
               "red_threshold", "effective_from", "effective_until",
               "created_by", "created_at", "active")
prior_kpi_hash = ""
kpi_count = 0
for tcode in ("T08", "T09", "T10", "T11", "T12"):
    tid = tech_ids[tcode]
    hd = tech_info[tid]["hire_date"]
    for kpi_key in ("pm_completion", "callback_rate"):
        canonical = {"tech_id": tid, "kpi_key": kpi_key,
                     "green_threshold": 0.75 if kpi_key == "pm_completion" else 0.10,
                     "amber_threshold": 0.60 if kpi_key == "pm_completion" else 0.20,
                     "red_threshold":   0.40 if kpi_key == "pm_completion" else 0.30,
                     "effective_from": hd, "effective_until": None,
                     "created_by": director_id, "created_at": NOW_ISO,
                     "active": 1}
        ch = fs_compute(prior_kpi_hash, canonical, _KPI_FIELDS)
        con.execute(
            """INSERT INTO technician_kpi_overrides
                (tech_id, kpi_key, green_threshold, amber_threshold, red_threshold,
                 reason, effective_from, effective_until, created_by, created_at,
                 active, prior_chain_hash, chain_hash)
               VALUES (?,?,?,?,?,?,?,?,?,?,1,?,?)""",
            (tid, kpi_key, canonical["green_threshold"],
             canonical["amber_threshold"], canonical["red_threshold"],
             encrypt("First 90 days softened targets"),
             hd, None, director_id, NOW_ISO, prior_kpi_hash, ch),
        )
        prior_kpi_hash = ch
        kpi_count += 1
        break  # one per tech to keep close to ~5 total
con.commit()
print(f"  kpi_overrides: {kpi_count}")

# ────────────────────────────────────────────────────────────────────────
# 13. 5S OVERRIDES
# ────────────────────────────────────────────────────────────────────────
print("seeding technician_5s_overrides …")
_5S_FIELDS = ("exception_id", "tech_id", "overridden_by", "overridden_at", "hub_id")
prior_5s_hash = ""
ov_count = 0
resolved_excs = [(eid, exc_st) for eid, exc_st in exc_status_chosen if exc_st == "resolved"]
for eid, _ in random.sample(resolved_excs, k=min(6, len(resolved_excs))):
    row = con.execute(
        "SELECT a.assigned_tech_id FROM fs_exceptions e "
        "JOIN fs_assets a ON a.id = e.asset_id WHERE e.id=?",
        (eid,),
    ).fetchone()
    if not row or not row[0]:
        continue
    tid = row[0]
    canonical = {"exception_id": eid, "tech_id": tid,
                 "overridden_by": director_id, "overridden_at": NOW_ISO,
                 "hub_id": 1}
    ch = fs_compute(prior_5s_hash, canonical, _5S_FIELDS)
    con.execute(
        """INSERT INTO technician_5s_overrides
            (exception_id, tech_id, reason, overridden_by, overridden_at,
             hub_id, prior_chain_hash, chain_hash)
           VALUES (?,?,?,?,?,1,?,?)""",
        (eid, tid,
         encrypt(random.choice(["Cleaned on-site immediately",
                                "Tool was loaned to T05, returned by EOD",
                                "Outside tech's control — supplier delay"])),
         director_id, NOW_ISO, prior_5s_hash, ch),
    )
    prior_5s_hash = ch
    ov_count += 1
con.commit()
print(f"  5s_overrides: {ov_count}")

# ────────────────────────────────────────────────────────────────────────
# 14. PAY PERIODS + PAYSLIPS (last 6 fortnightly)
# ────────────────────────────────────────────────────────────────────────
print("seeding pay_periods + payslips …")

# Fortnightly ending Fridays. Find most recent Friday ≤ TODAY
ref = TODAY
while ref.weekday() != 4:  # Friday = 4
    ref -= timedelta(days=1)

pay_periods = []  # list of (period_id, start, end, status)
for i in range(6):
    end_d = ref - timedelta(days=14 * i)
    start_d = end_d - timedelta(days=13)
    label = f"Wk{end_d.isocalendar()[1]} {end_d.year} (2wk)"
    # Idempotent — check
    exists = con.execute(
        "SELECT id FROM pay_periods WHERE period_start=? AND period_end=?",
        (start_d.isoformat(), end_d.isoformat()),
    ).fetchone()
    if exists:
        pid = exists[0]
    else:
        status = "pending" if i < 2 else "approved"
        con.execute(
            """INSERT INTO pay_periods
                (period_start, period_end, label, status, currency,
                 created_by, created_at)
               VALUES (?,?,?,?,?,?,?)""",
            (start_d.isoformat(), end_d.isoformat(), label,
             "draft" if status == "pending" else "approved",
             "JMD", admin_ids["hr"], NOW_ISO),
        )
        pid = con.execute("SELECT last_insert_rowid()").fetchone()[0]
    pay_periods.append((pid, start_d, end_d, "pending" if i < 2 else "approved"))
con.commit()

# Compute hours per tech per period from visits
payslip_count = 0
for pid, ps, pe, status in pay_periods:
    for tid, info in tech_info.items():
        hd = datetime.fromisoformat(info["hire_date"] + "T00:00:00+00:00").date()
        if hd > pe:
            continue  # not hired yet
        # Sum duration of completed visits in period
        rows = con.execute(
            """SELECT COALESCE(SUM(estimated_duration_min), 0) AS m
                 FROM maintenance_visits
                WHERE assigned_tech_id=? AND status='completed'
                  AND date(completed_date) BETWEEN ? AND ?""",
            (tid, ps.isoformat(), pe.isoformat()),
        ).fetchone()
        mins = float(rows[0] or 0)
        hours = round(mins / 60.0, 2)
        if hours <= 0:
            # give a baseline 65–80 hrs/2wk for active techs
            hours = round(random.uniform(60, 80), 2)
        rate = info["rate"]
        bonus = 0.0
        # T01 (lead) gets bonus on last 2 periods
        if info["code"] == "T01" and pid >= pay_periods[1][0]:
            bonus = 5000.0
        existing_ps = con.execute(
            "SELECT id FROM payslips WHERE pay_period_id=? AND subject_type='tech' AND subject_id=?",
            (pid, tid),
        ).fetchone()
        if existing_ps:
            continue
        amounts = compute_payslip_amounts(
            hours_regular=hours, hours_overtime=0,
            hourly_rate=rate, overtime_rate=0,
            fixed_salary=0, bonus=bonus, other_deductions=0,
        )
        con.execute(
            """INSERT INTO payslips
                (pay_period_id, subject_type, subject_id, subject_name, subject_prid,
                 hours_regular, hours_overtime, hourly_rate, overtime_rate,
                 fixed_salary, bonus, gross_pay,
                 paye_tax, nis, nht, education_tax, other_deductions,
                 total_deductions, net_pay, notes,
                 generated_by, generated_at)
               VALUES (?, 'tech', ?, ?, ?, ?, 0, ?, 0, 0, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?, ?)""",
            (pid, tid, info["name"],
             con.execute("SELECT prid FROM technicians WHERE id=?", (tid,)).fetchone()[0],
             hours, rate, bonus,
             amounts["gross_pay"], amounts["paye_tax"], amounts["nis"],
             amounts["nht"], amounts["education_tax"],
             amounts["total_deductions"], amounts["net_pay"],
             encrypt(""), admin_ids["hr"], NOW_ISO),
        )
        payslip_count += 1
con.commit()
print(f"  pay_periods: {len(pay_periods)}  payslips: {payslip_count}")

# ────────────────────────────────────────────────────────────────────────
# 15. SUMMARY
# ────────────────────────────────────────────────────────────────────────
print()
print("=" * 60)
print("FULL DEMO SEED COMPLETE — counts:")
print("=" * 60)
for t in ("admin_users", "technicians", "customers", "equipment",
          "maintenance_visits", "visit_readings", "visit_parts", "visit_photos",
          "parts", "invoices", "invoice_line_items", "invoice_payments",
          "fs_assets", "fs_audits", "fs_audit_items", "fs_exceptions",
          "fs_exception_events", "technician_reviews",
          "technician_kpi_overrides", "technician_5s_overrides",
          "pay_periods", "payslips", "fx_rates"):
    try:
        n = con.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
        print(f"  {t:34s} {n}")
    except Exception as e:
        print(f"  {t:34s} ERR: {e}")

print()
print("Customer PIN convention: customer.pin = 1000 + customer.id")
print("  e.g. RES-001 (id=1) → PIN 1001; COM-001 (id=56) → PIN 1056")
print()
print("Admin & tech credentials:")
print("  All admins password: PrimeCool!Dev2026")
print("  All techs PIN: 123456")
con.close()
