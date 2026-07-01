"""CMMS #6 — multi-entity / cost centres (entity model, work-order tagging,
per-entity P&L, entity-scoped reporting auth).

Self-isolating like the other CMMS API tests: copy the live submissions.db to a
temp file and point database.DB_PATH at the copy BEFORE the app lifespan runs
init_db(), so the live DB stays pristine.

Each test uses a FRESH entity (unique code via _CODE) and a UNIQUE far-future
date window (via _WIN) so its visits/invoices/labour/parts don't collide with
the live data carried in the copied DB or with the other tests here. The P&L
buckets untagged visits under the seeded default entity 1, but in our 2031+
windows there are no untagged live rows, so each test sees only what it created.
"""
import itertools
import os
import shutil
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

import database

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_LIVE_DB = _PROJECT_ROOT / "submissions.db"
_CODE = itertools.count(1)                 # unique entity codes per test
_WIN = itertools.count(2031)               # unique year window per test


def _now():
    return datetime.now(timezone.utc).isoformat()


@pytest.fixture(scope="module")
def iso_client():
    if not _LIVE_DB.exists():
        pytest.skip("submissions.db not present")
    import tempfile
    tmpdir = tempfile.mkdtemp(prefix="cmms_entity_api_")
    tmp_db = os.path.join(tmpdir, "submissions.db")
    shutil.copy(str(_LIVE_DB), tmp_db)
    for suffix in ("-wal", "-shm"):
        side = str(_LIVE_DB) + suffix
        if os.path.exists(side):
            shutil.copy(side, tmp_db + suffix)
    orig = database.DB_PATH
    database.DB_PATH = tmp_db
    os.chdir(str(_PROJECT_ROOT))
    from fastapi.testclient import TestClient
    import main
    try:
        with TestClient(main.app, headers={"Origin": "http://testserver"}) as c:
            yield c
    finally:
        database.DB_PATH = orig
        for suffix in ("", "-wal", "-shm"):
            try:
                os.remove(tmp_db + suffix)
            except OSError:
                pass


def _mint_token(admin_id):
    import main
    jti = uuid.uuid4().hex
    exp = datetime.now(timezone.utc) + timedelta(hours=2)
    token = main._make_token(
        {"sub": str(admin_id), "type": "admin", "jti": jti}, timedelta(hours=2))
    database.create_session(
        jti=jti, subject_type="admin", subject_id=admin_id,
        expires_at=exp.isoformat(), ip_address="127.0.0.1", user_agent="pytest")
    return token


@pytest.fixture(scope="module")
def super_admin_id(iso_client):
    con = sqlite3.connect(database.DB_PATH)
    row = con.execute(
        "SELECT id FROM admin_users WHERE role='super_admin' AND active=1 "
        "ORDER BY id LIMIT 1").fetchone()
    con.close()
    if not row:
        pytest.skip("no active super_admin in DB")
    return row[0]


@pytest.fixture(scope="module")
def admin_client(iso_client, super_admin_id):
    iso_client.headers.update({"Authorization": f"Bearer {_mint_token(super_admin_id)}"})
    return iso_client


@pytest.fixture(scope="module")
def customer_id(iso_client):
    con = sqlite3.connect(database.DB_PATH)
    cur = con.execute(
        "INSERT INTO customers (customer_code, name, created_at) VALUES (?,?,?)",
        ("ENTC1", "Entity Customer", _now()))
    cid = cur.lastrowid
    con.commit()
    con.close()
    return cid


def _new_visit(customer_id, scheduled_date, entity_id=None, est_min=None,
               assigned_tech_id=None, status="scheduled"):
    con = sqlite3.connect(database.DB_PATH)
    cur = con.execute(
        "INSERT INTO maintenance_visits "
        "(customer_id, visit_type, status, scheduled_date, assigned_tech_id, "
        " estimated_duration_min, entity_id, created_at) "
        "VALUES (?,?,?,?,?,?,?,?)",
        (customer_id, "CM", status, scheduled_date, assigned_tech_id,
         est_min, entity_id, _now()))
    vid = cur.lastrowid
    con.commit()
    con.close()
    return vid


def _new_invoice(customer_id, visit_id, total, issue_date):
    con = sqlite3.connect(database.DB_PATH)
    cur = con.execute(
        "INSERT INTO invoices "
        "(invoice_number, customer_id, visit_id, issue_date, due_date, status, "
        " total, created_at, updated_at) "
        "VALUES (?,?,?,?,?,?,?,?,?)",
        (f"INV-{uuid.uuid4().hex[:10]}", customer_id, visit_id, issue_date,
         issue_date, "sent", total, _now(), _now()))
    iid = cur.lastrowid
    con.commit()
    con.close()
    return iid


def _new_labor(visit_id, hours, cost_rate):
    con = sqlite3.connect(database.DB_PATH)
    con.execute(
        "INSERT INTO visit_labor_entries "
        "(visit_id, hours, cost_rate, billable, created_at) VALUES (?,?,?,1,?)",
        (visit_id, hours, cost_rate, _now()))
    con.commit()
    con.close()


def _new_part_usage(visit_id, quantity, unit_price):
    con = sqlite3.connect(database.DB_PATH)
    # visit_parts requires a part_id FK → make a throwaway part.
    cur = con.execute(
        "INSERT INTO parts (sku, name, created_at, updated_at) VALUES (?,?,?,?)",
        (f"P-{uuid.uuid4().hex[:8]}", "Test Part", _now(), _now()))
    pid = cur.lastrowid
    con.execute(
        "INSERT INTO visit_parts (visit_id, part_id, quantity, unit_price, created_at) "
        "VALUES (?,?,?,?,?)", (visit_id, pid, quantity, unit_price, _now()))
    con.commit()
    con.close()


def _mk_entity(admin_client, kind="cost_center", parent_id=None, currency="TTD"):
    code = f"E{next(_CODE):04d}{uuid.uuid4().hex[:4].upper()}"
    r = admin_client.post("/api/admin/entities", json={
        "code": code, "name": f"Entity {code}", "kind": kind,
        "parent_id": parent_id, "currency": currency})
    assert r.status_code == 200, r.text
    return r.json()["id"], code


# ── entity CRUD ─────────────────────────────────────────────────────────────
def test_create_list_entities(admin_client):
    parent, pcode = _mk_entity(admin_client, kind="legal_entity")
    child, ccode = _mk_entity(admin_client, kind="cost_center", parent_id=parent)
    body = admin_client.get("/api/admin/entities").json()
    by_id = {e["id"]: e for e in body["entities"]}
    assert by_id[parent]["kind"] == "legal_entity"
    assert by_id[child]["kind"] == "cost_center"
    assert by_id[child]["parent_id"] == parent
    # seeded default entity is always present
    assert 1 in by_id


def test_create_entity_bad_kind_422(admin_client):
    r = admin_client.post("/api/admin/entities",
                          json={"code": "BADK1", "name": "Bad", "kind": "galaxy"})
    assert r.status_code == 422


def test_create_entity_duplicate_code_422(admin_client):
    _eid, code = _mk_entity(admin_client)
    r = admin_client.post("/api/admin/entities",
                          json={"code": code, "name": "Dup"})
    assert r.status_code == 422


def test_update_entity_and_404(admin_client):
    eid, _code = _mk_entity(admin_client)
    r = admin_client.put(f"/api/admin/entities/{eid}",
                         json={"name": "Renamed", "active": False})
    assert r.status_code == 200, r.text
    assert r.json()["entity"]["name"] == "Renamed"
    assert r.json()["entity"]["active"] == 0
    miss = admin_client.put("/api/admin/entities/999999999", json={"name": "x"})
    assert miss.status_code == 404


def test_update_entity_self_parent_422(admin_client):
    eid, _code = _mk_entity(admin_client)
    r = admin_client.put(f"/api/admin/entities/{eid}", json={"parent_id": eid})
    assert r.status_code == 422


# ── work-order tagging ───────────────────────────────────────────────────────
def test_visit_create_and_update_carry_entity(admin_client, customer_id):
    eid, _c = _mk_entity(admin_client)
    eid2, _c2 = _mk_entity(admin_client)
    c = admin_client.post("/api/admin/visits", json={
        "customer_id": customer_id, "visit_type": "CM",
        "scheduled_date": "2031-09-09", "entity_id": eid})
    assert c.status_code == 200, c.text
    vid = c.json()["id"]
    con = sqlite3.connect(database.DB_PATH)
    got = con.execute("SELECT entity_id FROM maintenance_visits WHERE id=?",
                      (vid,)).fetchone()[0]
    con.close()
    assert got == eid
    # re-tag via update
    u = admin_client.put(f"/api/admin/visits/{vid}", json={
        "visit_type": "CM", "status": "scheduled", "entity_id": eid2})
    assert u.status_code == 200, u.text
    con = sqlite3.connect(database.DB_PATH)
    got2 = con.execute("SELECT entity_id FROM maintenance_visits WHERE id=?",
                       (vid,)).fetchone()[0]
    con.close()
    assert got2 == eid2


# ── per-entity P&L ───────────────────────────────────────────────────────────
def test_entity_pnl_rolls_up_revenue_and_costs(admin_client, customer_id):
    year = next(_WIN)
    d = f"{year}-03-15"
    eid, _c = _mk_entity(admin_client)
    vid = _new_visit(customer_id, d, entity_id=eid)
    _new_invoice(customer_id, vid, 1000.0, d)     # revenue 1000
    _new_labor(vid, 4.0, 50.0)                    # labour 200
    _new_part_usage(vid, 3.0, 30.0)               # parts 90
    r = admin_client.get(
        f"/api/admin/entities/pnl?start={year}-01-01&end={year}-12-31")
    assert r.status_code == 200, r.text
    body = r.json()
    me = next(e for e in body["entities"] if e["entity_id"] == eid)
    assert me["revenue"] == 1000.0
    assert me["labor_cost"] == 200.0
    assert me["parts_cost"] == 90.0
    assert me["total_cost"] == 290.0
    assert me["gross_profit"] == 710.0
    assert me["work_orders"] == 1
    assert me["margin_pct"] == 71.0


def test_entity_pnl_bad_dates_422(admin_client):
    r = admin_client.get("/api/admin/entities/pnl?start=nope&end=also-nope")
    assert r.status_code == 422


def test_entity_pnl_filter_by_entity_ids(admin_client, customer_id):
    year = next(_WIN)
    d = f"{year}-06-01"
    a, _ca = _mk_entity(admin_client)
    b, _cb = _mk_entity(admin_client)
    va = _new_visit(customer_id, d, entity_id=a)
    vb = _new_visit(customer_id, d, entity_id=b)
    _new_invoice(customer_id, va, 500.0, d)
    _new_invoice(customer_id, vb, 800.0, d)
    r = admin_client.get(
        f"/api/admin/entities/pnl?start={year}-01-01&end={year}-12-31&entity_ids={a}")
    body = r.json()
    ids = {e["entity_id"] for e in body["entities"]}
    assert a in ids and b not in ids


# ── entity-scoped reporting auth ─────────────────────────────────────────────
def test_entity_scope_filters_pnl_for_scoped_admin(admin_client, customer_id):
    year = next(_WIN)
    d = f"{year}-04-04"
    a, _ca = _mk_entity(admin_client)
    b, _cb = _mk_entity(admin_client)
    va = _new_visit(customer_id, d, entity_id=a)
    vb = _new_visit(customer_id, d, entity_id=b)
    _new_invoice(customer_id, va, 100.0, d)
    _new_invoice(customer_id, vb, 200.0, d)

    # create a second super_admin and scope it to entity `a` only
    con = sqlite3.connect(database.DB_PATH)
    cur = con.execute(
        "INSERT INTO admin_users "
        "(username, password_hash, name, email, role, active, created_at) "
        "VALUES (?,?,?,?,?,1,?)",
        (f"scoped_{uuid.uuid4().hex[:8]}", "x", "Scoped Admin",
         f"scoped_{uuid.uuid4().hex[:8]}@example.com", "super_admin", _now()))
    scoped_id = cur.lastrowid
    con.commit()
    con.close()

    s = admin_client.put(f"/api/admin/admins/{scoped_id}/entity-scope",
                         json={"entity_ids": [a]})
    assert s.status_code == 200, s.text
    assert s.json()["entity_ids"] == [a]

    # call P&L as the scoped admin → only entity `a` is visible
    import main
    scoped_token = _mint_token(scoped_id)
    from fastapi.testclient import TestClient
    with TestClient(main.app, headers={"Origin": "http://testserver"}) as sc:
        sc.headers.update({"Authorization": f"Bearer {scoped_token}"})
        r = sc.get(f"/api/admin/entities/pnl?start={year}-01-01&end={year}-12-31")
        assert r.status_code == 200, r.text
        ids = {e["entity_id"] for e in r.json()["entities"]}
        assert a in ids and b not in ids
        # entities list is likewise scoped
        el = sc.get("/api/admin/entities").json()
        assert el["scoped"] is True
        lids = {e["id"] for e in el["entities"]}
        assert lids == {a}


def test_entity_scope_empty_is_unrestricted(admin_client, super_admin_id):
    # the module's main super_admin has no scope rows → sees all + scoped=False
    body = admin_client.get("/api/admin/entities").json()
    assert body["scoped"] is False
    assert len(body["entities"]) >= 1
