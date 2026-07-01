"""CMMS #5 — workforce planning (demand/capacity, allocation, skill match).

Self-isolating like the other CMMS API tests: copy the live submissions.db to a
temp file and point database.DB_PATH at the copy BEFORE the app lifespan runs
init_db(), so the live DB stays pristine.

Every test grabs a FRESH hub_id (via _HUB) and creates its techs + visits in
that hub, then scopes the forecast/allocation/skill-match calls to it — that
isolates each test from the live techs/visits carried in the copied DB and from
the other tests in this module.
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
_HUB = itertools.count(99100)   # fresh, unused hub per test → isolation


def _now():
    return datetime.now(timezone.utc).isoformat()


@pytest.fixture(scope="module")
def iso_client():
    if not _LIVE_DB.exists():
        pytest.skip("submissions.db not present")
    import tempfile
    tmpdir = tempfile.mkdtemp(prefix="cmms_wf_api_")
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


@pytest.fixture(scope="module")
def admin_client(iso_client):
    import main
    con = sqlite3.connect(database.DB_PATH)
    row = con.execute(
        "SELECT id FROM admin_users WHERE role='super_admin' AND active=1 "
        "ORDER BY id LIMIT 1").fetchone()
    con.close()
    if not row:
        pytest.skip("no active super_admin in DB")
    admin_id = row[0]
    jti = uuid.uuid4().hex
    exp = datetime.now(timezone.utc) + timedelta(hours=2)
    token = main._make_token(
        {"sub": str(admin_id), "type": "admin", "jti": jti}, timedelta(hours=2))
    database.create_session(
        jti=jti, subject_type="admin", subject_id=admin_id,
        expires_at=exp.isoformat(), ip_address="127.0.0.1", user_agent="pytest")
    iso_client.headers.update({"Authorization": f"Bearer {token}"})
    return iso_client


@pytest.fixture(scope="module")
def customer_id(iso_client):
    con = sqlite3.connect(database.DB_PATH)
    cur = con.execute(
        "INSERT INTO customers (customer_code, name, created_at) VALUES (?,?,?)",
        ("WFC1", "Workforce Customer", _now()))
    cid = cur.lastrowid
    con.commit()
    con.close()
    return cid


def _new_tech(name, hub_id, capacity=8.0):
    con = sqlite3.connect(database.DB_PATH)
    cur = con.execute(
        "INSERT INTO technicians "
        "(tech_code, pin_hash, name, role, active, employment_status, "
        " staff_type, department, hub_id, daily_capacity_hours, hourly_rate, "
        " created_at) "
        "VALUES (?,?,?,?,1,'active','tech','field',?,?,?,?)",
        (f"WF-{uuid.uuid4().hex[:8]}", "x", name, "tech",
         hub_id, capacity, 40.0, _now()))
    tid = cur.lastrowid
    con.commit()
    con.close()
    return tid


def _new_visit(customer_id, hub_id, scheduled_date, est_min=None,
               assigned_tech_id=None, required_skill=None, status="scheduled"):
    con = sqlite3.connect(database.DB_PATH)
    cur = con.execute(
        "INSERT INTO maintenance_visits "
        "(customer_id, visit_type, status, scheduled_date, assigned_tech_id, "
        " estimated_duration_min, required_skill, hub_id, created_at) "
        "VALUES (?,?,?,?,?,?,?,?,?)",
        (customer_id, "CM", status, scheduled_date, assigned_tech_id,
         est_min, required_skill, hub_id, _now()))
    vid = cur.lastrowid
    con.commit()
    con.close()
    return vid


# ── forecast: demand vs capacity ──────────────────────────────────────────────
def test_forecast_demand_vs_capacity_and_over_capacity_alert(admin_client, customer_id):
    hub = next(_HUB)
    _new_tech("T1", hub, 8.0)
    _new_tech("T2", hub, 8.0)            # capacity = 16h/day
    d1, d2 = "2030-01-10", "2030-01-11"
    # D1: two 4h visits → 8h demand (under 16h)
    _new_visit(customer_id, hub, d1, est_min=240)
    _new_visit(customer_id, hub, d1, est_min=240)
    # D2: two 10h visits → 20h demand (over 16h)
    _new_visit(customer_id, hub, d2, est_min=600)
    _new_visit(customer_id, hub, d2, est_min=600)

    r = admin_client.get(f"/api/admin/workforce/forecast?start={d1}&end={d2}&hub_id={hub}")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["capacity_hours"] == 16
    assert body["tech_count"] == 2
    days = {d["date"]: d for d in body["days"]}
    assert days[d1]["demand_hours"] == 8 and days[d1]["over_capacity"] is False
    assert days[d2]["demand_hours"] == 20 and days[d2]["over_capacity"] is True
    assert any(a["date"] == d2 and a["type"] == "over_capacity"
               for a in body["alerts"])


def test_forecast_defaults_hours_when_no_estimate(admin_client, customer_id):
    hub = next(_HUB)
    _new_tech("Solo", hub, 8.0)
    d = "2030-02-01"
    _new_visit(customer_id, hub, d, est_min=None)   # → 2.0h default
    r = admin_client.get(f"/api/admin/workforce/forecast?start={d}&end={d}&hub_id={hub}")
    day = r.json()["days"][0]
    assert day["demand_hours"] == 2.0
    assert day["work_orders"] == 1


# ── allocation: per-tech over-allocation ──────────────────────────────────────
def test_allocation_flags_over_allocated_tech(admin_client, customer_id):
    hub = next(_HUB)
    tid = _new_tech("Busy", hub, 8.0)
    d = "2030-03-05"
    # 3 × 4h all assigned to the same tech on one day → 12h > 8h cap
    for _ in range(3):
        _new_visit(customer_id, hub, d, est_min=240, assigned_tech_id=tid)
    r = admin_client.get(f"/api/admin/workforce/allocation?start={d}&end={d}&hub_id={hub}")
    assert r.status_code == 200, r.text
    body = r.json()
    me = next(t for t in body["technicians"] if t["tech_id"] == tid)
    assert me["assigned_hours"] == 12
    assert me["work_orders"] == 3
    assert any(od["date"] == d for od in me["over_allocated_days"])
    assert any(a["tech_id"] == tid and a["type"] == "over_allocated"
               for a in body["alerts"])


# ── skill match ───────────────────────────────────────────────────────────────
def test_skill_match_ranks_skilled_first(admin_client, customer_id):
    hub = next(_HUB)
    skilled = _new_tech("Skilled", hub, 8.0)
    unskilled = _new_tech("Unskilled", hub, 8.0)
    admin_client.post(f"/api/admin/technicians/{skilled}/skills",
                      json={"skill": "refrigeration", "proficiency": "expert"})
    vid = _new_visit(customer_id, hub, "2030-04-01", est_min=120,
                     required_skill="refrigeration")
    r = admin_client.get(f"/api/admin/visits/{vid}/skill-match")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["required_skill"] == "refrigeration"
    cand = {c["tech_id"]: c for c in body["candidates"]}
    assert cand[skilled]["has_skill"] is True
    assert cand[unskilled]["has_skill"] is False
    # skilled tech ranks ahead of the unskilled one
    order = [c["tech_id"] for c in body["candidates"]]
    assert order.index(skilled) < order.index(unskilled)


def test_skill_match_prefers_freer_capacity(admin_client, customer_id):
    hub = next(_HUB)
    free = _new_tech("Free", hub, 8.0)
    loaded = _new_tech("Loaded", hub, 8.0)
    for t in (free, loaded):
        admin_client.post(f"/api/admin/technicians/{t}/skills",
                          json={"skill": "electrical"})
    day = "2030-05-02"
    # load the "loaded" tech with a 6h job that day
    _new_visit(customer_id, hub, day, est_min=360, assigned_tech_id=loaded)
    vid = _new_visit(customer_id, hub, day, est_min=120, required_skill="electrical")
    r = admin_client.get(f"/api/admin/visits/{vid}/skill-match")
    body = r.json()
    cand = {c["tech_id"]: c for c in body["candidates"]}
    assert cand[loaded]["assigned_hours"] == 6
    assert cand[free]["assigned_hours"] == 0
    order = [c["tech_id"] for c in body["candidates"]]
    # both skilled, so the freer tech ranks first
    assert order.index(free) < order.index(loaded)


def test_skill_match_404_missing_visit(admin_client):
    r = admin_client.get("/api/admin/visits/999999999/skill-match")
    assert r.status_code == 404


# ── skills registry CRUD ──────────────────────────────────────────────────────
def test_skills_add_list_remove(admin_client):
    hub = next(_HUB)
    tid = _new_tech("CRUD", hub, 8.0)
    a = admin_client.post(f"/api/admin/technicians/{tid}/skills",
                          json={"skill": "welding", "proficiency": "qualified"})
    assert a.status_code == 200, a.text
    assert any(s["skill"] == "welding" for s in a.json()["skills"])
    g = admin_client.get(f"/api/admin/technicians/{tid}/skills").json()
    assert any(s["skill"] == "welding" for s in g["skills"])
    d = admin_client.delete(f"/api/admin/technicians/{tid}/skills/welding")
    assert d.status_code == 200, d.text
    assert all(s["skill"] != "welding" for s in d.json()["skills"])
    # removing again → 404
    d2 = admin_client.delete(f"/api/admin/technicians/{tid}/skills/welding")
    assert d2.status_code == 404


def test_skill_bad_proficiency_422(admin_client):
    hub = next(_HUB)
    tid = _new_tech("BadProf", hub, 8.0)
    r = admin_client.post(f"/api/admin/technicians/{tid}/skills",
                          json={"skill": "hvac", "proficiency": "wizard"})
    assert r.status_code == 422


def test_skills_404_for_missing_tech(admin_client):
    r = admin_client.get("/api/admin/technicians/999999999/skills")
    assert r.status_code == 404


# ── capacity setter ────────────────────────────────────────────────────────────
def test_set_capacity_then_forecast_reflects_it(admin_client, customer_id):
    hub = next(_HUB)
    tid = _new_tech("CapTech", hub, 8.0)
    r = admin_client.post(f"/api/admin/technicians/{tid}/capacity",
                          json={"daily_capacity_hours": 12})
    assert r.status_code == 200, r.text
    f = admin_client.get(
        f"/api/admin/workforce/forecast?start=2030-06-01&end=2030-06-01&hub_id={hub}").json()
    assert f["capacity_hours"] == 12


def test_set_capacity_negative_422(admin_client, customer_id):
    hub = next(_HUB)
    tid = _new_tech("NegCap", hub, 8.0)
    r = admin_client.post(f"/api/admin/technicians/{tid}/capacity",
                          json={"daily_capacity_hours": -3})
    assert r.status_code == 422
