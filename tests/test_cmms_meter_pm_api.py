"""CMMS #2 — usage/condition meter-based PM triggers (HTTP).

Self-isolating like the other CMMS API tests: copy the live submissions.db to a
temp file and point database.DB_PATH at the copy BEFORE the app lifespan runs
init_db(), so the live DB stays pristine.
"""
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


def _now():
    return datetime.now(timezone.utc).isoformat()


@pytest.fixture(scope="module")
def iso_client():
    if not _LIVE_DB.exists():
        pytest.skip("submissions.db not present")
    import tempfile
    tmpdir = tempfile.mkdtemp(prefix="cmms_meter_api_")
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
        ("METERC1", "Meter PM Customer", _now()))
    cid = cur.lastrowid
    con.commit()
    con.close()
    return cid


def _new_equipment(customer_id, name="Chiller-1"):
    con = sqlite3.connect(database.DB_PATH)
    cur = con.execute(
        "INSERT INTO equipment (customer_id, name, type, created_at) VALUES (?,?,?,?)",
        (customer_id, name, "chiller", _now()))
    eid = cur.lastrowid
    con.commit()
    con.close()
    return eid


# ── usage trigger ────────────────────────────────────────────────────────────
def test_usage_trigger_fires_at_interval(admin_client, customer_id):
    eid = _new_equipment(customer_id, "RunHours-Unit")
    # baseline seeds at 0 (no readings yet)
    t = admin_client.post(f"/api/admin/equipment/{eid}/meter-triggers",
                          json={"meter_name": "run_hours", "mode": "usage",
                                "interval_value": 100})
    assert t.status_code == 200, t.text
    # 40 hrs → no fire
    r = admin_client.post(f"/api/admin/equipment/{eid}/meters",
                          json={"meter_name": "run_hours", "reading_value": 40})
    assert r.status_code == 200, r.text
    assert r.json()["generated_visits"] == []
    # 120 hrs → crosses 100 → fire
    r2 = admin_client.post(f"/api/admin/equipment/{eid}/meters",
                           json={"meter_name": "run_hours", "reading_value": 120})
    gen = r2.json()["generated_visits"]
    assert len(gen) == 1
    # generated visit is a predictive PM
    d = admin_client.get(f"/api/admin/visits/{gen[0]}").json()
    assert d["order_type"] == "predictive"
    assert d["visit_type"] == "PM"


def test_usage_trigger_no_double_fire_same_interval(admin_client, customer_id):
    eid = _new_equipment(customer_id, "RunHours-Unit2")
    admin_client.post(f"/api/admin/equipment/{eid}/meter-triggers",
                      json={"meter_name": "rh", "mode": "usage",
                            "interval_value": 50})
    admin_client.post(f"/api/admin/equipment/{eid}/meters",
                      json={"meter_name": "rh", "reading_value": 60})  # fires
    r = admin_client.post(f"/api/admin/equipment/{eid}/meters",
                          json={"meter_name": "rh", "reading_value": 70})  # still <100
    assert r.json()["generated_visits"] == []


# ── condition trigger ─────────────────────────────────────────────────────────
def test_condition_trigger_fires_and_debounces(admin_client, customer_id):
    eid = _new_equipment(customer_id, "Pressure-Unit")
    admin_client.post(f"/api/admin/equipment/{eid}/meter-triggers",
                      json={"meter_name": "discharge_psi", "mode": "condition",
                            "comparator": ">=", "threshold_value": 250})
    # under the line → no fire
    r1 = admin_client.post(f"/api/admin/equipment/{eid}/meters",
                           json={"meter_name": "discharge_psi", "reading_value": 200})
    assert r1.json()["generated_visits"] == []
    # crosses → fire
    r2 = admin_client.post(f"/api/admin/equipment/{eid}/meters",
                           json={"meter_name": "discharge_psi", "reading_value": 300})
    assert len(r2.json()["generated_visits"]) == 1
    # still over but disarmed → no re-fire
    r3 = admin_client.post(f"/api/admin/equipment/{eid}/meters",
                           json={"meter_name": "discharge_psi", "reading_value": 320})
    assert r3.json()["generated_visits"] == []
    # back across the line → re-arm (no fire)
    r4 = admin_client.post(f"/api/admin/equipment/{eid}/meters",
                           json={"meter_name": "discharge_psi", "reading_value": 100})
    assert r4.json()["generated_visits"] == []
    # crosses again → fires again
    r5 = admin_client.post(f"/api/admin/equipment/{eid}/meters",
                           json={"meter_name": "discharge_psi", "reading_value": 280})
    assert len(r5.json()["generated_visits"]) == 1


# ── validation ─────────────────────────────────────────────────────────────────
def test_usage_requires_positive_interval_422(admin_client, customer_id):
    eid = _new_equipment(customer_id, "Bad-Usage")
    r = admin_client.post(f"/api/admin/equipment/{eid}/meter-triggers",
                          json={"meter_name": "m", "mode": "usage",
                                "interval_value": 0})
    assert r.status_code == 422


def test_condition_requires_threshold_422(admin_client, customer_id):
    eid = _new_equipment(customer_id, "Bad-Cond")
    r = admin_client.post(f"/api/admin/equipment/{eid}/meter-triggers",
                          json={"meter_name": "m", "mode": "condition",
                                "comparator": ">="})
    assert r.status_code == 422


def test_bad_mode_422(admin_client, customer_id):
    eid = _new_equipment(customer_id, "Bad-Mode")
    r = admin_client.post(f"/api/admin/equipment/{eid}/meter-triggers",
                          json={"meter_name": "m", "mode": "bogus"})
    assert r.status_code == 422


def test_meters_404_for_missing_equipment(admin_client):
    r = admin_client.get("/api/admin/equipment/999999999/meters")
    assert r.status_code == 404


# ── toggle + list ───────────────────────────────────────────────────────────
def test_toggle_trigger_disables_firing(admin_client, customer_id):
    eid = _new_equipment(customer_id, "Toggle-Unit")
    t = admin_client.post(f"/api/admin/equipment/{eid}/meter-triggers",
                          json={"meter_name": "rh", "mode": "usage",
                                "interval_value": 10}).json()
    tid = t["id"]
    admin_client.post(f"/api/admin/meter-triggers/{tid}/toggle?active=false")
    r = admin_client.post(f"/api/admin/equipment/{eid}/meters",
                          json={"meter_name": "rh", "reading_value": 999})
    assert r.json()["generated_visits"] == []   # disabled trigger never fires


def test_meters_endpoint_lists_readings_and_triggers(admin_client, customer_id):
    eid = _new_equipment(customer_id, "List-Unit")
    admin_client.post(f"/api/admin/equipment/{eid}/meter-triggers",
                      json={"meter_name": "rh", "mode": "usage", "interval_value": 100})
    admin_client.post(f"/api/admin/equipment/{eid}/meters",
                      json={"meter_name": "rh", "reading_value": 5})
    g = admin_client.get(f"/api/admin/equipment/{eid}/meters").json()
    assert len(g["readings"]) == 1
    assert len(g["triggers"]) == 1
