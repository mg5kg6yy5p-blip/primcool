"""CMMS #3 — work-order labor entries + job costing (HTTP).

Self-isolating like the other CMMS API tests: copy the live submissions.db to a
temp file and point database.DB_PATH at the copy BEFORE the app lifespan runs
init_db(), so the live DB stays pristine. Auth mints a session for the first
active super_admin.
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
    tmpdir = tempfile.mkdtemp(prefix="cmms_labor_api_")
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
        ("WOLAB1", "WO Labor Customer", _now()))
    cid = cur.lastrowid
    con.commit()
    con.close()
    return cid


@pytest.fixture(scope="module")
def tech_id(iso_client):
    """A technician with a known hourly_rate so cost-rate snapshot is testable."""
    con = sqlite3.connect(database.DB_PATH)
    cur = con.execute(
        "INSERT INTO technicians (tech_code, name, pin_hash, hourly_rate, "
        "active, created_at) VALUES (?,?,?,?,?,?)",
        ("WOLABTECH", "Labor Tech", "x", 40.0, 1, _now()))
    tid = cur.lastrowid
    con.commit()
    con.close()
    return tid


def _new_visit(admin_client, customer_id, tech_id=None):
    body = {"customer_id": customer_id, "visit_type": "CM"}
    if tech_id:
        body["assigned_tech_id"] = tech_id
    r = admin_client.post("/api/admin/visits", json=body)
    assert r.status_code == 200, r.text
    return r.json()["id"]


# ── add + round-trip ─────────────────────────────────────────────────────────
def test_add_labor_and_costing(admin_client, customer_id):
    vid = _new_visit(admin_client, customer_id)
    r = admin_client.post(f"/api/admin/visits/{vid}/labor",
                          json={"hours": 2.5, "billable": True,
                                "cost_rate": 30, "bill_rate": 80})
    assert r.status_code == 200, r.text
    jc = r.json()["job_costing"]
    assert jc["labor_hours"] == 2.5
    assert jc["billable_hours"] == 2.5
    assert jc["labor_cost"] == 75.0          # 2.5 * 30
    assert jc["billable_amount"] == 200.0    # 2.5 * 80
    assert jc["source"] == "entries"
    assert jc["entry_count"] == 1


def test_cost_rate_snapshots_tech_rate(admin_client, customer_id, tech_id):
    vid = _new_visit(admin_client, customer_id, tech_id)
    # omit cost_rate → should snapshot the tech's hourly_rate (40)
    r = admin_client.post(f"/api/admin/visits/{vid}/labor",
                          json={"hours": 3, "tech_id": tech_id})
    assert r.status_code == 200, r.text
    entry = r.json()["entries"][0]
    assert entry["cost_rate"] == 40.0
    assert r.json()["job_costing"]["labor_cost"] == 120.0   # 3 * 40


def test_billable_vs_nonbillable_split(admin_client, customer_id):
    vid = _new_visit(admin_client, customer_id)
    admin_client.post(f"/api/admin/visits/{vid}/labor",
                      json={"hours": 4, "billable": True, "cost_rate": 25})
    admin_client.post(f"/api/admin/visits/{vid}/labor",
                      json={"hours": 1.5, "billable": False, "cost_rate": 25})
    jc = admin_client.get(f"/api/admin/visits/{vid}/labor").json()["job_costing"]
    assert jc["labor_hours"] == 5.5
    assert jc["billable_hours"] == 4.0
    assert jc["nonbillable_hours"] == 1.5
    assert jc["labor_cost"] == 137.5         # 5.5 * 25


def test_negative_hours_422(admin_client, customer_id):
    vid = _new_visit(admin_client, customer_id)
    r = admin_client.post(f"/api/admin/visits/{vid}/labor",
                          json={"hours": -2})
    assert r.status_code == 422


def test_delete_labor_entry(admin_client, customer_id):
    vid = _new_visit(admin_client, customer_id)
    add = admin_client.post(f"/api/admin/visits/{vid}/labor",
                            json={"hours": 2, "cost_rate": 10}).json()
    eid = add["id"]
    d = admin_client.delete(f"/api/admin/visits/{vid}/labor/{eid}")
    assert d.status_code == 200, d.text
    assert d.json()["job_costing"]["entry_count"] == 0
    # second delete of the same id → 404
    d2 = admin_client.delete(f"/api/admin/visits/{vid}/labor/{eid}")
    assert d2.status_code == 404


def test_delete_wrong_visit_scope_404(admin_client, customer_id):
    v1 = _new_visit(admin_client, customer_id)
    v2 = _new_visit(admin_client, customer_id)
    eid = admin_client.post(f"/api/admin/visits/{v1}/labor",
                            json={"hours": 1, "cost_rate": 10}).json()["id"]
    # try to delete v1's entry via v2's path → scoped delete misses → 404
    d = admin_client.delete(f"/api/admin/visits/{v2}/labor/{eid}")
    assert d.status_code == 404
    # v1's entry still there
    assert admin_client.get(
        f"/api/admin/visits/{v1}/labor").json()["job_costing"]["entry_count"] == 1


def test_visit_detail_includes_job_costing(admin_client, customer_id):
    vid = _new_visit(admin_client, customer_id)
    admin_client.post(f"/api/admin/visits/{vid}/labor",
                      json={"hours": 1, "cost_rate": 50})
    d = admin_client.get(f"/api/admin/visits/{vid}").json()
    assert "job_costing" in d
    assert d["job_costing"]["labor_cost"] == 50.0
    assert "labor_entries" in d and len(d["labor_entries"]) == 1


def test_labor_list_404_for_missing_visit(admin_client):
    r = admin_client.get("/api/admin/visits/999999999/labor")
    assert r.status_code == 404
