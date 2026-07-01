"""CMMS #7 — data-model coherence: cascading updates on work-order completion
(materialise the next contract PM, settle the job-costing rollup) and the single
authoritative dependent view (`/coherence`).

Self-isolating like the other CMMS API tests: copy the live submissions.db to a
temp file and point database.DB_PATH at the copy BEFORE the app lifespan runs
init_db(), so the live DB stays pristine.
"""
import itertools
import os
import shutil
import sqlite3
import uuid
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

import pytest

import database

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_LIVE_DB = _PROJECT_ROOT / "submissions.db"
_SEQ = itertools.count(1)


def _now():
    return datetime.now(timezone.utc).isoformat()


@pytest.fixture(scope="module")
def iso_client():
    if not _LIVE_DB.exists():
        pytest.skip("submissions.db not present")
    import tempfile
    tmpdir = tempfile.mkdtemp(prefix="cmms_coherence_")
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
        (f"COHC{next(_SEQ)}", "Coherence Customer", _now()))
    cid = cur.lastrowid
    con.commit()
    con.close()
    return cid


def _new_visit(customer_id, status="in_progress", pm_contract_id=None,
               scheduled_date=None):
    con = sqlite3.connect(database.DB_PATH)
    cur = con.execute(
        "INSERT INTO maintenance_visits "
        "(customer_id, visit_type, status, scheduled_date, pm_contract_id, "
        " start_time, created_at) VALUES (?,?,?,?,?,?,?)",
        (customer_id, "PM" if pm_contract_id else "CM", status,
         scheduled_date or date.today().isoformat(), pm_contract_id,
         _now(), _now()))
    vid = cur.lastrowid
    con.commit()
    con.close()
    return vid


def _new_contract(customer_id, start_date, end_date, frequency="monthly"):
    con = sqlite3.connect(database.DB_PATH)
    code = f"PMC-COH-{uuid.uuid4().hex[:8]}"
    cur = con.execute(
        "INSERT INTO pm_contracts "
        "(contract_code, customer_id, hub_id, title, start_date, end_date, "
        " frequency, status, created_at) VALUES (?,?,?,?,?,?,?,?,?)",
        (code, customer_id, 1, "Coherence PM", start_date, end_date,
         frequency, "active", _now()))
    ctid = cur.lastrowid
    con.commit()
    con.close()
    return ctid


def _add_labor(visit_id, hours, cost_rate):
    con = sqlite3.connect(database.DB_PATH)
    con.execute(
        "INSERT INTO visit_labor_entries "
        "(visit_id, hours, billable, cost_rate, created_at) VALUES (?,?,?,?,?)",
        (visit_id, hours, 1, cost_rate, _now()))
    con.commit()
    con.close()


# ── Tests ────────────────────────────────────────────────────────────────────

def test_completion_cascade_generates_next_pm(admin_client, customer_id):
    # A contract that started 40 days ago (monthly). Due dates fall at ~day -40,
    # -10, +20, +50 … Within the 30-day lookahead used by the cascade, day -10
    # and day +20 are due-and-unmaterialised once we complete the -40 one.
    today = date.today()
    start = (today - timedelta(days=40)).isoformat()
    end = (today + timedelta(days=180)).isoformat()
    ctid = _new_contract(customer_id, start, end, "monthly")
    # The WO we complete is dated day -40 and pre-materialised (in_progress).
    vid = _new_visit(customer_id, status="in_progress", pm_contract_id=ctid,
                     scheduled_date=start)

    r = admin_client.post(f"/api/admin/visits/{vid}/transition",
                          json={"status": "completed"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["new"] == "completed"
    cascade = body.get("cascade")
    assert cascade is not None, "expected a coherence cascade on completion"
    assert cascade["pm_contract_id"] == ctid
    assert cascade.get("next_pm_created"), \
        f"expected the next PM(s) to be auto-scheduled, got {cascade!r}"
    # The generated visits really exist, are PM, and belong to this contract.
    con = sqlite3.connect(database.DB_PATH)
    con.row_factory = sqlite3.Row
    for nid in cascade["next_pm_created"]:
        row = con.execute(
            "SELECT visit_type, pm_contract_id, status FROM maintenance_visits "
            "WHERE id = ?", (nid,)).fetchone()
        assert row["pm_contract_id"] == ctid
        assert row["visit_type"] == "PM"
        assert row["status"] == "scheduled"
    con.close()


def test_completion_cascade_settles_job_cost(admin_client, customer_id):
    vid = _new_visit(customer_id, status="in_progress")   # non-contract CM
    _add_labor(vid, hours=2.0, cost_rate=50.0)            # -> $100 labour
    r = admin_client.post(f"/api/admin/visits/{vid}/transition",
                          json={"status": "completed"})
    assert r.status_code == 200, r.text
    cascade = r.json().get("cascade")
    assert cascade is not None
    assert cascade["pm_contract_id"] is None
    assert cascade["next_pm_created"] == []
    jc = cascade["job_costing"]
    assert jc is not None
    assert jc["labor_cost"] == 100.0
    assert jc["total_cost"] == 100.0


def test_no_cascade_on_non_completion_transition(admin_client, customer_id):
    # scheduled -> in_progress must not fire the completion cascade.
    vid = _new_visit(customer_id, status="scheduled")
    r = admin_client.post(f"/api/admin/visits/{vid}/transition",
                          json={"status": "in_progress"})
    assert r.status_code == 200, r.text
    assert "cascade" not in r.json()


def test_coherence_view_for_contract_pm(admin_client, customer_id):
    today = date.today()
    start = (today - timedelta(days=5)).isoformat()
    end = (today + timedelta(days=120)).isoformat()
    ctid = _new_contract(customer_id, start, end, "monthly")
    vid = _new_visit(customer_id, status="in_progress", pm_contract_id=ctid,
                     scheduled_date=start)

    r = admin_client.get(f"/api/admin/visits/{vid}/coherence")
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["visit_id"] == vid
    assert data["pm_contract_id"] == ctid
    assert data["pm_contract"] is not None
    assert data["pm_contract"]["id"] == ctid
    # The WO itself is one of the contract's PM siblings.
    sib_ids = {s["id"] for s in data["pm_siblings"]}
    assert vid in sib_ids
    assert "job_costing" in data


def test_coherence_view_for_non_contract_wo(admin_client, customer_id):
    vid = _new_visit(customer_id, status="in_progress")
    _add_labor(vid, hours=1.0, cost_rate=40.0)
    r = admin_client.get(f"/api/admin/visits/{vid}/coherence")
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["pm_contract_id"] is None
    assert data["pm_contract"] is None
    assert data["pm_siblings"] == []
    assert data["job_costing"]["labor_cost"] == 40.0


def test_coherence_view_404_for_missing_visit(admin_client):
    r = admin_client.get("/api/admin/visits/999999999/coherence")
    assert r.status_code == 404
