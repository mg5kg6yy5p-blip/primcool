"""CMMS #1 — work-order classification: order_type, priority, SLA (HTTP).

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
    tmpdir = tempfile.mkdtemp(prefix="cmms_wo_api_")
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
        ("WOCLS1", "WO Class Customer", _now()))
    cid = cur.lastrowid
    con.commit()
    con.close()
    return cid


def _iso(dt):
    return dt.astimezone(timezone.utc).isoformat()


# ── create + round-trip ──────────────────────────────────────────────────────
def test_create_with_classification(admin_client, customer_id):
    deadline = _iso(datetime.now(timezone.utc) + timedelta(days=2))
    r = admin_client.post("/api/admin/visits",
                          json={"customer_id": customer_id, "visit_type": "CM",
                                "order_type": "predictive", "priority": "high",
                                "sla_deadline": deadline, "sla_basis": "resolve"})
    assert r.status_code == 200, r.text
    vid = r.json()["id"]
    g = admin_client.get(f"/api/admin/visits/{vid}")
    assert g.status_code == 200, g.text
    d = g.json()
    assert d["order_type"] == "predictive"
    assert d["priority"] == "high"
    assert d["sla_basis"] == "resolve"
    assert d["sla_status"] == "on_track"   # deadline 2 days out, still open


def test_default_order_type_reactive(admin_client, customer_id):
    r = admin_client.post("/api/admin/visits",
                          json={"customer_id": customer_id, "visit_type": "CM"})
    vid = r.json()["id"]
    d = admin_client.get(f"/api/admin/visits/{vid}").json()
    assert d["order_type"] == "reactive"
    assert d["priority"] == "normal"       # column default
    assert d["sla_status"] == "none"       # no deadline set


# ── validation ───────────────────────────────────────────────────────────────
def test_bad_order_type_422(admin_client, customer_id):
    r = admin_client.post("/api/admin/visits",
                          json={"customer_id": customer_id, "visit_type": "CM",
                                "order_type": "bogus"})
    assert r.status_code == 422


def test_bad_priority_422(admin_client, customer_id):
    r = admin_client.post("/api/admin/visits",
                          json={"customer_id": customer_id, "visit_type": "CM",
                                "priority": "supercritical"})
    assert r.status_code == 422


def test_bad_sla_basis_422(admin_client, customer_id):
    r = admin_client.post("/api/admin/visits",
                          json={"customer_id": customer_id, "visit_type": "CM",
                                "sla_basis": "whenever"})
    assert r.status_code == 422


# ── SLA badge transitions ────────────────────────────────────────────────────
def test_sla_breached_when_open_past_deadline(admin_client, customer_id):
    past = _iso(datetime.now(timezone.utc) - timedelta(hours=1))
    r = admin_client.post("/api/admin/visits",
                          json={"customer_id": customer_id, "visit_type": "CM",
                                "sla_deadline": past})
    vid = r.json()["id"]
    d = admin_client.get(f"/api/admin/visits/{vid}").json()
    assert d["sla_status"] == "breached"


def test_sla_due_soon(admin_client, customer_id):
    soon = _iso(datetime.now(timezone.utc) + timedelta(hours=3))
    r = admin_client.post("/api/admin/visits",
                          json={"customer_id": customer_id, "visit_type": "CM",
                                "sla_deadline": soon})
    vid = r.json()["id"]
    d = admin_client.get(f"/api/admin/visits/{vid}").json()
    assert d["sla_status"] == "due_soon"


# ── patch leaves classification intact when omitted, updates when sent ────────
def test_patch_preserves_then_updates(admin_client, customer_id):
    deadline = _iso(datetime.now(timezone.utc) + timedelta(days=3))
    vid = admin_client.post(
        "/api/admin/visits",
        json={"customer_id": customer_id, "visit_type": "CM",
              "order_type": "reactive", "priority": "urgent",
              "sla_deadline": deadline}).json()["id"]
    # legacy edit payload that omits the new fields must not wipe them
    admin_client.put(f"/api/admin/visits/{vid}",
                     json={"visit_type": "CM", "status": "scheduled"})
    d = admin_client.get(f"/api/admin/visits/{vid}").json()
    assert d["priority"] == "urgent"
    assert d["order_type"] == "reactive"
    # now actually change priority
    admin_client.put(f"/api/admin/visits/{vid}",
                     json={"visit_type": "CM", "status": "scheduled",
                           "priority": "low"})
    d2 = admin_client.get(f"/api/admin/visits/{vid}").json()
    assert d2["priority"] == "low"


# ── list endpoint surfaces sla_status ────────────────────────────────────────
def test_list_includes_sla_status(admin_client, customer_id):
    r = admin_client.get("/api/admin/visits")
    assert r.status_code == 200, r.text
    rows = r.json()
    assert isinstance(rows, list) and rows
    assert all("sla_status" in row for row in rows)
