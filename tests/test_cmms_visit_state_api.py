"""CMMS Gap #3 — HTTP route coverage for the visit lifecycle state machine.

Self-isolating: copies the live submissions.db to a temp file and points
`database.DB_PATH` at the copy BEFORE the app's lifespan runs init_db(), so the
live DB stays pristine. A dedicated TestClient drives the copy; DB_PATH is
restored on teardown. Auth mints a session directly for the first active
super_admin (dev passwords unknown), mirroring the Gap #1 API tests.
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
    tmpdir = tempfile.mkdtemp(prefix="cmms_visit_api_")
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
        "ORDER BY id LIMIT 1"
    ).fetchone()
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
        ("VSTAPI1", "Visit State API Customer", _now()),
    )
    cid = cur.lastrowid
    con.commit()
    con.close()
    return cid


def _make_visit(admin_client, customer_id, status="scheduled"):
    r = admin_client.post("/api/admin/visits",
                          json={"customer_id": customer_id, "visit_type": "PM",
                                "status": status})
    assert r.status_code == 200, r.text
    return r.json()["id"]


def _get_status(visit_id):
    con = sqlite3.connect(database.DB_PATH)
    row = con.execute(
        "SELECT status FROM maintenance_visits WHERE id=?", (visit_id,)
    ).fetchone()
    con.close()
    return row[0]


# ---------------------------------------------------------------------------
# Transition endpoint
# ---------------------------------------------------------------------------
def test_transition_legal_move(admin_client, customer_id):
    vid = _make_visit(admin_client, customer_id)
    r = admin_client.post(f"/api/admin/visits/{vid}/transition",
                          json={"status": "in_progress"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["old"] == "scheduled"
    assert body["new"] == "in_progress"
    assert _get_status(vid) == "in_progress"


def test_transition_illegal_move_409(admin_client, customer_id):
    vid = _make_visit(admin_client, customer_id)  # scheduled
    r = admin_client.post(f"/api/admin/visits/{vid}/transition",
                          json={"status": "completed"})
    assert r.status_code == 409, r.text
    detail = r.json()["detail"]
    assert detail["scope"] == "transition"
    assert detail["current"] == "scheduled"
    assert _get_status(vid) == "scheduled"  # unchanged


def test_transition_cancel_with_reason(admin_client, customer_id):
    vid = _make_visit(admin_client, customer_id)
    r = admin_client.post(f"/api/admin/visits/{vid}/transition",
                          json={"status": "cancelled", "reason": "dup booking"})
    assert r.status_code == 200, r.text
    assert _get_status(vid) == "cancelled"


def test_transition_alias_tech_complete(admin_client, customer_id):
    vid = _make_visit(admin_client, customer_id, status="in_progress")
    r = admin_client.post(f"/api/admin/visits/{vid}/transition",
                          json={"status": "tech_complete"})
    assert r.status_code == 200, r.text
    assert r.json()["new"] == "completed"


def test_transition_404_for_missing_visit(admin_client):
    r = admin_client.post("/api/admin/visits/99999999/transition",
                          json={"status": "in_progress"})
    assert r.status_code == 404


# ---------------------------------------------------------------------------
# update endpoint guarded by the same machine
# ---------------------------------------------------------------------------
def test_update_illegal_status_jump_409(admin_client, customer_id):
    vid = _make_visit(admin_client, customer_id)  # scheduled
    r = admin_client.put(f"/api/admin/visits/{vid}",
                         json={"visit_type": "PM", "status": "completed"})
    assert r.status_code == 409, r.text
    assert _get_status(vid) == "scheduled"


def test_update_frozen_completed_visit_409(admin_client, customer_id):
    vid = _make_visit(admin_client, customer_id, status="in_progress")
    admin_client.post(f"/api/admin/visits/{vid}/transition",
                      json={"status": "completed"})
    r = admin_client.put(f"/api/admin/visits/{vid}",
                         json={"visit_type": "PM", "status": "completed",
                               "scope_of_work": "edited after lock"})
    assert r.status_code == 409, r.text
