"""Admin Home dashboard overview (HTTP coverage).

Same isolation pattern as the other CMMS API tests: copy the live
submissions.db to a temp file and point database.DB_PATH at the copy BEFORE
the app lifespan runs init_db(), so the live DB stays pristine. Admin auth
mints a session for the first active super_admin.
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


@pytest.fixture(scope="module")
def iso_client():
    if not _LIVE_DB.exists():
        pytest.skip("submissions.db not present")
    import tempfile
    tmpdir = tempfile.mkdtemp(prefix="cmms_dash_api_")
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


def _mint_session(subject_type, subject_id):
    import main
    jti = uuid.uuid4().hex
    exp = datetime.now(timezone.utc) + timedelta(hours=2)
    token = main._make_token(
        {"sub": str(subject_id), "type": subject_type, "jti": jti},
        timedelta(hours=2))
    database.create_session(
        jti=jti, subject_type=subject_type, subject_id=subject_id,
        expires_at=exp.isoformat(), ip_address="127.0.0.1", user_agent="pytest")
    return token


def _auth(token):
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture(scope="module")
def admin_token(iso_client):
    con = sqlite3.connect(database.DB_PATH)
    row = con.execute(
        "SELECT id FROM admin_users WHERE role='super_admin' AND active=1 "
        "ORDER BY id LIMIT 1").fetchone()
    con.close()
    if not row:
        pytest.skip("no active super_admin in DB")
    return _mint_session("admin", row[0])


# ── Auth ─────────────────────────────────────────────────────────────────────
def test_requires_auth(iso_client):
    r = iso_client.get("/api/admin/dashboard/overview")
    assert r.status_code in (401, 403)


# ── Shape: super_admin sees every section ────────────────────────────────────
def test_overview_shape(iso_client, admin_token):
    r = iso_client.get("/api/admin/dashboard/overview", headers=_auth(admin_token))
    assert r.status_code == 200, r.text
    body = r.json()

    # date is today's ISO date
    today = datetime.now(timezone.utc).date().isoformat()
    assert body["date"] == today

    # jobs gauge (visit:view) — super_admin holds it
    assert "jobs" in body
    assert isinstance(body["jobs"]["completed"], int)
    assert isinstance(body["jobs"]["total"], int)
    assert body["jobs"]["completed"] <= body["jobs"]["total"]

    # kpis present, all ints
    kpis = body["kpis"]
    for key in ("new_jobs", "new_invoices", "new_estimates", "new_customers"):
        assert key in kpis, f"missing kpi {key}"
        assert isinstance(kpis[key], int)

    # today's jobs is a capped list
    assert isinstance(body["todays_jobs"], list)
    assert len(body["todays_jobs"]) <= 12

    # recent customers capped at 5
    assert isinstance(body["recent_customers"], list)
    assert len(body["recent_customers"]) <= 5


# ── Today's jobs reflect freshly-inserted rows ───────────────────────────────
def test_todays_jobs_counts(iso_client, admin_token):
    today = datetime.now(timezone.utc).date().isoformat()
    con = sqlite3.connect(database.DB_PATH)
    cur = con.execute("SELECT id FROM customers ORDER BY id LIMIT 1").fetchone()
    cust_id = cur[0] if cur else None
    base = con.execute(
        "SELECT COUNT(*) FROM maintenance_visits "
        "WHERE substr(scheduled_date,1,10)=?", (today,)).fetchone()[0]
    now = datetime.now(timezone.utc).isoformat()
    con.execute(
        "INSERT INTO maintenance_visits "
        "(customer_id, scheduled_date, scheduled_time, visit_type, status, "
        " technician, created_at) VALUES (?,?,?,?,?,?,?)",
        (cust_id, today, "09:30", "maintenance", "scheduled",
         "Dash Tester", now))
    con.execute(
        "INSERT INTO maintenance_visits "
        "(customer_id, scheduled_date, scheduled_time, visit_type, status, "
        " technician, created_at) VALUES (?,?,?,?,?,?,?)",
        (cust_id, today, "11:00", "maintenance", "completed",
         "Dash Tester", now))
    con.commit()
    con.close()

    r = iso_client.get("/api/admin/dashboard/overview", headers=_auth(admin_token))
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["jobs"]["total"] >= base + 2
    assert body["jobs"]["completed"] >= 1
    # the scheduled one should appear in todays_jobs ordering
    assert any(j.get("technician") == "Dash Tester" for j in body["todays_jobs"])
