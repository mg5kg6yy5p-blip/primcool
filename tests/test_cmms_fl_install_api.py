"""CMMS Gap #1 — HTTP route coverage for FL + equipment-install.

Self-isolating: copies the live submissions.db to a temp file and points
`database.DB_PATH` at the copy BEFORE the app's lifespan runs init_db(), so the
live DB stays pristine. A dedicated TestClient (not conftest's session-scoped
one) drives the copy; DB_PATH is restored on teardown.

Auth uses the same bootstrap-director credentials as conftest's admin_token.
Tests soft-skip if that login can't be acquired (e.g. MFA required).
"""
import os
import shutil
import sqlite3
from datetime import datetime, timezone
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
    tmpdir = tempfile.mkdtemp(prefix="cmms_api_")
    tmp_db = os.path.join(tmpdir, "submissions.db")
    shutil.copy(str(_LIVE_DB), tmp_db)
    # copy WAL sidecars too so the copy is consistent
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
    """Authenticate as the first active super_admin by minting a session token
    directly (we don't have the dev account passwords, and the goal here is to
    exercise the FL/install routes, not the login flow). This mirrors exactly
    what _issue_session does: a JWT carrying {sub,type,jti} plus a live session
    row keyed on that jti."""
    import uuid
    from datetime import timedelta
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
    """A throwaway customer created directly in the temp DB."""
    con = sqlite3.connect(database.DB_PATH)
    cur = con.execute(
        "INSERT INTO customers (customer_code, name, created_at) VALUES (?,?,?)",
        ("CMMSAPI1", "CMMS API Test Customer", _now()),
    )
    cid = cur.lastrowid
    con.commit()
    con.close()
    return cid


def _make_equipment(admin_client, customer_id, name):
    r = admin_client.post("/api/admin/equipment",
                          json={"customer_id": customer_id, "name": name})
    assert r.status_code == 200, r.text
    return r.json()["id"]


def _make_fl(admin_client, customer_id, name, **extra):
    body = {"customer_id": customer_id, "name": name}
    body.update(extra)
    r = admin_client.post("/api/admin/functional-locations", json=body)
    assert r.status_code == 200, r.text
    return r.json()["id"]


# ---------------------------------------------------------------------------
# FL CRUD + listing
# ---------------------------------------------------------------------------
def test_create_and_list_functional_locations(admin_client, customer_id):
    fl1 = _make_fl(admin_client, customer_id, "Apt 1 / LR", code="A1LR")
    fl2 = _make_fl(admin_client, customer_id, "Apt 2 / LR")
    r = admin_client.get(
        f"/api/admin/customers/{customer_id}/functional-locations")
    assert r.status_code == 200, r.text
    ids = {row["id"] for row in r.json()}
    assert {fl1, fl2} <= ids


def test_duplicate_fl_code_rejected(admin_client, customer_id):
    _make_fl(admin_client, customer_id, "Dup A", code="DUPCODE")
    r = admin_client.post("/api/admin/functional-locations",
                          json={"customer_id": customer_id, "name": "Dup B",
                                "code": "DUPCODE"})
    assert r.status_code == 422


# ---------------------------------------------------------------------------
# Install / remove + the invariant 409
# ---------------------------------------------------------------------------
def test_install_then_list_shows_occupant(admin_client, customer_id):
    fl = _make_fl(admin_client, customer_id, "Occupied Slot")
    eq = _make_equipment(admin_client, customer_id, "Installed Unit")
    r = admin_client.post(f"/api/admin/equipment/{eq}/install",
                          json={"functional_location_id": fl})
    assert r.status_code == 200, r.text
    assert r.json()["equipment"]["status"] == "installed"

    rl = admin_client.get(
        f"/api/admin/customers/{customer_id}/functional-locations")
    row = next(x for x in rl.json() if x["id"] == fl)
    assert row["active_equipment_id"] == eq
    assert row["active_equipment_name"] == "Installed Unit"


def test_second_unit_into_same_slot_409_fl(admin_client, customer_id):
    fl = _make_fl(admin_client, customer_id, "Single Slot")
    e1 = _make_equipment(admin_client, customer_id, "First")
    e2 = _make_equipment(admin_client, customer_id, "Second")
    assert admin_client.post(f"/api/admin/equipment/{e1}/install",
                             json={"functional_location_id": fl}).status_code == 200
    r = admin_client.post(f"/api/admin/equipment/{e2}/install",
                          json={"functional_location_id": fl})
    assert r.status_code == 409
    assert r.json()["detail"]["scope"] == "fl"


def test_same_unit_two_slots_409_equipment(admin_client, customer_id):
    fl1 = _make_fl(admin_client, customer_id, "Slot One")
    fl2 = _make_fl(admin_client, customer_id, "Slot Two")
    e1 = _make_equipment(admin_client, customer_id, "Roamer")
    assert admin_client.post(f"/api/admin/equipment/{e1}/install",
                             json={"functional_location_id": fl1}).status_code == 200
    r = admin_client.post(f"/api/admin/equipment/{e1}/install",
                          json={"functional_location_id": fl2})
    assert r.status_code == 409
    assert r.json()["detail"]["scope"] == "equipment"


def test_remove_then_reinstall_swap(admin_client, customer_id):
    fl = _make_fl(admin_client, customer_id, "Swap Slot")
    u1 = _make_equipment(admin_client, customer_id, "Old Unit")
    u2 = _make_equipment(admin_client, customer_id, "Loaner")
    admin_client.post(f"/api/admin/equipment/{u1}/install",
                      json={"functional_location_id": fl})
    # pull u1 to repair
    r = admin_client.post(f"/api/admin/equipment/{u1}/remove-install",
                          json={"new_status": "in_repair"})
    assert r.status_code == 200, r.text
    assert r.json()["equipment"]["status"] == "in_repair"
    # loaner drops in cleanly
    r2 = admin_client.post(f"/api/admin/equipment/{u2}/install",
                           json={"functional_location_id": fl})
    assert r2.status_code == 200, r2.text


def test_remove_when_not_installed_409(admin_client, customer_id):
    eq = _make_equipment(admin_client, customer_id, "Shelf Unit")
    r = admin_client.post(f"/api/admin/equipment/{eq}/remove-install", json={})
    assert r.status_code == 409


# ---------------------------------------------------------------------------
# History
# ---------------------------------------------------------------------------
def test_equipment_history_endpoint(admin_client, customer_id):
    fl1 = _make_fl(admin_client, customer_id, "Hist A")
    fl2 = _make_fl(admin_client, customer_id, "Hist B")
    eq = _make_equipment(admin_client, customer_id, "Traveler")
    admin_client.post(f"/api/admin/equipment/{eq}/install",
                      json={"functional_location_id": fl1})
    admin_client.post(f"/api/admin/equipment/{eq}/remove-install", json={})
    admin_client.post(f"/api/admin/equipment/{eq}/install",
                      json={"functional_location_id": fl2})
    r = admin_client.get(f"/api/admin/equipment/{eq}/history")
    assert r.status_code == 200, r.text
    hist = r.json()
    assert len(hist) == 2
    assert hist[0]["functional_location_id"] == fl2
    assert hist[0]["removed_at"] is None


def test_fl_history_endpoint(admin_client, customer_id):
    fl = _make_fl(admin_client, customer_id, "FL Hist")
    u1 = _make_equipment(admin_client, customer_id, "Occ 1")
    admin_client.post(f"/api/admin/equipment/{u1}/install",
                      json={"functional_location_id": fl})
    r = admin_client.get(f"/api/admin/functional-locations/{fl}/history")
    assert r.status_code == 200, r.text
    assert r.json()[0]["equipment_id"] == u1


# ---------------------------------------------------------------------------
# Equipment status/warranty via PATCH
# ---------------------------------------------------------------------------
def test_patch_status_and_warranty(admin_client, customer_id):
    eq = _make_equipment(admin_client, customer_id, "Warranty Unit")
    r = admin_client.patch(f"/api/admin/equipment/{eq}",
                           json={"status": "in_repair", "warranty_months": 24})
    assert r.status_code == 200, r.text
    after = r.json()["equipment"]
    assert after["status"] == "in_repair"
    assert after["warranty_months"] == 24


def test_patch_invalid_status_422(admin_client, customer_id):
    eq = _make_equipment(admin_client, customer_id, "Bad Status Unit")
    r = admin_client.patch(f"/api/admin/equipment/{eq}",
                           json={"status": "teleported"})
    assert r.status_code == 422
