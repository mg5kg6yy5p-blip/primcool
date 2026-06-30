"""CMMS Phase 6 — HTTP coverage for asset registry depth + BOM.

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


def _now():
    return datetime.now(timezone.utc).isoformat()


@pytest.fixture(scope="module")
def iso_client():
    if not _LIVE_DB.exists():
        pytest.skip("submissions.db not present")
    import tempfile
    tmpdir = tempfile.mkdtemp(prefix="cmms_asset_bom_api_")
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


def _auth(token):
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture(scope="module")
def customer(iso_client):
    con = sqlite3.connect(database.DB_PATH)
    cid = con.execute(
        "INSERT INTO customers (customer_code, name, created_at) VALUES (?,?,?)",
        ("BOMAPI1", "Asset-BOM Cust", _now())).lastrowid
    con.commit()
    con.close()
    return cid


def _make_equipment(iso_client, admin_token, customer_id, name, **extra):
    body = {"customer_id": customer_id, "name": name}
    body.update(extra)
    r = iso_client.post("/api/admin/equipment", json=body,
                        headers=_auth(admin_token))
    assert r.status_code == 200, r.text
    return r.json()["id"]


_PART_SEQ = [0]


def _make_part(iso_client, admin_token, name, **extra):
    _PART_SEQ[0] += 1
    body = {"sku": "BOMAPIP%04d" % _PART_SEQ[0], "name": name}
    body.update(extra)
    r = iso_client.post("/api/admin/parts", json=body, headers=_auth(admin_token))
    assert r.status_code == 200, r.text
    return r.json().get("id") or r.json().get("part", {}).get("id")


# ── Nameplate create + patch round-trip ─────────────────────────────────────
def test_create_with_nameplate(iso_client, admin_token, customer):
    eq = _make_equipment(iso_client, admin_token, customer, "Nameplate Unit",
                         manufacturer="Daikin", refrigerant_type="R-32",
                         capacity_btu=48000, voltage="230", phase="1",
                         specification="VRV IV-S")
    # confirm via the customer equipment list
    r = iso_client.get(f"/api/admin/customers/{customer}/equipment",
                       headers=_auth(admin_token))
    assert r.status_code == 200, r.text
    rows = r.json() if isinstance(r.json(), list) else r.json().get("equipment", [])
    row = next(x for x in rows if x["id"] == eq)
    assert row["manufacturer"] == "Daikin"
    assert row["capacity_btu"] == 48000
    assert row["refrigerant_type"] == "R-32"


def test_patch_nameplate(iso_client, admin_token, customer):
    eq = _make_equipment(iso_client, admin_token, customer, "Patch Unit",
                         manufacturer="Trane")
    r = iso_client.patch(f"/api/admin/equipment/{eq}",
                         json={"manufacturer": "York", "capacity_btu": 60000},
                         headers=_auth(admin_token))
    assert r.status_code == 200, r.text
    eqd = r.json()["equipment"]
    assert eqd["manufacturer"] == "York"
    assert eqd["capacity_btu"] == 60000


# ── BOM add / list / remove ─────────────────────────────────────────────────
def test_add_then_list_bom(iso_client, admin_token, customer):
    eq = _make_equipment(iso_client, admin_token, customer, "BOM Unit 1")
    part = _make_part(iso_client, admin_token, "Compressor", unit_cost=900.0)
    add = iso_client.post(f"/api/admin/equipment/{eq}/bom",
                          json={"part_id": part, "quantity": 2,
                                "position": "circuit A"},
                          headers=_auth(admin_token))
    assert add.status_code == 200, add.text
    assert add.json()["count"] == 1
    item = add.json()["items"][0]
    assert item["part_id"] == part
    assert item["quantity"] == 2
    assert item["line_cost"] == 1800.0

    lst = iso_client.get(f"/api/admin/equipment/{eq}/bom",
                         headers=_auth(admin_token))
    assert lst.status_code == 200, lst.text
    assert lst.json()["count"] == 1
    assert lst.json()["items"][0]["position"] == "circuit A"


def test_repost_updates_line(iso_client, admin_token, customer):
    eq = _make_equipment(iso_client, admin_token, customer, "BOM Unit 2")
    part = _make_part(iso_client, admin_token, "Drier")
    iso_client.post(f"/api/admin/equipment/{eq}/bom",
                    json={"part_id": part, "quantity": 1},
                    headers=_auth(admin_token))
    again = iso_client.post(f"/api/admin/equipment/{eq}/bom",
                            json={"part_id": part, "quantity": 5},
                            headers=_auth(admin_token))
    assert again.status_code == 200, again.text
    assert again.json()["count"] == 1            # upsert, not duplicate
    assert again.json()["items"][0]["quantity"] == 5


def test_remove_bom(iso_client, admin_token, customer):
    eq = _make_equipment(iso_client, admin_token, customer, "BOM Unit 3")
    part = _make_part(iso_client, admin_token, "Valve")
    iso_client.post(f"/api/admin/equipment/{eq}/bom",
                    json={"part_id": part}, headers=_auth(admin_token))
    rm = iso_client.delete(f"/api/admin/equipment/{eq}/bom/{part}",
                           headers=_auth(admin_token))
    assert rm.status_code == 200, rm.text
    assert rm.json()["items"] == []
    # removing again → 404 (not on BOM)
    rm2 = iso_client.delete(f"/api/admin/equipment/{eq}/bom/{part}",
                            headers=_auth(admin_token))
    assert rm2.status_code == 404


# ── Validation ───────────────────────────────────────────────────────────────
def test_bad_part_422(iso_client, admin_token, customer):
    eq = _make_equipment(iso_client, admin_token, customer, "BOM Unit 4")
    r = iso_client.post(f"/api/admin/equipment/{eq}/bom",
                        json={"part_id": 99999999, "quantity": 1},
                        headers=_auth(admin_token))
    assert r.status_code == 422, r.text


def test_zero_quantity_422(iso_client, admin_token, customer):
    eq = _make_equipment(iso_client, admin_token, customer, "BOM Unit 5")
    part = _make_part(iso_client, admin_token, "Gasket")
    r = iso_client.post(f"/api/admin/equipment/{eq}/bom",
                        json={"part_id": part, "quantity": 0},
                        headers=_auth(admin_token))
    assert r.status_code == 422, r.text


def test_missing_equipment_404(iso_client, admin_token):
    r = iso_client.get("/api/admin/equipment/99999999/bom",
                       headers=_auth(admin_token))
    assert r.status_code == 404


# ── Where-used reverse lookup ────────────────────────────────────────────────
def test_where_used(iso_client, admin_token, customer):
    eq1 = _make_equipment(iso_client, admin_token, customer, "WU Unit 1")
    eq2 = _make_equipment(iso_client, admin_token, customer, "WU Unit 2")
    part = _make_part(iso_client, admin_token, "Shared Sensor")
    iso_client.post(f"/api/admin/equipment/{eq1}/bom",
                    json={"part_id": part, "quantity": 1},
                    headers=_auth(admin_token))
    iso_client.post(f"/api/admin/equipment/{eq2}/bom",
                    json={"part_id": part, "quantity": 3},
                    headers=_auth(admin_token))
    r = iso_client.get(f"/api/admin/parts/{part}/where-used",
                       headers=_auth(admin_token))
    assert r.status_code == 200, r.text
    assert r.json()["count"] == 2
    ids = {a["equipment_id"] for a in r.json()["assets"]}
    assert ids == {eq1, eq2}


# ── Auth: routes require admin ──────────────────────────────────────────────
def test_bom_routes_require_admin(iso_client, admin_token, customer):
    eq = _make_equipment(iso_client, admin_token, customer, "Auth Unit")
    part = _make_part(iso_client, admin_token, "Auth Part")
    cases = (
        ("get", f"/api/admin/equipment/{eq}/bom", None),
        ("post", f"/api/admin/equipment/{eq}/bom", {"part_id": part}),
        ("delete", f"/api/admin/equipment/{eq}/bom/{part}", None),
        ("get", f"/api/admin/parts/{part}/where-used", None),
    )
    for method, url, body in cases:
        fn = getattr(iso_client, method)
        r = fn(url, json=body) if body is not None else fn(url)
        assert r.status_code in (401, 403), f"{method} {url} -> {r.status_code}"
