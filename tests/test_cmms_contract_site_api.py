"""CMMS Gap #5 — HTTP coverage for contract ↔ site management.

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
    tmpdir = tempfile.mkdtemp(prefix="cmms_contract_site_api_")
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
def two_customers(iso_client):
    con = sqlite3.connect(database.DB_PATH)
    a = con.execute(
        "INSERT INTO customers (customer_code, name, created_at) VALUES (?,?,?)",
        ("CSAPIA1", "Contract-Site Cust A", _now())).lastrowid
    b = con.execute(
        "INSERT INTO customers (customer_code, name, created_at) VALUES (?,?,?)",
        ("CSAPIB1", "Contract-Site Cust B", _now())).lastrowid
    con.commit()
    con.close()
    return a, b


def _make_contract(iso_client, admin_token, customer_id):
    r = iso_client.post("/api/admin/pm-contracts",
                        json={"customer_id": customer_id, "start_date": "2026-01-01",
                              "end_date": "2026-12-31", "frequency": "quarterly",
                              "contract_value": 500.0},
                        headers=_auth(admin_token))
    assert r.status_code == 200, r.text
    return r.json()["contract"]["id"]


def _make_fl(iso_client, admin_token, customer_id, name, fl_class="site"):
    r = iso_client.post("/api/admin/functional-locations",
                        json={"customer_id": customer_id, "name": name,
                              "fl_class": fl_class},
                        headers=_auth(admin_token))
    assert r.status_code == 200, r.text
    return r.json()["id"]


# ── Add / list / remove ─────────────────────────────────────────────────────
def test_add_then_list_sites(iso_client, admin_token, two_customers):
    a, _ = two_customers
    contract = _make_contract(iso_client, admin_token, a)
    fl = _make_fl(iso_client, admin_token, a, "Tower 1")
    add = iso_client.post(f"/api/admin/pm-contracts/{contract}/sites",
                          json={"functional_location_id": fl},
                          headers=_auth(admin_token))
    assert add.status_code == 200, add.text
    assert any(s["id"] == fl for s in add.json()["sites"])

    lst = iso_client.get(f"/api/admin/pm-contracts/{contract}/sites",
                         headers=_auth(admin_token))
    assert lst.status_code == 200, lst.text
    assert lst.json()["count"] == 1
    assert lst.json()["sites"][0]["name"] == "Tower 1"


def test_remove_site(iso_client, admin_token, two_customers):
    a, _ = two_customers
    contract = _make_contract(iso_client, admin_token, a)
    fl = _make_fl(iso_client, admin_token, a, "Tower 2")
    iso_client.post(f"/api/admin/pm-contracts/{contract}/sites",
                    json={"functional_location_id": fl}, headers=_auth(admin_token))
    rm = iso_client.delete(f"/api/admin/pm-contracts/{contract}/sites/{fl}",
                           headers=_auth(admin_token))
    assert rm.status_code == 200, rm.text
    assert rm.json()["sites"] == []
    # removing again → 404 (not linked)
    rm2 = iso_client.delete(f"/api/admin/pm-contracts/{contract}/sites/{fl}",
                            headers=_auth(admin_token))
    assert rm2.status_code == 404


def test_sites_surface_in_contract_detail(iso_client, admin_token, two_customers):
    a, _ = two_customers
    contract = _make_contract(iso_client, admin_token, a)
    fl = _make_fl(iso_client, admin_token, a, "Detail Site")
    iso_client.post(f"/api/admin/pm-contracts/{contract}/sites",
                    json={"functional_location_id": fl}, headers=_auth(admin_token))
    det = iso_client.get(f"/api/admin/pm-contracts/{contract}",
                         headers=_auth(admin_token))
    assert det.status_code == 200, det.text
    sites = det.json()["contract"]["sites"]
    assert any(s["id"] == fl for s in sites)


# ── Validation: cross-customer FL rejected ──────────────────────────────────
def test_cross_customer_fl_422(iso_client, admin_token, two_customers):
    a, b = two_customers
    contract_a = _make_contract(iso_client, admin_token, a)
    fl_b = _make_fl(iso_client, admin_token, b, "B Site")
    r = iso_client.post(f"/api/admin/pm-contracts/{contract_a}/sites",
                        json={"functional_location_id": fl_b},
                        headers=_auth(admin_token))
    assert r.status_code == 422, r.text


def test_missing_contract_404(iso_client, admin_token):
    r = iso_client.get("/api/admin/pm-contracts/99999999/sites",
                       headers=_auth(admin_token))
    assert r.status_code == 404


# ── Auth: routes require admin ──────────────────────────────────────────────
def test_site_routes_require_admin(iso_client, admin_token, two_customers):
    a, _ = two_customers
    contract = _make_contract(iso_client, admin_token, a)
    fl = _make_fl(iso_client, admin_token, a, "Auth Site")
    cases = (
        ("get", f"/api/admin/pm-contracts/{contract}/sites", None),
        ("post", f"/api/admin/pm-contracts/{contract}/sites",
         {"functional_location_id": fl}),
        ("delete", f"/api/admin/pm-contracts/{contract}/sites/{fl}", None),
    )
    for method, url, body in cases:
        fn = getattr(iso_client, method)
        r = fn(url, json=body) if body is not None else fn(url)
        assert r.status_code in (401, 403), f"{method} {url} -> {r.status_code}"
