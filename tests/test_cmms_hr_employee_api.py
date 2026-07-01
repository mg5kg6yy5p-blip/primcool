"""HR-1 — unified employee master (HTTP coverage).

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
    tmpdir = tempfile.mkdtemp(prefix="cmms_hr_api_")
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
    main._make_token({"sub": str(subject_id), "type": subject_type, "jti": jti},
                     timedelta(hours=2))
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
def tech_subject(iso_client):
    """A throwaway technician row to overlay HR profiles onto."""
    con = sqlite3.connect(database.DB_PATH)
    tid = con.execute(
        "INSERT INTO technicians (tech_code, pin_hash, name, created_at) "
        "VALUES (?,?,?,?)",
        ("HRAPI%s" % uuid.uuid4().hex[:6], "x", "HR API Tech", _now())).lastrowid
    con.commit()
    con.close()
    return tid


_SUBJ_SEQ = [0]


def _new_tech(name="Spare Tech"):
    _SUBJ_SEQ[0] += 1
    con = sqlite3.connect(database.DB_PATH)
    tid = con.execute(
        "INSERT INTO technicians (tech_code, pin_hash, name, created_at) "
        "VALUES (?,?,?,?)",
        ("HRX%s%04d" % (uuid.uuid4().hex[:4], _SUBJ_SEQ[0]), "x", name,
         _now())).lastrowid
    con.commit()
    con.close()
    return tid


# ── Reference data ───────────────────────────────────────────────────────────
def test_reference(iso_client, admin_token):
    r = iso_client.get("/api/admin/hr/reference", headers=_auth(admin_token))
    assert r.status_code == 200, r.text
    body = r.json()
    assert len(body["parishes"]) == 14
    assert "TRN" in body["id_types"] and "NIS" in body["id_types"]


# ── Create + get round-trip ──────────────────────────────────────────────────
def test_create_then_get(iso_client, admin_token, tech_subject):
    r = iso_client.post("/api/admin/hr/employees",
                        json={"subject_type": "tech", "subject_id": tech_subject,
                              "legal_first_name": "Marcus",
                              "legal_last_name": "Brown",
                              "parish": "St. Andrew",
                              "personal_phone": "876-555-0100",
                              "emergency_contact_name": "Joan Brown"},
                        headers=_auth(admin_token))
    assert r.status_code == 200, r.text
    emp = r.json()["employee"]
    assert emp["parish"] == "St. Andrew"
    assert emp["subject_name"] == "HR API Tech"

    g = iso_client.get(f"/api/admin/hr/employees/{emp['id']}",
                       headers=_auth(admin_token))
    assert g.status_code == 200, g.text
    got = g.json()["employee"]
    assert got["personal_phone"] == "876-555-0100"
    assert got["national_ids"] == []


def test_duplicate_profile_422(iso_client, admin_token):
    tid = _new_tech()
    first = iso_client.post("/api/admin/hr/employees",
                            json={"subject_type": "tech", "subject_id": tid},
                            headers=_auth(admin_token))
    assert first.status_code == 200, first.text
    dup = iso_client.post("/api/admin/hr/employees",
                          json={"subject_type": "tech", "subject_id": tid},
                          headers=_auth(admin_token))
    assert dup.status_code == 422


def test_bad_subject_422(iso_client, admin_token):
    r = iso_client.post("/api/admin/hr/employees",
                        json={"subject_type": "tech", "subject_id": 99999999},
                        headers=_auth(admin_token))
    assert r.status_code == 422


def test_bad_parish_422(iso_client, admin_token):
    tid = _new_tech()
    r = iso_client.post("/api/admin/hr/employees",
                        json={"subject_type": "tech", "subject_id": tid,
                              "parish": "Atlantis"},
                        headers=_auth(admin_token))
    assert r.status_code == 422


# ── Patch ────────────────────────────────────────────────────────────────────
def test_patch_profile(iso_client, admin_token):
    tid = _new_tech()
    c = iso_client.post("/api/admin/hr/employees",
                        json={"subject_type": "tech", "subject_id": tid,
                              "parish": "Clarendon"},
                        headers=_auth(admin_token))
    emp_id = c.json()["employee"]["id"]
    p = iso_client.patch(f"/api/admin/hr/employees/{emp_id}",
                         json={"parish": "Kingston", "marital_status": "single"},
                         headers=_auth(admin_token))
    assert p.status_code == 200, p.text
    emp = p.json()["employee"]
    assert emp["parish"] == "Kingston"
    assert emp["marital_status"] == "single"


def test_patch_bad_parish_422(iso_client, admin_token):
    tid = _new_tech()
    emp_id = iso_client.post("/api/admin/hr/employees",
                             json={"subject_type": "tech", "subject_id": tid},
                             headers=_auth(admin_token)).json()["employee"]["id"]
    r = iso_client.patch(f"/api/admin/hr/employees/{emp_id}",
                         json={"parish": "Narnia"}, headers=_auth(admin_token))
    assert r.status_code == 422


# ── National IDs ─────────────────────────────────────────────────────────────
def test_national_id_lifecycle(iso_client, admin_token):
    tid = _new_tech()
    emp_id = iso_client.post("/api/admin/hr/employees",
                             json={"subject_type": "tech", "subject_id": tid},
                             headers=_auth(admin_token)).json()["employee"]["id"]
    add = iso_client.post(f"/api/admin/hr/employees/{emp_id}/ids",
                          json={"id_type": "TRN", "id_number": "123456789",
                                "issued_date": "2010-01-01"},
                          headers=_auth(admin_token))
    assert add.status_code == 200, add.text
    assert add.json()["count"] == 1
    assert add.json()["national_ids"][0]["id_type"] == "TRN"
    assert add.json()["national_ids"][0]["id_number"] == "123456789"

    # upsert (same type updates in place)
    again = iso_client.post(f"/api/admin/hr/employees/{emp_id}/ids",
                            json={"id_type": "TRN", "id_number": "999999999"},
                            headers=_auth(admin_token))
    assert again.json()["count"] == 1
    assert again.json()["national_ids"][0]["id_number"] == "999999999"

    iso_client.post(f"/api/admin/hr/employees/{emp_id}/ids",
                    json={"id_type": "NIS", "id_number": "A1234567"},
                    headers=_auth(admin_token))
    g = iso_client.get(f"/api/admin/hr/employees/{emp_id}",
                       headers=_auth(admin_token))
    assert {i["id_type"] for i in g.json()["employee"]["national_ids"]} == {"TRN", "NIS"}

    rm = iso_client.delete(f"/api/admin/hr/employees/{emp_id}/ids/TRN",
                           headers=_auth(admin_token))
    assert rm.status_code == 200, rm.text
    assert {i["id_type"] for i in rm.json()["national_ids"]} == {"NIS"}
    # removing again → 404
    rm2 = iso_client.delete(f"/api/admin/hr/employees/{emp_id}/ids/TRN",
                            headers=_auth(admin_token))
    assert rm2.status_code == 404


def test_bad_id_type_422(iso_client, admin_token):
    tid = _new_tech()
    emp_id = iso_client.post("/api/admin/hr/employees",
                             json={"subject_type": "tech", "subject_id": tid},
                             headers=_auth(admin_token)).json()["employee"]["id"]
    r = iso_client.post(f"/api/admin/hr/employees/{emp_id}/ids",
                        json={"id_type": "BOGUS", "id_number": "1"},
                        headers=_auth(admin_token))
    assert r.status_code == 422


def test_missing_employee_404(iso_client, admin_token):
    r = iso_client.get("/api/admin/hr/employees/99999999",
                       headers=_auth(admin_token))
    assert r.status_code == 404


# ── Auth: routes require admin ──────────────────────────────────────────────
def test_hr_routes_require_admin(iso_client, admin_token, tech_subject):
    emp_id = iso_client.post(
        "/api/admin/hr/employees",
        json={"subject_type": "tech", "subject_id": _new_tech()},
        headers=_auth(admin_token)).json()["employee"]["id"]
    cases = (
        ("get", "/api/admin/hr/reference", None),
        ("get", "/api/admin/hr/employees", None),
        ("post", "/api/admin/hr/employees",
         {"subject_type": "tech", "subject_id": tech_subject}),
        ("get", f"/api/admin/hr/employees/{emp_id}", None),
        ("patch", f"/api/admin/hr/employees/{emp_id}", {"parish": "Kingston"}),
        ("post", f"/api/admin/hr/employees/{emp_id}/ids",
         {"id_type": "TRN", "id_number": "1"}),
        ("delete", f"/api/admin/hr/employees/{emp_id}/ids/TRN", None),
    )
    for method, url, body in cases:
        fn = getattr(iso_client, method)
        r = fn(url, json=body) if body is not None else fn(url)
        assert r.status_code in (401, 403), f"{method} {url} -> {r.status_code}"
