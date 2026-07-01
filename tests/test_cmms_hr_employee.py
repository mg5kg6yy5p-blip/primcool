"""HR-1 — unified employee master (storage layer).

Exercises employee_profiles (the personal/statutory record overlaid on a
technician or admin_user) and the employee_ids child (TRN/NIS/…) directly
against an isolated, throwaway SQLite file — never the live submissions.db.
DB_PATH is repointed, init_db() builds the schema, and we seed
technicians / admin_users directly.

Covers: schema smoke, subject overlay + join, encryption-at-rest, Jamaica
parish validation, duplicate-profile guard, patch round-trip, national-ID
upsert/list/remove, and ID-type validation.
"""
import sqlite3
from datetime import datetime, timezone

import pytest

import database


@pytest.fixture
def db(tmp_path, monkeypatch):
    db_file = tmp_path / "cmms_hr_employee.db"
    monkeypatch.setattr(database, "DB_PATH", str(db_file))
    database.init_db()
    yield database


def _now():
    return datetime.now(timezone.utc).isoformat()


_SEQ = [0]


def _seed_tech(db, name="Marcus Brown"):
    _SEQ[0] += 1
    con = db._con()
    tid = con.execute(
        "INSERT INTO technicians (tech_code, pin_hash, name, created_at) "
        "VALUES (?, ?, ?, ?)",
        ("HRT%04d" % _SEQ[0], "x", name, _now())).lastrowid
    con.commit()
    con.close()
    return tid


def _seed_admin(db, name="Office Admin"):
    _SEQ[0] += 1
    con = db._con()
    aid = con.execute(
        "INSERT INTO admin_users (username, password_hash, name, email, role, "
        "created_at) VALUES (?, ?, ?, ?, ?, ?)",
        ("hradmin%04d" % _SEQ[0], "x", name,
         "hr%04d@example.com" % _SEQ[0], "system_admin", _now())).lastrowid
    con.commit()
    con.close()
    return aid


# ── Schema smoke ─────────────────────────────────────────────────────────────
def test_tables_exist(db):
    con = db._con()
    ep = {r[1] for r in con.execute("PRAGMA table_info(employee_profiles)")}
    ei = {r[1] for r in con.execute("PRAGMA table_info(employee_ids)")}
    con.close()
    assert {"subject_type", "subject_id", "parish", "legal_first_name",
            "date_of_birth", "emergency_contact_name"} <= ep
    assert {"employee_id", "id_type", "id_number", "expiry_date"} <= ei


def test_parishes_and_id_types_constants(db):
    assert len(db.JAMAICA_PARISHES) == 14
    assert "Kingston" in db.JAMAICA_PARISHES and "Portland" in db.JAMAICA_PARISHES
    assert "TRN" in db.EMPLOYEE_ID_TYPES and "NIS" in db.EMPLOYEE_ID_TYPES


# ── Create + subject overlay ─────────────────────────────────────────────────
def test_create_over_tech_and_join(db):
    tid = _seed_tech(db, "Marcus Brown")
    eid = db.create_employee_profile({
        "subject_type": "tech", "subject_id": tid,
        "legal_first_name": "Marcus", "legal_last_name": "Brown",
        "parish": "St. Andrew"}, by_kind="admin", by_id=1)
    p = db.get_employee_profile(eid)
    assert p["subject_type"] == "tech"
    assert p["subject_name"] == "Marcus Brown"
    assert p["subject_role"] == "tech"
    assert p["parish"] == "St. Andrew"


def test_create_over_admin(db):
    aid = _seed_admin(db, "Janet Clarke")
    eid = db.create_employee_profile({
        "subject_type": "admin", "subject_id": aid,
        "legal_first_name": "Janet"}, by_kind="admin", by_id=1)
    p = db.get_employee_profile_by_subject("admin", aid)
    assert p["id"] == eid
    assert p["subject_name"] == "Janet Clarke"


def test_sensitive_columns_encrypted_at_rest(db):
    tid = _seed_tech(db)
    eid = db.create_employee_profile({
        "subject_type": "tech", "subject_id": tid,
        "personal_phone": "876-555-0100",
        "emergency_contact_name": "Joan Brown",
        "date_of_birth": "1990-05-12"})
    # the decrypted read returns plaintext
    p = db.get_employee_profile(eid)
    assert p["personal_phone"] == "876-555-0100"
    assert p["date_of_birth"] == "1990-05-12"
    # …but the raw bytes on disk are NOT the plaintext
    con = db._con()
    raw = con.execute("SELECT personal_phone, date_of_birth FROM "
                      "employee_profiles WHERE id=?", (eid,)).fetchone()
    con.close()
    assert raw[0] != "876-555-0100"
    assert raw[1] != "1990-05-12"


# ── Validation ───────────────────────────────────────────────────────────────
def test_bad_subject_rejected(db):
    with pytest.raises(ValueError):
        db.create_employee_profile({"subject_type": "tech", "subject_id": 999999})
    with pytest.raises(ValueError):
        db.create_employee_profile({"subject_type": "bogus", "subject_id": 1})


def test_bad_parish_rejected(db):
    tid = _seed_tech(db)
    with pytest.raises(ValueError):
        db.create_employee_profile({
            "subject_type": "tech", "subject_id": tid, "parish": "Atlantis"})


def test_duplicate_profile_rejected(db):
    tid = _seed_tech(db)
    db.create_employee_profile({"subject_type": "tech", "subject_id": tid})
    with pytest.raises(ValueError):
        db.create_employee_profile({"subject_type": "tech", "subject_id": tid})


def test_unique_index_blocks_raw_duplicate(db):
    tid = _seed_tech(db)
    db.create_employee_profile({"subject_type": "tech", "subject_id": tid})
    con = db._con()
    with pytest.raises(sqlite3.IntegrityError):
        con.execute("INSERT INTO employee_profiles (subject_type, subject_id, "
                    "created_at) VALUES (?, ?, ?)", ("tech", tid, _now()))
        con.commit()
    con.close()


# ── Update round-trip ────────────────────────────────────────────────────────
def test_update_profile(db):
    tid = _seed_tech(db)
    eid = db.create_employee_profile({
        "subject_type": "tech", "subject_id": tid, "parish": "Clarendon"})
    assert db.update_employee_profile(
        eid, {"parish": "Kingston", "marital_status": "married",
              "personal_email": "marcus@example.com"},
        by_kind="admin", by_id=1)
    p = db.get_employee_profile(eid)
    assert p["parish"] == "Kingston"
    assert p["marital_status"] == "married"
    assert p["personal_email"] == "marcus@example.com"


def test_update_bad_parish_rejected(db):
    tid = _seed_tech(db)
    eid = db.create_employee_profile({"subject_type": "tech", "subject_id": tid})
    with pytest.raises(ValueError):
        db.update_employee_profile(eid, {"parish": "Narnia"})


# ── List + filters ───────────────────────────────────────────────────────────
def test_list_and_filters(db):
    t1 = _seed_tech(db, "Andre Service")
    a1 = _seed_admin(db, "Beth Office")
    db.create_employee_profile({"subject_type": "tech", "subject_id": t1,
                                "legal_first_name": "Andre",
                                "legal_last_name": "Service",
                                "parish": "St. James"})
    db.create_employee_profile({"subject_type": "admin", "subject_id": a1,
                                "legal_first_name": "Beth",
                                "legal_last_name": "Office",
                                "parish": "Kingston"})
    assert len(db.list_employee_profiles()) == 2
    assert len(db.list_employee_profiles(subject_type="tech")) == 1
    assert len(db.list_employee_profiles(parish="Kingston")) == 1
    assert len(db.list_employee_profiles(q="Andre")) == 1


# ── National IDs (TRN/NIS) ───────────────────────────────────────────────────
def test_add_list_remove_national_ids(db):
    tid = _seed_tech(db)
    eid = db.create_employee_profile({"subject_type": "tech", "subject_id": tid})
    db.add_employee_id(eid, "TRN", "123456789", issued_date="2010-01-01")
    db.add_employee_id(eid, "nis", "A1234567")        # lowercased → NIS
    ids = db.list_employee_ids(eid)
    assert {i["id_type"] for i in ids} == {"TRN", "NIS"}
    by_type = {i["id_type"]: i for i in ids}
    assert by_type["TRN"]["id_number"] == "123456789"
    # encrypted at rest
    con = db._con()
    raw = con.execute("SELECT id_number FROM employee_ids WHERE employee_id=? "
                      "AND id_type='TRN'", (eid,)).fetchone()[0]
    con.close()
    assert raw != "123456789"
    # remove
    assert db.remove_employee_id(eid, "TRN") is True
    assert {i["id_type"] for i in db.list_employee_ids(eid)} == {"NIS"}
    assert db.remove_employee_id(eid, "TRN") is False   # already gone → no-op


def test_id_upsert_in_place(db):
    tid = _seed_tech(db)
    eid = db.create_employee_profile({"subject_type": "tech", "subject_id": tid})
    first = db.add_employee_id(eid, "TRN", "111111111")
    second = db.add_employee_id(eid, "TRN", "999999999", expiry_date="2030-01-01")
    assert first == second                              # same row, upserted
    ids = db.list_employee_ids(eid)
    assert len(ids) == 1
    assert ids[0]["id_number"] == "999999999"
    assert ids[0]["expiry_date"] == "2030-01-01"


def test_id_validation(db):
    tid = _seed_tech(db)
    eid = db.create_employee_profile({"subject_type": "tech", "subject_id": tid})
    with pytest.raises(ValueError):
        db.add_employee_id(eid, "BOGUS", "123")
    with pytest.raises(ValueError):
        db.add_employee_id(eid, "TRN", "")
    with pytest.raises(ValueError):
        db.add_employee_id(999999, "TRN", "123")        # no such employee


def test_unique_id_type_index(db):
    tid = _seed_tech(db)
    eid = db.create_employee_profile({"subject_type": "tech", "subject_id": tid})
    db.add_employee_id(eid, "TRN", "123")
    con = db._con()
    with pytest.raises(sqlite3.IntegrityError):
        con.execute("INSERT INTO employee_ids (employee_id, id_type, id_number, "
                    "created_at) VALUES (?, ?, ?, ?)", (eid, "TRN", "x", _now()))
        con.commit()
    con.close()
