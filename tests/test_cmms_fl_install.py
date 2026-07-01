"""CMMS Gap #1 — functional-location ↔ equipment temporal split.

Phase-1 gate: prove the two active-install invariants are enforced at the
storage layer, plus the install/remove/swap lifecycle and history queries.

These tests run against a FRESH, isolated SQLite file (never the live
submissions.db). We point `database.DB_PATH` at a temp file, build the schema
with `init_db()`, seed a customer + equipment directly, and exercise the new
helpers. DB_PATH is restored on teardown so other tests are unaffected.
"""
import importlib
import sqlite3
from datetime import datetime, timezone

import pytest

import database


@pytest.fixture
def db(tmp_path, monkeypatch):
    """Isolated DB with the full schema. Yields the `database` module with
    DB_PATH pointed at a throwaway file."""
    db_file = tmp_path / "cmms_test.db"
    monkeypatch.setattr(database, "DB_PATH", str(db_file))
    database.init_db()
    yield database
    # WAL sidecars are inside tmp_path; pytest cleans the dir.


def _now():
    return datetime.now(timezone.utc).isoformat()


_CUST_SEQ = [0]


def _seed_customer(db, name="Acme Apartments"):
    _CUST_SEQ[0] += 1
    con = db._con()
    cur = con.execute(
        "INSERT INTO customers (customer_code, name, created_at) VALUES (?, ?, ?)",
        ("CUST%04d" % _CUST_SEQ[0], name, _now()),
    )
    cid = cur.lastrowid
    con.commit()
    con.close()
    return cid


def _seed_equipment(db, customer_id, name):
    return db.create_equipment({"customer_id": customer_id, "name": name})


# ---------------------------------------------------------------------------
# Schema / migration smoke
# ---------------------------------------------------------------------------
def test_equipment_has_status_and_warranty_columns(db):
    con = db._con()
    cols = {r[1] for r in con.execute("PRAGMA table_info(equipment)")}
    con.close()
    assert "status" in cols
    assert "warranty_months" in cols


def test_new_equipment_defaults_to_in_storage(db):
    cid = _seed_customer(db)
    eid = _seed_equipment(db, cid, "Split A")
    row = db.get_equipment_by_id(eid)
    assert row["status"] == "in_storage"


def test_functional_location_tables_exist(db):
    con = db._con()
    names = {r[0] for r in con.execute(
        "SELECT name FROM sqlite_master WHERE type='table'")}
    idx = {r[0] for r in con.execute(
        "SELECT name FROM sqlite_master WHERE type='index'")}
    con.close()
    assert "functional_location" in names
    assert "equipment_install" in names
    assert "uq_active_install_per_fl" in idx
    assert "uq_active_install_per_equipment" in idx


# ---------------------------------------------------------------------------
# THE TWO INVARIANTS (the gate)
# ---------------------------------------------------------------------------
def test_one_active_install_per_fl(db):
    """A slot can hold at most one active unit. The second install raises
    InstallConflict(scope='fl')."""
    cid = _seed_customer(db)
    fl = db.create_functional_location({"customer_id": cid, "name": "Apt 1 / LR"})
    e1 = _seed_equipment(db, cid, "Unit 1")
    e2 = _seed_equipment(db, cid, "Unit 2")

    db.install_equipment(e1, fl)
    with pytest.raises(database.InstallConflict) as ei:
        db.install_equipment(e2, fl)
    assert ei.value.scope == "fl"


def test_one_active_install_per_equipment(db):
    """A unit can occupy at most one slot at a time. Installing it into a
    second slot raises InstallConflict(scope='equipment')."""
    cid = _seed_customer(db)
    fl1 = db.create_functional_location({"customer_id": cid, "name": "Apt 1 / LR"})
    fl2 = db.create_functional_location({"customer_id": cid, "name": "Apt 2 / LR"})
    e1 = _seed_equipment(db, cid, "Unit 1")

    db.install_equipment(e1, fl1)
    with pytest.raises(database.InstallConflict) as ei:
        db.install_equipment(e1, fl2)
    assert ei.value.scope == "equipment"


def test_raw_integrity_error_underlies_invariant(db):
    """Belt-and-braces: confirm the partial-unique index itself (not just the
    Python guard) rejects a duplicate active row, so the invariant holds even
    for code paths that bypass install_equipment()."""
    cid = _seed_customer(db)
    fl = db.create_functional_location({"customer_id": cid, "name": "Slot"})
    e1 = _seed_equipment(db, cid, "U1")
    e2 = _seed_equipment(db, cid, "U2")
    con = db._con()
    con.execute(
        "INSERT INTO equipment_install (equipment_id, functional_location_id, "
        "installed_at, created_at) VALUES (?,?,?,?)",
        (e1, fl, _now(), _now()),
    )
    con.commit()
    with pytest.raises(sqlite3.IntegrityError):
        con.execute(
            "INSERT INTO equipment_install (equipment_id, functional_location_id, "
            "installed_at, created_at) VALUES (?,?,?,?)",
            (e2, fl, _now(), _now()),
        )
        con.commit()
    con.close()


# ---------------------------------------------------------------------------
# Lifecycle: install → remove → reinstall (the swap)
# ---------------------------------------------------------------------------
def test_install_sets_status_installed(db):
    cid = _seed_customer(db)
    fl = db.create_functional_location({"customer_id": cid, "name": "Slot"})
    e1 = _seed_equipment(db, cid, "U1")
    db.install_equipment(e1, fl)
    assert db.get_equipment_by_id(e1)["status"] == "installed"
    active = db.get_active_install_for_equipment(e1)
    assert active is not None and active["functional_location_id"] == fl


def test_remove_frees_slot_and_sets_storage(db):
    cid = _seed_customer(db)
    fl = db.create_functional_location({"customer_id": cid, "name": "Slot"})
    e1 = _seed_equipment(db, cid, "U1")
    db.install_equipment(e1, fl)

    assert db.remove_equipment_install(e1) is True
    assert db.get_equipment_by_id(e1)["status"] == "in_storage"
    assert db.get_active_install_for_fl(fl) is None
    assert db.get_active_install_for_equipment(e1) is None


def test_remove_to_in_repair_then_swap(db):
    """The refurbish-and-swap loop: pull U1 to repair, drop loaner U2 in the
    same slot, and confirm both invariants stay satisfied throughout."""
    cid = _seed_customer(db)
    fl = db.create_functional_location({"customer_id": cid, "name": "Slot"})
    u1 = _seed_equipment(db, cid, "U1")
    u2 = _seed_equipment(db, cid, "U2")

    db.install_equipment(u1, fl)
    db.remove_equipment_install(u1, new_status="in_repair")
    assert db.get_equipment_by_id(u1)["status"] == "in_repair"

    # Slot is now free → loaner installs cleanly.
    db.install_equipment(u2, fl)
    assert db.get_equipment_by_id(u2)["status"] == "installed"

    # U1 finishes refurb and goes back to the shelf.
    db.set_equipment_status(u1, "in_storage")
    assert db.get_equipment_by_id(u1)["status"] == "in_storage"


def test_remove_when_not_installed_returns_false(db):
    cid = _seed_customer(db)
    e1 = _seed_equipment(db, cid, "U1")
    assert db.remove_equipment_install(e1) is False


# ---------------------------------------------------------------------------
# History / timeline
# ---------------------------------------------------------------------------
def test_equipment_history_records_every_swap(db):
    cid = _seed_customer(db)
    fl1 = db.create_functional_location({"customer_id": cid, "name": "Slot A"})
    fl2 = db.create_functional_location({"customer_id": cid, "name": "Slot B"})
    e1 = _seed_equipment(db, cid, "U1")

    db.install_equipment(e1, fl1)
    db.remove_equipment_install(e1)
    db.install_equipment(e1, fl2)

    hist = db.get_equipment_install_history(e1)
    assert len(hist) == 2
    # newest first → fl2 is current (removed_at NULL), fl1 is closed.
    assert hist[0]["functional_location_id"] == fl2
    assert hist[0]["removed_at"] is None
    assert hist[1]["functional_location_id"] == fl1
    assert hist[1]["removed_at"] is not None
    assert hist[0]["fl_name"] == "Slot B"


def test_fl_history_records_occupants(db):
    cid = _seed_customer(db)
    fl = db.create_functional_location({"customer_id": cid, "name": "Slot"})
    u1 = _seed_equipment(db, cid, "U1")
    u2 = _seed_equipment(db, cid, "U2")
    db.install_equipment(u1, fl)
    db.remove_equipment_install(u1)
    db.install_equipment(u2, fl)

    hist = db.get_fl_install_history(fl)
    assert len(hist) == 2
    assert hist[0]["equipment_id"] == u2
    assert hist[0]["equipment_name"] == "U2"


# ---------------------------------------------------------------------------
# FL CRUD + scoping
# ---------------------------------------------------------------------------
def test_fl_class_validation(db):
    cid = _seed_customer(db)
    with pytest.raises(ValueError):
        db.create_functional_location(
            {"customer_id": cid, "name": "Bad", "fl_class": "planet"})


def test_fl_code_unique_per_customer(db):
    cid = _seed_customer(db)
    db.create_functional_location({"customer_id": cid, "name": "A", "code": "SLOT1"})
    with pytest.raises(ValueError):
        db.create_functional_location(
            {"customer_id": cid, "name": "B", "code": "SLOT1"})


def test_fl_code_may_repeat_across_customers(db):
    c1 = _seed_customer(db, "C1")
    c2 = _seed_customer(db, "C2")
    db.create_functional_location({"customer_id": c1, "name": "A", "code": "SLOT1"})
    # same code, different customer → allowed
    fl = db.create_functional_location({"customer_id": c2, "name": "A", "code": "SLOT1"})
    assert fl > 0


def test_customer_fl_listing_scoped(db):
    c1 = _seed_customer(db, "C1")
    c2 = _seed_customer(db, "C2")
    db.create_functional_location({"customer_id": c1, "name": "A"})
    db.create_functional_location({"customer_id": c1, "name": "B"})
    db.create_functional_location({"customer_id": c2, "name": "C"})
    assert len(db.get_customer_functional_locations(c1)) == 2
    assert len(db.get_customer_functional_locations(c2)) == 1


def test_fl_tree_parent_child(db):
    cid = _seed_customer(db)
    site = db.create_functional_location(
        {"customer_id": cid, "name": "Building", "fl_class": "building"})
    slot = db.create_functional_location(
        {"customer_id": cid, "name": "Slot", "fl_class": "slot", "parent_fl_id": site})
    row = db.get_functional_location(slot)
    assert row["parent_fl_id"] == site


# ---------------------------------------------------------------------------
# Warranty computation
# ---------------------------------------------------------------------------
def test_warranty_expiry_none_when_unset(db):
    cid = _seed_customer(db)
    eid = _seed_equipment(db, cid, "U1")
    row = db.get_equipment_by_id(eid)
    assert db.compute_warranty_expiry(row) is None


def test_warranty_expiry_computed(db):
    cid = _seed_customer(db)
    eid = _seed_equipment(db, cid, "U1")
    con = db._con()
    con.execute(
        "UPDATE equipment SET warranty_months = 12, created_at = ? WHERE id = ?",
        ("2026-01-15T00:00:00+00:00", eid),
    )
    con.commit()
    con.close()
    row = db.get_equipment_by_id(eid)
    assert db.compute_warranty_expiry(row) == "2027-01-15"
