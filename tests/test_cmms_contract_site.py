"""CMMS Gap #5 — contract ↔ site (functional-location) coverage.

A PM contract can cover MANY functional locations (a multi-site service
agreement), not just the single optional equipment_id on pm_contracts. These
tests exercise the storage layer directly against an isolated, throwaway
SQLite file (never the live submissions.db): DB_PATH is repointed, init_db()
builds the schema, and we seed customers / contracts / FLs directly.

Covers: link create (idempotent), same-customer integrity guard, listing,
unlink, the reverse lookup, and the UNIQUE(contract_id, fl_id) backstop.
"""
import sqlite3
from datetime import datetime, timezone

import pytest

import database


@pytest.fixture
def db(tmp_path, monkeypatch):
    db_file = tmp_path / "cmms_contract_site.db"
    monkeypatch.setattr(database, "DB_PATH", str(db_file))
    database.init_db()
    yield database


def _now():
    return datetime.now(timezone.utc).isoformat()


_CUST_SEQ = [0]


def _seed_customer(db, name="Multi-Site Co"):
    _CUST_SEQ[0] += 1
    con = db._con()
    cid = con.execute(
        "INSERT INTO customers (customer_code, name, created_at) VALUES (?, ?, ?)",
        ("CSITE%04d" % _CUST_SEQ[0], name, _now())).lastrowid
    con.commit()
    con.close()
    return cid


def _seed_contract(db, customer_id, code_suffix="A"):
    return db.create_pm_contract({
        "customer_id": customer_id,
        "start_date": "2026-01-01",
        "end_date": "2026-12-31",
        "frequency": "quarterly",
        "contract_value": 1000.0,
    })


def _seed_fl(db, customer_id, name, fl_class="site", code=None):
    return db.create_functional_location({
        "customer_id": customer_id, "name": name,
        "fl_class": fl_class, "code": code})


# ── Schema smoke ─────────────────────────────────────────────────────────────
def test_contract_site_table_exists(db):
    con = db._con()
    cols = {r[1] for r in con.execute("PRAGMA table_info(contract_site)")}
    con.close()
    assert {"contract_id", "functional_location_id"} <= cols


# ── Link / list / unlink lifecycle ──────────────────────────────────────────
def test_add_and_list_sites(db):
    cid = _seed_customer(db)
    contract = _seed_contract(db, cid)
    site1 = _seed_fl(db, cid, "Downtown Tower", code="DT")
    site2 = _seed_fl(db, cid, "Airport Branch", fl_class="building")
    db.add_contract_site(contract, site1, by_kind="admin", by_id=None)
    db.add_contract_site(contract, site2, by_kind="admin", by_id=None)
    sites = db.list_contract_sites(contract)
    assert len(sites) == 2
    ids = {s["id"] for s in sites}
    assert ids == {site1, site2}
    # joined display columns are present
    by_id = {s["id"]: s for s in sites}
    assert by_id[site1]["name"] == "Downtown Tower"
    assert by_id[site1]["code"] == "DT"
    assert by_id[site2]["fl_class"] == "building"


def test_add_is_idempotent(db):
    cid = _seed_customer(db)
    contract = _seed_contract(db, cid)
    site = _seed_fl(db, cid, "Site X")
    first = db.add_contract_site(contract, site)
    second = db.add_contract_site(contract, site)
    assert first == second
    assert len(db.list_contract_sites(contract)) == 1


def test_remove_site(db):
    cid = _seed_customer(db)
    contract = _seed_contract(db, cid)
    site = _seed_fl(db, cid, "Site Y")
    db.add_contract_site(contract, site)
    assert db.remove_contract_site(contract, site) is True
    assert db.list_contract_sites(contract) == []
    # removing again is a no-op (False), not an error
    assert db.remove_contract_site(contract, site) is False


# ── Integrity: same-customer only ───────────────────────────────────────────
def test_cross_customer_fl_rejected(db):
    cust_a = _seed_customer(db, "Cust A")
    cust_b = _seed_customer(db, "Cust B")
    contract_a = _seed_contract(db, cust_a)
    fl_b = _seed_fl(db, cust_b, "B's Site")
    with pytest.raises(ValueError):
        db.add_contract_site(contract_a, fl_b)
    assert db.list_contract_sites(contract_a) == []


def test_missing_contract_or_fl_rejected(db):
    cid = _seed_customer(db)
    contract = _seed_contract(db, cid)
    site = _seed_fl(db, cid, "Real Site")
    with pytest.raises(ValueError):
        db.add_contract_site(contract, 99999999)   # no such FL
    with pytest.raises(ValueError):
        db.add_contract_site(99999999, site)        # no such contract


# ── UNIQUE backstop at the index level ──────────────────────────────────────
def test_unique_index_blocks_raw_duplicate(db):
    cid = _seed_customer(db)
    contract = _seed_contract(db, cid)
    site = _seed_fl(db, cid, "Site Z")
    db.add_contract_site(contract, site)
    con = db._con()
    with pytest.raises(sqlite3.IntegrityError):
        con.execute(
            "INSERT INTO contract_site (contract_id, functional_location_id, created_at) "
            "VALUES (?, ?, ?)", (contract, site, _now()))
        con.commit()
    con.close()


# ── Reverse lookup ──────────────────────────────────────────────────────────
def test_list_site_contracts(db):
    cid = _seed_customer(db)
    c_active = _seed_contract(db, cid)
    c_other = _seed_contract(db, cid)
    site = _seed_fl(db, cid, "Shared Site")
    db.add_contract_site(c_active, site)
    db.add_contract_site(c_other, site)
    # cancel one so active_only can filter it out
    db.update_pm_contract(c_other, {"status": "cancelled"})
    all_contracts = db.list_site_contracts(site)
    assert {c["id"] for c in all_contracts} == {c_active, c_other}
    active_only = db.list_site_contracts(site, active_only=True)
    assert {c["id"] for c in active_only} == {c_active}
