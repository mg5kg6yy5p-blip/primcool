"""CMMS Phase 6 — asset registry depth + bill of materials (storage layer).

Exercises the asset_bom many-to-many (equipment ↔ parts) and the new
equipment nameplate/specification columns directly against an isolated,
throwaway SQLite file (never the live submissions.db): DB_PATH is repointed,
init_db() builds the schema, and we seed customers / equipment / parts
directly.

Covers: nameplate column round-trip, BOM add (upsert), list with joined part
columns + computed line_cost, remove, validation (missing equipment/part,
non-positive quantity), the UNIQUE(equipment_id, part_id) backstop, and the
where-used reverse lookup.
"""
import sqlite3
from datetime import datetime, timezone

import pytest

import database


@pytest.fixture
def db(tmp_path, monkeypatch):
    db_file = tmp_path / "cmms_asset_bom.db"
    monkeypatch.setattr(database, "DB_PATH", str(db_file))
    database.init_db()
    yield database


def _now():
    return datetime.now(timezone.utc).isoformat()


_SEQ = [0]


def _seed_customer(db, name="BOM Co"):
    _SEQ[0] += 1
    con = db._con()
    cid = con.execute(
        "INSERT INTO customers (customer_code, name, created_at) VALUES (?, ?, ?)",
        ("BOM%04d" % _SEQ[0], name, _now())).lastrowid
    con.commit()
    con.close()
    return cid


def _seed_equipment(db, customer_id, name="Chiller A", **extra):
    data = {"customer_id": customer_id, "name": name}
    data.update(extra)
    return db.create_equipment(data)


def _seed_part(db, name, sku=None, unit_cost=0.0, quantity=0.0):
    _SEQ[0] += 1
    return db.create_part({
        "sku": sku or ("BOMP%04d" % _SEQ[0]),
        "name": name,
        "unit_cost": unit_cost,
        "quantity": quantity,
    })


# ── Schema smoke ─────────────────────────────────────────────────────────────
def test_asset_bom_table_exists(db):
    con = db._con()
    cols = {r[1] for r in con.execute("PRAGMA table_info(asset_bom)")}
    con.close()
    assert {"equipment_id", "part_id", "quantity", "position"} <= cols


def test_equipment_nameplate_columns_exist(db):
    con = db._con()
    cols = {r[1] for r in con.execute("PRAGMA table_info(equipment)")}
    con.close()
    assert {"manufacturer", "specification", "commissioned_date",
            "refrigerant_type", "capacity_btu", "voltage", "phase"} <= cols


# ── Nameplate round-trip ─────────────────────────────────────────────────────
def test_nameplate_round_trip(db):
    cid = _seed_customer(db)
    eq = _seed_equipment(
        db, cid, name="Rooftop Unit",
        manufacturer="Carrier", specification="30RB-080 air-cooled",
        commissioned_date="2024-03-01", refrigerant_type="R-410A",
        capacity_btu=960000, voltage="460", phase="3")
    row = db.get_equipment_by_id(eq)
    assert row["manufacturer"] == "Carrier"
    assert row["specification"] == "30RB-080 air-cooled"
    assert row["commissioned_date"] == "2024-03-01"
    assert row["refrigerant_type"] == "R-410A"
    assert row["capacity_btu"] == 960000
    assert row["voltage"] == "460"
    assert row["phase"] == "3"


def test_nameplate_update(db):
    cid = _seed_customer(db)
    eq = _seed_equipment(db, cid, manufacturer="Trane")
    assert db.update_equipment(eq, {"manufacturer": "York", "capacity_btu": 120000})
    row = db.get_equipment_by_id(eq)
    assert row["manufacturer"] == "York"
    assert row["capacity_btu"] == 120000


# ── BOM link / list / remove lifecycle ──────────────────────────────────────
def test_add_and_list_bom(db):
    cid = _seed_customer(db)
    eq = _seed_equipment(db, cid)
    compressor = _seed_part(db, "Scroll Compressor", sku="CMP-1",
                            unit_cost=1200.0, quantity=3)
    filter_drier = _seed_part(db, "Filter Drier", sku="FD-1",
                              unit_cost=45.5, quantity=20)
    db.add_asset_bom_item(eq, compressor, quantity=1, by_kind="admin")
    db.add_asset_bom_item(eq, filter_drier, quantity=2, position="suction line")
    items = db.list_asset_bom(eq)
    assert len(items) == 2
    by_part = {i["part_id"]: i for i in items}
    # joined display columns present
    assert by_part[compressor]["sku"] == "CMP-1"
    assert by_part[compressor]["name"] == "Scroll Compressor"
    assert by_part[compressor]["on_hand"] == 3
    # computed line cost = unit_cost * qty
    assert by_part[filter_drier]["line_cost"] == 91.0
    assert by_part[filter_drier]["position"] == "suction line"


def test_add_is_idempotent_upsert(db):
    cid = _seed_customer(db)
    eq = _seed_equipment(db, cid)
    part = _seed_part(db, "Contactor")
    first = db.add_asset_bom_item(eq, part, quantity=1)
    second = db.add_asset_bom_item(eq, part, quantity=4, position="panel")
    assert first == second                      # same row, upserted
    items = db.list_asset_bom(eq)
    assert len(items) == 1
    assert items[0]["quantity"] == 4
    assert items[0]["position"] == "panel"


def test_remove_bom_item(db):
    cid = _seed_customer(db)
    eq = _seed_equipment(db, cid)
    part = _seed_part(db, "Capacitor")
    db.add_asset_bom_item(eq, part)
    assert db.remove_asset_bom_item(eq, part) is True
    assert db.list_asset_bom(eq) == []
    # removing again is a no-op (False), not an error
    assert db.remove_asset_bom_item(eq, part) is False


# ── Validation ───────────────────────────────────────────────────────────────
def test_missing_equipment_or_part_rejected(db):
    cid = _seed_customer(db)
    eq = _seed_equipment(db, cid)
    part = _seed_part(db, "Real Part")
    with pytest.raises(ValueError):
        db.add_asset_bom_item(eq, 99999999)         # no such part
    with pytest.raises(ValueError):
        db.add_asset_bom_item(99999999, part)        # no such equipment


def test_non_positive_quantity_rejected(db):
    cid = _seed_customer(db)
    eq = _seed_equipment(db, cid)
    part = _seed_part(db, "Sensor")
    with pytest.raises(ValueError):
        db.add_asset_bom_item(eq, part, quantity=0)
    with pytest.raises(ValueError):
        db.add_asset_bom_item(eq, part, quantity=-3)
    assert db.list_asset_bom(eq) == []


# ── UNIQUE backstop at the index level ──────────────────────────────────────
def test_unique_index_blocks_raw_duplicate(db):
    cid = _seed_customer(db)
    eq = _seed_equipment(db, cid)
    part = _seed_part(db, "Fan Motor")
    db.add_asset_bom_item(eq, part)
    con = db._con()
    with pytest.raises(sqlite3.IntegrityError):
        con.execute(
            "INSERT INTO asset_bom (equipment_id, part_id, quantity, created_at) "
            "VALUES (?, ?, ?, ?)", (eq, part, 1, _now()))
        con.commit()
    con.close()


# ── Reverse lookup (where-used) ──────────────────────────────────────────────
def test_where_used(db):
    cid = _seed_customer(db)
    eq1 = _seed_equipment(db, cid, name="Chiller 1")
    eq2 = _seed_equipment(db, cid, name="Chiller 2")
    shared = _seed_part(db, "Common Valve")
    only1 = _seed_part(db, "Niche Gasket")
    db.add_asset_bom_item(eq1, shared, quantity=2)
    db.add_asset_bom_item(eq2, shared, quantity=1)
    db.add_asset_bom_item(eq1, only1)
    used = db.list_part_where_used(shared)
    assert {u["equipment_id"] for u in used} == {eq1, eq2}
    by_eq = {u["equipment_id"]: u for u in used}
    assert by_eq[eq1]["quantity"] == 2
    assert by_eq[eq1]["equipment_name"] == "Chiller 1"
    # the niche part is only on one asset
    assert {u["equipment_id"] for u in db.list_part_where_used(only1)} == {eq1}
