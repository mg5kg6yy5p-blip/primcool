"""CMMS Gap #4 — confirmation reversal restores consumed stock.

Phase-4 gate: reversing a visit confirmation must give the parts the visit
consumed back to inventory, atomically with the re-open, and be idempotent
(a second reversal restores nothing). Runs against a FRESH isolated SQLite DB.
"""
from datetime import datetime, timezone

import pytest

import database


@pytest.fixture
def db(tmp_path, monkeypatch):
    db_file = tmp_path / "cmms_rev_test.db"
    monkeypatch.setattr(database, "DB_PATH", str(db_file))
    database.init_db()
    yield database


def _now():
    return datetime.now(timezone.utc).isoformat()


_SEQ = [0]


def _seed_customer(db):
    _SEQ[0] += 1
    con = db._con()
    cur = con.execute(
        "INSERT INTO customers (customer_code, name, created_at) VALUES (?,?,?)",
        ("REVC%04d" % _SEQ[0], "Reversal Cust", _now()),
    )
    cid = cur.lastrowid
    con.commit()
    con.close()
    return cid


def _seed_part(db, qty=10.0, sku=None):
    _SEQ[0] += 1
    return db.create_part({"sku": sku or ("REVP%04d" % _SEQ[0]),
                           "name": "Compressor Capacitor",
                           "unit_cost": 50.0, "quantity": qty})


def _seed_completed_visit(db, customer_id):
    vid = db.create_visit({"customer_id": customer_id, "visit_type": "CM",
                           "status": "in_progress"})
    db.transition_visit(vid, "completed", actor_kind="admin", actor_id=1)
    return vid


def _qty(db, part_id):
    return db.get_part_by_id(part_id)["quantity"]


# ---------------------------------------------------------------------------
def test_reversal_restores_consumed_stock(db):
    cid = _seed_customer(db)
    pid = _seed_part(db, qty=10.0)
    vid = _seed_completed_visit(db, cid)
    db.add_visit_part(vid, pid, 3.0)            # 10 → 7
    assert _qty(db, pid) == 7.0
    res = db.reverse_visit_confirmation(vid, "wrong diagnosis",
                                        actor_kind="admin", actor_id=1)
    assert _qty(db, pid) == 10.0                # restored
    assert res["restored"]
    assert res["restored"][0]["part_id"] == pid
    assert res["restored"][0]["quantity"] == 3.0


def test_reversal_is_idempotent_on_stock(db):
    cid = _seed_customer(db)
    pid = _seed_part(db, qty=8.0)
    vid = _seed_completed_visit(db, cid)
    db.add_visit_part(vid, pid, 2.0)            # 8 → 6
    db.reverse_visit_confirmation(vid, "first", actor_kind="admin", actor_id=1)
    assert _qty(db, pid) == 8.0
    # Re-complete then reverse again — nothing further should be given back
    # for the already-restored consumption (net is 0).
    db.transition_visit(vid, "in_progress", actor_kind="admin", actor_id=1)
    db.transition_visit(vid, "completed", actor_kind="admin", actor_id=1)
    res2 = db.reverse_visit_confirmation(vid, "second", actor_kind="admin",
                                         actor_id=1)
    assert _qty(db, pid) == 8.0                 # unchanged
    assert res2["restored"] == []


def test_reversal_nets_partial_removal(db):
    cid = _seed_customer(db)
    pid = _seed_part(db, qty=20.0)
    vid = _seed_completed_visit(db, cid)
    vp = db.add_visit_part(vid, pid, 5.0)       # 20 → 15
    db.remove_visit_part(vp)                     # +5 back → 20 (net 0)
    res = db.reverse_visit_confirmation(vid, "n/a", actor_kind="admin", actor_id=1)
    assert _qty(db, pid) == 20.0
    assert res["restored"] == []                # net already zero


def test_reversal_restores_multiple_parts(db):
    cid = _seed_customer(db)
    p1 = _seed_part(db, qty=10.0)
    p2 = _seed_part(db, qty=4.0)
    vid = _seed_completed_visit(db, cid)
    db.add_visit_part(vid, p1, 4.0)             # 10 → 6
    db.add_visit_part(vid, p2, 1.0)             # 4 → 3
    res = db.reverse_visit_confirmation(vid, "redo", actor_kind="admin", actor_id=1)
    assert _qty(db, p1) == 10.0
    assert _qty(db, p2) == 4.0
    restored = {r["part_id"]: r["quantity"] for r in res["restored"]}
    assert restored == {p1: 4.0, p2: 1.0}


def test_reversal_writes_ledger_movement(db):
    cid = _seed_customer(db)
    pid = _seed_part(db, qty=10.0)
    vid = _seed_completed_visit(db, cid)
    db.add_visit_part(vid, pid, 3.0)
    db.reverse_visit_confirmation(vid, "x", actor_kind="admin", actor_id=1)
    moves = db.get_part_movements(pid)
    # newest first: the restoration 'received' movement should be present
    restock = [m for m in moves if m["movement_type"] == "received"
               and "reversal" in (m["reason"] or "").lower()]
    assert restock and restock[0]["quantity_delta"] == 3.0


def test_reversal_can_skip_restore(db):
    cid = _seed_customer(db)
    pid = _seed_part(db, qty=10.0)
    vid = _seed_completed_visit(db, cid)
    db.add_visit_part(vid, pid, 3.0)            # 10 → 7
    res = db.reverse_visit_confirmation(vid, "keep consumed",
                                        actor_kind="admin", actor_id=1,
                                        restore_stock=False)
    assert _qty(db, pid) == 7.0                 # NOT restored
    assert res["restored"] == []


def test_reversal_snapshot_records_restored(db):
    cid = _seed_customer(db)
    pid = _seed_part(db, qty=10.0)
    vid = _seed_completed_visit(db, cid)
    db.add_visit_part(vid, pid, 2.0)
    db.reverse_visit_confirmation(vid, "snap", actor_kind="admin", actor_id=1)
    events = db.list_visit_confirmation_events(vid)
    rev = next(e for e in events if e["event_type"] == "reversal")
    assert rev["snapshot"].get("restored_stock")
    assert rev["snapshot"]["restored_stock"][0]["part_id"] == pid
