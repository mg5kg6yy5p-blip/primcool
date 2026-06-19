"""CMMS Gap #3 — single enforced visit lifecycle state machine.

Phase-3 gate: prove transition_visit() is the ONE authority for status
changes — legal moves succeed with the right side-effects, illegal jumps are
rejected, spec aliases normalise, and a completed visit's descriptive fields
are frozen (the only way back is a confirmation reversal).

Runs against a FRESH, isolated SQLite file (never the live submissions.db):
DB_PATH is pointed at a temp file, init_db() builds the schema, rows are seeded
directly, and DB_PATH is restored on teardown.
"""
import sqlite3
from datetime import datetime, timezone

import pytest

import database


@pytest.fixture
def db(tmp_path, monkeypatch):
    db_file = tmp_path / "cmms_visit_test.db"
    monkeypatch.setattr(database, "DB_PATH", str(db_file))
    database.init_db()
    yield database


def _now():
    return datetime.now(timezone.utc).isoformat()


_CUST_SEQ = [0]


def _seed_customer(db, name="Acme HVAC"):
    _CUST_SEQ[0] += 1
    con = db._con()
    cur = con.execute(
        "INSERT INTO customers (customer_code, name, created_at) VALUES (?, ?, ?)",
        ("VSTC%04d" % _CUST_SEQ[0], name, _now()),
    )
    cid = cur.lastrowid
    con.commit()
    con.close()
    return cid


def _seed_visit(db, customer_id, status="scheduled", visit_type="PM", **extra):
    data = {"customer_id": customer_id, "visit_type": visit_type, "status": status}
    data.update(extra)
    return db.create_visit(data)


def _status(db, visit_id):
    con = db._con()
    row = con.execute(
        "SELECT * FROM maintenance_visits WHERE id = ?", (visit_id,)
    ).fetchone()
    con.close()
    return dict(row)


# ---------------------------------------------------------------------------
# Schema / migration smoke
# ---------------------------------------------------------------------------
def test_lifecycle_columns_exist(db):
    con = db._con()
    cols = {r[1] for r in con.execute("PRAGMA table_info(maintenance_visits)")}
    con.close()
    for c in ("closed_at", "closed_by_kind", "cancelled_at", "cancelled_reason"):
        assert c in cols


def test_lifecycle_graph_shape(db):
    assert db._VISIT_LIFECYCLE["created"] == {"scheduled", "cancelled"}
    assert db._VISIT_LIFECYCLE["scheduled"] == {"in_progress", "cancelled"}
    assert db._VISIT_LIFECYCLE["in_progress"] == {"completed"}
    assert db._VISIT_LIFECYCLE["completed"] == {"closed"}
    assert db._VISIT_LIFECYCLE["closed"] == set()
    assert db._VISIT_LIFECYCLE["cancelled"] == set()


# ---------------------------------------------------------------------------
# Happy-path transitions + side-effects
# ---------------------------------------------------------------------------
def test_scheduled_to_in_progress_sets_start_time(db):
    cid = _seed_customer(db)
    vid = _seed_visit(db, cid)
    res = db.transition_visit(vid, "in_progress", actor_kind="admin", actor_id=1)
    assert res == {"old": "scheduled", "new": "in_progress", "noop": False}
    row = _status(db, vid)
    assert row["status"] == "in_progress"
    assert row["start_time"]


def test_in_progress_to_completed_sets_submitted_and_completed(db):
    cid = _seed_customer(db)
    vid = _seed_visit(db, cid, status="in_progress")
    db.transition_visit(vid, "completed", actor_kind="admin", actor_id=1)
    row = _status(db, vid)
    assert row["status"] == "completed"
    assert row["submitted_at"]
    assert row["completed_date"]


def test_completed_to_closed_records_actor(db):
    cid = _seed_customer(db)
    vid = _seed_visit(db, cid, status="completed")
    db.transition_visit(vid, "closed", actor_kind="admin", actor_id=42)
    row = _status(db, vid)
    assert row["status"] == "closed"
    assert row["closed_at"]
    assert row["closed_by_kind"] == "admin"
    assert row["closed_by_id"] == 42


def test_cancel_from_scheduled_records_reason(db):
    cid = _seed_customer(db)
    vid = _seed_visit(db, cid)
    db.transition_visit(vid, "cancelled", actor_kind="admin", actor_id=7,
                        reason="customer no-show")
    row = _status(db, vid)
    assert row["status"] == "cancelled"
    assert row["cancelled_at"]
    assert row["cancelled_reason"] == "customer no-show"


def test_full_lifecycle_walk(db):
    cid = _seed_customer(db)
    vid = _seed_visit(db, cid, status="created")
    for nxt in ("scheduled", "in_progress", "completed", "closed"):
        db.transition_visit(vid, nxt, actor_kind="admin", actor_id=1)
    assert _status(db, vid)["status"] == "closed"


# ---------------------------------------------------------------------------
# Aliases
# ---------------------------------------------------------------------------
def test_tech_complete_alias_maps_to_completed(db):
    cid = _seed_customer(db)
    vid = _seed_visit(db, cid, status="in_progress")
    res = db.transition_visit(vid, "tech_complete", actor_kind="admin", actor_id=1)
    assert res["new"] == "completed"
    assert _status(db, vid)["status"] == "completed"


def test_canceled_us_spelling_normalises(db):
    cid = _seed_customer(db)
    vid = _seed_visit(db, cid)
    db.transition_visit(vid, "canceled", actor_kind="admin", actor_id=1)
    assert _status(db, vid)["status"] == "cancelled"


def test_normalize_and_predicate_helpers(db):
    assert db.normalize_visit_status("tech_complete") == "completed"
    assert db.visit_transition_allowed("scheduled", "in_progress") is True
    assert db.visit_transition_allowed("scheduled", "completed") is False
    # no-op always allowed
    assert db.visit_transition_allowed("completed", "completed") is True


# ---------------------------------------------------------------------------
# Illegal transitions (the Phase-3 gate)
# ---------------------------------------------------------------------------
def test_scheduled_to_completed_illegal(db):
    cid = _seed_customer(db)
    vid = _seed_visit(db, cid)
    with pytest.raises(database.VisitTransitionError) as ei:
        db.transition_visit(vid, "completed", actor_kind="admin", actor_id=1)
    assert ei.value.kind == "transition"
    assert ei.value.current == "scheduled"
    assert _status(db, vid)["status"] == "scheduled"  # unchanged


def test_completed_to_in_progress_illegal(db):
    cid = _seed_customer(db)
    vid = _seed_visit(db, cid, status="completed")
    with pytest.raises(database.VisitTransitionError):
        db.transition_visit(vid, "in_progress", actor_kind="admin", actor_id=1)


def test_cancel_from_completed_illegal(db):
    cid = _seed_customer(db)
    vid = _seed_visit(db, cid, status="completed")
    with pytest.raises(database.VisitTransitionError):
        db.transition_visit(vid, "cancelled", actor_kind="admin", actor_id=1)


def test_closed_is_terminal(db):
    cid = _seed_customer(db)
    vid = _seed_visit(db, cid, status="closed")
    for nxt in ("scheduled", "in_progress", "completed", "cancelled"):
        with pytest.raises(database.VisitTransitionError):
            db.transition_visit(vid, nxt, actor_kind="admin", actor_id=1)


def test_unknown_status_rejected(db):
    cid = _seed_customer(db)
    vid = _seed_visit(db, cid)
    with pytest.raises(database.VisitTransitionError):
        db.transition_visit(vid, "teleported", actor_kind="admin", actor_id=1)


def test_noop_transition_is_allowed(db):
    cid = _seed_customer(db)
    vid = _seed_visit(db, cid, status="in_progress")
    res = db.transition_visit(vid, "in_progress", actor_kind="admin", actor_id=1)
    assert res["noop"] is True


# ---------------------------------------------------------------------------
# update_visit is guarded by the same machine
# ---------------------------------------------------------------------------
def test_update_visit_rejects_illegal_status_jump(db):
    cid = _seed_customer(db)
    vid = _seed_visit(db, cid)  # scheduled
    with pytest.raises(database.VisitTransitionError):
        db.update_visit(vid, {"visit_type": "PM", "status": "completed"})


def test_update_visit_allows_legal_status_jump(db):
    cid = _seed_customer(db)
    vid = _seed_visit(db, cid)
    db.update_visit(vid, {"visit_type": "PM", "status": "in_progress"})
    assert _status(db, vid)["status"] == "in_progress"


# ---------------------------------------------------------------------------
# Frozen descriptive fields after completion
# ---------------------------------------------------------------------------
def test_completed_visit_freezes_descriptive_edit(db):
    cid = _seed_customer(db)
    vid = _seed_visit(db, cid, status="completed", scope_of_work="orig")
    with pytest.raises(database.VisitTransitionError) as ei:
        db.update_visit(vid, {"visit_type": "PM", "status": "completed",
                              "scope_of_work": "CHANGED"})
    assert ei.value.kind == "frozen"


def test_completed_visit_allows_resave_identical_content(db):
    cid = _seed_customer(db)
    vid = _seed_visit(db, cid, status="completed", scope_of_work="orig",
                      work_done="did the thing")
    # Re-saving the SAME (decrypted) content must not trip the freeze guard.
    db.update_visit(vid, {"visit_type": "PM", "status": "completed",
                          "scope_of_work": "orig", "work_done": "did the thing"})
    assert _status(db, vid)["status"] == "completed"


def test_assert_edit_allowed_noop_on_open_visit(db):
    cid = _seed_customer(db)
    vid = _seed_visit(db, cid)  # scheduled, not frozen
    # Should not raise even with a descriptive change.
    db.assert_visit_edit_allowed(vid, {"scope_of_work": "anything"})


def test_reversal_unlocks_frozen_visit(db):
    """A completed visit is frozen; reversing the confirmation re-opens it to
    'scheduled', after which descriptive edits are allowed again."""
    cid = _seed_customer(db)
    vid = _seed_visit(db, cid, status="in_progress")
    db.transition_visit(vid, "completed", actor_kind="admin", actor_id=1)
    # frozen now
    with pytest.raises(database.VisitTransitionError):
        db.update_visit(vid, {"visit_type": "PM", "status": "completed",
                              "scope_of_work": "x"})
    db.reverse_visit_confirmation(vid, "wrong unit", actor_kind="admin", actor_id=1)
    assert _status(db, vid)["status"] == "scheduled"
    # editable again
    db.update_visit(vid, {"visit_type": "PM", "status": "scheduled",
                          "scope_of_work": "corrected"})
