"""TP-1b: overtime approval helpers."""
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

import pytest

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_DB = str(_PROJECT_ROOT / "submissions.db")


def _pick_tech_id():
    if not Path(_DB).exists():
        pytest.skip("submissions.db not present")
    con = sqlite3.connect(_DB)
    try:
        row = con.execute(
            "SELECT id FROM technicians ORDER BY id DESC LIMIT 1"
        ).fetchone()
    finally:
        con.close()
    if not row:
        pytest.skip("no technicians seeded")
    return row[0]


def _pick_admin_id():
    con = sqlite3.connect(_DB)
    try:
        row = con.execute(
            "SELECT id FROM admin_users WHERE active = 1 ORDER BY id LIMIT 1"
        ).fetchone()
    finally:
        con.close()
    if not row:
        pytest.skip("no admin users seeded")
    return row[0]


def _clear_today(tech_id):
    today_iso = datetime.now(timezone.utc).date().isoformat()
    con = sqlite3.connect(_DB)
    try:
        con.execute(
            "DELETE FROM tech_overtime_approvals WHERE tech_id = ? AND work_date = ?",
            (tech_id, today_iso),
        )
        con.commit()
    finally:
        con.close()


def test_approve_overtime_is_idempotent():
    import database
    tid = _pick_tech_id()
    aid = _pick_admin_id()
    _clear_today(tid)
    a = database.approve_overtime(tid, aid, notes="first")
    b = database.approve_overtime(tid, aid, notes="second")
    assert a == b


def test_is_overtime_approved_false_without_approval():
    import database
    tid = _pick_tech_id()
    _clear_today(tid)
    assert database.is_overtime_approved(tid) is False


def test_is_overtime_approved_true_after_approve():
    import database
    tid = _pick_tech_id()
    aid = _pick_admin_id()
    _clear_today(tid)
    database.approve_overtime(tid, aid, notes="ot ok")
    assert database.is_overtime_approved(tid) is True
