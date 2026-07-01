"""TP-1b: tech schedule helpers + admin endpoint permission gating."""
import os
import sqlite3
from datetime import datetime, timezone, date
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
            "SELECT id FROM technicians ORDER BY id LIMIT 1"
        ).fetchone()
    finally:
        con.close()
    if not row:
        pytest.skip("no technicians seeded")
    return row[0]


def _clear_schedule(tech_id):
    con = sqlite3.connect(_DB)
    try:
        con.execute("DELETE FROM tech_schedules WHERE tech_id = ?", (tech_id,))
        con.commit()
    finally:
        con.close()


def test_set_and_get_schedule_day():
    import database
    tid = _pick_tech_id()
    _clear_schedule(tid)
    # Today's weekday
    dow = datetime.now(timezone.utc).date().weekday()
    database.set_tech_schedule_day(tid, dow, "08:00", "17:00", 1)
    sched = database.get_tech_schedule(tid)
    assert len(sched) == 7
    today_row = sched[dow]
    assert today_row["start_time"] == "08:00"
    assert today_row["end_time"] == "17:00"
    assert today_row["active"] == 1


def test_scheduled_end_today_returns_iso_for_active_day():
    import database
    tid = _pick_tech_id()
    _clear_schedule(tid)
    today = datetime.now(timezone.utc).date()
    database.set_tech_schedule_day(tid, today.weekday(), "08:00", "17:00", 1)
    end = database.get_tech_scheduled_end_today(tid, today=today)
    assert end is not None
    parsed = datetime.fromisoformat(end)
    assert parsed.hour == 17 and parsed.minute == 0
    assert parsed.date() == today


def test_scheduled_end_today_missing_day_returns_none():
    import database
    tid = _pick_tech_id()
    _clear_schedule(tid)
    today = datetime.now(timezone.utc).date()
    assert database.get_tech_scheduled_end_today(tid, today=today) is None


def test_scheduled_end_today_inactive_day_returns_none():
    import database
    tid = _pick_tech_id()
    _clear_schedule(tid)
    today = datetime.now(timezone.utc).date()
    database.set_tech_schedule_day(tid, today.weekday(), "08:00", "17:00", 0)
    assert database.get_tech_scheduled_end_today(tid, today=today) is None


def test_is_tech_scheduled_today_behaves_correctly():
    import database
    tid = _pick_tech_id()
    _clear_schedule(tid)
    today = datetime.now(timezone.utc).date()
    assert database.is_tech_scheduled_today(tid, today=today) is False
    database.set_tech_schedule_day(tid, today.weekday(), "08:00", "17:00", 1)
    assert database.is_tech_scheduled_today(tid, today=today) is True


def test_admin_set_schedule_requires_perm(client, tech_token):
    """A tech (no admin perm) cannot POST to the admin schedule endpoint."""
    tid = _pick_tech_id()
    r = client.post(
        f"/api/admin/technicians/{tid}/schedule",
        json={"day_of_week": 0, "start_time": "08:00",
              "end_time": "17:00", "active": 1},
        cookies={"pc_tech_session": tech_token},
    )
    # Tech cookie isn't an admin → unauthenticated_admin (401) or 403.
    assert r.status_code in (401, 403)
