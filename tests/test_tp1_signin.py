"""TP-1b: sign-in / sign-out 5S gating and day-off alert."""
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

import pytest

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_DB = str(_PROJECT_ROOT / "submissions.db")


def _tech_id_from_cookie(client, tech_token):
    # Tech profile reflects who the cookie identifies.
    r = client.get(
        "/api/tech/me/profile",
        cookies={"pc_tech_session": tech_token},
    )
    if r.status_code != 200:
        pytest.skip(f"tech profile not reachable: {r.status_code} {r.text[:200]}")
    body = r.json()
    return body["id"]


def _delete_5s_today(tech_id):
    today_iso = datetime.now(timezone.utc).date().isoformat()
    con = sqlite3.connect(_DB)
    try:
        con.execute(
            "DELETE FROM fs_audits WHERE auditor_id = ? AND auditor_kind = 'tech' "
            "AND substr(audit_ts, 1, 10) = ?",
            (tech_id, today_iso),
        )
        con.commit()
    finally:
        con.close()


def _delete_clock_today(tech_id):
    today_iso = datetime.now(timezone.utc).date().isoformat()
    con = sqlite3.connect(_DB)
    try:
        con.execute(
            "DELETE FROM tech_clock_events WHERE tech_id = ? AND work_date = ?",
            (tech_id, today_iso),
        )
        con.commit()
    finally:
        con.close()


def _insert_5s_audit(tech_id, phase):
    """Insert a minimal fs_audit row directly to satisfy the 5S gate."""
    now = datetime.now(timezone.utc).isoformat()
    con = sqlite3.connect(_DB)
    try:
        con.execute(
            "INSERT INTO fs_audits (asset_id, auditor_id, auditor_kind, phase, "
            "audit_ts, overall_pass, hub_id, prior_chain_hash, chain_hash) "
            "VALUES (1, ?, 'tech', ?, ?, 1, 1, '', ?)",
            (tech_id, phase, now, f"test_chain_{tech_id}_{phase}_{now}"),
        )
        con.commit()
    finally:
        con.close()


def _set_today_schedule(tech_id, active):
    import database
    today = datetime.now(timezone.utc).date()
    database.set_tech_schedule_day(tech_id, today.weekday(),
                                   "08:00", "17:00", int(active))


def _clear_schedule(tech_id):
    con = sqlite3.connect(_DB)
    try:
        con.execute("DELETE FROM tech_schedules WHERE tech_id = ?", (tech_id,))
        con.commit()
    finally:
        con.close()


def test_signin_without_5s_returns_409(client, tech_token):
    tid = _tech_id_from_cookie(client, tech_token)
    _delete_5s_today(tid)
    _delete_clock_today(tid)
    _set_today_schedule(tid, 1)
    r = client.post(
        "/api/tech/me/sign-in", json={},
        cookies={"pc_tech_session": tech_token},
    )
    assert r.status_code == 409
    assert "5s_start_shift_required" in r.text


def test_signin_after_5s_succeeds(client, tech_token):
    tid = _tech_id_from_cookie(client, tech_token)
    _delete_5s_today(tid)
    _delete_clock_today(tid)
    _set_today_schedule(tid, 1)
    _insert_5s_audit(tid, "start_shift")
    r = client.post(
        "/api/tech/me/sign-in", json={},
        cookies={"pc_tech_session": tech_token},
    )
    assert r.status_code == 200, r.text
    assert r.json()["ok"] is True


def test_signin_dayoff_no_reason_returns_409(client, tech_token):
    tid = _tech_id_from_cookie(client, tech_token)
    _delete_5s_today(tid)
    _delete_clock_today(tid)
    _clear_schedule(tid)
    _insert_5s_audit(tid, "start_shift")
    r = client.post(
        "/api/tech/me/sign-in", json={},
        cookies={"pc_tech_session": tech_token},
    )
    assert r.status_code == 409
    assert "dayoff_reason_required" in r.text


def test_signin_dayoff_with_reason_succeeds_and_alerts(client, tech_token):
    tid = _tech_id_from_cookie(client, tech_token)
    _delete_5s_today(tid)
    _delete_clock_today(tid)
    _clear_schedule(tid)
    _insert_5s_audit(tid, "start_shift")
    r = client.post(
        "/api/tech/me/sign-in",
        json={"dayoff_reason": "Covering for a sick teammate"},
        cookies={"pc_tech_session": tech_token},
    )
    assert r.status_code == 200, r.text
    # Verify the security alert was created.
    con = sqlite3.connect(_DB)
    try:
        row = con.execute(
            "SELECT 1 FROM security_alerts WHERE kind = 'tech_dayoff_signin' "
            "AND actor_id = ? ORDER BY id DESC LIMIT 1",
            (tid,),
        ).fetchone()
    finally:
        con.close()
    assert row is not None


def test_signout_without_5s_returns_409(client, tech_token):
    tid = _tech_id_from_cookie(client, tech_token)
    _delete_5s_today(tid)
    _delete_clock_today(tid)
    _set_today_schedule(tid, 1)
    # Make tech currently clocked in, but no end_shift 5S.
    _insert_5s_audit(tid, "start_shift")
    r = client.post(
        "/api/tech/me/sign-in", json={},
        cookies={"pc_tech_session": tech_token},
    )
    assert r.status_code == 200, r.text
    r = client.post(
        "/api/tech/me/sign-out",
        cookies={"pc_tech_session": tech_token},
    )
    assert r.status_code == 409
    assert "5s_end_shift_required" in r.text
