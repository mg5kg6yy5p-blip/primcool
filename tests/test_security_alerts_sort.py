"""list_security_alerts must return OPEN-FIRST, then created_at DESC.

The admin UX depends on this sort:
  - super_admin opens the Security Alerts panel
  - works the top of the list (always the next-up open alert)
  - resolves one — the resolved row drops to its chronological position
    among the resolved alerts, the next open alert rises to the top
  - admin keeps working from the top of the list without scrolling

If this contract breaks, super_admin will have to scroll past resolved
rows to find unresolved work. The fix lives in database.py
list_security_alerts ORDER BY.
"""
import os
import time
import sqlite3
from datetime import datetime, timedelta, timezone

import pytest

if "JWT_SECRET" not in os.environ:
    try:
        for line in open(".dev.env"):
            if line.startswith("export "):
                k, v = line[7:].strip().split("=", 1)
                os.environ.setdefault(k, v.strip('"'))
    except FileNotFoundError:
        pytest.skip(".dev.env not present", allow_module_level=True)

import database


@pytest.fixture
def alert_table_isolated():
    """Snapshot+restore the security_alerts table so the test runs without
    polluting the dev DB. Uses a TEMP table for the snapshot."""
    con = database._con()
    try:
        # Stash existing rows
        con.execute("CREATE TEMP TABLE _alerts_snapshot AS "
                    "SELECT * FROM security_alerts")
        con.execute("DELETE FROM security_alerts")
        con.commit()
        yield con
    finally:
        # Restore exactly what was there before
        con.execute("DELETE FROM security_alerts")
        con.execute("INSERT INTO security_alerts SELECT * FROM _alerts_snapshot")
        con.commit()
        con.close()


def _insert(con, status: str, when_iso: str, summary: str = "test",
            kind: str = "test_kind", severity: str = "medium"):
    con.execute(
        "INSERT INTO security_alerts "
        "(kind, severity, summary, status, created_at) "
        "VALUES (?, ?, ?, ?, ?)",
        (kind, severity, summary, status, when_iso),
    )
    con.commit()
    return con.execute("SELECT last_insert_rowid()").fetchone()[0]


def _iso(offset_seconds: int) -> str:
    """Build an ISO timestamp offset from 'now'."""
    return (datetime.now(timezone.utc)
            + timedelta(seconds=offset_seconds)).isoformat()


def test_open_alerts_always_come_before_non_open(alert_table_isolated):
    """Even when a resolved alert is MUCH more recent than an open one,
    the open one must come first."""
    con = alert_table_isolated
    # The resolved one is more recent (offset=0); the open one is older
    # (offset=-3600). Pre-fix sort (created_at DESC only) would put the
    # resolved first. Post-fix puts the open first.
    resolved_id = _insert(con, status="resolved", when_iso=_iso(0),
                          summary="recent but resolved")
    open_id = _insert(con, status="open", when_iso=_iso(-3600),
                      summary="older but still open")
    rows = database.list_security_alerts(limit=10)
    assert rows[0]["id"] == open_id, (
        f"OPEN-FIRST sort broken: list_security_alerts returned id "
        f"{rows[0]['id']} ({rows[0]['status']!r}) as the first row; "
        f"the older OPEN alert id={open_id} should be first regardless "
        f"of created_at."
    )
    # And the resolved one is below it
    assert any(r["id"] == resolved_id and r["status"] == "resolved"
               for r in rows[1:])


def test_within_open_group_sort_by_created_at_desc(alert_table_isolated):
    """Among open alerts, most-recently-created comes first."""
    con = alert_table_isolated
    old_id  = _insert(con, status="open", when_iso=_iso(-7200),
                      summary="old open")
    new_id  = _insert(con, status="open", when_iso=_iso(0),
                      summary="new open")
    mid_id  = _insert(con, status="open", when_iso=_iso(-3600),
                      summary="middle open")
    rows = database.list_security_alerts(limit=10)
    ids = [r["id"] for r in rows]
    assert ids == [new_id, mid_id, old_id], (
        f"Within-open ordering broken: expected newest-first "
        f"[{new_id}, {mid_id}, {old_id}], got {ids}"
    )


def test_within_non_open_group_sort_by_created_at_desc(alert_table_isolated):
    """Among resolved/dismissed, most-recently-created comes first.
    A resolved alert that was OLD when it was created stays in its
    chronological slot among other non-open alerts when it's resolved.
    This is what the user described as 'returns to its normal position
    based on alarm operation time'."""
    con = alert_table_isolated
    old_resolved = _insert(con, status="resolved", when_iso=_iso(-7200),
                           summary="old resolved")
    new_dismissed = _insert(con, status="dismissed", when_iso=_iso(0),
                            summary="new dismissed")
    mid_resolved = _insert(con, status="resolved", when_iso=_iso(-3600),
                           summary="middle resolved")
    rows = database.list_security_alerts(limit=10)
    ids = [r["id"] for r in rows]
    assert ids == [new_dismissed, mid_resolved, old_resolved], (
        f"Within-non-open ordering broken: expected newest-first "
        f"[{new_dismissed}, {mid_resolved}, {old_resolved}], got {ids}"
    )


def test_full_mixed_sort_matches_admin_ux_contract(alert_table_isolated):
    """The end-to-end shape the admin panel relies on:
        [open newest] [open older] ... [resolved newest] [resolved older] ...

    Simulates a realistic backlog: 3 open + 3 resolved interleaved in
    time. Verifies the rotation behavior the user requested — opens
    always at the top, resolveds dropping into chronological position
    below the opens.
    """
    con = alert_table_isolated
    # Created in the order: open-old, resolved-newest, open-newest,
    # dismissed-mid, open-mid, resolved-old.
    o_old   = _insert(con, status="open",      when_iso=_iso(-5*3600))
    r_new   = _insert(con, status="resolved",  when_iso=_iso(0))
    o_new   = _insert(con, status="open",      when_iso=_iso(-1*3600))
    d_mid   = _insert(con, status="dismissed", when_iso=_iso(-3*3600))
    o_mid   = _insert(con, status="open",      when_iso=_iso(-2*3600))
    r_old   = _insert(con, status="resolved",  when_iso=_iso(-6*3600))

    rows = database.list_security_alerts(limit=10)
    ids = [r["id"] for r in rows]
    # Opens: newest → middle → oldest
    # Then non-opens: newest → middle → oldest
    expected = [o_new, o_mid, o_old, r_new, d_mid, r_old]
    assert ids == expected, (
        f"Mixed-status sort broken.\n"
        f"  expected (open-first newest-to-old, then non-open newest-to-old):\n"
        f"    {expected}\n"
        f"  got: {ids}\n"
        f"  status sequence: {[r['status'] for r in rows]}"
    )


def test_status_filter_still_works(alert_table_isolated):
    """When a status filter is passed, the WHERE clause limits to one
    group. The OPEN-FIRST tier is moot — the group order is created_at
    DESC. Regression check: the new ORDER BY must not break the filter
    path."""
    con = alert_table_isolated
    _insert(con, status="open",     when_iso=_iso(-100))
    _insert(con, status="resolved", when_iso=_iso(0))
    _insert(con, status="open",     when_iso=_iso(0))
    open_only = database.list_security_alerts(status="open", limit=10)
    assert all(r["status"] == "open" for r in open_only), \
        f"status filter leaked non-open rows: {open_only}"
    assert len(open_only) == 2
