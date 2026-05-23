"""TP-1b: completed-jobs tab redacts customer details; today tab does not."""
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

import pytest

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_DB = str(_PROJECT_ROOT / "submissions.db")


def _tech_id_from_cookie(client, tech_token):
    r = client.get("/api/tech/me/profile",
                   cookies={"pc_tech_session": tech_token})
    if r.status_code != 200:
        pytest.skip(f"tech profile not reachable: {r.status_code}")
    return r.json()["id"]


def test_jobs_done_redacts_customer_fields(client, tech_token):
    tid = _tech_id_from_cookie(client, tech_token)
    # Ensure at least one completed visit exists for this tech.
    con = sqlite3.connect(_DB)
    try:
        row = con.execute(
            "SELECT id FROM maintenance_visits WHERE assigned_tech_id = ? "
            "AND status = 'completed' ORDER BY id DESC LIMIT 1",
            (tid,),
        ).fetchone()
        if not row:
            # Flip an existing visit (if any) into completed for this tech.
            any_row = con.execute(
                "SELECT id FROM maintenance_visits WHERE assigned_tech_id = ? "
                "ORDER BY id DESC LIMIT 1",
                (tid,),
            ).fetchone()
            if not any_row:
                pytest.skip("no visits for this tech to redact")
            con.execute(
                "UPDATE maintenance_visits SET status = 'completed' WHERE id = ?",
                (any_row[0],),
            )
            con.commit()
    finally:
        con.close()
    r = client.get(
        "/api/tech/me/jobs-done?limit=10",
        cookies={"pc_tech_session": tech_token},
    )
    assert r.status_code == 200, r.text
    jobs = r.json()
    if not jobs:
        pytest.skip("no completed jobs for this tech")
    for j in jobs:
        assert j["customer_name"] == "—"
        assert j["customer_address"] == "—"
        assert j["customer_phone"] == "—"
        assert j["customer_code"] == "—"


def test_jobs_today_keeps_customer_name(client, tech_token):
    """Sanity check that today differs from done — name should not be '—' for
    today's jobs (or list empty)."""
    tid = _tech_id_from_cookie(client, tech_token)
    today_iso = datetime.now(timezone.utc).date().isoformat()
    con = sqlite3.connect(_DB)
    try:
        row = con.execute(
            "SELECT id FROM maintenance_visits WHERE assigned_tech_id = ? "
            "AND scheduled_date = ? LIMIT 1",
            (tid, today_iso),
        ).fetchone()
        if not row:
            # Schedule one of this tech's visits to today.
            any_row = con.execute(
                "SELECT id FROM maintenance_visits WHERE assigned_tech_id = ? "
                "ORDER BY id DESC LIMIT 1",
                (tid,),
            ).fetchone()
            if not any_row:
                pytest.skip("no visits for this tech")
            con.execute(
                "UPDATE maintenance_visits SET scheduled_date = ? WHERE id = ?",
                (today_iso, any_row[0]),
            )
            con.commit()
    finally:
        con.close()
    r = client.get(
        "/api/tech/me/jobs-today",
        cookies={"pc_tech_session": tech_token},
    )
    assert r.status_code == 200, r.text
    jobs = r.json()
    if not jobs:
        pytest.skip("no jobs today for this tech")
    # At least one should NOT be the dash placeholder.
    assert any((j.get("customer_name") or "") != "—" for j in jobs)
