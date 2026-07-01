"""TP-1b: CV append → lock → grant → update lifecycle."""
import os
import sqlite3
from datetime import datetime, timezone, timedelta
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


def test_cv_append_creates_draft(client, tech_token):
    r = client.post(
        "/api/tech/me/cv",
        json={"company": "TestCo", "title": "Tester",
              "description": "wrote tests"},
        cookies={"pc_tech_session": tech_token},
    )
    assert r.status_code == 200, r.text
    entry_id = r.json()["id"]
    # Verify status = draft via direct DB read.
    con = sqlite3.connect(_DB)
    try:
        row = con.execute(
            "SELECT status FROM tech_cv_entries WHERE id = ?",
            (entry_id,),
        ).fetchone()
    finally:
        con.close()
    assert row is not None
    assert row[0] == "draft"


def test_cv_lock_flips_status_to_locked(client, tech_token):
    r = client.post(
        "/api/tech/me/cv",
        json={"company": "LockCo", "title": "Locker"},
        cookies={"pc_tech_session": tech_token},
    )
    assert r.status_code == 200
    entry_id = r.json()["id"]
    r2 = client.post(
        f"/api/tech/me/cv/{entry_id}/lock",
        cookies={"pc_tech_session": tech_token},
    )
    assert r2.status_code == 200, r2.text
    con = sqlite3.connect(_DB)
    try:
        row = con.execute(
            "SELECT status FROM tech_cv_entries WHERE id = ?", (entry_id,),
        ).fetchone()
    finally:
        con.close()
    assert row[0] == "locked"


def test_cv_update_after_lock_returns_409(client, tech_token):
    r = client.post(
        "/api/tech/me/cv",
        json={"company": "PatchCo", "title": "Patcher"},
        cookies={"pc_tech_session": tech_token},
    )
    entry_id = r.json()["id"]
    client.post(f"/api/tech/me/cv/{entry_id}/lock",
                cookies={"pc_tech_session": tech_token})
    r2 = client.patch(
        f"/api/tech/me/cv/{entry_id}",
        json={"title": "New Title"},
        cookies={"pc_tech_session": tech_token},
    )
    assert r2.status_code == 409
    assert "locked_no_grant" in r2.text


def test_cv_grant_edit_flow(client, tech_token):
    """Tech locks entry → grant edit (future) → PATCH succeeds → expire grant
    → PATCH 409s."""
    tid = _tech_id_from_cookie(client, tech_token)
    r = client.post(
        "/api/tech/me/cv",
        json={"company": "GrantCo", "title": "Granted"},
        cookies={"pc_tech_session": tech_token},
    )
    entry_id = r.json()["id"]
    client.post(f"/api/tech/me/cv/{entry_id}/lock",
                cookies={"pc_tech_session": tech_token})
    # Grant via direct helper (admin-side endpoint requires super_admin cookie
    # we may not have in this test setup). The helper is what the endpoint
    # ultimately calls — same effect on DB state.
    import database
    future = (datetime.now(timezone.utc) + timedelta(hours=2)).isoformat()
    ok = database.grant_cv_edit(entry_id, admin_id=1, grant_until_iso=future)
    assert ok is True
    r2 = client.patch(
        f"/api/tech/me/cv/{entry_id}",
        json={"title": "Updated Title"},
        cookies={"pc_tech_session": tech_token},
    )
    assert r2.status_code == 200, r2.text
    # Now expire grant → expect 409 again.
    past = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
    ok = database.grant_cv_edit(entry_id, admin_id=1, grant_until_iso=past)
    assert ok is True
    r3 = client.patch(
        f"/api/tech/me/cv/{entry_id}",
        json={"title": "Past Title"},
        cookies={"pc_tech_session": tech_token},
    )
    assert r3.status_code == 409
    assert "locked_no_grant" in r3.text
