"""CMMS #4 — audit-trail depth: field-level old→new diffs, the captured "why"
(reason), and the per-entity history timeline.

Self-isolating like the other CMMS API tests: copy the live submissions.db to a
temp file and point database.DB_PATH at the copy BEFORE the app lifespan runs
init_db(), so the live DB stays pristine.

What this verifies:
  * editing a work order records a `changed_fields` diff with only the touched
    field(s) — NOT every column on the full record snapshot;
  * the diff carries old AND new values in a {field, old, new} shape;
  * a free-text justification supplied via the X-Change-Reason request header is
    captured on the audit row and surfaced by the history endpoint;
  * PII-bearing fields (e.g. notes) are redacted inside the diff;
  * the tamper-evident hash chain still verifies after the new columns exist
    (reason/changed_fields are stored OFF the hashed payload by design).
"""
import itertools
import os
import shutil
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

import database

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_LIVE_DB = _PROJECT_ROOT / "submissions.db"
_CUST = itertools.count(1)


def _now():
    return datetime.now(timezone.utc).isoformat()


@pytest.fixture(scope="module")
def iso_client():
    if not _LIVE_DB.exists():
        pytest.skip("submissions.db not present")
    import tempfile
    tmpdir = tempfile.mkdtemp(prefix="cmms_audit_diff_")
    tmp_db = os.path.join(tmpdir, "submissions.db")
    shutil.copy(str(_LIVE_DB), tmp_db)
    for suffix in ("-wal", "-shm"):
        side = str(_LIVE_DB) + suffix
        if os.path.exists(side):
            shutil.copy(side, tmp_db + suffix)
    orig = database.DB_PATH
    database.DB_PATH = tmp_db
    os.chdir(str(_PROJECT_ROOT))
    from fastapi.testclient import TestClient
    import main
    try:
        with TestClient(main.app, headers={"Origin": "http://testserver"}) as c:
            yield c
    finally:
        database.DB_PATH = orig
        for suffix in ("", "-wal", "-shm"):
            try:
                os.remove(tmp_db + suffix)
            except OSError:
                pass


def _mint_token(admin_id):
    import main
    jti = uuid.uuid4().hex
    exp = datetime.now(timezone.utc) + timedelta(hours=2)
    token = main._make_token(
        {"sub": str(admin_id), "type": "admin", "jti": jti}, timedelta(hours=2))
    database.create_session(
        jti=jti, subject_type="admin", subject_id=admin_id,
        expires_at=exp.isoformat(), ip_address="127.0.0.1", user_agent="pytest")
    return token


@pytest.fixture(scope="module")
def super_admin_id(iso_client):
    con = sqlite3.connect(database.DB_PATH)
    row = con.execute(
        "SELECT id FROM admin_users WHERE role='super_admin' AND active=1 "
        "ORDER BY id LIMIT 1").fetchone()
    con.close()
    if not row:
        pytest.skip("no active super_admin in DB")
    return row[0]


@pytest.fixture(scope="module")
def admin_client(iso_client, super_admin_id):
    iso_client.headers.update({"Authorization": f"Bearer {_mint_token(super_admin_id)}"})
    return iso_client


@pytest.fixture(scope="module")
def customer_id(iso_client):
    con = sqlite3.connect(database.DB_PATH)
    cur = con.execute(
        "INSERT INTO customers (customer_code, name, created_at) VALUES (?,?,?)",
        (f"AUDC{next(_CUST)}", "Audit Diff Customer", _now()))
    cid = cur.lastrowid
    con.commit()
    con.close()
    return cid


def _new_visit(customer_id, scope="orig scope"):
    """Create a CM work order with known field values directly in the DB."""
    con = sqlite3.connect(database.DB_PATH)
    cur = con.execute(
        "INSERT INTO maintenance_visits "
        "(customer_id, visit_type, status, scope_of_work, created_at) "
        "VALUES (?,?,?,?,?)",
        (customer_id, "CM", "scheduled", scope, _now()))
    vid = cur.lastrowid
    con.commit()
    con.close()
    return vid


def _update_body(**overrides):
    """A complete VisitUpdate body that mirrors the WO edit modal (all fields
    sent), so the audit diff isn't polluted by Optional-None defaults."""
    body = {
        "visit_type": "CM",
        "status": "scheduled",
        "scheduled_date": "",
        "scheduled_time": "",
        "completed_date": "",
        "technician": "",
        "work_done": "",
        "parts_replaced": "",
        "notes": "",
        "scope_of_work": "orig scope",
        "contact_person_name": "",
        "contact_person_phone": "",
        "hazards": "",
        "access_codes": "",
    }
    body.update(overrides)
    return body


def _history(admin_client, target_type, target_id):
    r = admin_client.get(f"/api/admin/history/{target_type}/{target_id}?limit=200")
    assert r.status_code == 200, r.text
    return r.json()


def _latest_mutation(rows, action=None):
    for r in rows:
        if r.get("event_kind") == "mutation" and (action is None or r.get("action") == action):
            return r
    return None


# ── Tests ────────────────────────────────────────────────────────────────────

def test_changed_fields_records_only_touched_field(admin_client, customer_id):
    vid = _new_visit(customer_id, scope="before edit")
    body = _update_body(scope_of_work="after edit")
    r = admin_client.put(f"/api/admin/visits/{vid}", json=body)
    assert r.status_code == 200, r.text

    rows = _history(admin_client, "visit", vid)
    mut = _latest_mutation(rows, "visit.update")
    assert mut is not None, "expected a visit.update mutation in history"
    cf = mut.get("changed_fields")
    assert isinstance(cf, list) and cf, f"changed_fields should be a non-empty list, got {cf!r}"
    fields = {c["field"] for c in cf}
    assert "scope_of_work" in fields
    # The full record has dozens of columns; the diff must NOT list untouched
    # ones like visit_type/status that were sent unchanged.
    assert "visit_type" not in fields
    assert "status" not in fields
    change = next(c for c in cf if c["field"] == "scope_of_work")
    assert change["old"] == "before edit"
    assert change["new"] == "after edit"


def test_no_diff_when_nothing_changes(admin_client, customer_id):
    vid = _new_visit(customer_id, scope="steady")
    body = _update_body(scope_of_work="steady")
    r = admin_client.put(f"/api/admin/visits/{vid}", json=body)
    assert r.status_code == 200, r.text
    rows = _history(admin_client, "visit", vid)
    mut = _latest_mutation(rows, "visit.update")
    assert mut is not None
    # An edit that changed nothing substantive carries a null diff.
    assert mut.get("changed_fields") in (None, [])


def test_change_reason_header_captured(admin_client, customer_id):
    vid = _new_visit(customer_id, scope="reasoned-before")
    reason = "Customer rescheduled per call " + uuid.uuid4().hex[:8]
    body = _update_body(scope_of_work="reasoned-after")
    r = admin_client.put(f"/api/admin/visits/{vid}", json=body,
                         headers={"X-Change-Reason": reason})
    assert r.status_code == 200, r.text

    rows = _history(admin_client, "visit", vid)
    mut = _latest_mutation(rows, "visit.update")
    assert mut is not None
    assert mut.get("reason") == reason


def test_no_reason_when_header_absent(admin_client, customer_id):
    vid = _new_visit(customer_id, scope="quiet-before")
    body = _update_body(scope_of_work="quiet-after")
    r = admin_client.put(f"/api/admin/visits/{vid}", json=body)
    assert r.status_code == 200, r.text
    rows = _history(admin_client, "visit", vid)
    mut = _latest_mutation(rows, "visit.update")
    assert mut is not None
    assert mut.get("reason") in (None, "")


def test_pii_redacted_inside_diff(admin_client, customer_id):
    vid = _new_visit(customer_id, scope="pii-scope")
    secret = "868-555-" + uuid.uuid4().hex[:4]
    body = _update_body(notes=secret)  # notes is a PII-bearing column
    r = admin_client.put(f"/api/admin/visits/{vid}", json=body)
    assert r.status_code == 200, r.text

    rows = _history(admin_client, "visit", vid)
    mut = _latest_mutation(rows, "visit.update")
    assert mut is not None
    cf = mut.get("changed_fields") or []
    notes_change = next((c for c in cf if c["field"] == "notes"), None)
    assert notes_change is not None, f"notes change missing; diff={cf!r}"
    # The raw secret must never appear; it should be redacted.
    assert notes_change["new"] == "[redacted]"
    assert secret not in (notes_change.get("new") or "")
    # Belt-and-braces: the secret is nowhere in the serialized diff.
    import json as _json
    assert secret not in _json.dumps(cf)


def test_audit_chain_still_verifies(admin_client, customer_id):
    # Generate some audited mutations first.
    vid = _new_visit(customer_id, scope="chain-before")
    admin_client.put(f"/api/admin/visits/{vid}",
                     json=_update_body(scope_of_work="chain-after"),
                     headers={"X-Change-Reason": "verifying chain integrity"})
    result = database.verify_audit_chain()
    assert result["ok"] is True, f"audit chain broken: {result!r}"
