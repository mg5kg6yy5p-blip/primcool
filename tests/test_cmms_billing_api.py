"""CMMS Gap #2 — HTTP coverage for the billing-class layer + draft invoices,
plus the portal-scoping leak guard.

Self-isolating (same pattern as the other CMMS API tests): copies the live
submissions.db to a temp file and points database.DB_PATH at the copy BEFORE the
app lifespan runs init_db(), so the live DB stays pristine. Admin auth mints a
session for the first active super_admin; a customer session is minted directly
(dev PINs unknown) to exercise portal scoping.
"""
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


def _now():
    return datetime.now(timezone.utc).isoformat()


@pytest.fixture(scope="module")
def iso_client():
    if not _LIVE_DB.exists():
        pytest.skip("submissions.db not present")
    import tempfile
    tmpdir = tempfile.mkdtemp(prefix="cmms_billing_api_")
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


def _mint_session(subject_type, subject_id):
    import main
    jti = uuid.uuid4().hex
    exp = datetime.now(timezone.utc) + timedelta(hours=2)
    token = main._make_token(
        {"sub": str(subject_id), "type": subject_type, "jti": jti},
        timedelta(hours=2))
    database.create_session(
        jti=jti, subject_type=subject_type, subject_id=subject_id,
        expires_at=exp.isoformat(), ip_address="127.0.0.1", user_agent="pytest")
    return token


@pytest.fixture(scope="module")
def admin_token(iso_client):
    con = sqlite3.connect(database.DB_PATH)
    row = con.execute(
        "SELECT id FROM admin_users WHERE role='super_admin' AND active=1 "
        "ORDER BY id LIMIT 1").fetchone()
    con.close()
    if not row:
        pytest.skip("no active super_admin in DB")
    return _mint_session("admin", row[0])


def _auth(token):
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture(scope="module")
def two_customers(iso_client):
    con = sqlite3.connect(database.DB_PATH)
    a = con.execute(
        "INSERT INTO customers (customer_code, name, created_at) VALUES (?,?,?)",
        ("BILLA1", "Billing Cust A", _now())).lastrowid
    b = con.execute(
        "INSERT INTO customers (customer_code, name, created_at) VALUES (?,?,?)",
        ("BILLB1", "Billing Cust B", _now())).lastrowid
    con.commit()
    con.close()
    return a, b


def _make_completed_visit(iso_client, admin_token, customer_id):
    r = iso_client.post("/api/admin/visits",
                        json={"customer_id": customer_id, "visit_type": "CM",
                              "status": "in_progress"}, headers=_auth(admin_token))
    assert r.status_code == 200, r.text
    vid = r.json()["id"]
    r = iso_client.post(f"/api/admin/visits/{vid}/transition",
                        json={"status": "completed"}, headers=_auth(admin_token))
    assert r.status_code == 200, r.text
    return vid


# ── Admin billing-class endpoints ──────────────────────────────────────────
def test_resolve_billing_class_default_billable(iso_client, admin_token, two_customers):
    a, _ = two_customers
    vid = _make_completed_visit(iso_client, admin_token, a)
    r = iso_client.get(f"/api/admin/visits/{vid}/billing-class",
                       headers=_auth(admin_token))
    assert r.status_code == 200, r.text
    assert r.json()["billing_class"] == "billable"


def test_set_billing_class_override_goodwill(iso_client, admin_token, two_customers):
    a, _ = two_customers
    vid = _make_completed_visit(iso_client, admin_token, a)
    r = iso_client.post(f"/api/admin/visits/{vid}/billing-class",
                        json={"billing_class": "goodwill", "reason": "VIP"},
                        headers=_auth(admin_token))
    assert r.status_code == 200, r.text
    assert r.json()["billing_class"] == "goodwill"
    # resolution now reflects the override
    r2 = iso_client.get(f"/api/admin/visits/{vid}/billing-class",
                        headers=_auth(admin_token))
    assert r2.json()["source"] == "override"


def test_set_billing_class_rejects_unknown_422(iso_client, admin_token, two_customers):
    a, _ = two_customers
    vid = _make_completed_visit(iso_client, admin_token, a)
    r = iso_client.post(f"/api/admin/visits/{vid}/billing-class",
                        json={"billing_class": "freebie"},
                        headers=_auth(admin_token))
    assert r.status_code == 422, r.text


def test_billing_class_404_missing_visit(iso_client, admin_token):
    r = iso_client.get("/api/admin/visits/99999999/billing-class",
                       headers=_auth(admin_token))
    assert r.status_code == 404


# ── Draft invoice generation ────────────────────────────────────────────────
def test_preview_then_generate_draft_invoice(iso_client, admin_token, two_customers):
    a, _ = two_customers
    vid = _make_completed_visit(iso_client, admin_token, a)
    # add a part so there's something to bill (seed via the DB helper — there is
    # no admin HTTP route for visit-parts; parts are added by techs in-field)
    pid = database.create_part({"sku": "BILLPART1", "name": "Cap",
                                "unit_cost": 50.0, "quantity": 20.0})
    database.add_visit_part(vid, pid, 2.0)

    # preview (no write)
    prev = iso_client.get(f"/api/admin/visits/{vid}/draft-invoice?tax_rate=0.15",
                          headers=_auth(admin_token))
    assert prev.status_code == 200, prev.text
    assert prev.json()["billing_class"] == "billable"
    assert prev.json()["gross_before_class"] == 100.0

    # generate (writes a draft invoice)
    gen = iso_client.post(f"/api/admin/visits/{vid}/draft-invoice",
                          json={"tax_rate": 0.15}, headers=_auth(admin_token))
    assert gen.status_code == 200, gen.text
    body = gen.json()
    assert body["billing_class"] == "billable"
    assert body["subtotal"] == 100.0
    assert body["tax_amount"] == 15.0
    assert body["total"] == 115.0
    assert body["invoice_id"]


# ── Auth: admin billing routes are NOT reachable without admin auth ─────────
def test_billing_routes_require_admin(iso_client, admin_token, two_customers):
    a, _ = two_customers
    vid = _make_completed_visit(iso_client, admin_token, a)
    # Valid bodies so request validation passes and the route's auth check is
    # what rejects us (not a 422). No Authorization header → unauthorized.
    cases = (
        ("get", f"/api/admin/visits/{vid}/billing-class", None),
        ("post", f"/api/admin/visits/{vid}/billing-class", {"billing_class": "billable"}),
        ("get", f"/api/admin/visits/{vid}/draft-invoice", None),
        ("post", f"/api/admin/visits/{vid}/draft-invoice", {"tax_rate": 0.0}),
    )
    for method, url, body in cases:
        fn = getattr(iso_client, method)
        r = fn(url, json=body) if body is not None else fn(url)
        assert r.status_code in (401, 403), f"{method} {url} -> {r.status_code}"


# ── Portal scoping leak guard ────────────────────────────────────────────────
def test_portal_cannot_see_other_customers_or_drafts(iso_client, admin_token, two_customers):
    a, b = two_customers
    # Generate a draft invoice for customer A from a completed visit.
    vid = _make_completed_visit(iso_client, admin_token, a)
    gen = iso_client.post(f"/api/admin/visits/{vid}/draft-invoice",
                          json={"tax_rate": 0.0}, headers=_auth(admin_token))
    assert gen.status_code == 200, gen.text
    a_draft_id = gen.json()["invoice_id"]

    # Customer B logs in (cookie session) and must NOT see A's invoice.
    b_token = _mint_session("customer", b)
    iso_client.cookies.set("pc_customer_session", b_token)
    try:
        lst = iso_client.get("/api/portal/invoices")
        assert lst.status_code == 200, lst.text
        ids = {inv["id"] for inv in lst.json()}
        assert a_draft_id not in ids, "customer B saw customer A's invoice"

        # Direct fetch of A's invoice as B → indistinguishable 404.
        det = iso_client.get(f"/api/portal/invoices/{a_draft_id}")
        assert det.status_code == 404
    finally:
        iso_client.cookies.delete("pc_customer_session")

    # Even customer A (the owner) cannot see it while it's a DRAFT.
    a_token = _mint_session("customer", a)
    iso_client.cookies.set("pc_customer_session", a_token)
    try:
        det = iso_client.get(f"/api/portal/invoices/{a_draft_id}")
        assert det.status_code == 404, "draft invoice leaked to owning customer"
    finally:
        iso_client.cookies.delete("pc_customer_session")
