"""CMMS Gap #2 — billing-class resolution + draft-invoice-from-confirmations.

Phase-5 gate: every order (visit) resolves to ONE billing class that decides
who pays — warranty / contract / billable / goodwill — and a draft invoice
generated from the visit's confirmed work prices BILLABLE lines normally while
documenting covered (warranty/contract/goodwill) lines at zero. Runs against a
FRESH isolated SQLite DB.

Resolution precedence (highest first):
    1. manual override  (the only path to 'goodwill')
    2. warranty   — equipment under manufacturer warranty at the visit date
    3. contract   — active PM contract within yearly entitlement (overage → billable)
    4. billable   — the customer pays (default)
"""
from datetime import datetime, timezone

import pytest

import database


@pytest.fixture
def db(tmp_path, monkeypatch):
    db_file = tmp_path / "cmms_billing_test.db"
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
        ("BCLC%04d" % _SEQ[0], "Billing Cust", _now()),
    )
    cid = cur.lastrowid
    con.commit()
    con.close()
    return cid


def _seed_contract(db, customer_id, *, included=0, start="2026-01-01",
                   end="2026-12-31", status="active"):
    _SEQ[0] += 1
    con = db._con()
    cur = con.execute(
        "INSERT INTO pm_contracts (contract_code, customer_id, start_date, "
        "end_date, frequency, status, included_pm_visits_per_year, created_at) "
        "VALUES (?,?,?,?,?,?,?,?)",
        ("BCT%04d" % _SEQ[0], customer_id, start, end, "quarterly", status,
         included, _now()),
    )
    ct = cur.lastrowid
    con.commit()
    con.close()
    return ct


def _completed_visit(db, customer_id, **extra):
    data = {"customer_id": customer_id, "visit_type": extra.pop("visit_type", "CM"),
            "status": "in_progress"}
    data.update(extra)
    vid = db.create_visit(data)
    db.transition_visit(vid, "completed", actor_kind="admin", actor_id=1)
    return vid


# ── Scenario 1: BILLABLE (no warranty, no contract) ────────────────────────
def test_billable_default(db):
    cid = _seed_customer(db)
    eq = db.create_equipment({"customer_id": cid, "name": "AC", "type": "split",
                              "warranty_months": 0})
    vid = _completed_visit(db, cid, equipment_id=eq)
    r = db.resolve_billing_class(vid)
    assert r["billing_class"] == "billable"
    assert r["source"] == "default"
    assert r["overridden"] is False


# ── Scenario 2: WARRANTY (equipment under manufacturer warranty) ───────────
def test_warranty_when_under_manufacturer_warranty(db):
    cid = _seed_customer(db)
    # Equipment created now with a 24-month warranty → expiry is in the future.
    eq = db.create_equipment({"customer_id": cid, "name": "AC", "type": "split",
                              "warranty_months": 24})
    vid = _completed_visit(db, cid, equipment_id=eq)
    r = db.resolve_billing_class(vid)
    assert r["billing_class"] == "warranty"
    assert r["source"] == "warranty"
    assert r["warranty_expiry"] is not None


def test_warranty_lapsed_falls_back_to_billable(db):
    cid = _seed_customer(db)
    eq = db.create_equipment({"customer_id": cid, "name": "AC", "type": "split",
                              "warranty_months": 12})
    # Backdate equipment created_at so warranty (12 mo) has already lapsed.
    con = db._con()
    con.execute("UPDATE equipment SET created_at=? WHERE id=?",
                ("2020-01-01T00:00:00+00:00", eq))
    con.commit()
    con.close()
    vid = _completed_visit(db, cid, equipment_id=eq)
    r = db.resolve_billing_class(vid)
    assert r["billing_class"] == "billable"


# ── Scenario 3: CONTRACT (active contract within entitlement) ──────────────
def test_contract_unlimited_entitlement(db):
    cid = _seed_customer(db)
    ct = _seed_contract(db, cid, included=0)  # 0 = unlimited
    vid = _completed_visit(db, cid, visit_type="PM", pm_contract_id=ct,
                           scheduled_date="2026-03-15")
    r = db.resolve_billing_class(vid)
    assert r["billing_class"] == "contract"
    assert r["source"] == "contract"
    assert r["contract_id"] == ct


def test_contract_overage_past_entitlement_is_billable(db):
    cid = _seed_customer(db)
    ct = _seed_contract(db, cid, included=2)  # only 2 included per year
    visits = []
    for i in range(3):
        v = _completed_visit(db, cid, visit_type="PM", pm_contract_id=ct,
                             scheduled_date="2026-0%d-15" % (i + 2))
        visits.append(v)
    classes = [db.resolve_billing_class(v)["billing_class"] for v in visits]
    assert classes == ["contract", "contract", "billable"]
    # The 3rd is overage, explicitly flagged in the reason.
    assert "exhausted" in db.resolve_billing_class(visits[2])["reason"].lower()


def test_contract_inactive_does_not_cover(db):
    cid = _seed_customer(db)
    ct = _seed_contract(db, cid, included=0, status="expired")
    vid = _completed_visit(db, cid, visit_type="PM", pm_contract_id=ct,
                           scheduled_date="2026-03-15")
    r = db.resolve_billing_class(vid)
    assert r["billing_class"] == "billable"


# ── Scenario 4: GOODWILL (manual override) ─────────────────────────────────
def test_goodwill_via_override(db):
    cid = _seed_customer(db)
    vid = _completed_visit(db, cid)
    db.set_visit_billing_class(vid, "goodwill", reason="customer relations",
                               actor_kind="admin", actor_id=1)
    r = db.resolve_billing_class(vid)
    assert r["billing_class"] == "goodwill"
    assert r["source"] == "override"
    assert r["overridden"] is True


def test_override_beats_warranty(db):
    cid = _seed_customer(db)
    eq = db.create_equipment({"customer_id": cid, "name": "AC", "type": "split",
                              "warranty_months": 24})
    vid = _completed_visit(db, cid, equipment_id=eq)
    assert db.resolve_billing_class(vid)["billing_class"] == "warranty"
    db.set_visit_billing_class(vid, "billable", reason="warranty void — abuse",
                               actor_kind="admin", actor_id=1)
    assert db.resolve_billing_class(vid)["billing_class"] == "billable"


def test_set_billing_class_rejects_unknown(db):
    cid = _seed_customer(db)
    vid = _completed_visit(db, cid)
    with pytest.raises(ValueError):
        db.set_visit_billing_class(vid, "free_lunch", actor_kind="admin", actor_id=1)


# ── Draft invoice from confirmations ────────────────────────────────────────
def _seed_part(db, qty=20.0, cost=50.0):
    _SEQ[0] += 1
    return db.create_part({"sku": "BCP%04d" % _SEQ[0], "name": "Capacitor",
                           "unit_cost": cost, "quantity": qty})


def test_draft_invoice_billable_prices_lines(db):
    cid = _seed_customer(db)
    eq = db.create_equipment({"customer_id": cid, "name": "AC", "type": "split",
                              "warranty_months": 0})
    vid = _completed_visit(db, cid, equipment_id=eq)
    pid = _seed_part(db)
    db.add_visit_part(vid, pid, 2.0)
    draft = db.build_draft_invoice_from_visit(vid)
    assert draft["billing_class"] == "billable"
    assert draft["chargeable"] is True
    part_lines = [l for l in draft["line_items"] if l["line_type"] == "part"]
    assert part_lines and part_lines[0]["unit_price"] == 50.0
    assert draft["gross_before_class"] == 100.0


def test_draft_invoice_warranty_zeroes_lines(db):
    cid = _seed_customer(db)
    eq = db.create_equipment({"customer_id": cid, "name": "AC", "type": "split",
                              "warranty_months": 24})
    vid = _completed_visit(db, cid, equipment_id=eq)
    pid = _seed_part(db)
    db.add_visit_part(vid, pid, 2.0)
    draft = db.build_draft_invoice_from_visit(vid)
    assert draft["billing_class"] == "warranty"
    assert draft["chargeable"] is False
    for l in draft["line_items"]:
        assert l["unit_price"] == 0.0
        assert "covered (warranty)" in l["description"]
    # gross (pre-class) still records what it WOULD have cost
    assert draft["gross_before_class"] == 100.0


def test_generate_draft_invoice_creates_zero_total_for_warranty(db):
    cid = _seed_customer(db)
    eq = db.create_equipment({"customer_id": cid, "name": "AC", "type": "split",
                              "warranty_months": 24})
    vid = _completed_visit(db, cid, equipment_id=eq)
    pid = _seed_part(db)
    db.add_visit_part(vid, pid, 2.0)
    res = db.generate_draft_invoice_for_visit(vid, created_by=None)
    assert res["billing_class"] == "warranty"
    assert res["total"] == 0.0
    assert res["gross_before_class"] == 100.0
    inv = db.get_invoice_by_id(res["invoice_id"])
    assert inv["status"] == "draft"
    assert inv["visit_id"] == vid
    # the resolved class is cached onto the visit (non-override)
    v = db.get_visit_by_id(vid)
    assert v["billing_class"] == "warranty"
    assert (v["billing_class_overridden"] or 0) == 0


def test_generate_draft_invoice_billable_with_gct(db):
    cid = _seed_customer(db)
    eq = db.create_equipment({"customer_id": cid, "name": "AC", "type": "split",
                              "warranty_months": 0})
    vid = _completed_visit(db, cid, equipment_id=eq)
    pid = _seed_part(db)
    db.add_visit_part(vid, pid, 2.0)
    res = db.generate_draft_invoice_for_visit(vid, tax_rate=0.15, created_by=None)
    assert res["billing_class"] == "billable"
    assert res["subtotal"] == 100.0
    assert res["tax_amount"] == 15.0       # single GCT % line
    assert res["total"] == 115.0


def test_generate_does_not_overwrite_manual_override(db):
    cid = _seed_customer(db)
    eq = db.create_equipment({"customer_id": cid, "name": "AC", "type": "split",
                              "warranty_months": 24})
    vid = _completed_visit(db, cid, equipment_id=eq)
    # Manager overrides to goodwill BEFORE generating.
    db.set_visit_billing_class(vid, "goodwill", reason="VIP",
                               actor_kind="admin", actor_id=1)
    res = db.generate_draft_invoice_for_visit(vid, created_by=None)
    assert res["billing_class"] == "goodwill"
    v = db.get_visit_by_id(vid)
    assert v["billing_class"] == "goodwill"
    assert v["billing_class_overridden"] == 1   # override preserved


# ── Entitlement accounting helper ───────────────────────────────────────────
def test_entitlement_window_and_count(db):
    cid = _seed_customer(db)
    ct = _seed_contract(db, cid, included=2, start="2026-01-01")
    for i in range(2):
        _completed_visit(db, cid, visit_type="PM", pm_contract_id=ct,
                         scheduled_date="2026-0%d-10" % (i + 3))
    ent = db.count_contract_visits_in_year(ct, "2026-06-19")
    assert ent["window_start"] == "2026-01-01"
    assert ent["window_end"] == "2027-01-01"
    assert ent["included"] == 2
    assert ent["used"] == 2
    assert ent["exhausted"] is False


def test_entitlement_counts_per_contract_year(db):
    cid = _seed_customer(db)
    ct = _seed_contract(db, cid, included=1, start="2026-01-01",
                        end="2027-12-31")
    # one in 2026, one in 2027 → each its own window, neither exhausted
    _completed_visit(db, cid, visit_type="PM", pm_contract_id=ct,
                     scheduled_date="2026-05-10")
    _completed_visit(db, cid, visit_type="PM", pm_contract_id=ct,
                     scheduled_date="2027-05-10")
    ent_2026 = db.count_contract_visits_in_year(ct, "2026-06-19")
    ent_2027 = db.count_contract_visits_in_year(ct, "2027-06-19")
    assert ent_2026["used"] == 1 and ent_2026["window_start"] == "2026-01-01"
    assert ent_2027["used"] == 1 and ent_2027["window_start"] == "2027-01-01"
