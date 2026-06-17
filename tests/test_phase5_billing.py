"""Phase 5 gate (billing): four billing-class scenarios produce correct draft
lines; entitlement decrements; reversed confirmations excluded;
draft regeneratable until issued."""
from datetime import date, timedelta


def _customer(client, name="Acme", gct=0.0):
    c = client.post("/api/v1/customers",
                    json={"name": name, "type": "commercial"}).json()
    if gct > 0:
        client.patch(f"/api/v1/customers/{c['id']}", json={"gct_rate": gct})
    return c


def _site(client, cust_id, name="Site"):
    return client.post("/api/v1/sites",
                       json={"customer_account_id": cust_id, "name": name}).json()


def _eq(client, *, warranty=None, serial=None):
    return client.post("/api/v1/equipment", json={
        "equipment_class": "package_unit", "serial": serial,
        "warranty_months": warranty,
    }).json()


def _fl(client, site_id):
    return client.post("/api/v1/functional-locations", json={
        "site_id": site_id, "name": "FL", "fl_class": "package_unit",
    }).json()


def _order(client, cust_id, site_id, *, equipment_id=None, order_type="corrective",
           billing_class="billable", pm_schedule_id=None):
    body = {
        "customer_account_id": cust_id, "site_id": site_id,
        "order_type": order_type, "priority": "medium", "title": "WO",
        "billing_class": billing_class,
    }
    if equipment_id: body["equipment_id"] = equipment_id
    return client.post("/api/v1/work-orders", json=body).json()


def _drive_to_tech_complete(client, order, op_hours=2.0):
    op = client.post(f"/api/v1/work-orders/{order['id']}/operations",
                     json={"description": "Work", "planned_hours": op_hours}).json()
    client.post(f"/api/v1/work-orders/{order['id']}/transition", json={"target": "scheduled"})
    client.post(f"/api/v1/work-orders/{order['id']}/transition",
                json={"target": "in_progress"})
    return op


# --- 1: billable ---
def test_billable_charges_labor_and_marked_up_parts(client):
    cust = _customer(client); site = _site(client, cust["id"])
    order = _order(client, cust["id"], site["id"], billing_class="billable")
    op = _drive_to_tech_complete(client, order)

    # Add a part and consume some.
    mat = client.post("/api/v1/materials", json={
        "part_number": "FILTER-A", "unit_cost": 1000,
    }).json()
    loc = client.post("/api/v1/stock-locations", json={"name": "Van"}).json()
    client.put("/api/v1/stock", json={
        "material_id": mat["id"], "stock_location_id": loc["id"], "qty": 10,
    })

    client.post(f"/api/v1/operations/{op['id']}/confirm", json={
        "actual_hours": 1.5, "is_final": True,
        "parts": [{"material_id": mat["id"], "stock_location_id": loc["id"], "qty_used": 2}],
    })

    r = client.post(f"/api/v1/work-orders/{order['id']}/invoice-draft")
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["billing_class"] == "billable"
    # Labor: 1.5h × 3000 JMD/h (technician rate from the seeded admin user
    # who confirmed in tests is admin = 5000/h).
    labor = next(line for line in body["lines"] if line["kind"] == "labor")
    assert labor["unit_amount"] == 5000  # admin rate from seed (test admin)
    assert labor["total"] == 7500
    # Parts: qty 2 × unit_cost_at_use 1000 × markup 1.5 = 3000
    part = next(line for line in body["lines"] if line["kind"] == "part")
    assert part["unit_amount"] == 1500
    assert part["total"] == 3000
    assert body["subtotal"] == 7500 + 3000
    assert body["total"] == body["subtotal"]


# --- 2: warranty ---
def test_warranty_zero_charge(client):
    cust = _customer(client); site = _site(client, cust["id"])
    fl = _fl(client, site["id"])
    eq = _eq(client, warranty=12, serial="UNDER-WARRANTY")
    # Install at "today" so warranty is active.
    client.post(f"/api/v1/equipment/{eq['id']}/install", json={"fl_id": fl["id"]})

    order = _order(client, cust["id"], site["id"], equipment_id=eq["id"],
                   billing_class="billable")  # billable on the order;
                                              # engine overrides to warranty
    op = _drive_to_tech_complete(client, order)
    client.post(f"/api/v1/operations/{op['id']}/confirm",
                json={"actual_hours": 2, "is_final": True})

    r = client.post(f"/api/v1/work-orders/{order['id']}/invoice-draft").json()
    assert r["billing_class"] == "warranty"
    assert r["subtotal"] == 0
    labor = next(line for line in r["lines"] if line["kind"] == "labor")
    assert labor["unit_amount"] == 0
    assert labor["qty"] == 2  # qty preserved so the customer sees what was done


# --- 3: contract (PM under active contract, entitlement remaining) ---
def test_contract_zero_charge_and_entitlement_decrement(client):
    cust = _customer(client); site = _site(client, cust["id"])
    today = date.today()
    contract = client.post("/api/v1/contracts", json={
        "customer_account_id": cust["id"], "name": "Annual",
        "starts_on": (today - timedelta(days=30)).isoformat(),
        "ends_on": (today + timedelta(days=365)).isoformat(),
        "included_pm_visits_per_year": 4,
        "site_ids": [site["id"]],
    }).json()
    assert contract["used_this_year"] == 0

    # PM schedule linked to that contract.
    sched = client.post("/api/v1/pm-schedules", json={
        "customer_account_id": cust["id"], "site_id": site["id"],
        "name": "Q PM", "order_title": "Quarterly",
        "trigger_kind": "calendar", "interval_days": 90,
        "start_at": (today - timedelta(days=100)).isoformat() + "T00:00:00+00:00",
        "billing_class": "billable", "priority": "medium",
        "service_contract_id": contract["id"],
    }).json()
    order_id = client.post("/api/v1/pm-schedules/scan").json()[
        "generated_work_order_ids"][0]
    order = client.get(f"/api/v1/work-orders/{order_id}").json()

    op = _drive_to_tech_complete(client, order)
    client.post(f"/api/v1/operations/{op['id']}/confirm",
                json={"actual_hours": 2, "is_final": True})

    draft = client.post(f"/api/v1/work-orders/{order_id}/invoice-draft").json()
    assert draft["billing_class"] == "contract"
    assert draft["subtotal"] == 0

    # Entitlement counter reflects the contract usage.
    refreshed = client.get(f"/api/v1/contracts/{contract['id']}").json()
    assert refreshed["used_this_year"] == 1
    assert sched  # silence


# --- 4: goodwill ---
def test_goodwill_zero_charge_with_flag(client):
    cust = _customer(client); site = _site(client, cust["id"])
    order = _order(client, cust["id"], site["id"], billing_class="goodwill")
    op = _drive_to_tech_complete(client, order)
    client.post(f"/api/v1/operations/{op['id']}/confirm",
                json={"actual_hours": 1, "is_final": True})

    r = client.post(f"/api/v1/work-orders/{order['id']}/invoice-draft").json()
    assert r["billing_class"] == "goodwill"
    assert r["subtotal"] == 0


# --- regeneration ---
def test_regenerate_voids_old_draft_and_makes_new(client):
    cust = _customer(client); site = _site(client, cust["id"])
    order = _order(client, cust["id"], site["id"])
    op = _drive_to_tech_complete(client, order)
    client.post(f"/api/v1/operations/{op['id']}/confirm",
                json={"actual_hours": 1, "is_final": True})

    first = client.post(f"/api/v1/work-orders/{order['id']}/invoice-draft").json()
    second = client.post(f"/api/v1/work-orders/{order['id']}/invoice-draft").json()
    assert second["id"] != first["id"]
    # Active draft endpoint returns the second one.
    active = client.get(f"/api/v1/work-orders/{order['id']}/invoice-draft").json()
    assert active["id"] == second["id"]


def test_issued_invoice_not_regeneratable(client):
    cust = _customer(client); site = _site(client, cust["id"])
    order = _order(client, cust["id"], site["id"])
    op = _drive_to_tech_complete(client, order)
    client.post(f"/api/v1/operations/{op['id']}/confirm",
                json={"actual_hours": 1, "is_final": True})

    draft = client.post(f"/api/v1/work-orders/{order['id']}/invoice-draft").json()
    issued = client.post(f"/api/v1/invoices/{draft['id']}/issue").json()
    assert issued["status"] == "issued"
    # New draft sits alongside the issued one.
    new = client.post(f"/api/v1/work-orders/{order['id']}/invoice-draft").json()
    assert new["id"] != draft["id"]
    # Re-issuing an already-issued one is 409.
    assert client.post(f"/api/v1/invoices/{draft['id']}/issue").status_code == 409


# --- reversed confirmations excluded ---
def test_reversed_confirmations_excluded_from_draft(client):
    cust = _customer(client); site = _site(client, cust["id"])
    order = _order(client, cust["id"], site["id"])
    op = _drive_to_tech_complete(client, order)

    cnf = client.post(f"/api/v1/operations/{op['id']}/confirm",
                      json={"actual_hours": 1, "is_final": False}).json()
    client.post(f"/api/v1/confirmations/{cnf['id']}/reverse",
                json={"reason": "wrong"})
    # Now do the real confirmation.
    client.post(f"/api/v1/operations/{op['id']}/confirm",
                json={"actual_hours": 2, "is_final": True})

    draft = client.post(f"/api/v1/work-orders/{order['id']}/invoice-draft").json()
    # Only ONE labor line — the reversed pair is excluded.
    labor_lines = [line for line in draft["lines"] if line["kind"] == "labor"]
    assert len(labor_lines) == 1
    assert labor_lines[0]["qty"] == 2


# --- can't generate against an order that isn't tech_complete/closed ---
def test_cannot_generate_for_in_progress(client):
    cust = _customer(client); site = _site(client, cust["id"])
    order = _order(client, cust["id"], site["id"])
    client.post(f"/api/v1/work-orders/{order['id']}/transition", json={"target": "scheduled"})
    client.post(f"/api/v1/work-orders/{order['id']}/transition",
                json={"target": "in_progress"})
    r = client.post(f"/api/v1/work-orders/{order['id']}/invoice-draft")
    assert r.status_code == 409


# --- GCT line appears when configured ---
def test_gct_line_added_when_customer_has_rate(client):
    cust = _customer(client, gct=10.0); site = _site(client, cust["id"])
    order = _order(client, cust["id"], site["id"])
    op = _drive_to_tech_complete(client, order)
    client.post(f"/api/v1/operations/{op['id']}/confirm",
                json={"actual_hours": 1, "is_final": True})

    draft = client.post(f"/api/v1/work-orders/{order['id']}/invoice-draft").json()
    tax_lines = [line for line in draft["lines"] if line["kind"] == "tax"]
    assert len(tax_lines) == 1
    assert draft["gct_rate"] == 10.0
    assert draft["gct_amount"] == round(draft["subtotal"] * 0.1, 2)
    assert draft["total"] == draft["subtotal"] + draft["gct_amount"]


# --- BOM where-used reverse query ---
def test_bom_where_used(client):
    cust = _customer(client); site = _site(client, cust["id"])
    fl = _fl(client, site["id"])
    eq = _eq(client, serial="EQ1")
    client.post(f"/api/v1/equipment/{eq['id']}/install", json={"fl_id": fl["id"]})
    mat = client.post("/api/v1/materials",
                      json={"part_number": "F-100", "unit_cost": 100}).json()

    client.put(f"/api/v1/equipment/{eq['id']}/bom", json={
        "items": [{"material_id": mat["id"], "quantity": 2}],
    })
    rows = client.get(f"/api/v1/materials/{mat['id']}/where-used").json()
    assert len(rows) == 1
    assert rows[0]["equipment_id"] == eq["id"]
    assert rows[0]["qty"] == 2


# --- audit on draft creation ---
def test_audit_on_invoice_draft(client):
    cust = _customer(client); site = _site(client, cust["id"])
    order = _order(client, cust["id"], site["id"])
    op = _drive_to_tech_complete(client, order)
    client.post(f"/api/v1/operations/{op['id']}/confirm",
                json={"actual_hours": 1, "is_final": True})
    draft = client.post(f"/api/v1/work-orders/{order['id']}/invoice-draft").json()
    rows = client.get(
        f"/api/v1/audit?entity_type=invoice_draft&entity_id={draft['id']}"
    ).json()
    assert any(r["action"] == "create" for r in rows)
