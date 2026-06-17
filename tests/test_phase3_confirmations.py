"""Phase 3 gate: confirm + reverse + parts + stock + auto-tech_complete +
append-only proof + reversal exclusion."""


def _setup(client):
    cust = client.post("/api/v1/customers",
                       json={"name": "Acme", "type": "commercial"}).json()
    site = client.post("/api/v1/sites",
                       json={"customer_account_id": cust["id"], "name": "S"}).json()
    order = client.post("/api/v1/work-orders", json={
        "customer_account_id": cust["id"], "site_id": site["id"],
        "order_type": "corrective", "priority": "medium", "title": "Job",
    }).json()
    client.post(f"/api/v1/work-orders/{order['id']}/transition", json={"target": "scheduled"})
    client.post(f"/api/v1/work-orders/{order['id']}/transition",
                json={"target": "in_progress"})
    op1 = client.post(f"/api/v1/work-orders/{order['id']}/operations",
                      json={"description": "Recharge", "planned_hours": 2}).json()
    op2 = client.post(f"/api/v1/work-orders/{order['id']}/operations",
                      json={"description": "Clean coils", "planned_hours": 1,
                            "sequence": 20}).json()
    return order, op1, op2


def _material(client, part="P-1", cost=10.0):
    return client.post("/api/v1/materials", json={
        "part_number": part, "description": part, "unit_cost": cost,
    }).json()


def _location(client, name="Van A"):
    return client.post("/api/v1/stock-locations", json={"name": name}).json()


def _set_stock(client, material_id, location_id, qty):
    return client.put("/api/v1/stock", json={
        "material_id": material_id, "stock_location_id": location_id, "qty": qty,
    }).json()


# --- happy-path confirm + parts decrement stock ---
def test_confirm_with_parts_decrements_stock(client):
    _, op1, _ = _setup(client)
    m = _material(client); loc = _location(client)
    _set_stock(client, m["id"], loc["id"], 10.0)

    r = client.post(f"/api/v1/operations/{op1['id']}/confirm", json={
        "actual_hours": 1.5, "is_final": False,
        "parts": [{"material_id": m["id"], "stock_location_id": loc["id"], "qty_used": 3}],
    })
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["actual_hours"] == 1.5
    assert len(body["parts"]) == 1
    assert body["parts"][0]["qty_used"] == 3
    assert body["parts"][0]["unit_cost_at_use"] == 10.0  # snapshot

    # Stock decremented.
    stock = client.get(f"/api/v1/stock?material_id={m['id']}").json()
    assert stock[0]["qty"] == 7.0


def test_confirm_with_insufficient_stock_rejected(client):
    _, op1, _ = _setup(client)
    m = _material(client); loc = _location(client)
    _set_stock(client, m["id"], loc["id"], 1.0)
    r = client.post(f"/api/v1/operations/{op1['id']}/confirm", json={
        "actual_hours": 1, "is_final": False,
        "parts": [{"material_id": m["id"], "stock_location_id": loc["id"], "qty_used": 5}],
    })
    assert r.status_code == 409
    # And no stock should be moved.
    stock = client.get(f"/api/v1/stock?material_id={m['id']}").json()
    assert stock[0]["qty"] == 1.0


# --- reversal: new row, original untouched, stock restored ---
def test_reverse_creates_new_row_and_restores_stock(client):
    _, op1, _ = _setup(client)
    m = _material(client); loc = _location(client)
    _set_stock(client, m["id"], loc["id"], 10.0)

    cnf = client.post(f"/api/v1/operations/{op1['id']}/confirm", json={
        "actual_hours": 1, "is_final": False,
        "parts": [{"material_id": m["id"], "stock_location_id": loc["id"], "qty_used": 3}],
    }).json()
    assert client.get(f"/api/v1/stock?material_id={m['id']}").json()[0]["qty"] == 7.0

    rev = client.post(f"/api/v1/confirmations/{cnf['id']}/reverse",
                      json={"reason": "wrong part"}).json()
    assert rev["reversal_of_id"] == cnf["id"]
    assert rev["actual_hours"] == -1.0

    # Stock restored.
    assert client.get(f"/api/v1/stock?material_id={m['id']}").json()[0]["qty"] == 10.0

    # Both rows are visible — append-only.
    rows = client.get(f"/api/v1/operations/{op1['id']}/confirmations").json()
    assert len(rows) == 2


def test_double_reverse_rejected(client):
    _, op1, _ = _setup(client)
    cnf = client.post(f"/api/v1/operations/{op1['id']}/confirm", json={
        "actual_hours": 1, "is_final": False, "parts": [],
    }).json()
    client.post(f"/api/v1/confirmations/{cnf['id']}/reverse", json={"reason": "x"})
    r = client.post(f"/api/v1/confirmations/{cnf['id']}/reverse", json={"reason": "y"})
    assert r.status_code == 409


def test_reverse_of_reversal_rejected(client):
    _, op1, _ = _setup(client)
    cnf = client.post(f"/api/v1/operations/{op1['id']}/confirm", json={
        "actual_hours": 1, "is_final": False, "parts": [],
    }).json()
    rev = client.post(f"/api/v1/confirmations/{cnf['id']}/reverse",
                      json={"reason": "x"}).json()
    r = client.post(f"/api/v1/confirmations/{rev['id']}/reverse", json={"reason": "y"})
    assert r.status_code == 409


# --- auto-tech_complete on all-operations-final ---
def test_all_final_auto_advances_to_tech_complete(client):
    order, op1, op2 = _setup(client)
    client.post(f"/api/v1/operations/{op1['id']}/confirm", json={
        "actual_hours": 1, "is_final": True, "parts": [],
    })
    # One op final, one still open -> order remains in_progress
    assert client.get(f"/api/v1/work-orders/{order['id']}").json()["status"] == "in_progress"
    client.post(f"/api/v1/operations/{op2['id']}/confirm", json={
        "actual_hours": 0.5, "is_final": True, "parts": [],
    })
    # Now both final -> auto-advance
    assert client.get(f"/api/v1/work-orders/{order['id']}").json()["status"] == "tech_complete"


# --- reversal excluded from "effectively final" rollup ---
def test_reversal_walks_operation_back_to_open(client):
    order, op1, _ = _setup(client)
    cnf = client.post(f"/api/v1/operations/{op1['id']}/confirm", json={
        "actual_hours": 1, "is_final": True, "parts": [],
    }).json()
    # Operation marked confirmed by the final confirmation.
    ops = client.get(f"/api/v1/work-orders/{order['id']}/operations").json()
    assert next(o for o in ops if o["id"] == op1["id"])["status"] == "confirmed"

    client.post(f"/api/v1/confirmations/{cnf['id']}/reverse",
                json={"reason": "incorrect"})
    ops = client.get(f"/api/v1/work-orders/{order['id']}/operations").json()
    # Effective state after reversal: back to open.
    assert next(o for o in ops if o["id"] == op1["id"])["status"] == "open"


# --- cannot confirm against a terminal order ---
def test_confirm_blocked_when_order_tech_complete(client):
    order, op1, op2 = _setup(client)
    # Final-confirm both ops -> order auto-advances to tech_complete.
    client.post(f"/api/v1/operations/{op1['id']}/confirm", json={
        "actual_hours": 1, "is_final": True, "parts": [],
    })
    client.post(f"/api/v1/operations/{op2['id']}/confirm", json={
        "actual_hours": 1, "is_final": True, "parts": [],
    })
    assert client.get(f"/api/v1/work-orders/{order['id']}").json()["status"] == "tech_complete"

    # Any further confirm against either operation must be rejected.
    r = client.post(f"/api/v1/operations/{op1['id']}/confirm", json={
        "actual_hours": 0.1, "is_final": False, "parts": [],
    })
    assert r.status_code == 409


# --- append-only: there's NO endpoint to update or delete confirmations ---
def test_no_update_endpoint_for_confirmations(client):
    _, op1, _ = _setup(client)
    cnf = client.post(f"/api/v1/operations/{op1['id']}/confirm", json={
        "actual_hours": 1, "is_final": False, "parts": [],
    }).json()
    # PATCH and DELETE both unsupported (method not allowed / not found).
    assert client.patch(f"/api/v1/confirmations/{cnf['id']}",
                        json={"actual_hours": 99}).status_code in (404, 405)
    assert client.delete(f"/api/v1/confirmations/{cnf['id']}").status_code in (404, 405)


# --- where-used endpoint exists (BOM lands in Phase 5) ---
def test_where_used_returns_empty_for_now(client):
    m = _material(client)
    r = client.get(f"/api/v1/materials/{m['id']}/where-used")
    assert r.status_code == 200
    assert r.json() == []


# --- validation parity ---
def test_confirm_validation_422(client):
    _, op1, _ = _setup(client)
    r = client.post(f"/api/v1/operations/{op1['id']}/confirm", json={
        "actual_hours": -1,  # ge=0
    })
    assert r.status_code == 422


# --- audit on confirm + reverse ---
def test_audit_on_confirm_and_reverse(client):
    _, op1, _ = _setup(client)
    cnf = client.post(f"/api/v1/operations/{op1['id']}/confirm", json={
        "actual_hours": 1, "is_final": True, "parts": [],
    }).json()
    rows = client.get(f"/api/v1/audit?entity_type=confirmation&entity_id={cnf['id']}").json()
    assert any(r["action"] == "create" for r in rows)
    rev = client.post(f"/api/v1/confirmations/{cnf['id']}/reverse",
                      json={"reason": "z"}).json()
    rows = client.get(f"/api/v1/audit?entity_type=confirmation&entity_id={rev['id']}").json()
    assert any(r["action"] == "create" for r in rows)
