"""Phase 1 gate tests: invariants A/B, audit trail, timeline, scoping."""


def _make_customer(client, name="Acme Apartments", type_="apartment_complex"):
    r = client.post("/api/v1/customers", json={"name": name, "type": type_})
    assert r.status_code == 201, r.text
    return r.json()


def _make_site(client, customer_id, name="Sunrise Complex"):
    r = client.post(
        "/api/v1/sites", json={"customer_account_id": customer_id, "name": name}
    )
    assert r.status_code == 201, r.text
    return r.json()


def _make_fl(client, site_id, name="Rooftop B"):
    r = client.post(
        "/api/v1/functional-locations",
        json={"site_id": site_id, "name": name, "fl_class": "package_unit"},
    )
    assert r.status_code == 201, r.text
    return r.json()


def _make_equipment(client, serial=None):
    r = client.post(
        "/api/v1/equipment",
        json={"equipment_class": "package_unit", "serial": serial, "warranty_months": 12},
    )
    assert r.status_code == 201, r.text
    return r.json()


# --- Invariant A: at most one active install per FL ---
def test_invariant_a_one_active_install_per_fl(client):
    cust = _make_customer(client)
    site = _make_site(client, cust["id"])
    fl = _make_fl(client, site["id"])
    e1 = _make_equipment(client, serial="E1")
    e2 = _make_equipment(client, serial="E2")

    r1 = client.post(f"/api/v1/equipment/{e1['id']}/install", json={"fl_id": fl["id"]})
    assert r1.status_code == 201, r1.text

    # Second unit into the same occupied slot -> rejected by partial unique index
    r2 = client.post(f"/api/v1/equipment/{e2['id']}/install", json={"fl_id": fl["id"]})
    assert r2.status_code == 409, r2.text


# --- Invariant B: at most one active install per equipment ---
def test_invariant_b_one_active_install_per_equipment(client):
    cust = _make_customer(client)
    site = _make_site(client, cust["id"])
    fl1 = _make_fl(client, site["id"], name="Rooftop A")
    fl2 = _make_fl(client, site["id"], name="Rooftop B")
    e1 = _make_equipment(client, serial="E1")

    assert client.post(f"/api/v1/equipment/{e1['id']}/install",
                       json={"fl_id": fl1["id"]}).status_code == 201
    # Same unit into a second slot while still active -> rejected
    r = client.post(f"/api/v1/equipment/{e1['id']}/install", json={"fl_id": fl2["id"]})
    assert r.status_code == 409, r.text


# --- Swap: remove frees both the FL and the equipment ---
def test_swap_after_removal(client):
    cust = _make_customer(client)
    site = _make_site(client, cust["id"])
    fl = _make_fl(client, site["id"])
    e1 = _make_equipment(client, serial="E1")
    e2 = _make_equipment(client, serial="E2")

    client.post(f"/api/v1/equipment/{e1['id']}/install", json={"fl_id": fl["id"]})
    assert client.post(f"/api/v1/equipment/{e1['id']}/remove", json={}).status_code == 200
    # Slot now free -> e2 installs cleanly
    r = client.post(f"/api/v1/equipment/{e2['id']}/install", json={"fl_id": fl["id"]})
    assert r.status_code == 201, r.text


# --- Audit trail written for create + install ---
def test_audit_written_on_mutations(client):
    cust = _make_customer(client)
    r = client.get(f"/api/v1/audit?entity_type=customer_account&entity_id={cust['id']}")
    assert r.status_code == 200
    rows = r.json()
    assert len(rows) == 1
    assert rows[0]["action"] == "create"
    assert rows[0]["after"]["name"] == "Acme Apartments"


def test_audit_written_on_install_and_status_change(client):
    cust = _make_customer(client)
    site = _make_site(client, cust["id"])
    fl = _make_fl(client, site["id"])
    e1 = _make_equipment(client, serial="E1")
    client.post(f"/api/v1/equipment/{e1['id']}/install", json={"fl_id": fl["id"]})

    install_rows = client.get("/api/v1/audit?entity_type=equipment_install").json()
    assert any(row["action"] == "install" for row in install_rows)
    eq_rows = client.get(f"/api/v1/audit?entity_type=equipment&entity_id={e1['id']}").json()
    assert any(row["action"] == "status_change" for row in eq_rows)


# --- Customer-account scoping on list endpoint ---
def test_site_list_scoped_by_customer(client):
    c1 = _make_customer(client, name="Cust One")
    c2 = _make_customer(client, name="Cust Two")
    _make_site(client, c1["id"], name="Site for One")
    _make_site(client, c2["id"], name="Site for Two")

    only_one = client.get(f"/api/v1/sites?customer_account_id={c1['id']}").json()
    assert len(only_one) == 1
    assert only_one[0]["name"] == "Site for One"


# --- Equipment timeline renders install + meter reading events in order ---
def test_equipment_timeline(client):
    cust = _make_customer(client)
    site = _make_site(client, cust["id"])
    fl = _make_fl(client, site["id"])
    e1 = _make_equipment(client, serial="E1")

    client.post(f"/api/v1/equipment/{e1['id']}/install", json={"fl_id": fl["id"]})
    meter = client.post(
        "/api/v1/meters",
        json={"equipment_id": e1["id"], "meter_type": "run_hours", "unit": "h"},
    ).json()
    client.post(f"/api/v1/meters/{meter['id']}/readings", json={"reading_value": 1500})

    hist = client.get(f"/api/v1/equipment/{e1['id']}/history").json()
    kinds = [e["kind"] for e in hist["events"]]
    assert "install" in kinds
    assert "meter_reading" in kinds
    # Sorted ascending by timestamp
    times = [e["at"] for e in hist["events"]]
    assert times == sorted(times)


# --- Validation parity: a missing required field yields 422 ---
def test_customer_validation_422(client):
    r = client.post("/api/v1/customers", json={"name": "No Type"})
    assert r.status_code == 422


def test_warranty_expiry_computed(client):
    cust = _make_customer(client)
    site = _make_site(client, cust["id"])
    fl = _make_fl(client, site["id"])
    e1 = _make_equipment(client, serial="E1")  # warranty_months=12
    r = client.post(
        f"/api/v1/equipment/{e1['id']}/install",
        json={"fl_id": fl["id"], "installed_at": "2026-01-15T00:00:00+00:00"},
    )
    assert r.status_code == 201
    assert r.json()["warranty_expires_at"].startswith("2027-01-15")
