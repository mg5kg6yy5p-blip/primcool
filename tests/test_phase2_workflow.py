"""Phase 2 gate tests: notification lifecycle, work-order state machine,
work queue default lens + emergency sort, frozen fields, audit, scoping."""


def _customer(client, name="Acme"):
    return client.post("/api/v1/customers", json={"name": name, "type": "commercial"}).json()


def _site(client, customer_id, name="Site"):
    return client.post(
        "/api/v1/sites", json={"customer_account_id": customer_id, "name": name}
    ).json()


def _notif(client, customer_id, site_id, severity="high", title="AC not cooling"):
    r = client.post("/api/v1/notifications", json={
        "customer_account_id": customer_id, "site_id": site_id,
        "category": "cooling", "severity": severity, "title": title,
    })
    assert r.status_code == 201, r.text
    return r.json()


def _order(client, customer_id, site_id, priority="medium", title="WO"):
    r = client.post("/api/v1/work-orders", json={
        "customer_account_id": customer_id, "site_id": site_id,
        "order_type": "corrective", "priority": priority, "title": title,
    })
    assert r.status_code == 201, r.text
    return r.json()


# --- Notification lifecycle ---
def test_notification_acknowledge(client):
    c = _customer(client); s = _site(client, c["id"])
    n = _notif(client, c["id"], s["id"])
    assert n["status"] == "new"
    r = client.post(f"/api/v1/notifications/{n['id']}/acknowledge")
    assert r.status_code == 200
    assert r.json()["status"] == "acknowledged"
    assert r.json()["acknowledged_at"] is not None


def test_notification_double_acknowledge_rejected(client):
    c = _customer(client); s = _site(client, c["id"])
    n = _notif(client, c["id"], s["id"])
    client.post(f"/api/v1/notifications/{n['id']}/acknowledge")
    r = client.post(f"/api/v1/notifications/{n['id']}/acknowledge")
    assert r.status_code == 409


def test_close_no_action_requires_reason(client):
    c = _customer(client); s = _site(client, c["id"])
    n = _notif(client, c["id"], s["id"])
    # Missing reason -> 422
    assert client.post(f"/api/v1/notifications/{n['id']}/close-no-action",
                       json={}).status_code == 422
    r = client.post(f"/api/v1/notifications/{n['id']}/close-no-action",
                    json={"reason": "duplicate of #12"})
    assert r.status_code == 200
    assert r.json()["status"] == "closed_no_action"


def test_convert_to_order_copies_fields_and_marks_converted(client):
    c = _customer(client); s = _site(client, c["id"])
    n = _notif(client, c["id"], s["id"], severity="emergency", title="Compressor down")
    r = client.post(f"/api/v1/notifications/{n['id']}/convert-to-order")
    assert r.status_code == 201, r.text
    order = r.json()
    assert order["priority"] == "emergency"     # severity -> priority
    assert order["site_id"] == s["id"]
    assert order["title"] == "Compressor down"
    assert order["notification_id"] == n["id"]
    assert order["order_type"] == "corrective"
    # Notification now converted
    assert client.get(f"/api/v1/notifications/{n['id']}").json()["status"] == "converted"


def test_convert_terminal_notification_rejected(client):
    c = _customer(client); s = _site(client, c["id"])
    n = _notif(client, c["id"], s["id"])
    client.post(f"/api/v1/notifications/{n['id']}/convert-to-order")
    r = client.post(f"/api/v1/notifications/{n['id']}/convert-to-order")
    assert r.status_code == 409


# --- Work-order state machine ---
def test_work_order_happy_path(client):
    c = _customer(client); s = _site(client, c["id"])
    o = _order(client, c["id"], s["id"])
    for target in ["scheduled", "in_progress", "tech_complete", "closed"]:
        r = client.post(f"/api/v1/work-orders/{o['id']}/transition", json={"target": target})
        assert r.status_code == 200, r.text
        assert r.json()["status"] == target
    assert client.get(f"/api/v1/work-orders/{o['id']}").json()["closed_at"] is not None


def test_work_order_illegal_backward_rejected(client):
    c = _customer(client); s = _site(client, c["id"])
    o = _order(client, c["id"], s["id"])
    client.post(f"/api/v1/work-orders/{o['id']}/transition", json={"target": "scheduled"})
    # scheduled -> created is illegal
    r = client.post(f"/api/v1/work-orders/{o['id']}/transition", json={"target": "created"})
    assert r.status_code == 409


def test_work_order_skip_state_rejected(client):
    c = _customer(client); s = _site(client, c["id"])
    o = _order(client, c["id"], s["id"])
    # created -> in_progress (skipping scheduled) illegal
    r = client.post(f"/api/v1/work-orders/{o['id']}/transition", json={"target": "in_progress"})
    assert r.status_code == 409


def test_cancel_from_created_ok_but_not_from_in_progress(client):
    c = _customer(client); s = _site(client, c["id"])
    o1 = _order(client, c["id"], s["id"])
    assert client.post(f"/api/v1/work-orders/{o1['id']}/transition",
                       json={"target": "cancelled"}).status_code == 200

    o2 = _order(client, c["id"], s["id"])
    client.post(f"/api/v1/work-orders/{o2['id']}/transition", json={"target": "scheduled"})
    client.post(f"/api/v1/work-orders/{o2['id']}/transition", json={"target": "in_progress"})
    r = client.post(f"/api/v1/work-orders/{o2['id']}/transition", json={"target": "cancelled"})
    assert r.status_code == 409


def test_transition_from_terminal_rejected(client):
    c = _customer(client); s = _site(client, c["id"])
    o = _order(client, c["id"], s["id"])
    client.post(f"/api/v1/work-orders/{o['id']}/transition", json={"target": "cancelled"})
    r = client.post(f"/api/v1/work-orders/{o['id']}/transition", json={"target": "scheduled"})
    assert r.status_code == 409


def test_legal_transitions_exposed(client):
    c = _customer(client); s = _site(client, c["id"])
    o = _order(client, c["id"], s["id"])
    assert set(o["legal_transitions"]) == {"scheduled", "cancelled"}


# --- Frozen fields after tech_complete ---
def test_fields_frozen_after_tech_complete(client):
    c = _customer(client); s = _site(client, c["id"])
    o = _order(client, c["id"], s["id"])
    for t in ["scheduled", "in_progress", "tech_complete"]:
        client.post(f"/api/v1/work-orders/{o['id']}/transition", json={"target": t})
    r = client.patch(f"/api/v1/work-orders/{o['id']}", json={"title": "new title"})
    assert r.status_code == 409


# --- Work queue default lens + emergency sort ---
def test_queue_excludes_closed_and_cancelled_by_default(client):
    c = _customer(client); s = _site(client, c["id"])
    keep = _order(client, c["id"], s["id"], title="Open one")
    cancel = _order(client, c["id"], s["id"], title="Cancel one")
    client.post(f"/api/v1/work-orders/{cancel['id']}/transition", json={"target": "cancelled"})

    titles = [o["title"] for o in client.get("/api/v1/work-orders").json()]
    assert "Open one" in titles
    assert "Cancel one" not in titles
    # include_closed surfaces it
    titles_all = [o["title"] for o in
                  client.get("/api/v1/work-orders?include_closed=true").json()]
    assert "Cancel one" in titles_all
    assert keep  # silence lint


def test_emergency_sorts_to_top(client):
    c = _customer(client); s = _site(client, c["id"])
    _order(client, c["id"], s["id"], priority="low", title="low")
    _order(client, c["id"], s["id"], priority="emergency", title="emergency")
    _order(client, c["id"], s["id"], priority="medium", title="medium")
    first = client.get("/api/v1/work-orders").json()[0]
    assert first["priority"] == "emergency"


# --- Saved view drives the queue ---
def test_saved_view_filters_queue(client):
    c1 = _customer(client, "C1"); s1 = _site(client, c1["id"])
    c2 = _customer(client, "C2"); s2 = _site(client, c2["id"])
    _order(client, c1["id"], s1["id"], title="for c1")
    _order(client, c2["id"], s2["id"], title="for c2")

    view = client.post("/api/v1/saved-views", json={
        "name": "C1 only", "filters": {"customer_account_id": c1["id"]},
    }).json()
    titles = [o["title"] for o in
              client.get(f"/api/v1/work-orders?view_id={view['id']}").json()]
    assert titles == ["for c1"]


# --- Operations ---
def test_add_operation(client):
    c = _customer(client); s = _site(client, c["id"])
    o = _order(client, c["id"], s["id"])
    r = client.post(f"/api/v1/work-orders/{o['id']}/operations",
                    json={"description": "Recharge", "planned_hours": 2})
    assert r.status_code == 201
    ops = client.get(f"/api/v1/work-orders/{o['id']}/operations").json()
    assert len(ops) == 1 and ops[0]["status"] == "open"


# --- Audit + scoping + validation parity ---
def test_audit_on_convert(client):
    c = _customer(client); s = _site(client, c["id"])
    n = _notif(client, c["id"], s["id"])
    client.post(f"/api/v1/notifications/{n['id']}/convert-to-order")
    rows = client.get(f"/api/v1/audit?entity_type=notification&entity_id={n['id']}").json()
    assert any(r["action"] == "status_change" for r in rows)


def test_notification_list_scoped(client):
    c1 = _customer(client, "One"); s1 = _site(client, c1["id"])
    c2 = _customer(client, "Two"); s2 = _site(client, c2["id"])
    _notif(client, c1["id"], s1["id"], title="for one")
    _notif(client, c2["id"], s2["id"], title="for two")
    only = client.get(f"/api/v1/notifications?customer_account_id={c1['id']}").json()
    assert [n["title"] for n in only] == ["for one"]


def test_notification_validation_422(client):
    c = _customer(client); s = _site(client, c["id"])
    r = client.post("/api/v1/notifications", json={
        "customer_account_id": c["id"], "site_id": s["id"],
        "category": "cooling", "severity": "high",  # missing title
    })
    assert r.status_code == 422
