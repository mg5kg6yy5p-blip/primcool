"""Phase 4 gate: calendar + meter triggers each generate one order;
one-open-cycle preserved; completion re-baselines (cadence-holds)."""
from datetime import datetime, timedelta, timezone


def _setup_hierarchy(client):
    cust = client.post("/api/v1/customers",
                       json={"name": "Acme", "type": "commercial"}).json()
    site = client.post("/api/v1/sites",
                       json={"customer_account_id": cust["id"], "name": "S"}).json()
    eq = client.post("/api/v1/equipment",
                     json={"equipment_class": "package_unit"}).json()
    return cust, site, eq


def _calendar_schedule(client, cust_id, site_id, *, days=90, start_at=None):
    body = {
        "customer_account_id": cust_id, "site_id": site_id,
        "name": "Quarterly PM", "order_title": "Quarterly PM visit",
        "trigger_kind": "calendar", "interval_days": days,
        "billing_class": "contract", "priority": "medium",
    }
    if start_at is not None:
        body["start_at"] = start_at
    r = client.post("/api/v1/pm-schedules", json=body)
    assert r.status_code == 201, r.text
    return r.json()


def _meter_schedule(client, cust_id, site_id, eq_id, *, every=2000.0, start=0.0):
    meter = client.post("/api/v1/meters", json={
        "equipment_id": eq_id, "meter_type": "run_hours", "unit": "h",
    }).json()
    r = client.post("/api/v1/pm-schedules", json={
        "customer_account_id": cust_id, "site_id": site_id, "equipment_id": eq_id,
        "name": "2000-hr service", "order_title": "Compressor 2000-hr",
        "trigger_kind": "meter", "meter_id": meter["id"],
        "interval_value": every, "start_value": start,
        "billing_class": "contract", "priority": "medium",
    })
    assert r.status_code == 201, r.text
    return r.json(), meter


# --- calendar trigger ---
def test_calendar_due_generates_exactly_one_order(client):
    cust, site, _ = _setup_hierarchy(client)
    past = (datetime.now(timezone.utc) - timedelta(days=100)).isoformat()
    sched = _calendar_schedule(client, cust["id"], site["id"], days=90, start_at=past)

    r1 = client.post("/api/v1/pm-schedules/scan")
    assert r1.status_code == 200
    assert len(r1.json()["generated_work_order_ids"]) == 1

    # Second scan: same schedule already has an open cycle -> nothing new.
    r2 = client.post("/api/v1/pm-schedules/scan")
    assert r2.json()["generated_work_order_ids"] == []
    assert sched  # silence lint


def test_calendar_not_yet_due_generates_nothing(client):
    cust, site, _ = _setup_hierarchy(client)
    future = (datetime.now(timezone.utc) + timedelta(days=10)).isoformat()
    _calendar_schedule(client, cust["id"], site["id"], days=90, start_at=future)
    r = client.post("/api/v1/pm-schedules/scan")
    assert r.json()["generated_work_order_ids"] == []


# --- meter trigger ---
def test_meter_due_generates_exactly_one_order(client):
    cust, site, eq = _setup_hierarchy(client)
    sched, meter = _meter_schedule(client, cust["id"], site["id"], eq["id"],
                                   every=2000, start=0)
    # Log a reading at 2100h -> over the threshold.
    client.post(f"/api/v1/meters/{meter['id']}/readings", json={"reading_value": 2100})

    r = client.post("/api/v1/pm-schedules/scan")
    assert len(r.json()["generated_work_order_ids"]) == 1
    # One-open-cycle holds.
    r2 = client.post("/api/v1/pm-schedules/scan")
    assert r2.json()["generated_work_order_ids"] == []
    assert sched  # silence


def test_meter_below_threshold_generates_nothing(client):
    cust, site, eq = _setup_hierarchy(client)
    _, meter = _meter_schedule(client, cust["id"], site["id"], eq["id"],
                               every=2000, start=0)
    client.post(f"/api/v1/meters/{meter['id']}/readings", json={"reading_value": 1500})
    r = client.post("/api/v1/pm-schedules/scan")
    assert r.json()["generated_work_order_ids"] == []


# --- one-open-cycle invariant ---
def test_open_cycle_blocks_regeneration_even_when_overdue(client):
    cust, site, _ = _setup_hierarchy(client)
    past = (datetime.now(timezone.utc) - timedelta(days=200)).isoformat()
    sched = _calendar_schedule(client, cust["id"], site["id"], days=90, start_at=past)
    client.post("/api/v1/pm-schedules/scan")
    # Even though we're 200 days overdue, second scan shouldn't generate.
    r = client.post(f"/api/v1/pm-schedules/{sched['id']}/scan")
    assert r.json()["generated_work_order_ids"] == []


# --- completion re-baselines (the cadence-holds rule) ---
def test_completion_rebaselines_calendar(client):
    cust, site, _ = _setup_hierarchy(client)
    past = (datetime.now(timezone.utc) - timedelta(days=100)).isoformat()
    sched = _calendar_schedule(client, cust["id"], site["id"], days=90, start_at=past)

    order_id = client.post("/api/v1/pm-schedules/scan").json()[
        "generated_work_order_ids"][0]
    # Walk the order through the state machine to closed.
    for t in ("scheduled", "in_progress", "tech_complete", "closed"):
        client.post(f"/api/v1/work-orders/{order_id}/transition", json={"target": t})

    refreshed = client.get(f"/api/v1/pm-schedules/{sched['id']}").json()
    # next_due_at is anchored AT completion (now-ish), not at the original due
    # date -> roughly 90 days from now. SQLite roundtrip strips tzinfo from
    # the serialized value; coerce both sides to UTC for the comparison.
    next_due = datetime.fromisoformat(refreshed["next_due_at"])
    if next_due.tzinfo is None:
        next_due = next_due.replace(tzinfo=timezone.utc)
    diff = (next_due - datetime.now(timezone.utc)).days
    assert 89 <= diff <= 91, f"expected ~90 days from now, got {diff}"

    # And immediately after completion the schedule should NOT be due.
    assert client.post("/api/v1/pm-schedules/scan").json()["generated_work_order_ids"] == []


def test_completion_rebaselines_meter(client):
    cust, site, eq = _setup_hierarchy(client)
    sched, meter = _meter_schedule(client, cust["id"], site["id"], eq["id"],
                                   every=2000, start=0)
    client.post(f"/api/v1/meters/{meter['id']}/readings", json={"reading_value": 2050})
    order_id = client.post("/api/v1/pm-schedules/scan").json()[
        "generated_work_order_ids"][0]

    # Meter ticks up while the order is open; reading at completion is what
    # anchors the next-due value.
    client.post(f"/api/v1/meters/{meter['id']}/readings", json={"reading_value": 2120})
    for t in ("scheduled", "in_progress", "tech_complete", "closed"):
        client.post(f"/api/v1/work-orders/{order_id}/transition", json={"target": t})

    refreshed = client.get(f"/api/v1/pm-schedules/{sched['id']}").json()
    assert refreshed["last_completed_value"] == 2120
    assert refreshed["next_due_value"] == 2120 + 2000


# --- paused schedules don't generate ---
def test_paused_schedule_doesnt_generate(client):
    cust, site, _ = _setup_hierarchy(client)
    past = (datetime.now(timezone.utc) - timedelta(days=100)).isoformat()
    sched = _calendar_schedule(client, cust["id"], site["id"], days=90, start_at=past)
    client.patch(f"/api/v1/pm-schedules/{sched['id']}", json={"is_active": False})

    assert client.post("/api/v1/pm-schedules/scan").json()["generated_work_order_ids"] == []


# --- generated order inherits defaults ---
def test_generated_order_inherits_billing_class_and_priority(client):
    cust, site, _ = _setup_hierarchy(client)
    past = (datetime.now(timezone.utc) - timedelta(days=100)).isoformat()
    r = client.post("/api/v1/pm-schedules", json={
        "customer_account_id": cust["id"], "site_id": site["id"],
        "name": "Warranty PM", "order_title": "Warranty PM visit",
        "trigger_kind": "calendar", "interval_days": 90, "start_at": past,
        "billing_class": "warranty", "priority": "high",
    })
    assert r.status_code == 201, r.text

    order_id = client.post("/api/v1/pm-schedules/scan").json()[
        "generated_work_order_ids"][0]
    order = client.get(f"/api/v1/work-orders/{order_id}").json()
    assert order["billing_class"] == "warranty"
    assert order["priority"] == "high"
    assert order["order_type"] == "preventive"
    assert order["pm_schedule_id"] is not None


# --- validation parity on the create form ---
def test_calendar_without_interval_days_422(client):
    cust, site, _ = _setup_hierarchy(client)
    r = client.post("/api/v1/pm-schedules", json={
        "customer_account_id": cust["id"], "site_id": site["id"],
        "name": "Bad", "order_title": "X",
        "trigger_kind": "calendar",  # missing interval_days
    })
    assert r.status_code == 422


def test_meter_without_meter_id_422(client):
    cust, site, _ = _setup_hierarchy(client)
    r = client.post("/api/v1/pm-schedules", json={
        "customer_account_id": cust["id"], "site_id": site["id"],
        "name": "Bad", "order_title": "X",
        "trigger_kind": "meter", "interval_value": 1000,  # missing meter_id
    })
    assert r.status_code == 422


# --- audit attribution on scan ---
def test_audit_on_generation(client):
    cust, site, _ = _setup_hierarchy(client)
    past = (datetime.now(timezone.utc) - timedelta(days=100)).isoformat()
    sched = _calendar_schedule(client, cust["id"], site["id"], days=90, start_at=past)
    order_id = client.post("/api/v1/pm-schedules/scan").json()[
        "generated_work_order_ids"][0]
    rows = client.get(
        f"/api/v1/audit?entity_type=pm_schedule&entity_id={sched['id']}"
    ).json()
    assert any(r["action"] == "update" for r in rows)
    wo_rows = client.get(
        f"/api/v1/audit?entity_type=work_order&entity_id={order_id}"
    ).json()
    assert any(r["action"] == "create" for r in wo_rows)
