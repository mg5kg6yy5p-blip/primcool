"""Phase 5 gate (portal): explicit cross-account-leak test + portal scoping."""
import pytest


@pytest.fixture
def two_accounts(raw_client):
    """Bootstrap admin, then create two customer accounts with one portal
    user each. Returns dict with both tokens + ids."""
    admin_token = raw_client.post("/api/auth/bootstrap", json={
        "email": "admin@x.co", "password": "ssssecret1", "full_name": "Admin",
    }).json()["access_token"]
    auth = lambda t: {"Authorization": f"Bearer {t}"}  # noqa: E731

    a_cust = raw_client.post("/api/v1/customers", json={
        "name": "Account A", "type": "apartment_complex",
    }, headers=auth(admin_token)).json()
    b_cust = raw_client.post("/api/v1/customers", json={
        "name": "Account B", "type": "apartment_complex",
    }, headers=auth(admin_token)).json()
    a_site = raw_client.post("/api/v1/sites", json={
        "customer_account_id": a_cust["id"], "name": "A Site",
    }, headers=auth(admin_token)).json()
    b_site = raw_client.post("/api/v1/sites", json={
        "customer_account_id": b_cust["id"], "name": "B Site",
    }, headers=auth(admin_token)).json()

    raw_client.post("/api/v1/users", json={
        "email": "portal-a@x.co", "password": "ssssecret1", "full_name": "Portal A",
        "role": "portal_user", "customer_account_id": a_cust["id"],
    }, headers=auth(admin_token))
    raw_client.post("/api/v1/users", json={
        "email": "portal-b@x.co", "password": "ssssecret1", "full_name": "Portal B",
        "role": "portal_user", "customer_account_id": b_cust["id"],
    }, headers=auth(admin_token))

    a_token = raw_client.post("/api/auth/login", json={
        "email": "portal-a@x.co", "password": "ssssecret1",
    }).json()["access_token"]
    b_token = raw_client.post("/api/auth/login", json={
        "email": "portal-b@x.co", "password": "ssssecret1",
    }).json()["access_token"]

    return {
        "client": raw_client, "admin_token": admin_token,
        "a_cust": a_cust, "b_cust": b_cust,
        "a_site": a_site, "b_site": b_site,
        "a_token": a_token, "b_token": b_token,
    }


def auth(t): return {"Authorization": f"Bearer {t}"}


# --- /me / sites scoping ---
def test_portal_me_returns_portal_user(two_accounts):
    c = two_accounts["client"]
    me = c.get("/api/customer-portal/me", headers=auth(two_accounts["a_token"])).json()
    assert me["role"] == "portal_user"
    assert me["customer_account_id"] == two_accounts["a_cust"]["id"]


def test_portal_sites_only_own_account(two_accounts):
    c = two_accounts["client"]
    sites_a = c.get("/api/customer-portal/sites",
                    headers=auth(two_accounts["a_token"])).json()
    assert len(sites_a) == 1
    assert sites_a[0]["id"] == two_accounts["a_site"]["id"]


# --- raise a request, then verify B can't see it (LEAK TEST) ---
def test_portal_cross_account_leak_blocked(two_accounts):
    c = two_accounts["client"]
    a_token, b_token = two_accounts["a_token"], two_accounts["b_token"]

    a_notif = c.post("/api/customer-portal/notifications", json={
        "customer_account_id": two_accounts["a_cust"]["id"],
        "site_id": two_accounts["a_site"]["id"],
        "category": "cooling", "severity": "high", "title": "A's AC down",
    }, headers=auth(a_token)).json()
    assert "id" in a_notif

    # B's list does NOT include A's notification.
    b_list = c.get("/api/customer-portal/notifications",
                   headers=auth(b_token)).json()
    assert all(n["id"] != a_notif["id"] for n in b_list)
    # A's list includes it.
    a_list = c.get("/api/customer-portal/notifications",
                   headers=auth(a_token)).json()
    assert any(n["id"] == a_notif["id"] for n in a_list)


def test_portal_user_cannot_raise_for_another_account(two_accounts):
    c = two_accounts["client"]
    # A tries to raise a notification on B's account+site.
    r = c.post("/api/customer-portal/notifications", json={
        "customer_account_id": two_accounts["b_cust"]["id"],
        "site_id": two_accounts["b_site"]["id"],
        "category": "cooling", "severity": "high", "title": "phishing",
    }, headers=auth(two_accounts["a_token"]))
    assert r.status_code == 403


def test_portal_user_cannot_raise_against_other_account_site(two_accounts):
    c = two_accounts["client"]
    # A passes own customer_account_id but B's site_id -> 404 (don't leak).
    r = c.post("/api/customer-portal/notifications", json={
        "customer_account_id": two_accounts["a_cust"]["id"],
        "site_id": two_accounts["b_site"]["id"],
        "category": "cooling", "severity": "high", "title": "X",
    }, headers=auth(two_accounts["a_token"]))
    assert r.status_code == 404


# --- work-order portal view scoped ---
def test_portal_work_orders_scoped(two_accounts):
    c = two_accounts["client"]
    admin = two_accounts["admin_token"]
    # Admin creates an order against B's account.
    b_order = c.post("/api/v1/work-orders", json={
        "customer_account_id": two_accounts["b_cust"]["id"],
        "site_id": two_accounts["b_site"]["id"],
        "order_type": "corrective", "priority": "medium", "title": "B WO",
    }, headers=auth(admin)).json()

    # A's portal list does not see it.
    a_list = c.get("/api/customer-portal/work-orders",
                   headers=auth(two_accounts["a_token"])).json()
    assert all(o["id"] != b_order["id"] for o in a_list)

    # And direct GET by id returns 404 (not 403) — don't leak existence.
    r = c.get(f"/api/customer-portal/work-orders/{b_order['id']}",
              headers=auth(two_accounts["a_token"]))
    assert r.status_code == 404


def test_staff_cannot_use_portal_endpoint(two_accounts):
    c = two_accounts["client"]
    # Admin token is staff, not portal -> 403 on portal endpoints.
    r = c.get("/api/customer-portal/me",
              headers=auth(two_accounts["admin_token"]))
    assert r.status_code == 403


def test_portal_user_cannot_use_internal_admin_endpoints(two_accounts):
    c = two_accounts["client"]
    # The /api/v1/* surfaces require admin/dispatcher (or staff for work-orders).
    assert c.get("/api/v1/customers",
                 headers=auth(two_accounts["a_token"])).status_code == 403
    assert c.get("/api/v1/users",
                 headers=auth(two_accounts["a_token"])).status_code == 403


# --- audit row written from the portal flow attributes to the portal user ---
def test_portal_audit_attributes_to_portal_user(two_accounts):
    c = two_accounts["client"]
    notif = c.post("/api/customer-portal/notifications", json={
        "customer_account_id": two_accounts["a_cust"]["id"],
        "site_id": two_accounts["a_site"]["id"],
        "category": "leak", "severity": "medium", "title": "Drip",
    }, headers=auth(two_accounts["a_token"])).json()
    rows = c.get(
        f"/api/v1/audit?entity_type=notification&entity_id={notif['id']}",
        headers=auth(two_accounts["admin_token"]),
    ).json()
    assert len(rows) >= 1
    assert rows[0]["actor_user_id"] is not None
