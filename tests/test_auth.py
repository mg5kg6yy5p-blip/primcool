"""Auth unit gate: bootstrap, login, /me, role enforcement, expired/invalid
tokens, audit attribution."""
from datetime import datetime, timedelta, timezone

import pytest
from jose import jwt


@pytest.fixture
def bootstrapped(raw_client):
    """Returns (client, token) with one admin user created via /bootstrap."""
    r = raw_client.post("/api/auth/bootstrap", json={
        "email": "admin@x.co", "password": "ssssecret1", "full_name": "Admin",
    })
    assert r.status_code == 201, r.text
    token = r.json()["access_token"]
    return raw_client, token


def auth(token):
    return {"Authorization": f"Bearer {token}"}


# --- /status + bootstrap ---
def test_status_reports_empty(raw_client):
    assert raw_client.get("/api/auth/status").json() == {"users_exist": False}


def test_bootstrap_creates_admin_when_empty(raw_client):
    r = raw_client.post("/api/auth/bootstrap", json={
        "email": "first@x.co", "password": "ssssecret1", "full_name": "First",
    })
    assert r.status_code == 201
    assert "access_token" in r.json()
    assert raw_client.get("/api/auth/status").json() == {"users_exist": True}


def test_bootstrap_refuses_when_users_exist(bootstrapped):
    client, _ = bootstrapped
    r = client.post("/api/auth/bootstrap", json={
        "email": "second@x.co", "password": "ssssecret1",
    })
    assert r.status_code == 403


# --- login + /me ---
def test_login_succeeds_with_correct_creds(bootstrapped):
    client, _ = bootstrapped
    r = client.post("/api/auth/login", json={"email": "admin@x.co", "password": "ssssecret1"})
    assert r.status_code == 200
    assert "access_token" in r.json()


def test_login_fails_with_wrong_password(bootstrapped):
    client, _ = bootstrapped
    r = client.post("/api/auth/login", json={"email": "admin@x.co", "password": "nope"})
    assert r.status_code == 401


def test_login_fails_for_unknown_email(bootstrapped):
    client, _ = bootstrapped
    r = client.post("/api/auth/login", json={
        "email": "ghost@x.co", "password": "anything12",
    })
    assert r.status_code == 401


def test_me_returns_current_user(bootstrapped):
    client, token = bootstrapped
    r = client.get("/api/auth/me", headers=auth(token))
    assert r.status_code == 200
    body = r.json()
    assert body["email"] == "admin@x.co"
    assert body["role"] == "admin"


def test_me_without_token_401(bootstrapped):
    client, _ = bootstrapped
    assert client.get("/api/auth/me").status_code == 401


def test_protected_endpoint_without_token_401(bootstrapped):
    client, _ = bootstrapped
    assert client.get("/api/v1/customers").status_code == 401


def test_protected_endpoint_with_token_200(bootstrapped):
    client, token = bootstrapped
    assert client.get("/api/v1/customers", headers=auth(token)).status_code == 200


# --- role enforcement ---
def test_technician_cannot_access_admin_or_dispatcher_routes(bootstrapped):
    client, admin_token = bootstrapped
    # Admin creates a technician user.
    r = client.post("/api/v1/users", json={
        "email": "tech@x.co", "password": "ssssecret1",
        "full_name": "Tech", "role": "technician",
    }, headers=auth(admin_token))
    assert r.status_code == 201
    tech_token = client.post("/api/auth/login", json={
        "email": "tech@x.co", "password": "ssssecret1",
    }).json()["access_token"]
    # Customers requires admin/dispatcher -> 403 for technician.
    assert client.get("/api/v1/customers", headers=auth(tech_token)).status_code == 403


def test_user_management_admin_only(bootstrapped):
    client, admin_token = bootstrapped
    client.post("/api/v1/users", json={
        "email": "disp@x.co", "password": "ssssecret1",
        "full_name": "Disp", "role": "dispatcher",
    }, headers=auth(admin_token))
    disp_token = client.post("/api/auth/login", json={
        "email": "disp@x.co", "password": "ssssecret1",
    }).json()["access_token"]
    # Dispatchers can't manage users.
    assert client.get("/api/v1/users", headers=auth(disp_token)).status_code == 403
    assert client.get("/api/v1/users", headers=auth(admin_token)).status_code == 200


# --- token shape / expiry ---
def test_expired_token_rejected(bootstrapped):
    client, _ = bootstrapped
    # Build a token expired one minute ago using the test JWT_SECRET.
    past = datetime.now(timezone.utc) - timedelta(minutes=1)
    claims = {"sub": "00000000-0000-0000-0000-000000000000", "role": "admin",
              "exp": int(past.timestamp())}
    token = jwt.encode(claims, "test-secret", algorithm="HS256")
    assert client.get("/api/auth/me", headers=auth(token)).status_code == 401


def test_malformed_token_rejected(bootstrapped):
    client, _ = bootstrapped
    assert client.get("/api/auth/me", headers=auth("not.a.jwt")).status_code == 401


def test_inactive_user_cannot_use_token(bootstrapped):
    client, admin_token = bootstrapped
    r = client.post("/api/v1/users", json={
        "email": "soon-off@x.co", "password": "ssssecret1",
        "full_name": "Off", "role": "dispatcher",
    }, headers=auth(admin_token))
    user_id = r.json()["id"]
    user_token = client.post("/api/auth/login", json={
        "email": "soon-off@x.co", "password": "ssssecret1",
    }).json()["access_token"]
    assert client.get("/api/auth/me", headers=auth(user_token)).status_code == 200
    client.patch(f"/api/v1/users/{user_id}", json={"is_active": False},
                 headers=auth(admin_token))
    assert client.get("/api/auth/me", headers=auth(user_token)).status_code == 401


# --- audit attribution via ContextVar ---
def test_audit_attributes_actor_from_token(bootstrapped):
    client, token = bootstrapped
    # Create a customer; audit_log should attribute to the admin user.
    r = client.post("/api/v1/customers", json={"name": "AcctCo", "type": "commercial"},
                    headers=auth(token))
    customer_id = r.json()["id"]
    rows = client.get(
        f"/api/v1/audit?entity_type=customer_account&entity_id={customer_id}",
        headers=auth(token),
    ).json()
    assert len(rows) == 1
    assert rows[0]["actor_user_id"] is not None
