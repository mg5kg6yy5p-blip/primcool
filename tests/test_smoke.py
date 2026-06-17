def test_app_imports() -> None:
    from app.main import app
    assert app.title == "PrimeCool"


def test_health(client) -> None:
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_submissions_requires_admin_token(client) -> None:
    # Wrong token -> 401
    r = client.get("/api/submissions", headers={"Authorization": "Bearer wrong"})
    assert r.status_code == 401


def test_consult_roundtrip(client) -> None:
    payload = {
        "fname": "Test",
        "lname": "User",
        "email": "t@example.com",
        "tier": "residential",
        "msg": "demo",
    }
    r = client.post("/api/consult", json=payload)
    assert r.status_code == 200
    assert r.json() == {"ok": True}

    r = client.get(
        "/api/submissions",
        headers={"Authorization": "Bearer test-admin-token"},
    )
    assert r.status_code == 200
    body = r.json()
    assert len(body["submissions"]) == 1
    assert body["submissions"][0]["email"] == "t@example.com"


def test_consult_rejects_invalid_email(client) -> None:
    r = client.post(
        "/api/consult",
        json={
            "fname": "T",
            "lname": "U",
            "email": "not-an-email",
            "tier": "residential",
        },
    )
    assert r.status_code == 422
