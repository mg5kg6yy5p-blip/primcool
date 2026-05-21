"""Shared pytest fixtures for backend HTTP acceptance tests.

This conftest:
  * Loads `.dev.env` into os.environ BEFORE importing `main` so the FastAPI
    app initializes with the same JWT_SECRET / FIELD_ENCRYPTION_KEY the running
    server uses.
  * Exposes session-scoped fixtures for the FastAPI app, an httpx ASGI client,
    and authenticated cookies for director / supervisor / tech.
  * Pulls a small set of seeded record IDs out of submissions.db so tests can
    target stable rows without recomputing them.
"""
import os
import re
import sqlite3
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Environment bootstrap — MUST happen before `import main`.
# ---------------------------------------------------------------------------
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_DEV_ENV = _PROJECT_ROOT / ".dev.env"


def _load_dev_env() -> None:
    if not _DEV_ENV.exists():
        return
    pat = re.compile(r'^\s*(?:export\s+)?([A-Z_][A-Z0-9_]*)\s*=\s*(.*?)\s*$')
    for line in _DEV_ENV.read_text().splitlines():
        if not line or line.startswith("#"):
            continue
        m = pat.match(line)
        if not m:
            continue
        k, v = m.group(1), m.group(2)
        if (v.startswith('"') and v.endswith('"')) or (v.startswith("'") and v.endswith("'")):
            v = v[1:-1]
        os.environ.setdefault(k, v)


_load_dev_env()
# Try to discourage background tasks from doing damage during tests. Not
# guaranteed to be honored by main.py (we cannot modify it).
os.environ.setdefault("PC_DISABLE_BG_TASKS", "1")
os.environ.setdefault("DISABLE_BG_TASKS", "1")


@pytest.fixture(scope="session")
def dev_env():
    """No-op fixture; the load happens at import time. Provided for tests
    that want to declare the dependency explicitly."""
    return dict(os.environ)


@pytest.fixture(scope="session")
def app(dev_env):
    # Import lazily so env is already in place.
    os.chdir(str(_PROJECT_ROOT))
    from main import app as _app
    return _app


@pytest.fixture(scope="session")
def client(app):
    import httpx
    transport = httpx.ASGITransport(app=app)
    with httpx.Client(transport=transport, base_url="http://test") as c:
        yield c


# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------
def _extract_session_cookie(resp, cookie_name: str):
    """Pull the named cookie out of a login response (Set-Cookie or body 'token')."""
    val = resp.cookies.get(cookie_name)
    if val:
        return val
    try:
        body = resp.json()
        if isinstance(body, dict) and body.get("token"):
            return body["token"]
    except Exception:
        pass
    return None


@pytest.fixture(scope="session")
def admin_token(client):
    """Director (bootstrap super_admin) JWT cookie value."""
    r = client.post(
        "/api/admin/login",
        json={
            "username": os.environ.get("BOOTSTRAP_ADMIN_USERNAME", "director"),
            "password": os.environ.get("BOOTSTRAP_ADMIN_PASSWORD", "PrimeCool!Dev2026"),
        },
    )
    if r.status_code != 200:
        pytest.skip(f"director login failed: {r.status_code} {r.text[:200]}")
    body = r.json()
    if body.get("requires_mfa"):
        pytest.skip("director login requires MFA — cannot acquire session in tests")
    tok = _extract_session_cookie(r, "pc_admin_session")
    if not tok:
        pytest.skip("director login: no session cookie returned")
    return tok


@pytest.fixture(scope="session")
def supervisor_token(client):
    """A non-super supervisor admin if one exists. Otherwise skip."""
    conn = sqlite3.connect(str(_PROJECT_ROOT / "submissions.db"))
    try:
        row = conn.execute(
            "SELECT username FROM admin_users "
            "WHERE role = 'supervisor_admin' AND active = 1 LIMIT 1"
        ).fetchone()
    finally:
        conn.close()
    if not row:
        pytest.skip("no supervisor_admin user in DB")
    username = row[0]
    # We don't know the password; try the dev bootstrap password as a guess.
    candidates = [
        os.environ.get("BOOTSTRAP_ADMIN_PASSWORD", "PrimeCool!Dev2026"),
        "PrimeCool!Dev2026",
        "password",
    ]
    for pw in candidates:
        r = client.post("/api/admin/login", json={"username": username, "password": pw})
        if r.status_code == 200:
            body = r.json()
            if body.get("requires_mfa"):
                continue
            tok = _extract_session_cookie(r, "pc_admin_session")
            if tok:
                return tok
    pytest.skip(f"could not log in supervisor_admin '{username}' with known dev passwords")


@pytest.fixture(scope="session")
def tech_token(client):
    """First active tech with PIN 123456 (or other dev PIN). Skip if no auth works."""
    conn = sqlite3.connect(str(_PROJECT_ROOT / "submissions.db"))
    try:
        row = conn.execute(
            "SELECT tech_code FROM technicians WHERE active = 1 ORDER BY id LIMIT 1"
        ).fetchone()
    finally:
        conn.close()
    if not row:
        pytest.skip("no technicians seeded")
    tech_code = row[0]
    for pin in ("123456", "1234", "000000"):
        r = client.post("/api/tech/login", json={"tech_code": tech_code, "pin": pin})
        if r.status_code == 200:
            tok = _extract_session_cookie(r, "pc_tech_session")
            if tok:
                return tok
    pytest.skip(f"could not log in tech '{tech_code}' with known dev PINs")


@pytest.fixture(scope="session")
def seeded_resources():
    """Return a dict of seeded record IDs for tests to consume. Returns None
    for any record kind that is not present in the DB; consumers should
    soft-skip if a needed ID is None."""
    db_path = str(_PROJECT_ROOT / "submissions.db")
    if not Path(db_path).exists():
        pytest.skip("submissions.db not present")
    conn = sqlite3.connect(db_path)
    try:
        def _one(sql, *params):
            try:
                row = conn.execute(sql, params).fetchone()
                return row[0] if row else None
            except sqlite3.OperationalError:
                return None

        customer_id = _one("SELECT id FROM customers ORDER BY id LIMIT 1")
        customer_id_alt = None
        if customer_id is not None:
            customer_id_alt = _one(
                "SELECT id FROM customers WHERE id > ? ORDER BY id LIMIT 1",
                customer_id,
            )
        visit_id = _one("SELECT id FROM maintenance_visits ORDER BY id LIMIT 1")
        invoice_id = _one("SELECT id FROM invoices ORDER BY id LIMIT 1")
        tech_id = _one("SELECT id FROM technicians ORDER BY id LIMIT 1")

        try:
            sup_row = conn.execute(
                "SELECT id FROM admin_users WHERE role = 'supervisor_admin' LIMIT 1"
            ).fetchone()
        except sqlite3.OperationalError:
            sup_row = None
        supervisor_user_id = sup_row[0] if sup_row else None

        payslip_id = None
        other_tech_payslip_id = None
        try:
            ps_row = conn.execute(
                "SELECT id, tech_id FROM payslips ORDER BY id LIMIT 1"
            ).fetchone()
            if ps_row:
                payslip_id = ps_row[0]
                other_row = conn.execute(
                    "SELECT id FROM payslips WHERE tech_id != ? ORDER BY id LIMIT 1",
                    (ps_row[1],),
                ).fetchone()
                other_tech_payslip_id = other_row[0] if other_row else None
        except sqlite3.OperationalError:
            pass

        return {
            "customer_id": customer_id,
            "customer_id_alt": customer_id_alt,
            "visit_id": visit_id,
            "invoice_id": invoice_id,
            "tech_id": tech_id,
            "supervisor_user_id": supervisor_user_id,
            "payslip_id": payslip_id,
            "other_tech_payslip_id": other_tech_payslip_id,
        }
    finally:
        conn.close()
