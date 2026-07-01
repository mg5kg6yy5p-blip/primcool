"""PC-003 — _client_ip must NOT honor X-Forwarded-For at the app layer.

Pre-fix behavior: any internet client could send X-Forwarded-For: 1.2.3.4
and the app would record 1.2.3.4 as the client IP, defeating per-IP rate
limits and polluting audit ip_address.

Post-fix behavior: _client_ip returns request.client.host ONLY. The
X-Forwarded-For resolution is handled UPSTREAM by uvicorn's --proxy-headers
flag (railway.toml) and is gated by --forwarded-allow-ips. Without that
gate, no app-layer code reads the header.

These are unit tests on _client_ip directly. They construct a Starlette
Request from a synthetic ASGI scope so we control client.host and headers.
"""
from starlette.requests import Request

# Make _client_ip importable without booting the full app preflight.
# main.py runs _preflight_run() at import time and requires JWT_SECRET +
# FIELD_ENCRYPTION_KEY in env. conftest.py loads .dev.env; if that's
# unavailable, skip this module.
try:
    import os
    if "JWT_SECRET" not in os.environ:
        # Fallback: try the dev env file directly.
        try:
            for line in open(".dev.env"):
                if line.startswith("export "):
                    k, v = line[7:].strip().split("=", 1)
                    os.environ.setdefault(k, v.strip('"'))
        except FileNotFoundError:
            pass
    from main import _client_ip
except Exception as e:
    import pytest
    pytest.skip(f"main.py preflight failed (likely missing env): {e}",
                allow_module_level=True)


def _make_request(client_host: str = "203.0.113.42",
                  headers: dict = None) -> Request:
    """Build a Starlette Request with controllable client.host + headers."""
    headers = headers or {}
    raw_headers = [(k.lower().encode(), v.encode()) for k, v in headers.items()]
    scope = {
        "type":         "http",
        "method":       "GET",
        "scheme":       "http",
        "path":         "/",
        "raw_path":     b"/",
        "query_string": b"",
        "headers":      raw_headers,
        "client":       (client_host, 50000),
        "server":       ("testserver", 80),
    }
    return Request(scope)


def test_client_ip_returns_actual_client_host_no_headers():
    """Sanity: with no XFF header, return the real client.host."""
    req = _make_request(client_host="203.0.113.42")
    assert _client_ip(req) == "203.0.113.42"


def test_client_ip_ignores_forged_x_forwarded_for():
    """PC-003 core: a forged X-Forwarded-For must NOT change the returned IP.

    Pre-fix this returned '1.2.3.4' because the app trusted the header.
    Post-fix it must return the real connecting client's IP unchanged.
    """
    req = _make_request(client_host="203.0.113.42",
                        headers={"X-Forwarded-For": "1.2.3.4"})
    assert _client_ip(req) == "203.0.113.42", (
        "PC-003 regression: _client_ip should ignore X-Forwarded-For at the "
        "app layer. The fix lives in railway.toml (--proxy-headers + "
        "--forwarded-allow-ips). If a forged header is changing the return "
        "value, the app-layer header read has crept back in."
    )


def test_client_ip_ignores_chain_of_forged_hops():
    """Even with a comma-separated chain, no header value should leak in."""
    req = _make_request(client_host="203.0.113.42",
                        headers={"X-Forwarded-For":
                                 "1.2.3.4, 5.6.7.8, 9.10.11.12"})
    assert _client_ip(req) == "203.0.113.42"


def test_client_ip_ignores_x_real_ip_too():
    """Other proxy headers must also be untrusted at the app layer."""
    req = _make_request(client_host="203.0.113.42",
                        headers={"X-Real-IP": "1.2.3.4",
                                 "Forwarded": "for=1.2.3.4"})
    assert _client_ip(req) == "203.0.113.42"


def test_client_ip_handles_missing_client_gracefully():
    """If somehow scope.client is None, return the '?' sentinel — not crash
    and not silently return any header value."""
    scope = {
        "type":         "http",
        "method":       "GET",
        "scheme":       "http",
        "path":         "/",
        "raw_path":     b"/",
        "query_string": b"",
        "headers":      [(b"x-forwarded-for", b"1.2.3.4")],
        "client":       None,
        "server":       ("testserver", 80),
    }
    req = Request(scope)
    assert _client_ip(req) == "?"
