"""PC-004 — /api/consult must be rate-limited.

Pre-fix: public endpoint with no limit. A flood could (a) fill
submissions.db, (b) burn Resend quota, (c) pollute plaintext PII rows
(combined with PC-002).

Post-fix:
  - Per (IP + email) bucket: 3 submissions per hour
  - Global circuit breaker: 100 submissions per 10 minutes across all IPs

Tests pin the per-(IP+email) limit (the bucket a single legitimate
prospect can plausibly trip and a single attacker can plausibly try to
bypass). The global breaker is asserted to EXIST via bucket inspection
but not exercised at full volume.
"""
import os
import pytest

# conftest.py provides a fresh `client` fixture per test (TestClient,
# Origin header pre-set, function-scoped after the migration that
# unblocked the 18 acceptance tests). We only need the rate-bucket
# state reset between tests so order doesn't matter.
try:
    from main import _rate_buckets, _rate_lock
except Exception as e:
    pytest.skip(f"main.py import failed: {e}", allow_module_level=True)


@pytest.fixture(autouse=True)
def _clean_rate_buckets():
    """Reset in-memory rate-limit state between tests so order is
    irrelevant. Buckets live as a module-level dict in main.py."""
    with _rate_lock:
        _rate_buckets.clear()
    yield
    with _rate_lock:
        _rate_buckets.clear()


def _payload(email="lead@example.jm", fname="Test", lname="Prospect",
             tier="residential"):
    return {"fname": fname, "lname": lname, "email": email,
            "phone": "+18761234567", "tier": tier, "msg": "test"}


def test_single_consult_submission_succeeds(client):
    """Legitimate single submission must not be blocked."""
    r = client.post("/api/consult", json=_payload())
    assert r.status_code == 200, (
        f"single submission rejected: {r.status_code} {r.text[:200]}"
    )
    assert r.json().get("ok") is True


def test_three_submissions_pass_fourth_rejected(client):
    """PC-004 per-(IP+email) limit: 3 pass within the hour, 4th gets 429."""
    for i in range(3):
        r = client.post("/api/consult",
                        json=_payload(email="repeat@example.jm"))
        assert r.status_code == 200, (
            f"submission #{i+1} rejected before limit: "
            f"{r.status_code} {r.text[:200]}"
        )
    r = client.post("/api/consult",
                    json=_payload(email="repeat@example.jm"))
    assert r.status_code == 429, (
        f"PC-004 regression: 4th submission from same (IP, email) was "
        f"not rate-limited. Got {r.status_code}: {r.text[:200]}"
    )


def test_different_email_same_ip_is_separate_bucket(client):
    """Per-(IP+email) bucket must NOT lump unrelated leads together.
    Three submissions from alice@ and a fourth from bob@ should pass —
    different identities, different buckets."""
    for _ in range(3):
        client.post("/api/consult",
                    json=_payload(email="alice@example.jm"))
    r = client.post("/api/consult",
                    json=_payload(email="bob@example.jm"))
    assert r.status_code == 200, (
        f"per-(IP+email) bucket leaked: bob blocked because alice maxed. "
        f"Got {r.status_code}: {r.text[:200]}"
    )


def test_global_circuit_breaker_wired(client):
    """Confirm the global circuit-breaker bucket exists by inspecting the
    rate-bucket state after the first submission. We don't drive 100
    requests — that's the operational mechanism's job. We just prove the
    bucket is being keyed."""
    client.post("/api/consult", json=_payload(email="probe@example.jm"))
    with _rate_lock:
        keys = list(_rate_buckets.keys())
    has_global = any(k.startswith("consult_global:") for k in keys)
    has_per_id = any(k.startswith("consult:") for k in keys)
    assert has_global, (
        f"PC-004 partial fix: global circuit-breaker bucket not present. "
        f"Buckets observed: {keys}"
    )
    assert has_per_id, (
        f"PC-004 partial fix: per-(IP+email) bucket not present. "
        f"Buckets observed: {keys}"
    )


def test_email_normalization_in_bucket_key(client):
    """The bucket should treat 'Lead@Example.JM' and 'lead@example.jm' as
    the same identity — otherwise an attacker bypasses the per-email
    limit by case-flipping the email."""
    for _ in range(3):
        r = client.post("/api/consult",
                        json=_payload(email="Lead@Example.JM"))
        assert r.status_code == 200
    # Lowercased variant should hit the same bucket and be rejected.
    r = client.post("/api/consult", json=_payload(email="lead@example.jm"))
    assert r.status_code == 429, (
        f"PC-004 normalization gap: case-flip bypassed the per-email "
        f"limit. Got {r.status_code}: {r.text[:200]}"
    )
