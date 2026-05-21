"""Acceptance tests for spec criterion #3 — delegation lifecycle.

Verifies that:
  * Granting a record-level delegation to a non-super admin actually opens
    up the URL the supervisor was previously denied.
  * Revoking that delegation closes access again.
  * A delegation with valid_until in the past does not grant access.

These tests mutate global state (insert and revoke delegations). They run
inside the in-process app fixture, so changes persist into submissions.db.
That is intentional — the test asserts the real authorization path, not a
mock. Each test cleans up its own delegation row on success.
"""
from datetime import datetime, timedelta, timezone

import pytest


def _post_grant(client, admin_token, recipient_id, customer_id,
                permission_level="read", valid_until=None, notes="test"):
    payload = {
        "recipient_id": recipient_id,
        "delegation_type": "record",
        "scope_record_type": "customer",
        "scope_record_id": customer_id,
        "permission_level": permission_level,
        "grantor_notes": notes,
    }
    if valid_until is not None:
        payload["valid_until"] = valid_until
    return client.post(
        "/api/admin/delegations",
        cookies={"pc_admin_session": admin_token},
        json=payload,
    )


def _revoke(client, admin_token, delegation_id):
    return client.post(
        f"/api/admin/delegations/{delegation_id}/revoke",
        cookies={"pc_admin_session": admin_token},
        json={"reason": "test cleanup"},
    )


def test_delegation_grants_then_revokes_access(
    client, admin_token, supervisor_token, seeded_resources
):
    """super_admin grants supervisor record-level read on a customer → supervisor
    can read. Then super_admin revokes → supervisor denied."""
    customer_id = seeded_resources.get("customer_id")
    supervisor_user_id = seeded_resources.get("supervisor_user_id")
    if customer_id is None or supervisor_user_id is None:
        pytest.skip("missing customer or supervisor in seed data")

    # 1. Probe initial state. We don't assert denial here because the
    #    supervisor's role-grants may already include customer:view; that case
    #    makes the rest of this test a no-op and we skip.
    pre = client.get(
        f"/api/admin/customers/{customer_id}",
        cookies={"pc_admin_session": supervisor_token},
    )
    if pre.status_code == 200:
        pytest.skip("supervisor already has role-level access — cannot exercise grant flip")

    # 2. Grant
    grant = _post_grant(client, admin_token, supervisor_user_id, customer_id)
    assert grant.status_code in (200, 201), grant.text[:300]
    body = grant.json()
    delegation_id = body.get("id") or body.get("delegation_id")
    assert delegation_id, f"grant response missing id: {body!r}"

    try:
        # 3. supervisor should now read the customer
        res2 = client.get(
            f"/api/admin/customers/{customer_id}",
            cookies={"pc_admin_session": supervisor_token},
        )
        assert res2.status_code == 200, \
            f"supervisor still denied after grant: {res2.status_code} {res2.text[:200]}"
    finally:
        # 4. revoke (always, even if assertions above failed)
        rev = _revoke(client, admin_token, delegation_id)
        assert rev.status_code in (200, 204), rev.text[:200]

    # 5. supervisor should be denied again
    res3 = client.get(
        f"/api/admin/customers/{customer_id}",
        cookies={"pc_admin_session": supervisor_token},
    )
    assert res3.status_code in (403, 404), \
        f"supervisor still has access after revoke: {res3.status_code}"


def test_expired_delegation_denies_access(
    client, admin_token, supervisor_token, seeded_resources
):
    """Grant with valid_until in the past → access denied."""
    customer_id = seeded_resources.get("customer_id_alt") or seeded_resources.get("customer_id")
    supervisor_user_id = seeded_resources.get("supervisor_user_id")
    if customer_id is None or supervisor_user_id is None:
        pytest.skip("missing customer or supervisor in seed data")

    pre = client.get(
        f"/api/admin/customers/{customer_id}",
        cookies={"pc_admin_session": supervisor_token},
    )
    if pre.status_code == 200:
        pytest.skip("supervisor already has role-level access — cannot exercise expiry")

    yesterday = (datetime.now(timezone.utc) - timedelta(days=1)).strftime("%Y-%m-%d")
    grant = _post_grant(
        client, admin_token, supervisor_user_id, customer_id,
        valid_until=yesterday, notes="expired test",
    )
    # The grant may be rejected outright (422) for being already-expired, or
    # may be accepted but treated as inactive on read. Both are acceptable.
    delegation_id = None
    if grant.status_code in (200, 201):
        body = grant.json()
        delegation_id = body.get("id") or body.get("delegation_id")
    else:
        assert grant.status_code in (400, 422), grant.text[:200]

    try:
        res = client.get(
            f"/api/admin/customers/{customer_id}",
            cookies={"pc_admin_session": supervisor_token},
        )
        assert res.status_code in (403, 404), \
            f"expired delegation still grants access: {res.status_code}"
    finally:
        if delegation_id is not None:
            _revoke(client, admin_token, delegation_id)


def test_self_grant_rejected(client, admin_token, seeded_resources):
    """Sanity: super_admin cannot grant a delegation to themselves.
    Catches the 'locked rule 4' regression in one HTTP round-trip."""
    customer_id = seeded_resources.get("customer_id")
    if customer_id is None:
        pytest.skip("no customer in seed data")
    # Fetch own admin id via /api/admin/me
    me = client.get("/api/admin/me", cookies={"pc_admin_session": admin_token})
    if me.status_code != 200:
        pytest.skip("could not introspect own admin id")
    own_id = me.json().get("id")
    if not own_id:
        pytest.skip("admin/me did not return id")
    res = _post_grant(client, admin_token, own_id, customer_id, notes="self grant")
    assert res.status_code in (400, 422), \
        f"self-grant should be rejected, got {res.status_code}"
