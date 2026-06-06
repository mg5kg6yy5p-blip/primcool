"""Acceptance tests for the 2026-06-06 delegation retrofit.

Before the retrofit, a large set of admin endpoints (invoice metrics/list/
export, fx-rates, parts search, every technician sub-resource, customer
visit history, visit photos, invoice send/cancel/payment) hard-gated on the
super_admin role via `_require_super_admin`. After the retrofit:

  * record-scoped endpoints (path names a customer/visit/invoice/technician)
    flow through `_require_record_access`, so a matching record / record_type /
    power delegation opens them;
  * collection / global endpoints flow through `_require_admin_or_power`, so
    only a blanket *power* delegation (or the super_admin role) opens them;
  * two meta-governance surfaces stay hard super_admin on purpose — the
    access-denied audit reader and the delegation regrant-request queue — so a
    power-delegate must NOT reach them.

These assert the live authorization path (no mocks). Each test cleans up its
own delegation rows.
"""
import pytest


# Representative endpoints for each retrofit class.
COLLECTION_EP = "/api/admin/invoices/metrics"          # power-or-super
GOVERNANCE_EP = "/api/admin/audit/access-denied?limit=1"  # stays super_admin-only


def _tech_ep(tech_id):
    # record-scoped (read) on a technician record
    return f"/api/admin/technicians/{tech_id}/certifications"


def _grant(client, admin_token, *, recipient_id, delegation_type,
           scope_record_type=None, scope_record_id=None,
           permission_level=None, notes="retrofit test"):
    payload = {
        "recipient_id": recipient_id,
        "recipient_kind": "admin",
        "delegation_type": delegation_type,
        "grantor_notes": notes,
    }
    if scope_record_type is not None:
        payload["scope_record_type"] = scope_record_type
    if scope_record_id is not None:
        payload["scope_record_id"] = scope_record_id
    if permission_level is not None:
        payload["permission_level"] = permission_level
    return client.post("/api/admin/delegations",
                       cookies={"pc_admin_session": admin_token}, json=payload)


def _revoke(client, admin_token, delegation_id):
    return client.post(f"/api/admin/delegations/{delegation_id}/revoke",
                       cookies={"pc_admin_session": admin_token},
                       json={"reason": "retrofit test cleanup"})


def _grant_id(resp):
    body = resp.json()
    return body.get("id") or body.get("delegation_id")


def test_superadmin_still_passes_retrofitted_endpoints(client, admin_token, seeded_resources):
    """Regression guard: the super_admin role must still reach every
    retrofitted endpoint exactly as before."""
    tech_id = seeded_resources.get("tech_id")
    if tech_id is None:
        pytest.skip("no tech seeded")
    r1 = client.get(COLLECTION_EP, cookies={"pc_admin_session": admin_token})
    assert r1.status_code == 200, f"collection ep regressed for super_admin: {r1.status_code} {r1.text[:200]}"
    r2 = client.get(_tech_ep(tech_id), cookies={"pc_admin_session": admin_token})
    assert r2.status_code == 200, f"tech ep regressed for super_admin: {r2.status_code} {r2.text[:200]}"
    r3 = client.get(GOVERNANCE_EP, cookies={"pc_admin_session": admin_token})
    assert r3.status_code == 200, f"governance ep regressed for super_admin: {r3.status_code} {r3.text[:200]}"


def test_supervisor_denied_without_delegation(client, supervisor_token, seeded_resources):
    """No widening: a non-super admin with no delegation is still denied on
    the retrofitted endpoints, just as `_require_super_admin` denied them."""
    tech_id = seeded_resources.get("tech_id")
    if tech_id is None:
        pytest.skip("no tech seeded")
    r1 = client.get(COLLECTION_EP, cookies={"pc_admin_session": supervisor_token})
    assert r1.status_code in (401, 403), f"collection ep wrongly open to supervisor: {r1.status_code}"
    r2 = client.get(_tech_ep(tech_id), cookies={"pc_admin_session": supervisor_token})
    assert r2.status_code in (401, 403), f"tech ep wrongly open to supervisor: {r2.status_code}"


def test_power_delegation_opens_collection_and_record(client, admin_token, supervisor_token, seeded_resources):
    """A blanket power delegation lets a supervisor reach BOTH a collection
    endpoint and a record-scoped endpoint. Revoking closes them again."""
    tech_id = seeded_resources.get("tech_id")
    sup_id = seeded_resources.get("supervisor_user_id")
    if tech_id is None or sup_id is None:
        pytest.skip("missing tech or supervisor in seed data")
    # Pre-state must be denied, else the flip is unobservable.
    pre = client.get(COLLECTION_EP, cookies={"pc_admin_session": supervisor_token})
    if pre.status_code == 200:
        pytest.skip("supervisor already reaches collection ep — cannot exercise grant flip")

    g = _grant(client, admin_token, recipient_id=sup_id, delegation_type="power")
    assert g.status_code in (200, 201), g.text[:300]
    did = _grant_id(g)
    assert did, f"power grant missing id: {g.json()!r}"
    try:
        r1 = client.get(COLLECTION_EP, cookies={"pc_admin_session": supervisor_token})
        assert r1.status_code == 200, f"power deleg did not open collection ep: {r1.status_code} {r1.text[:200]}"
        r2 = client.get(_tech_ep(tech_id), cookies={"pc_admin_session": supervisor_token})
        assert r2.status_code == 200, f"power deleg did not open tech ep: {r2.status_code} {r2.text[:200]}"
        # Governance surface must stay locked even for a power delegate.
        r3 = client.get(GOVERNANCE_EP, cookies={"pc_admin_session": supervisor_token})
        assert r3.status_code in (401, 403), \
            f"power deleg wrongly opened governance ep: {r3.status_code}"
    finally:
        rev = _revoke(client, admin_token, did)
        assert rev.status_code in (200, 204), rev.text[:200]
    # Closed again after revoke.
    r4 = client.get(COLLECTION_EP, cookies={"pc_admin_session": supervisor_token})
    assert r4.status_code in (401, 403), f"collection ep still open after revoke: {r4.status_code}"


def test_record_type_delegation_opens_record_not_collection(client, admin_token, supervisor_token, seeded_resources):
    """A technician record_type delegation opens technician record endpoints
    but NOT a collection endpoint (which only a power grant covers)."""
    tech_id = seeded_resources.get("tech_id")
    sup_id = seeded_resources.get("supervisor_user_id")
    if tech_id is None or sup_id is None:
        pytest.skip("missing tech or supervisor in seed data")
    pre = client.get(_tech_ep(tech_id), cookies={"pc_admin_session": supervisor_token})
    if pre.status_code == 200:
        pytest.skip("supervisor already reaches tech ep — cannot exercise grant flip")

    g = _grant(client, admin_token, recipient_id=sup_id,
               delegation_type="record_type", scope_record_type="technician",
               permission_level="read")
    assert g.status_code in (200, 201), g.text[:300]
    did = _grant_id(g)
    assert did, f"record_type grant missing id: {g.json()!r}"
    try:
        r1 = client.get(_tech_ep(tech_id), cookies={"pc_admin_session": supervisor_token})
        assert r1.status_code == 200, f"record_type deleg did not open tech ep: {r1.status_code} {r1.text[:200]}"
        # A record_type(technician) grant must NOT reach the collection endpoint.
        r2 = client.get(COLLECTION_EP, cookies={"pc_admin_session": supervisor_token})
        assert r2.status_code in (401, 403), \
            f"record_type deleg wrongly opened collection ep: {r2.status_code}"
    finally:
        rev = _revoke(client, admin_token, did)
        assert rev.status_code in (200, 204), rev.text[:200]
    r3 = client.get(_tech_ep(tech_id), cookies={"pc_admin_session": supervisor_token})
    assert r3.status_code in (401, 403), f"tech ep still open after revoke: {r3.status_code}"
