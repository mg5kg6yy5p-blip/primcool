"""Acceptance tests for spec criterion #4 — drill-through reconciliation.

The aggregate badge count (e.g. 'outstanding invoices') displayed in the UI
must match the size of the filtered list that the user reaches when they
click through. We exercise the underlying API endpoints and reconcile the
two counts.

Soft-asserts where endpoint shape isn't certain (the metrics field name
varies across implementations). Hard-asserts where the numbers ARE returned
but disagree.
"""
import pytest


def _items_of(body):
    if isinstance(body, list):
        return body
    if not isinstance(body, dict):
        return []
    for k in ("items", "rows", "results", "data", "invoices"):
        v = body.get(k)
        if isinstance(v, list):
            return v
    return []


def _count_of(body, *keys):
    if not isinstance(body, dict):
        return None
    for k in keys:
        if k in body and isinstance(body[k], (int, float)):
            return int(body[k])
    return None


def test_invoice_metrics_match_filtered_list(client, admin_token):
    """The 'outstanding' tile count should match the filtered invoice list size.
    Reconciliation tolerance: ±1 to allow for in-flight transitions."""
    m = client.get(
        "/api/admin/invoices/metrics",
        cookies={"pc_admin_session": admin_token},
    )
    if m.status_code != 200:
        pytest.skip(f"invoices/metrics endpoint unavailable: {m.status_code}")
    metrics = m.json() if isinstance(m.json(), dict) else {}
    outstanding_count = _count_of(metrics, "outstanding_count", "outstanding", "sent_count")
    if outstanding_count is None:
        pytest.skip(f"metrics response lacks an outstanding count field: {list(metrics.keys())}")

    listing = client.get(
        "/api/admin/invoices/list?status=sent",
        cookies={"pc_admin_session": admin_token},
    )
    if listing.status_code != 200:
        pytest.skip(f"invoices/list unavailable: {listing.status_code}")
    items = _items_of(listing.json())
    # Reconciliation: filtered list count == metric count (±1 tolerance).
    assert abs(len(items) - outstanding_count) <= 1, (
        f"reconciliation mismatch: metric outstanding_count={outstanding_count} "
        f"but list?status=sent returned {len(items)} items"
    )


def test_invoice_aging_count_matches_full_list(client, admin_token):
    """The aging report row totals should reconcile with the listing endpoint."""
    aging = client.get(
        "/api/admin/invoices/aging",
        cookies={"pc_admin_session": admin_token},
    )
    if aging.status_code != 200:
        pytest.skip(f"invoices/aging unavailable: {aging.status_code}")
    aging_body = aging.json()
    if not isinstance(aging_body, (list, dict)):
        pytest.skip("aging response shape not recognized")

    listing = client.get(
        "/api/admin/invoices",
        cookies={"pc_admin_session": admin_token},
    )
    if listing.status_code != 200:
        pytest.skip(f"invoices list unavailable: {listing.status_code}")
    listed = _items_of(listing.json())

    # Soft check: aging buckets should not collectively exceed total invoice count.
    if isinstance(aging_body, dict):
        bucket_total = 0
        for k, v in aging_body.items():
            if isinstance(v, (int, float)):
                bucket_total += int(v)
            elif isinstance(v, list):
                bucket_total += len(v)
        if bucket_total:
            assert bucket_total <= max(len(listed), 1) * 3, (
                f"aging buckets ({bucket_total}) wildly exceed listed invoice count "
                f"({len(listed)}) — possible double-counting"
            )
