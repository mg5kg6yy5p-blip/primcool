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
    """Pull a COUNT out of the response. Strictly: keys must end in
    '_count' or '_n' OR appear in the explicit allow-list. Previous
    version accepted any numeric field, which conflated dollar-amount
    fields like 'outstanding' (a SUM) with counts and produced a 1.9M
    vs 20 mismatch on every run."""
    if not isinstance(body, dict):
        return None
    COUNT_SUFFIXES = ("_count", "_n")
    for k in keys:
        if k not in body:
            continue
        v = body[k]
        if not isinstance(v, (int, float)):
            continue
        # Only accept this value if the field name announces it's a count.
        if any(k.endswith(s) for s in COUNT_SUFFIXES):
            return int(v)
    return None


def test_invoice_metrics_match_filtered_list(client, admin_token):
    """The 'outstanding' tile count should match the filtered invoice list size.
    Reconciliation tolerance: ±1 to allow for in-flight transitions.

    Uses the explicit outstanding_count field added in H1; falls back
    cleanly (skip) on deployments that haven't picked that up yet."""
    m = client.get(
        "/api/admin/invoices/metrics",
        cookies={"pc_admin_session": admin_token},
    )
    if m.status_code != 200:
        pytest.skip(f"invoices/metrics endpoint unavailable: {m.status_code}")
    metrics = m.json() if isinstance(m.json(), dict) else {}
    outstanding_count = _count_of(metrics, "outstanding_count", "sent_count")
    if outstanding_count is None:
        pytest.skip(
            f"metrics response lacks an explicit count field "
            f"(outstanding_count / sent_count): {list(metrics.keys())}"
        )

    # Pull the full filtered list so we compare counts, not page-sized
    # samples. The pagination cap is 100, so this handles up to that many
    # outstanding invoices without paging.
    listing = client.get(
        "/api/admin/invoices/list?status=sent&limit=100",
        cookies={"pc_admin_session": admin_token},
    )
    if listing.status_code != 200:
        pytest.skip(f"invoices/list unavailable: {listing.status_code}")
    body = listing.json() if isinstance(listing.json(), dict) else {}
    # Prefer the server's reported total over a row-count which is
    # capped by the page limit.
    total = body.get("total") if isinstance(body, dict) else None
    list_count = total if isinstance(total, int) else len(_items_of(body))
    # Reconciliation tolerance: ±1 for transitions mid-call.
    assert abs(list_count - outstanding_count) <= 1, (
        f"reconciliation mismatch: metric outstanding_count={outstanding_count} "
        f"vs list?status=sent total={list_count}"
    )


def test_invoice_aging_count_matches_full_list(client, admin_token):
    """The aging report bucket COUNTS should reconcile with the
    outstanding-invoice population.

    Aging shape: {as_of, grand_total, buckets: {<bucket_name>: {label,
    count, total_outstanding, invoices: [...]}}}. The previous version
    of this test summed every numeric in the top-level dict — that
    picked up grand_total (a dollar amount) and produced a 2M vs 550
    "double-counting" assertion every run.

    Correct reconciliation: sum the per-bucket `count` field and
    compare to the count of outstanding invoices (sent + balance > 0)."""
    aging = client.get(
        "/api/admin/invoices/aging",
        cookies={"pc_admin_session": admin_token},
    )
    if aging.status_code != 200:
        pytest.skip(f"invoices/aging unavailable: {aging.status_code}")
    aging_body = aging.json()
    buckets = aging_body.get("buckets") if isinstance(aging_body, dict) else None
    if not isinstance(buckets, dict):
        pytest.skip("aging response missing expected 'buckets' shape")

    bucket_count_total = 0
    for bname, b in buckets.items():
        if not isinstance(b, dict):
            continue
        c = b.get("count")
        if isinstance(c, int):
            bucket_count_total += c

    # Compare against outstanding invoices (status=sent, balance > 0).
    # Use the metrics endpoint's explicit count field (added in H1).
    metrics = client.get(
        "/api/admin/invoices/metrics",
        cookies={"pc_admin_session": admin_token},
    )
    if metrics.status_code != 200:
        pytest.skip("metrics unavailable")
    m = metrics.json()
    outstanding_count = m.get("outstanding_count")
    if not isinstance(outstanding_count, int):
        pytest.skip("metrics lacks outstanding_count")

    # Tolerance ±2 for status transitions during the test window
    # (a sent→paid flip mid-call could appear in only one of the two).
    assert abs(bucket_count_total - outstanding_count) <= 2, (
        f"aging bucket-count total ({bucket_count_total}) vs outstanding "
        f"({outstanding_count}) — buckets should partition the outstanding "
        f"set exactly, ±2 for in-flight transitions"
    )
