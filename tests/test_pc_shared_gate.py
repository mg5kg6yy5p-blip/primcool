"""
Tests for the access-gate decision matrix. We mirror the PC.canRead /
PC.canWrite logic from static/pc_shared.js in Python here so we can run
the matrix without a JS runtime. If you change one, update the other.

This is a SHADOW test — it does not directly exercise the .js code. A future
upgrade should wire Playwright or Node's jest with JSDOM to run the actual
JS. Until then, this provides regression coverage for the decision rules.
"""
import pytest


def can_read(bundle, target_type, target_id=None):
    if not bundle:
        return False
    if bundle.get('role') == 'super_admin':
        return True
    role_grants = bundle.get('role_grants', [])
    if (target_type + ':view') in role_grants:
        return True
    delegs = bundle.get('delegations', {}) or {}
    by_type = (delegs.get('by_record_type') or {}).get(target_type, [])
    if 'read' in by_type or 'read_write' in by_type:
        return True
    if target_id is not None:
        for g in (delegs.get('by_specific_record') or []):
            if g['resource_type'] == target_type:
                rid = g['resource_id']
                try:
                    matches = rid == target_id or rid == int(target_id)
                except (TypeError, ValueError):
                    matches = False
                if matches and g['permission'] in ('read', 'read_write'):
                    return True
    user_kind = bundle.get('user_kind')
    scope = bundle.get('scope')
    if user_kind == 'tech' and scope == 'assigned_records_only':
        if target_type in ('visit', 'fs_audit', 'fs_exception', 'kpi_score', 'kpi_flag', 'payslip'):
            return True
    if user_kind == 'customer' and scope == 'own_records_only':
        if target_type in ('customer', 'invoice', 'visit', 'equipment', 'payment'):
            return True
    return False


def can_write(bundle, target_type, target_id=None):
    if not bundle:
        return False
    if bundle.get('role') == 'super_admin':
        return True
    rg = bundle.get('role_grants', [])
    if (target_type + ':edit') in rg or (target_type + ':write') in rg:
        return True
    delegs = bundle.get('delegations', {}) or {}
    by_type = (delegs.get('by_record_type') or {}).get(target_type, [])
    if 'read_write' in by_type:
        return True
    if target_id is not None:
        for g in (delegs.get('by_specific_record') or []):
            if g['resource_type'] == target_type:
                rid = g['resource_id']
                try:
                    matches = rid == target_id or rid == int(target_id)
                except (TypeError, ValueError):
                    matches = False
                if matches and g['permission'] == 'read_write':
                    return True
    return False


# ── Fixtures ──────────────────────────────────────────────
def _bundle(**overrides):
    base = {
        'user_id': 1, 'user_kind': 'admin', 'role': 'supervisor_admin',
        'role_grants': [],
        'delegations': {'by_record_type': {}, 'by_specific_record': []},
    }
    base.update(overrides)
    return base


def test_super_admin_always_reads_and_writes():
    b = _bundle(role='super_admin')
    assert can_read(b, 'customer', 123)
    assert can_read(b, 'invoice')
    assert can_read(b, 'audit_log')
    assert can_write(b, 'customer', 123)


def test_no_bundle_denies_all():
    assert not can_read(None, 'customer')
    assert not can_write(None, 'customer')


def test_role_view_grants_read_only():
    b = _bundle(role_grants=['customer:view'])
    assert can_read(b, 'customer', 7)
    assert not can_write(b, 'customer', 7)


def test_role_edit_grants_write():
    b = _bundle(role_grants=['customer:view', 'customer:edit'])
    assert can_write(b, 'customer', 7)


def test_type_level_delegation_read_only():
    b = _bundle(delegations={'by_record_type': {'customer': ['read']}, 'by_specific_record': []})
    assert can_read(b, 'customer', 1)
    assert not can_write(b, 'customer', 1)


def test_type_level_delegation_read_write():
    b = _bundle(delegations={'by_record_type': {'visit': ['read_write']}, 'by_specific_record': []})
    assert can_write(b, 'visit', 1)


def test_record_level_delegation():
    b = _bundle(delegations={'by_record_type': {}, 'by_specific_record': [
        {'resource_type': 'invoice', 'resource_id': 123, 'permission': 'read'}
    ]})
    assert can_read(b, 'invoice', 123)
    assert not can_read(b, 'invoice', 124)
    assert not can_write(b, 'invoice', 123)


def test_record_level_read_write():
    b = _bundle(delegations={'by_record_type': {}, 'by_specific_record': [
        {'resource_type': 'invoice', 'resource_id': 123, 'permission': 'read_write'}
    ]})
    assert can_write(b, 'invoice', 123)


def test_tech_self_scope_reads_own_types():
    b = _bundle(user_kind='tech', scope='assigned_records_only', role='tech')
    assert can_read(b, 'visit', 99)
    assert can_read(b, 'payslip', 99)
    assert not can_read(b, 'customer', 99)


def test_customer_self_scope_reads_own_types():
    b = _bundle(user_kind='customer', scope='own_records_only', role='customer')
    assert can_read(b, 'invoice', 99)
    assert not can_read(b, 'audit_log')


def test_unknown_type_denies():
    b = _bundle(role_grants=['customer:view'])
    assert not can_read(b, 'totally_made_up_thing')


def test_delegation_record_id_type_coercion():
    b = _bundle(delegations={'by_record_type': {}, 'by_specific_record': [
        {'resource_type': 'invoice', 'resource_id': 123, 'permission': 'read'}
    ]})
    assert can_read(b, 'invoice', '123')
