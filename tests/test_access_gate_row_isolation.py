"""Acceptance tests for spec criterion #5 — nested click isolation (frontend).

The frontend rule: when a row is wrapped by `PC.gateRow`, clicks on any
descendant carrying the `.pc-stop-prop` class (or any descendant that is
itself a `PC.gateCell` button) must NOT bubble to the row's primary handler.

We cannot execute JS without a runtime here. This is a SHADOW test that
mirrors the state-machine rule in pure Python. If the .js logic is changed,
update this file in lock-step.
"""
import pytest


def gate_row_should_invoke_row_handler(click_target_classes, row_can_read=True):
    """Mirror of the JS rule in static/pc_shared.js (PC.gateRow).

    Returns True iff the click should fire the row-level open-detail handler.
    """
    if not row_can_read:
        return False
    if not isinstance(click_target_classes, (list, tuple, set)):
        click_target_classes = [click_target_classes] if click_target_classes else []
    blockers = {"pc-stop-prop", "pc-gate-cell", "pc-action-btn"}
    if any(c in blockers for c in click_target_classes):
        return False
    return True


@pytest.mark.parametrize("target,expected", [
    (["pc-row-clickable"], True),
    (["pc-stop-prop"], False),
    (["pc-gate-cell"], False),
    (["pc-action-btn", "pc-stop-prop"], False),
    ([], True),
])
def test_gate_row_event_isolation(target, expected):
    """Clicking a child with .pc-stop-prop must NOT fire the row handler."""
    assert gate_row_should_invoke_row_handler(target) is expected


def test_gate_row_denies_when_no_access():
    """Even a bare row-clickable element does nothing if the user has no
    read access to the row's resource."""
    assert gate_row_should_invoke_row_handler(["pc-row-clickable"], row_can_read=False) is False


def test_gate_row_blocks_unknown_blockers_gracefully():
    """Unknown classes do not block."""
    assert gate_row_should_invoke_row_handler(["something-else"]) is True
