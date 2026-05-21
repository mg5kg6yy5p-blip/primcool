# PrimeCool tests

This directory holds Python-side unit tests for the access-gate decision
matrix used by the SPA gate helpers in `static/pc_shared.js`.

## Why this directory exists

Before the universal access-gated navigation work, the codebase had no
isolated unit-test surface for the new permission logic that powers
`PC.canRead` / `PC.canWrite` and the `PC.gate*` render helpers. Without
tests, the boolean decision rules (role grants, type-level delegations,
record-level delegations, self-scope) are easy to regress silently.

## The shadow-test pattern

We do not run JavaScript in this test suite. Instead, the test file
`test_pc_shared_gate.py` reimplements the same decision logic in Python
and runs a fixture table through it. This gives us regression coverage
of the rules without taking a JS-runtime dependency (Node + JSDOM, or
Playwright).

**Contract:** when you change `PC.canRead` or `PC.canWrite` in
`static/pc_shared.js`, update the Python mirror in
`tests/test_pc_shared_gate.py` to match. They MUST stay in sync.

## How to run

```
pytest tests/
```

If pytest isn't installed:
```
pip install pytest
pytest tests/
```

## What's NOT tested yet

- The actual JavaScript code in `static/pc_shared.js` is not executed.
- No Playwright / Selenium / JSDOM browser-render assertions.
- No end-to-end coverage of `PC.gateLink`, `PC.gateRow`, `PC.gateBadge`
  DOM behavior (event handlers, class application, click-target
  isolation).
- No coverage of the access-bundle loader caching/expiry behavior.
- No coverage of the auto-detected access-bundle URL by path.

Future upgrade: wire Node + jest + JSDOM (or Playwright) to exercise
the real JS so the shadow can be retired.
