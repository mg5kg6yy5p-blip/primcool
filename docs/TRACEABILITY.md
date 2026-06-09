# Traceability Matrix

Each entity from §3 of the build spec gets a row. A phase gate passes only when
every cell in every row that phase touched is checked **and** pytest is green.

Legend: ☐ = not started · ☑ = complete

| Entity | SQLAlchemy model | Alembic migration | Pydantic schemas | API routes | UI list | UI create/edit | UI detail | Tests |
|---|---|---|---|---|---|---|---|---|
| customer_account     | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ |
| site                 | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ |
| building             | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ |
| space                | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ |
| functional_location  | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ |
| equipment            | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ |
| equipment_install    | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ |
| meter                | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ |
| meter_reading        | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ |
| material             | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ |
| stock_location       | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ |
| stock_quant          | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ |
| equipment_bom        | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ |
| bom_item             | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ |
| notification         | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ |
| work_order           | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ |
| operation            | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ |
| confirmation         | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ |
| confirmation_part    | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ |
| saved_view           | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ |
| service_contract     | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ |
| contract_site        | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ |
| invoice_draft        | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ |
| invoice_draft_line   | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ |
| pm_schedule          | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ |
| audit_log            | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ |

## Phase ownership

- **Phase 1 — Hierarchy & assets:** customer_account, site, building, space,
  functional_location, equipment, equipment_install, meter, meter_reading,
  audit_log.
- **Phase 2 — Notification → triage → order:** notification, work_order,
  operation, saved_view.
- **Phase 3 — Confirmations:** confirmation, confirmation_part, material,
  stock_location, stock_quant (consumption side).
- **Phase 4 — PM engine wiring:** pm_schedule (and meter/meter_reading
  finalization).
- **Phase 5 — Contracts & billing:** service_contract, contract_site,
  invoice_draft, invoice_draft_line, equipment_bom, bom_item.

Some entities span phases (e.g. `material` lifts in Phase 3 for consumption,
but its full UI may not land until Phase 5 alongside billing). Each cell will
be checked when the work for that surface is genuinely shippable, not stubbed.

Last updated: Phase 0 — 2026-06-09
