"""One-off cleanup: remove every tech except T01 + their owned operational
configuration. Run from the project root after a `cp submissions.db
submissions.db.before-tech-cleanup-*` backup.

What gets deleted (per non-T01 tech):
  * fs_assets where assigned_tech_id matches.
  * tech_schedules, tech_on_call_overrides.
  * tech_certifications, tech_cv_entries, tech_cv_edit_requests.
  * tech_overtime_approvals, technician_5s_overrides,
    technician_kpi_overrides, technician_reviews.
  * tech_clock_events, tech_pin_resets.
  * KPI per-tech rows (scores, composites, flags, notes, goals,
    recompute_log, kpi_periods_released_to_tech).
  * fs_coaching_log entries authored by the tech (auditor_id).
  * Finally, the technicians row.

Preserved:
  * fs_audits — append-only chain. Rows for deleted techs stay; the
    chain hash continues to validate. The auditor_id becomes a soft
    reference.
  * maintenance_visits — assigned_tech_id is NULLed so the visit
    history survives without a tech link.
  * invoice_line_items — tech_id is NULLed for the same reason.
  * payslips — historical financial records; subject_id stays even
    though it no longer resolves to a current tech row.

Reason: this is a dev-time reset so that only T01 remains active for
testing the new-tech creation flow (which auto-provisions a vehicle
+ toolkit + Mon–Fri schedule modelled on T01).
"""
from __future__ import annotations

import sqlite3
import sys
from pathlib import Path

DB = Path(__file__).resolve().parent.parent / "submissions.db"
KEEP_TECH_CODE = "T01"


def main() -> int:
    if not DB.exists():
        print(f"submissions.db not found at {DB}", file=sys.stderr)
        return 1
    con = sqlite3.connect(str(DB))
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys = OFF")

    keep_row = con.execute(
        "SELECT id FROM technicians WHERE tech_code = ?", (KEEP_TECH_CODE,)
    ).fetchone()
    if not keep_row:
        print(f"Tech {KEEP_TECH_CODE} not found; nothing safe to do.",
              file=sys.stderr)
        return 1
    keep_id = keep_row["id"]
    targets = [r["id"] for r in con.execute(
        "SELECT id FROM technicians WHERE id != ? ORDER BY id", (keep_id,)
    ).fetchall()]
    if not targets:
        print("Only T01 already; nothing to delete.")
        return 0
    print(f"Kept: tech_id={keep_id} ({KEEP_TECH_CODE})")
    print(f"Targets to remove ({len(targets)}): {targets}")

    placeholders = ",".join("?" * len(targets))

    # Owned config — hard delete.
    owned_tables = [
        # (table, fk_column)
        ("fs_assets",                       "assigned_tech_id"),
        ("tech_schedules",                  "tech_id"),
        ("tech_on_call_overrides",          "tech_id"),
        ("tech_certifications",             "tech_id"),
        ("tech_cv_edit_requests",           "tech_id"),
        ("tech_cv_entries",                 "tech_id"),
        ("tech_overtime_approvals",         "tech_id"),
        ("tech_clock_events",               "tech_id"),
        ("tech_pin_resets",                 "tech_id"),
        ("technician_5s_overrides",         "tech_id"),
        ("technician_kpi_overrides",        "tech_id"),
        ("technician_reviews",              "tech_id"),
        ("kpi_periods_released_to_tech",    "tech_id"),
        ("kpi_scores",                      "tech_id"),
        ("kpi_composite_scores",            "tech_id"),
        ("kpi_flags",                       "tech_id"),
        ("kpi_notes",                       "tech_id"),
        ("kpi_goals",                       "tech_id"),
        ("kpi_recompute_log",               "tech_id"),
        ("fs_coaching_log",                 "tech_id"),
    ]
    for table, col in owned_tables:
        try:
            cur = con.execute(
                f"DELETE FROM {table} WHERE {col} IN ({placeholders})",
                targets,
            )
            print(f"  - {table}.{col}: {cur.rowcount} row(s) removed")
        except sqlite3.OperationalError as e:
            print(f"  - {table}: skipped ({e})")

    # Soft-handled — preserve history with no tech link.
    cur = con.execute(
        f"UPDATE maintenance_visits SET assigned_tech_id = NULL "
        f"WHERE assigned_tech_id IN ({placeholders})", targets,
    )
    print(f"  - maintenance_visits.assigned_tech_id NULLed: {cur.rowcount}")
    try:
        cur = con.execute(
            f"UPDATE invoice_line_items SET tech_id = NULL "
            f"WHERE tech_id IN ({placeholders})", targets,
        )
        print(f"  - invoice_line_items.tech_id NULLed: {cur.rowcount}")
    except sqlite3.OperationalError as e:
        print(f"  - invoice_line_items: skipped ({e})")

    # Finally, the technicians row itself.
    cur = con.execute(
        f"DELETE FROM technicians WHERE id IN ({placeholders})", targets,
    )
    print(f"  - technicians: {cur.rowcount} row(s) removed")

    con.commit()
    con.close()
    print("Done.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
