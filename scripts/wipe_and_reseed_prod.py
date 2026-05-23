"""Wipe dev seed data and prepare submissions.db for the first real
customer record.

USAGE
-----
    python3 scripts/wipe_and_reseed_prod.py            # dry-run; prints plan
    python3 scripts/wipe_and_reseed_prod.py --apply    # mutate the DB

WHAT IT REMOVES
---------------
Per pre-launch checklist item #4 in docs/FIXMES.md: every row that was
created by the demo seeders (seed_demo.py / seed_full_demo.py).

  * Customers + every dependent row (visits, equipment, invoices,
    invoice_payments, invoice_line_items, reviews, documents)
  * Maintenance visits + visit_readings / visit_parts / visit_photos
  * Invoices + line items + payments + adjustments
  * fs_audits + fs_audit_items + fs_exceptions + fs_exception_events
  * KPI scores / composite scores / flags / notes / goals / recompute_log
  * Audit + access logs (operational; financial 7-year retention
    obligation means we KEEP rows where target_type='invoice' /
    'invoice_payment' regardless)
  * security_alerts (re-emit on first real boot)
  * sessions (forces every active user to re-login)
  * tech_clock_events + tech_certifications + tech_cv_entries +
    technician_reviews (the operational scaffolding around tests)

WHAT IT PRESERVES
-----------------
  * admin_users — keep, but flag must_change_credentials=1 on each so
    the first prod login forces a password reset (item #2).
  * technicians — keep, but flag must_change_credentials=1 on each.
  * Schema. No DROP TABLE. All tables remain; only rows go.
  * audit_log rows for retention-eligible financial actions.
  * FIXMES.md, scripts/, .env.example, code.

POST-RUN CHECKLIST
------------------
  1. Run `bash scripts/backup_restore_drill.sh` — should pass.
  2. Start the app with PROD_MODE=true, fresh secrets from
     `python3 scripts/rotate_secrets.py > .env.prod`.
  3. Bootstrap super_admin via the BOOTSTRAP_ADMIN_* env vars at
     first boot; bootstrap_super_admin sets must_change_credentials=1
     automatically.
  4. Sign in as that super_admin and exercise the forced-reset flow.
  5. Re-add real prospect customers via the admin UI.

This script is intentionally REVERSIBLE only via the most recent
backup. It refuses to run unless a *.tar.gpg or *.db.bak-* file
younger than 24h exists in the project root (or BACKUP_DIR), so a
runtime accident doesn't nuke a fresh-seeded prod DB."""
from __future__ import annotations

import argparse
import datetime as _dt
import os
import sqlite3
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DB = ROOT / "submissions.db"

# Rows to delete in dependency-safe order (child tables first).
DELETE_ORDER = [
    # 5S forensics chain
    "fs_audit_items",
    "fs_exception_events",
    "fs_exceptions",
    "fs_audits",
    "fs_coaching_log",
    # KPI per-tech
    "kpi_scores",
    "kpi_composite_scores",
    "kpi_flags",
    "kpi_notes",
    "kpi_goals",
    "kpi_recompute_log",
    "kpi_periods_released_to_tech",
    # Tech operational
    "tech_overtime_approvals",
    "tech_on_call_overrides",
    "tech_clock_events",
    "tech_schedules",
    "tech_cv_edit_requests",
    "tech_cv_entries",
    "tech_certifications",
    "tech_pin_resets",
    "technician_5s_overrides",
    "technician_kpi_overrides",
    "technician_reviews",
    # Invoicing — order matters
    "invoice_payments",
    "invoice_line_items",
    "invoices",
    # Visits / equipment
    "visit_readings",
    "visit_parts",
    "visit_photos",
    "maintenance_visits",
    "equipment",
    # Customer-facing
    "reviews",
    "submissions",
    "customer_credit_movements",
    "documents",
    "delegations",
    "delegation_regrant_requests",
    # Customers — last among customer-tree
    "customers",
    # Assets (per-tech vehicles + toolkits seeded by create_tech)
    "fs_assets",
    # Messaging + ops
    "company_messages",
    "security_alerts",
    "sessions",
    "admin_password_resets",
    # Access / audit operational tables (financial retention preserved
    # by keeping rows whose target_type is invoice or invoice_payment)
    "access_log",
]

# audit_log rows we KEEP for the 7-year financial retention obligation.
AUDIT_FINANCIAL_TARGETS = {"invoice", "invoice_payment", "payroll_run",
                           "payslip", "pay_period"}


def _recent_backup_exists(max_age_hours: int = 24) -> bool:
    cutoff = _dt.datetime.now() - _dt.timedelta(hours=max_age_hours)
    for p in list(ROOT.glob("*.tar.gpg")) + list(ROOT.glob("submissions.db.bak-*")):
        if _dt.datetime.fromtimestamp(p.stat().st_mtime) > cutoff:
            return True
    backup_dir = Path(os.environ.get("BACKUP_DIR", ROOT / "backups"))
    if backup_dir.exists():
        for p in backup_dir.glob("primcool-*.tar.gpg"):
            if _dt.datetime.fromtimestamp(p.stat().st_mtime) > cutoff:
                return True
    return False


def _count(con, table: str) -> int:
    try:
        return con.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
    except sqlite3.OperationalError:
        return -1  # table absent


def _plan(con) -> list:
    rows = []
    for t in DELETE_ORDER:
        n = _count(con, t)
        if n > 0:
            rows.append((t, n))
    return rows


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply", action="store_true",
                    help="actually mutate; without this it's a dry-run")
    ap.add_argument("--force-no-backup", action="store_true",
                    help="bypass the recent-backup safety check")
    args = ap.parse_args()

    if not DB.exists():
        print(f"FATAL: {DB} not found", file=sys.stderr)
        return 1

    if args.apply and not args.force_no_backup and not _recent_backup_exists():
        print("FATAL: no backup file younger than 24h found.", file=sys.stderr)
        print("  Run scripts/backup.sh first (or pass --force-no-backup).",
              file=sys.stderr)
        return 1

    con = sqlite3.connect(str(DB))
    con.row_factory = sqlite3.Row

    plan = _plan(con)
    print("Wipe plan:")
    total = 0
    for t, n in plan:
        print(f"  {n:>8d}  {t}")
        total += n
    print(f"  ─────")
    print(f"  {total:>8d}  TOTAL rows to delete")

    # audit_log: count what stays vs goes
    try:
        a_keep = con.execute(
            f"SELECT COUNT(*) FROM audit_log WHERE target_type IN "
            f"({','.join('?'*len(AUDIT_FINANCIAL_TARGETS))})",
            list(AUDIT_FINANCIAL_TARGETS),
        ).fetchone()[0]
        a_total = con.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
        print(f"  audit_log: keep {a_keep} financial rows; "
              f"delete {a_total - a_keep} operational rows.")
    except sqlite3.OperationalError:
        a_keep = a_total = 0

    # Forced-reset flag plan
    try:
        admins_to_flag = con.execute(
            "SELECT COUNT(*) FROM admin_users WHERE active = 1"
        ).fetchone()[0]
        techs_to_flag = con.execute(
            "SELECT COUNT(*) FROM technicians WHERE active = 1"
        ).fetchone()[0]
        print(f"  Flag must_change_credentials=1 on {admins_to_flag} active "
              f"admins + {techs_to_flag} active techs.")
    except sqlite3.OperationalError:
        admins_to_flag = techs_to_flag = 0

    if not args.apply:
        print()
        print("DRY-RUN. Re-run with --apply to execute.")
        return 0

    print()
    print("Applying…")
    con.execute("BEGIN IMMEDIATE")
    try:
        for t in DELETE_ORDER:
            try:
                con.execute(f"DELETE FROM {t}")
            except sqlite3.OperationalError:
                pass  # absent table
        # audit_log: keep financial, drop the rest
        try:
            con.execute(
                f"DELETE FROM audit_log WHERE target_type NOT IN "
                f"({','.join('?'*len(AUDIT_FINANCIAL_TARGETS))}) "
                f"OR target_type IS NULL",
                list(AUDIT_FINANCIAL_TARGETS),
            )
        except sqlite3.OperationalError:
            pass
        # Flag every remaining admin + tech for forced reset
        try:
            con.execute("UPDATE admin_users SET must_change_credentials = 1 "
                        "WHERE active = 1")
        except sqlite3.OperationalError:
            pass
        try:
            con.execute("UPDATE technicians SET must_change_credentials = 1 "
                        "WHERE active = 1")
        except sqlite3.OperationalError:
            pass
        con.commit()
    except Exception as e:
        con.rollback()
        print(f"FATAL during apply: {e}", file=sys.stderr)
        return 2
    finally:
        con.close()

    print("Done.")
    print()
    print("Next steps:")
    print("  1. bash scripts/backup_restore_drill.sh")
    print("  2. python3 scripts/rotate_secrets.py > .env.prod  "
          "(copy to your secret store; don't commit)")
    print("  3. Start the app with PROD_MODE=true + the new env.")
    print("  4. Sign in as the bootstrap admin — first login forces "
          "password reset.")
    print("  5. Re-add real prospect customers via the admin UI.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
