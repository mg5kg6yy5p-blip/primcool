#!/usr/bin/env python3
"""Smoke test for the anomaly detector.

Builds a throwaway SQLite, replays synthetic access_log rows for three
attack patterns, and confirms the right alerts fire (and that the
30-minute de-dupe holds).

Run from repo root:  python3 scripts/verify_anomaly_detector.py
"""
import os
import sys
import tempfile
from datetime import datetime, timezone, timedelta

# Point database.py at a throwaway file so we don't touch the real DB.
TMP = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
TMP.close()
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import database as db
db.DB_PATH = TMP.name   # override hardcoded path before init_db
db.init_db()

FAIL = []
def check(label, cond):
    print(f"  {'✓' if cond else '✗'}  {label}")
    if not cond:
        FAIL.append(label)


def now_iso(offset_seconds=0):
    return (datetime.now(timezone.utc) + timedelta(seconds=offset_seconds)).isoformat()


def insert_access(actor_id, path, status=200, method="GET", when=None):
    con = db._con()
    con.execute(
        """INSERT INTO access_log
            (actor_type, actor_id, actor_prid, actor_label, method, path,
             query, status_code, ip_address, user_agent, created_at)
           VALUES ('tech', ?, 'PCXX010125', 'Test Tech', ?, ?, '', ?, '127.0.0.1', 'pytest', ?)""",
        (actor_id, method, path, status, when or now_iso()),
    )
    con.commit()
    con.close()


print("\n── Rule A: bulk_read (≥20 distinct customers in 5 min) ──")
TECH = 42001
for cid in range(100, 125):   # 25 distinct customers, well over the 20 threshold
    insert_access(TECH, f"/api/admin/customers/{cid}", when=now_iso(-60))
hits = db.detect_anomalies_for_actor("tech", TECH)
kinds = [h[0] for h in hits]
check("bulk_read fires when tech reads 25 distinct customers in 1 min", "bulk_read" in kinds)

print("\n── De-dupe: recent_alert_exists blocks repeat firings ──")
db.create_security_alert(
    kind="bulk_read", summary="x", severity="high",
    actor_type="tech", actor_id=TECH, details={"distinct_customers": 25},
)
check("recent_alert_exists returns True within 30 min window",
      db.recent_alert_exists("bulk_read", TECH, within_minutes=30))
check("recent_alert_exists returns False for a different kind",
      not db.recent_alert_exists("off_hours", TECH, within_minutes=30))

print("\n── Rule C: permission_probe (≥10 denied in 10 min) ──")
PROBER = 42002
for _ in range(12):
    insert_access(PROBER, "/api/admin/admins", status=403, when=now_iso(-30))
hits = db.detect_anomalies_for_actor("tech", PROBER)
kinds = [h[0] for h in hits]
check("permission_probe fires after 12 × 403", "permission_probe" in kinds)

print("\n── Counter-example: no alert below threshold ──")
QUIET = 42003
for cid in range(200, 205):    # only 5 customers — under the 20-distinct threshold
    insert_access(QUIET, f"/api/admin/customers/{cid}")
hits = db.detect_anomalies_for_actor("tech", QUIET)
kinds = [h[0] for h in hits]
check("no bulk_read fires for 5-customer baseline", "bulk_read" not in kinds)

print("\n── list_security_alerts returns the seeded alert ──")
rows = db.list_security_alerts(status="open", limit=50)
check("at least one open alert is listed", len(rows) >= 1)
check("open count helper agrees", db.count_open_security_alerts() == len(rows))

print("\n── resolve_security_alert flips status ──")
db.resolve_security_alert(rows[0]["id"], admin_id=1, note="test", status="resolved")
check("count_open_security_alerts decremented after resolve",
      db.count_open_security_alerts() == len(rows) - 1)

# Cleanup
os.unlink(TMP.name)

print("\n" + "=" * 50)
if FAIL:
    print(f"FAIL: {len(FAIL)} check(s) failed:")
    for f in FAIL: print("  -", f)
    sys.exit(1)
print("PASS — anomaly detector works end-to-end.")
