"""KPI module smoke test runner — Phase 1 + Phase 2 sanity checks."""
import ast, sys, os, sqlite3
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

mode = sys.argv[1] if len(sys.argv) > 1 else "ast"

if mode == "ast":
    ast.parse(open("database.py").read())
    print("AST_OK")
elif mode == "mig":
    from database import init_db
    init_db()
    print("MIG_OK")
elif mode == "seed":
    c = sqlite3.connect("submissions.db")
    print("kpi_definitions count:", c.execute("SELECT COUNT(*) FROM kpi_definitions").fetchone()[0])
    print("kpi_thresholds count:", c.execute("SELECT COUNT(*) FROM kpi_thresholds").fetchone()[0])
elif mode == "tables":
    c = sqlite3.connect("submissions.db")
    for t in ("kpi_definitions","kpi_thresholds","kpi_periods","kpi_scores",
              "kpi_composite_scores","kpi_flags","kpi_recompute_log"):
        try:
            n = c.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
            print(f"{t}: {n}")
        except Exception as e:
            print(f"{t}: ERROR {e}")
elif mode == "compute":
    from database import recompute_kpi_scores, get_or_create_period, get_all_techs
    techs = get_all_techs()
    if not techs:
        print("no techs"); sys.exit(0)
    pk = get_or_create_period()
    tid = techs[0]["id"]
    out = recompute_kpi_scores(tid, pk)
    print(f"recompute tech_id={tid} period={pk}:")
    for k, v in out.items():
        print(f"  {k}: {v}")
