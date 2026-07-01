"""Pre-deploy hardening: every new connection enforces WAL + FULL + FK.

Closes:
  - C1: journal_mode=delete + synchronous=NORMAL → mid-write corruption
        risk for the audit chain
  - O1: foreign_keys=OFF → orphan rows possible despite FK declarations

These pragmas have two lifetimes:
  - journal_mode lives in the DB header (sticky, set once)
  - synchronous + foreign_keys are per-connection (must be re-applied)
The fix re-applies all three on every _con() call. WAL is a no-op after
the first, but FK and synchronous DO need to fire every time.
"""
import os
import pytest

if "JWT_SECRET" not in os.environ:
    try:
        for line in open(".dev.env"):
            if line.startswith("export "):
                k, v = line[7:].strip().split("=", 1)
                os.environ.setdefault(k, v.strip('"'))
    except FileNotFoundError:
        pytest.skip(".dev.env not present", allow_module_level=True)

import database


def _pragma(con, name):
    return con.execute(f"PRAGMA {name}").fetchone()[0]


def test_journal_mode_is_wal():
    con = database._con()
    try:
        assert _pragma(con, "journal_mode") == "wal", (
            "PRAGMA journal_mode is NOT 'wal'. Closes C1 — without WAL, "
            "a crash mid-write can leave the DB inconsistent, breaking "
            "the audit chain_hash invariant."
        )
    finally:
        con.close()


def test_synchronous_is_full():
    con = database._con()
    try:
        # 2 = FULL; 1 = NORMAL; 0 = OFF
        assert _pragma(con, "synchronous") == 2, (
            f"PRAGMA synchronous is {_pragma(con, 'synchronous')}, expected "
            "2 (FULL). NORMAL allows the WAL to lose committed transactions "
            "across a power loss — incompatible with the audit chain's "
            "append-only guarantee."
        )
    finally:
        con.close()


def test_foreign_keys_on():
    con = database._con()
    try:
        assert _pragma(con, "foreign_keys") == 1, (
            "PRAGMA foreign_keys is OFF. Closes O1 — FK constraints in "
            "schema declarations are not enforced; orphan rows can exist."
        )
    finally:
        con.close()


def test_pragmas_applied_on_every_connection():
    """All three pragmas must fire on every _con() — synchronous and FK
    are per-connection settings that don't survive a close."""
    for i in range(3):
        con = database._con()
        try:
            assert _pragma(con, "journal_mode") == "wal", \
                f"connection #{i+1}: WAL not active"
            assert _pragma(con, "synchronous") == 2, \
                f"connection #{i+1}: synchronous reverted"
            assert _pragma(con, "foreign_keys") == 1, \
                f"connection #{i+1}: foreign_keys reverted"
        finally:
            con.close()


def test_foreign_key_enforcement_is_live():
    """Don't just trust the PRAGMA flag — actually try to insert a row
    with a bad FK and prove SQLite rejects it. Uses a transient probe
    table that's rolled back so the dev DB stays clean."""
    con = database._con()
    try:
        con.execute("BEGIN")
        con.execute("CREATE TEMP TABLE _fk_probe_parent (id INTEGER PRIMARY KEY)")
        con.execute("""
            CREATE TEMP TABLE _fk_probe_child (
                id INTEGER PRIMARY KEY,
                parent_id INTEGER NOT NULL REFERENCES _fk_probe_parent(id)
            )
        """)
        # Bad FK insert must raise IntegrityError.
        import sqlite3 as _sql
        raised = False
        try:
            con.execute("INSERT INTO _fk_probe_child (parent_id) VALUES (999)")
        except _sql.IntegrityError:
            raised = True
        assert raised, (
            "FK constraint did NOT raise on bad insert. PRAGMA reports "
            "foreign_keys=1 but enforcement is not happening — investigate."
        )
        con.rollback()
    finally:
        con.close()
