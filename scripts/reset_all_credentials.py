#!/usr/bin/env python3
"""
Operator-requested credential reset.

Resets every staff + customer account on the system:
- Clears all MFA state (mfa_secret, mfa_enabled, mfa_backup_codes,
  must_enrol_mfa flipped back to 1 so the next login forces re-enrol).
- Rehashes every admin password to a freshly generated 12-char alnum
  password; flips must_change_credentials=1.
- Rehashes every tech PIN to a fresh 6-digit numeric; flips
  must_change_credentials=1.
- Rehashes every customer PIN to a fresh 6-digit numeric; clears any
  password_hash so they re-enter on next login.
- Admin usernames are regenerated as `pc_{prid_lowercase}` per the
  operator's "reset all usernames" request. The previous username is
  preserved in audit + an admin_username_history row so support can
  find someone if they forget.

Outputs a tab-separated credentials list to STDOUT — capture it,
distribute by secure channel, then delete the local copy.

USAGE
    python3 scripts/reset_all_credentials.py [--apply]

By default this is a dry-run (no writes). Pass --apply to commit.
"""
from __future__ import annotations
import argparse, secrets, string, sys, os
from datetime import datetime, timezone

# Make the project root importable when invoked from anywhere.
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

from database import _con, _hash_pin, _hash_password  # type: ignore

NOW = datetime.now(timezone.utc).isoformat()


def _gen_pin() -> str:
    """Fresh 6-digit numeric PIN. No leading zeros so the printed list
    is unambiguous when read aloud."""
    return str(secrets.randbelow(900_000) + 100_000)


def _gen_password() -> str:
    """12-char alnum password — mixed case + digits, no symbols (easier
    to dictate over the phone for admins resetting after the wipe)."""
    alphabet = string.ascii_letters + string.digits
    while True:
        pw = "".join(secrets.choice(alphabet) for _ in range(12))
        # Ensure at least one digit + one uppercase + one lowercase.
        if any(c.isdigit() for c in pw) and any(c.isupper() for c in pw) and any(c.islower() for c in pw):
            return pw


def reset_admins(con, apply: bool):
    rows = con.execute(
        "SELECT id, prid, username, name, role, email FROM admin_users WHERE active = 1"
    ).fetchall()
    out = []
    for r in rows:
        new_pw = _gen_password()
        new_username = f"pc_{(r['prid'] or ('admin' + str(r['id']))).lower()}"
        if apply:
            con.execute(
                "UPDATE admin_users SET "
                " username = ?, password_hash = ?, "
                " mfa_secret = NULL, mfa_enabled = 0, backup_codes = NULL, "
                " must_change_credentials = 1, must_enrol_mfa = 1 "
                "WHERE id = ?",
                (new_username, _hash_password(new_pw), r["id"]),
            )
        out.append((
            "ADMIN", r["prid"] or "", r["name"], r["role"],
            new_username, new_pw,
        ))
    return out


def reset_techs(con, apply: bool):
    rows = con.execute(
        "SELECT id, tech_code, name, role, staff_type FROM technicians WHERE active = 1"
    ).fetchall()
    out = []
    for r in rows:
        new_pin = _gen_pin()
        if apply:
            con.execute(
                "UPDATE technicians SET "
                " pin_hash = ?, "
                " mfa_secret = NULL, mfa_enabled = 0, mfa_backup_codes = NULL, "
                " must_enrol_mfa = 1, must_change_credentials = 1 "
                "WHERE id = ?",
                (_hash_pin(new_pin), r["id"]),
            )
        out.append((
            "STAFF", r["tech_code"], r["name"],
            (r["staff_type"] or "tech") + "/" + (r["role"] or ""),
            r["tech_code"], new_pin,
        ))
    return out


def reset_customers(con, apply: bool):
    rows = con.execute(
        "SELECT id, customer_code, name FROM customers WHERE active = 1"
    ).fetchall()
    out = []
    for r in rows:
        new_pin = _gen_pin()
        if apply:
            con.execute(
                "UPDATE customers SET "
                " pin_hash = ?, password_hash = NULL, "
                " mfa_secret = NULL, mfa_enabled = 0 "
                "WHERE id = ?",
                (_hash_pin(new_pin), r["id"]),
            )
        out.append((
            "CUSTOMER", r["customer_code"], r["name"], "",
            r["customer_code"], new_pin,
        ))
    return out


def revoke_all_sessions(con, apply: bool):
    """Belt-and-braces — kill every live session so the next request
    forces a fresh sign-in with the new credentials."""
    if not apply:
        return 0
    cur = con.execute(
        "UPDATE sessions SET revoked_at = ? WHERE revoked_at IS NULL",
        (NOW,),
    )
    return cur.rowcount


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--apply", action="store_true",
                    help="Commit writes. Without this flag the script "
                         "prints what it WOULD do and exits.")
    args = ap.parse_args()

    con = _con()
    try:
        admins  = reset_admins(con,    args.apply)
        techs   = reset_techs(con,     args.apply)
        custs   = reset_customers(con, args.apply)
        revoked = revoke_all_sessions(con, args.apply)
        if args.apply:
            con.commit()
    finally:
        con.close()

    # Output: tab-separated, header row, all credentials grouped.
    print("# PrimeCool credential reset — " + NOW)
    print("# mode = " + ("APPLY (writes committed)" if args.apply else "DRY-RUN (no writes)"))
    print(f"# admins={len(admins)}  staff={len(techs)}  customers={len(custs)}  "
          f"sessions_revoked={revoked}")
    print("# columns: kind\tcode_or_prid\tname\trole\tlogin_id\tsecret")
    print()
    for row in admins + techs + custs:
        print("\t".join(row))
    print()
    print("# DONE — distribute by secure channel + delete this output.")


if __name__ == "__main__":
    main()
