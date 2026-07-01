#!/usr/bin/env bash
# PrimeCool — restore from an encrypted backup tarball.
#
# Usage:  ./scripts/restore.sh <path/to/primcool-YYYYMMDDTHHMMSSZ.tar.gpg> [target-dir]
#
# Decrypts the backup with your gpg private key, untars it to a target dir
# (default: ./restore-<timestamp>), and prints a checklist for swapping it
# into place safely.
#
# This script is for the RESTORE DRILL too — periodically run it against a
# recent backup into a throwaway dir to confirm the encryption + tarball are
# both readable. If the drill fails, you have a silent backup problem.

set -euo pipefail

if [ -z "${1:-}" ]; then
  echo "usage: $0 <backup.tar.gpg> [target-dir]" >&2
  exit 1
fi

SRC="$1"
TARGET="${2:-./restore-$(date -u +%Y%m%dT%H%M%SZ)}"

if [ ! -f "$SRC" ]; then
  echo "FATAL: backup not found: $SRC" >&2
  exit 1
fi

mkdir -p "$TARGET"
echo "Decrypting $SRC → $TARGET"
gpg --decrypt "$SRC" | tar -xzf - -C "$TARGET"

echo ""
echo "✓ Restored. Files in $TARGET:"
ls -la "$TARGET"

echo ""
echo "─── Restore checklist ───────────────────────────────────────────"
echo "  1. Stop the running server (e.g. systemctl stop primcool)."
echo "  2. Back up the CURRENT live data first:"
echo "       cp submissions.db submissions.db.pre-restore-\$(date +%s)"
echo "       mv uploads uploads.pre-restore-\$(date +%s)"
echo "  3. Copy restored data into place:"
echo "       cp $TARGET/submissions.db ."
echo "       cp -a $TARGET/uploads ."
echo "  4. Verify file ownership matches the app user."
echo "  5. Start the server. Watch logs."
echo "  6. Spot-check: sign in as super_admin, run Verify Audit Chain,"
echo "     pick a tech and open one of their visits, view a photo."
echo "  7. If something is wrong, restore the .pre-restore- snapshots."
echo "─────────────────────────────────────────────────────────────────"
