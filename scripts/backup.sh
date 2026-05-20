#!/usr/bin/env bash
# PrimeCool — encrypted daily backup
#
# Captures:
#   - submissions.db (sqlite3 .backup for a safe online snapshot)
#   - uploads/ (photos + documents)
# Output: a single gpg-encrypted tarball under $BACKUP_DIR.
#
# Required env:
#   BACKUP_GPG_RECIPIENT   — gpg key ID or email (set up `gpg --import publickey.asc`
#                            and `gpg --edit-key <id> trust 5` first).
# Optional env:
#   APP_DIR        (default: parent of this script's parent)
#   BACKUP_DIR     (default: $APP_DIR/backups)
#   RETAIN_DAYS    (default: 30)
#   REMOTE_TARGET  (optional, e.g. "s3://primecool-backups/" — uses aws cli or rclone)
#
# Recommended cron entry (run as the app user, 02:30 daily):
#   30 2 * * * /opt/primcool/scripts/backup.sh >> /var/log/primcool-backup.log 2>&1

set -euo pipefail

APP_DIR="${APP_DIR:-$(cd "$(dirname "$0")/.." && pwd)}"
BACKUP_DIR="${BACKUP_DIR:-$APP_DIR/backups}"
RETAIN_DAYS="${RETAIN_DAYS:-30}"
GPG_RECIPIENT="${BACKUP_GPG_RECIPIENT:-}"

if [ -z "$GPG_RECIPIENT" ]; then
  echo "FATAL: set BACKUP_GPG_RECIPIENT to a gpg key id/email" >&2
  exit 1
fi

mkdir -p "$BACKUP_DIR"
TS="$(date -u +%Y%m%dT%H%M%SZ)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

echo "[$(date -u +%FT%TZ)] backing up to $BACKUP_DIR"

# 1. Safe SQLite snapshot (no need to stop the server)
if [ -f "$APP_DIR/submissions.db" ]; then
  sqlite3 "$APP_DIR/submissions.db" ".backup '$WORK/submissions.db'"
  echo "  ✓ db snapshot ($(stat -f%z "$WORK/submissions.db" 2>/dev/null || stat -c%s "$WORK/submissions.db") bytes)"
else
  echo "  ⚠ submissions.db not found at $APP_DIR — empty backup"
fi

# 2. Copy uploads
if [ -d "$APP_DIR/uploads" ]; then
  cp -a "$APP_DIR/uploads" "$WORK/uploads"
  echo "  ✓ uploads copied ($(du -sh "$WORK/uploads" | awk '{print $1}'))"
fi

# 3. Tar + gpg encrypt to recipient (only their private key can decrypt)
OUT="$BACKUP_DIR/primcool-$TS.tar.gpg"
tar -C "$WORK" -czf - . | gpg --encrypt --recipient "$GPG_RECIPIENT" --output "$OUT"
chmod 600 "$OUT"
echo "  ✓ encrypted backup: $OUT ($(du -h "$OUT" | awk '{print $1}'))"

# 4. Off-site copy (optional)
if [ -n "${REMOTE_TARGET:-}" ]; then
  if command -v aws >/dev/null && [[ "$REMOTE_TARGET" =~ ^s3:// ]]; then
    aws s3 cp "$OUT" "$REMOTE_TARGET" && echo "  ✓ uploaded to $REMOTE_TARGET"
  elif command -v rclone >/dev/null; then
    rclone copy "$OUT" "$REMOTE_TARGET" && echo "  ✓ rcloned to $REMOTE_TARGET"
  else
    echo "  ⚠ REMOTE_TARGET set but neither aws nor rclone is installed"
  fi
fi

# 5. Prune old backups
find "$BACKUP_DIR" -name 'primcool-*.tar.gpg' -mtime "+$RETAIN_DAYS" -delete
KEPT=$(find "$BACKUP_DIR" -name 'primcool-*.tar.gpg' | wc -l | tr -d ' ')
echo "  ✓ retention: $KEPT backups kept (older than $RETAIN_DAYS days removed)"

echo "[$(date -u +%FT%TZ)] backup done."
