"""Automated, encrypted, point-in-time database backups.

A backup is a consistent snapshot of submissions.db — taken with SQLite's
online backup API so it is safe under WAL and concurrent writers — that is
gzip-compressed and then encrypted with AES-256-GCM under a key derived
(HKDF-SHA256) from FIELD_ENCRYPTION_KEY. The artifact is self-describing and
can be verified for restorability without ever touching the live database.

Why this exists
---------------
Everything the business depends on — invoices, payroll, the 7-year chained
audit trail — lives in one SQLite file. A lost or corrupted file means the
business is gone. This module produces recoverable copies that live OFF the
live file, on a daily cron and on demand, with retention pruning and an
integrity check that proves a backup is restorable.

Local vs production (honest behaviour)
--------------------------------------
* Encryption is REAL whenever FIELD_ENCRYPTION_KEY is set — and it is set in
  .dev.env — so local backups are encrypted exactly the way production ones
  are. No mocking.
* If the key is absent the snapshot is still written, but as a PLAINTEXT
  gzip artifact whose name ends ``.db.gz`` (no ``.enc``); a warning is
  logged. We never silently skip the backup: a recoverable plaintext copy
  beats no copy at all.
* "Off-box" replication (S3 / Backblaze / rsync / etc.) is an env-gated hook
  (BACKUP_OFFSITE_CMD). When set, the command is run with the new artifact's
  path appended; the artifact is the source of truth either way. Unset (the
  local default), so NO external call ever fires during local development.

Artifact envelope (encrypted form)
-----------------------------------
  magic  = b"PCBK1\n"
  then repeated chunks until EOF:
      nonce (12 bytes) || ct_len (4 bytes, big-endian) || ciphertext

Each chunk is an independent AES-256-GCM box over <= 1 MiB of gzipped
plaintext, so files of any size stream without loading the whole thing into
memory and a single corrupted chunk is detectable.
"""
from __future__ import annotations

import base64
import gzip
import hashlib
import json
import logging
import os
import re
import secrets
import shutil
import sqlite3
import subprocess
import tempfile
import time
from datetime import datetime, timezone, timedelta
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

import database

logger = logging.getLogger("primecool.backup")

# ── Configuration (all env-overridable) ─────────────────────────────────────
BACKUP_DIR        = os.environ.get("BACKUP_DIR", "backups")
RETAIN_DAYS       = int(os.environ.get("BACKUP_RETAIN_DAYS", "30"))
RETAIN_MIN        = int(os.environ.get("BACKUP_RETAIN_MIN", "14"))
INTERVAL_HOURS    = int(os.environ.get("BACKUP_INTERVAL_HOURS", "24"))
OFFSITE_CMD       = os.environ.get("BACKUP_OFFSITE_CMD", "").strip()

_MAGIC      = b"PCBK1\n"
_CHUNK      = 1024 * 1024            # 1 MiB plaintext per AES-GCM box
_NAME_RE    = re.compile(r"^primecool-\d{8}T\d{6}Z\.db\.gz(\.enc)?$")


# ── Key handling ─────────────────────────────────────────────────────────────
def _backup_key() -> Optional[bytes]:
    """32-byte file-encryption key derived from FIELD_ENCRYPTION_KEY, or None
    when no key is configured (plaintext-backup fallback)."""
    raw = os.environ.get("FIELD_ENCRYPTION_KEY", "")
    if not raw or len(raw) < 32:
        return None
    return HKDF(algorithm=hashes.SHA256(), length=32,
                salt=b"pc-backup-v1", info=b"primecool-backup-file").derive(raw.encode())


def encryption_available() -> bool:
    return _backup_key() is not None


# ── Streaming encrypt / decrypt ──────────────────────────────────────────────
def _encrypt_file(src_path: str, dst_path: str, key: bytes) -> None:
    aes = AESGCM(key)
    with open(src_path, "rb") as src, open(dst_path, "wb") as dst:
        dst.write(_MAGIC)
        while True:
            chunk = src.read(_CHUNK)
            if not chunk:
                break
            nonce = secrets.token_bytes(12)
            ct = aes.encrypt(nonce, chunk, None)
            dst.write(nonce)
            dst.write(len(ct).to_bytes(4, "big"))
            dst.write(ct)


def _decrypt_file(src_path: str, dst_path: str, key: bytes) -> None:
    aes = AESGCM(key)
    with open(src_path, "rb") as src, open(dst_path, "wb") as dst:
        magic = src.read(len(_MAGIC))
        if magic != _MAGIC:
            raise ValueError("not a PrimeCool encrypted backup (bad magic)")
        while True:
            nonce = src.read(12)
            if not nonce:
                break
            if len(nonce) != 12:
                raise ValueError("truncated backup (nonce)")
            ln_b = src.read(4)
            if len(ln_b) != 4:
                raise ValueError("truncated backup (length)")
            ln = int.from_bytes(ln_b, "big")
            ct = src.read(ln)
            if len(ct) != ln:
                raise ValueError("truncated backup (ciphertext)")
            dst.write(aes.decrypt(nonce, ct, None))


def _sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(_CHUNK), b""):
            h.update(chunk)
    return h.hexdigest()


# ── Core operations ──────────────────────────────────────────────────────────
def _ensure_dir() -> str:
    os.makedirs(BACKUP_DIR, exist_ok=True)
    return BACKUP_DIR


def _snapshot_to(tmp_db_path: str) -> None:
    """Consistent online-backup snapshot of the live DB into tmp_db_path.

    sqlite3's backup API copies committed pages while holding the right locks,
    so this is safe under WAL with concurrent writers and never produces a
    torn read — unlike a raw file copy."""
    src = sqlite3.connect(database.DB_PATH)
    try:
        dst = sqlite3.connect(tmp_db_path)
        try:
            src.backup(dst)
        finally:
            dst.close()
    finally:
        src.close()


def create_backup(reason: str = "manual", actor: Optional[str] = None) -> dict:
    """Take a snapshot, compress, encrypt (if key present), prune, optional
    off-box push. Returns the artifact's metadata dict. Raises on hard
    failure (caller — cron — swallows so the loop keeps running)."""
    _ensure_dir()
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    key = _backup_key()
    encrypted = key is not None

    tmpdir = tempfile.mkdtemp(prefix="pcbk_", dir=BACKUP_DIR)
    try:
        snap = os.path.join(tmpdir, "snap.db")
        _snapshot_to(snap)
        source_sha = _sha256(snap)
        sqlite_bytes = os.path.getsize(snap)

        gz = os.path.join(tmpdir, "snap.db.gz")
        with open(snap, "rb") as f_in, gzip.open(gz, "wb", compresslevel=6) as f_out:
            shutil.copyfileobj(f_in, f_out, length=_CHUNK)

        if encrypted:
            name = f"primecool-{ts}.db.gz.enc"
            final = os.path.join(BACKUP_DIR, name)
            _encrypt_file(gz, final, key)
        else:
            name = f"primecool-{ts}.db.gz"
            final = os.path.join(BACKUP_DIR, name)
            shutil.move(gz, final)
            logger.warning("[backup] FIELD_ENCRYPTION_KEY absent — wrote PLAINTEXT "
                           "backup %s. Set the key for encrypted backups.", name)

        artifact_bytes = os.path.getsize(final)
        artifact_sha = _sha256(final)
        meta = {
            "name": name,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "reason": reason,
            "actor": actor,
            "encrypted": encrypted,
            "sqlite_bytes": sqlite_bytes,
            "artifact_bytes": artifact_bytes,
            "artifact_sha256": artifact_sha,
            "source_sha256": source_sha,
        }
        with open(os.path.join(BACKUP_DIR, name + ".meta.json"), "w") as mf:
            json.dump(meta, mf, indent=2)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

    # Off-box hook (env-gated; no-op locally). Best-effort — a failed push
    # never invalidates the local artifact, which is the source of truth.
    if OFFSITE_CMD:
        try:
            subprocess.run(OFFSITE_CMD.split() + [final], check=True,
                           timeout=300, capture_output=True)
            logger.info("[backup] off-box push ok: %s", name)
        except Exception as e:  # noqa: BLE001
            logger.error("[backup] off-box push FAILED for %s: %s", name, e)

    pruned = prune_backups()
    meta["pruned"] = pruned
    return meta


def list_backups() -> list[dict]:
    """Newest-first list of backup artifacts with metadata. Reads sidecar
    .meta.json when present, otherwise reconstructs basics from the file."""
    if not os.path.isdir(BACKUP_DIR):
        return []
    out = []
    for fn in os.listdir(BACKUP_DIR):
        if not _NAME_RE.match(fn):
            continue
        path = os.path.join(BACKUP_DIR, fn)
        meta_path = path + ".meta.json"
        if os.path.exists(meta_path):
            try:
                with open(meta_path) as mf:
                    meta = json.load(mf)
            except Exception:
                meta = {}
        else:
            meta = {}
        st = os.stat(path)
        meta.setdefault("name", fn)
        meta.setdefault("encrypted", fn.endswith(".enc"))
        meta.setdefault("artifact_bytes", st.st_size)
        meta.setdefault("created_at",
                        datetime.fromtimestamp(st.st_mtime, timezone.utc).isoformat())
        out.append(meta)
    out.sort(key=lambda m: m.get("created_at", ""), reverse=True)
    return out


def prune_backups() -> list[str]:
    """Delete artifacts older than RETAIN_DAYS, but always keep the RETAIN_MIN
    most-recent regardless of age. Returns the names removed."""
    items = list_backups()  # newest-first
    cutoff = datetime.now(timezone.utc) - timedelta(days=RETAIN_DAYS)
    removed = []
    for idx, m in enumerate(items):
        if idx < RETAIN_MIN:
            continue  # always retain the freshest N
        try:
            created = datetime.fromisoformat(m["created_at"])
        except Exception:
            continue
        if created < cutoff:
            name = m["name"]
            for p in (os.path.join(BACKUP_DIR, name),
                      os.path.join(BACKUP_DIR, name + ".meta.json")):
                try:
                    if os.path.exists(p):
                        os.remove(p)
                except OSError:
                    pass
            removed.append(name)
    return removed


def _safe_path(name: str) -> str:
    """Resolve an artifact name to an absolute path inside BACKUP_DIR, or
    raise ValueError on traversal / bad name."""
    if not _NAME_RE.match(name):
        raise ValueError("invalid backup name")
    base = os.path.realpath(BACKUP_DIR)
    full = os.path.realpath(os.path.join(BACKUP_DIR, name))
    if os.path.dirname(full) != base:
        raise ValueError("path traversal blocked")
    if not os.path.exists(full):
        raise FileNotFoundError(name)
    return full


def restore_to(name: str, dest_path: str) -> dict:
    """Decrypt (if needed) + gunzip a backup into dest_path (a fresh SQLite
    file). Never writes over the live DB implicitly — the caller picks dest.
    Returns a small summary. This is the routine the restore script uses."""
    src = _safe_path(name)
    key = _backup_key()
    tmpdir = tempfile.mkdtemp(prefix="pcrestore_", dir=BACKUP_DIR)
    try:
        if name.endswith(".enc"):
            if key is None:
                raise RuntimeError("FIELD_ENCRYPTION_KEY required to decrypt this backup")
            gz = os.path.join(tmpdir, "out.db.gz")
            _decrypt_file(src, gz, key)
        else:
            gz = src
        with gzip.open(gz, "rb") as f_in, open(dest_path, "wb") as f_out:
            shutil.copyfileobj(f_in, f_out, length=_CHUNK)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
    return {"name": name, "restored_to": dest_path,
            "bytes": os.path.getsize(dest_path)}


def verify_backup(name: str) -> dict:
    """Prove a backup is restorable WITHOUT touching the live DB: decrypt +
    gunzip into a throwaway temp file, run PRAGMA integrity_check, and count a
    couple of canary tables. Returns {ok, integrity, tables:{...}}."""
    tmpdir = tempfile.mkdtemp(prefix="pcverify_", dir=BACKUP_DIR)
    try:
        dest = os.path.join(tmpdir, "verify.db")
        restore_to(name, dest)
        con = sqlite3.connect(dest)
        try:
            integrity = con.execute("PRAGMA integrity_check").fetchone()[0]
            tables = {}
            for t in ("invoices", "customers", "payslips", "audit_log"):
                try:
                    tables[t] = con.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
                except sqlite3.Error:
                    tables[t] = None
        finally:
            con.close()
        return {"name": name, "ok": integrity == "ok",
                "integrity": integrity, "tables": tables}
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def config_summary() -> dict:
    return {
        "dir": BACKUP_DIR,
        "retain_days": RETAIN_DAYS,
        "retain_min": RETAIN_MIN,
        "interval_hours": INTERVAL_HOURS,
        "encryption_available": encryption_available(),
        "offsite_configured": bool(OFFSITE_CMD),
    }


# ── CLI: `python3 backup.py [create|list|verify <name>|restore <name> <dest>]`
if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO)
    cmd = sys.argv[1] if len(sys.argv) > 1 else "create"
    if cmd == "create":
        print(json.dumps(create_backup(reason="cli"), indent=2))
    elif cmd == "list":
        print(json.dumps(list_backups(), indent=2))
    elif cmd == "verify":
        print(json.dumps(verify_backup(sys.argv[2]), indent=2))
    elif cmd == "restore":
        print(json.dumps(restore_to(sys.argv[2], sys.argv[3]), indent=2))
    else:
        print("usage: backup.py [create|list|verify <name>|restore <name> <dest>]")
        sys.exit(2)
