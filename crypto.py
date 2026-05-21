"""Application-layer field encryption.

Disk FDE only stops disk theft. A logical breach of the database (stolen file,
leaked backup, SQL injection in a future feature, a curious DBA) yields plain
rows unless we encrypt at the application layer too. This module does that for
the sensitive columns identified in Phase 2.

Modes:
  - encrypt() / decrypt() use AES-256-GCM with a fresh random nonce per row.
    Same plaintext encrypts to different ciphertexts. Use for phone, address,
    notes, MFA secrets, signature blobs — anywhere we never need to search.
  - det_encrypt() / det_decrypt() use AES-256-SIV (RFC 5297) which is
    deterministic — same plaintext + same key always yields the same
    ciphertext, but reveals no information beyond "these two cells are equal".
    Use ONLY for columns that need equality lookup (emails).
  - email_hash() returns an HMAC-SHA256 fingerprint of a normalized email,
    suitable as a blind-index column for forgot-password equality lookups
    when we want fast index seeks without exposing ciphertext patterns.

Key handling: a single FIELD_ENCRYPTION_KEY env var (≥32 bytes after decoding)
seeds both AES keys via HKDF. The key is NEVER in source. Phase 1's pre-flight
gate refuses to boot if it's missing once Phase 2 ships.

Ciphertext envelope format (so we can tell ciphertext from any stray plaintext
during the migration and forever after):

  randomized:    "v1:r:<base64(nonce || ciphertext_with_tag)>"
  deterministic: "v1:d:<base64(siv_tag || ciphertext)>"

A version prefix lets us rotate algorithms later without touching column types.
"""
import base64
import hashlib
import hmac
import os
import secrets
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM, AESSIV
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes


CIPHER_PREFIX_RAND = "v1:r:"
CIPHER_PREFIX_DET  = "v1:d:"


class _Keyring:
    """Holds derived sub-keys. Initialised lazily so importing this module
    doesn't fail before pre-flight has had a chance to refuse a missing key."""
    _aead = None       # 32-byte AES-GCM key
    _det  = None       # 64-byte AES-SIV key
    _hmac = None       # 32-byte HMAC key for blind-index hashes
    _loaded = False
    _missing_ok = True   # toggle: True until Phase 2 hard-requires the key

    @classmethod
    def _load(cls):
        if cls._loaded:
            return
        raw = os.environ.get("FIELD_ENCRYPTION_KEY", "")
        if not raw:
            if cls._missing_ok:
                cls._loaded = True
                return
            raise RuntimeError("FIELD_ENCRYPTION_KEY is not set")
        if len(raw) < 32:
            raise RuntimeError(f"FIELD_ENCRYPTION_KEY length {len(raw)} < 32")
        # Use HKDF to derive three independent sub-keys from one input.
        base = raw.encode()
        cls._aead = HKDF(algorithm=hashes.SHA256(), length=32,
                          salt=b"pc-aead-v1", info=b"primecool-field-aead"
                          ).derive(base)
        cls._det  = HKDF(algorithm=hashes.SHA256(), length=64,
                          salt=b"pc-det-v1",  info=b"primecool-field-det"
                          ).derive(base)
        cls._hmac = HKDF(algorithm=hashes.SHA256(), length=32,
                          salt=b"pc-hmac-v1", info=b"primecool-blind-index"
                          ).derive(base)
        cls._loaded = True

    @classmethod
    def aead(cls):
        cls._load()
        if cls._aead is None:
            raise RuntimeError("Field encryption key not configured")
        return AESGCM(cls._aead)

    @classmethod
    def det(cls):
        cls._load()
        if cls._det is None:
            raise RuntimeError("Field encryption key not configured")
        return AESSIV(cls._det)

    @classmethod
    def hmac_key(cls):
        cls._load()
        if cls._hmac is None:
            raise RuntimeError("Field encryption key not configured")
        return cls._hmac

    @classmethod
    def lock_required(cls):
        """Call this after Phase 2 migration completes; missing key then fails hard."""
        cls._missing_ok = False
        cls._loaded = False


# ── Randomized encryption (default for one-way columns) ─────────────────────
def encrypt(plain: Optional[str]) -> Optional[str]:
    """Encrypt plaintext for storage. None / empty pass through so the wrapper
    is safe to call on nullable columns without losing the null."""
    if plain is None:
        return None
    if plain == "":
        return ""
    nonce = secrets.token_bytes(12)
    ct = _Keyring.aead().encrypt(nonce, plain.encode("utf-8"), None)
    return CIPHER_PREFIX_RAND + base64.urlsafe_b64encode(nonce + ct).decode("ascii")


def decrypt(stored: Optional[str]) -> Optional[str]:
    """Decrypt stored ciphertext. Passes through None, empty, and values that
    don't start with our envelope prefix (those are pre-migration plaintext
    that we tolerate during rollout; after migration, no such value should
    exist for an encrypted column)."""
    if stored is None:
        return None
    if stored == "":
        return ""
    if not isinstance(stored, str) or not stored.startswith(CIPHER_PREFIX_RAND):
        return stored   # pre-migration plaintext fallthrough
    blob = base64.urlsafe_b64decode(stored[len(CIPHER_PREFIX_RAND):])
    nonce, ct = blob[:12], blob[12:]
    return _Keyring.aead().decrypt(nonce, ct, None).decode("utf-8")


# ── Deterministic encryption (for searchable columns) ───────────────────────
def det_encrypt(plain: Optional[str]) -> Optional[str]:
    if plain is None:
        return None
    if plain == "":
        return ""
    ct = _Keyring.det().encrypt(plain.encode("utf-8"), None)
    return CIPHER_PREFIX_DET + base64.urlsafe_b64encode(ct).decode("ascii")


def det_decrypt(stored: Optional[str]) -> Optional[str]:
    if stored is None:
        return None
    if stored == "" or not isinstance(stored, str) or not stored.startswith(CIPHER_PREFIX_DET):
        return stored
    ct = base64.urlsafe_b64decode(stored[len(CIPHER_PREFIX_DET):])
    return _Keyring.det().decrypt(ct, None).decode("utf-8")


# ── Blind index for email lookup (HMAC-SHA256 of normalized email) ──────────
def email_hash(email: Optional[str]) -> Optional[str]:
    """Returns a 32-char hex digest suitable as a blind-index column. Lowercased
    + stripped first so case/whitespace variation collapses to the same hash."""
    if not email:
        return None
    norm = email.strip().lower().encode("utf-8")
    return hmac.new(_Keyring.hmac_key(), norm, hashlib.sha256).hexdigest()


def is_ciphertext(value) -> bool:
    return isinstance(value, str) and (value.startswith(CIPHER_PREFIX_RAND) or value.startswith(CIPHER_PREFIX_DET))
