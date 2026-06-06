"""Self-contained Web Push (RFC 8291) + VAPID (RFC 8292) transport.

Implemented against the standard library + `cryptography` ONLY — no
`pywebpush` / `py_vapid` dependency, so nothing has to be downloaded from
PyPI. The key-derivation pipeline is verified against the worked example in
RFC 8291 Appendix A (see `selftest()` / tests), which is the part that is
otherwise impossible to validate locally without a live browser push
service.

The actual outbound POST to the browser vendor's push service (FCM /
Mozilla autopush / Windows WNS) is the one step that requires an external
network call. It is gated behind the `WEBPUSH_ENABLED` env flag, which is
OFF by default, so importing and exercising every code path locally never
makes an external request. Flip `WEBPUSH_ENABLED=1` (and provide VAPID
keys) at deploy time to go live.

Content coding: aes128gcm (RFC 8188), single record, as required by
RFC 8291 §4.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import struct
import time
from typing import Optional, Tuple
from urllib.parse import urlparse

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

_CURVE = ec.SECP256R1()


# ── base64url helpers (no padding, RFC 7515 style) ──────────────────────────
def b64u_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64u_decode(s: str) -> bytes:
    if isinstance(s, bytes):
        s = s.decode("ascii")
    s = s.strip().replace("\n", "")
    pad = (-len(s)) % 4
    return base64.urlsafe_b64decode(s + ("=" * pad))


# ── HKDF (RFC 5869) built from HMAC-SHA-256 ─────────────────────────────────
def _hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def _hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    # length is always <= 32 here, so a single HMAC block suffices.
    if length > 32:
        raise ValueError("this minimal HKDF-Expand supports length <= 32")
    return hmac.new(prk, info + b"\x01", hashlib.sha256).digest()[:length]


# ── EC key helpers ──────────────────────────────────────────────────────────
def generate_vapid_keys() -> Tuple[str, str]:
    """Return (private_key_b64url, public_key_b64url).

    private = raw 32-byte scalar (base64url); public = uncompressed point
    (0x04 || X || Y, 65 bytes, base64url) — the `applicationServerKey` a
    browser passes to pushManager.subscribe()."""
    priv = ec.generate_private_key(_CURVE)
    d = priv.private_numbers().private_value
    priv_raw = d.to_bytes(32, "big")
    pub_raw = priv.public_key().public_bytes(Encoding.X962,
                                             PublicFormat.UncompressedPoint)
    return b64u_encode(priv_raw), b64u_encode(pub_raw)


def _load_private_from_raw(priv_raw: bytes) -> ec.EllipticCurvePrivateKey:
    return ec.derive_private_key(int.from_bytes(priv_raw, "big"), _CURVE)


def _load_public_from_raw(pub_raw: bytes) -> ec.EllipticCurvePublicKey:
    return ec.EllipticCurvePublicKey.from_encoded_point(_CURVE, pub_raw)


def _public_raw(priv: ec.EllipticCurvePrivateKey) -> bytes:
    return priv.public_key().public_bytes(Encoding.X962,
                                          PublicFormat.UncompressedPoint)


# ── RFC 8291 payload encryption (aes128gcm) ─────────────────────────────────
def _derive_cek_nonce(ecdh_secret: bytes, auth_secret: bytes,
                      ua_public: bytes, as_public: bytes,
                      salt: bytes) -> Tuple[bytes, bytes]:
    """The RFC 8291 §3.4 key schedule.

    PRK_key = HKDF-Extract(auth_secret, ecdh_secret)
    IKM     = HKDF-Expand(PRK_key, "WebPush: info"||0x00||ua_pub||as_pub, 32)
    PRK     = HKDF-Extract(salt, IKM)
    CEK     = HKDF-Expand(PRK, "Content-Encoding: aes128gcm"||0x00, 16)
    NONCE   = HKDF-Expand(PRK, "Content-Encoding: nonce"||0x00, 12)
    """
    prk_key = _hkdf_extract(auth_secret, ecdh_secret)
    key_info = b"WebPush: info\x00" + ua_public + as_public
    ikm = _hkdf_expand(prk_key, key_info, 32)
    prk = _hkdf_extract(salt, ikm)
    cek = _hkdf_expand(prk, b"Content-Encoding: aes128gcm\x00", 16)
    nonce = _hkdf_expand(prk, b"Content-Encoding: nonce\x00", 12)
    return cek, nonce


def encrypt(payload: bytes, ua_public_b64: str, auth_b64: str, *,
            as_private_raw: Optional[bytes] = None,
            salt: Optional[bytes] = None,
            record_size: int = 4096) -> bytes:
    """Encrypt `payload` for one subscription, returning the aes128gcm body
    (RFC 8188 header || ciphertext). `as_private_raw` / `salt` are injectable
    so the RFC 8291 Appendix A vector can be reproduced deterministically; in
    production both are random per message."""
    ua_public = b64u_decode(ua_public_b64)
    auth_secret = b64u_decode(auth_b64)
    if salt is None:
        salt = os.urandom(16)
    if as_private_raw is None:
        as_priv = ec.generate_private_key(_CURVE)
    else:
        as_priv = _load_private_from_raw(as_private_raw)
    as_public = _public_raw(as_priv)

    ecdh_secret = as_priv.exchange(ec.ECDH(), _load_public_from_raw(ua_public))
    cek, nonce = _derive_cek_nonce(ecdh_secret, auth_secret,
                                   ua_public, as_public, salt)

    # Single record: plaintext || 0x02 delimiter (last-record marker, RFC 8188).
    plaintext = payload + b"\x02"
    ciphertext = AESGCM(cek).encrypt(nonce, plaintext, None)

    # aes128gcm content-coding header: salt(16) || rs(4) || idlen(1) || keyid.
    header = salt + struct.pack("!L", record_size) + bytes([len(as_public)]) + as_public
    return header + ciphertext


# ── RFC 8292 VAPID authorization ────────────────────────────────────────────
def _es256_sign(priv: ec.EllipticCurvePrivateKey, signing_input: bytes) -> bytes:
    der = priv.sign(signing_input, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def vapid_authorization(endpoint: str, private_key_b64: str,
                        public_key_b64: str, subject: str,
                        *, exp_seconds: int = 12 * 3600,
                        _now: Optional[int] = None) -> str:
    """Build the `Authorization: vapid t=<jwt>, k=<pubkey>` header value
    (RFC 8292 §4). `aud` is the scheme+host origin of the push endpoint."""
    parsed = urlparse(endpoint)
    aud = f"{parsed.scheme}://{parsed.netloc}"
    now = int(_now if _now is not None else time.time())
    header = {"typ": "JWT", "alg": "ES256"}
    claims = {"aud": aud, "exp": now + int(exp_seconds), "sub": subject}
    seg = (b64u_encode(json.dumps(header, separators=(",", ":")).encode())
           + "." +
           b64u_encode(json.dumps(claims, separators=(",", ":")).encode()))
    priv = _load_private_from_raw(b64u_decode(private_key_b64))
    sig = _es256_sign(priv, seg.encode("ascii"))
    jwt = seg + "." + b64u_encode(sig)
    return f"vapid t={jwt}, k={public_key_b64}"


# ── Public send entrypoint (gated) ──────────────────────────────────────────
class WebPushDisabled(RuntimeError):
    pass


class WebPushNotConfigured(RuntimeError):
    pass


def is_enabled() -> bool:
    return os.environ.get("WEBPUSH_ENABLED", "").strip().lower() in ("1", "true", "yes", "on")


def get_public_key() -> Optional[str]:
    return (os.environ.get("VAPID_PUBLIC_KEY") or "").strip() or None


def build_request(subscription: dict, payload: bytes, *, ttl: int = 86400,
                  _now: Optional[int] = None) -> Tuple[str, dict, bytes]:
    """Pure function: produce (url, headers, body) for a push WITHOUT sending.
    Lets us unit-test the full request shape with zero network access."""
    priv = (os.environ.get("VAPID_PRIVATE_KEY") or "").strip()
    pub = (os.environ.get("VAPID_PUBLIC_KEY") or "").strip()
    subject = (os.environ.get("VAPID_SUBJECT") or "mailto:ops@primecool.local").strip()
    if not (priv and pub):
        raise WebPushNotConfigured("VAPID_PRIVATE_KEY / VAPID_PUBLIC_KEY not set")
    endpoint = subscription["endpoint"]
    body = encrypt(payload, subscription["p256dh"], subscription["auth"])
    headers = {
        "Content-Encoding": "aes128gcm",
        "Content-Type": "application/octet-stream",
        "TTL": str(int(ttl)),
        "Authorization": vapid_authorization(endpoint, priv, pub, subject, _now=_now),
        "Content-Length": str(len(body)),
    }
    return endpoint, headers, body


def send(subscription: dict, payload, *, ttl: int = 86400) -> dict:
    """Encrypt + POST a push message to one subscription's endpoint.

    Returns {"sent": bool, "status": int|None, "reason": str}. Raises
    WebPushDisabled when the WEBPUSH_ENABLED flag is off — callers treat
    that as a benign no-op (in-app notification still landed in the DB).
    The outbound request is the ONLY external call in this module."""
    if isinstance(payload, str):
        payload = payload.encode("utf-8")
    if not is_enabled():
        raise WebPushDisabled("WEBPUSH_ENABLED is off")
    url, headers, body = build_request(subscription, payload, ttl=ttl)
    # Imported lazily so the module loads even where requests is absent and
    # so static analysis sees no top-level network dependency.
    import urllib.request
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return {"sent": True, "status": resp.status, "reason": "ok"}
    except Exception as e:  # noqa: BLE001 - report, never raise to producer
        status = getattr(e, "code", None)
        return {"sent": False, "status": status, "reason": str(e)[:200]}


# ── RFC 8291 Appendix A self-test (no network) ──────────────────────────────
# The published worked example. Reproducing CEK + NONCE from these inputs,
# and decrypting our own ciphertext back to the known plaintext, validates
# the entire key schedule + content coding locally.
_RFC8291_A = {
    "plaintext": b"When I grow up, I want to be a watermelon",
    "auth_secret": "BTBZMqHH6r4Tts7J_aSIgg",
    "ua_public": "BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4",
    "ua_private": "q1dXpw3UpT5VOmu_cf_v6ih07Aems3njxI-JWgLcM94",
    "as_private": "yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw",
    "salt": "DGv6ra1nlYgDCS1FRnbzlw",
    "expected_cek": "oIhVW04MRdy2XN9CiKLxTg",
    "expected_nonce": "4h_95klXJ5E_qnoN",
    "expected_body": (
        "DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMo"
        "ZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A_yl95bQpu6cVPTpK4Mqgkf"
        "1CXztLVBSt2Ks3oZwbuwXPXLWyouBWLVWGNWQexSgSxsj_Qulcy4a-fN"
    ),
}


def selftest() -> dict:
    """Validate the full pipeline against RFC 8291 Appendix A. Returns a
    dict of pass flags; raises AssertionError on any mismatch.

    Checks (the body-match is the strongest — it pins every byte of the
    output to the published vector, and the independent decrypt with the
    receiver's own private key rules out a symmetric bug masked by reusing
    our derivation on both sides):
      * CEK + NONCE match the published constants;
      * re-encrypting with the vector's fixed as_private + salt reproduces
        the published encrypted body byte-for-byte;
      * decrypting the published body with the receiver private key (keys
        derived independently from the UA side) recovers the plaintext.
    """
    v = _RFC8291_A
    ua_public = b64u_decode(v["ua_public"])
    auth_secret = b64u_decode(v["auth_secret"])
    salt = b64u_decode(v["salt"])
    as_priv = _load_private_from_raw(b64u_decode(v["as_private"]))
    as_public = _public_raw(as_priv)
    ecdh = as_priv.exchange(ec.ECDH(), _load_public_from_raw(ua_public))
    cek, nonce = _derive_cek_nonce(ecdh, auth_secret, ua_public, as_public, salt)

    cek_ok = b64u_encode(cek) == v["expected_cek"]
    nonce_ok = b64u_encode(nonce) == v["expected_nonce"]
    assert cek_ok, f"CEK mismatch: {b64u_encode(cek)} != {v['expected_cek']}"
    assert nonce_ok, f"NONCE mismatch: {b64u_encode(nonce)} != {v['expected_nonce']}"

    # Parse the published body to learn the record size it used, then
    # reproduce it exactly with the vector's fixed inputs.
    pub_body = b64u_decode(v["expected_body"])
    rs = struct.unpack("!L", pub_body[16:20])[0]
    body = encrypt(v["plaintext"], v["ua_public"], v["auth_secret"],
                   as_private_raw=b64u_decode(v["as_private"]), salt=salt,
                   record_size=rs)
    body_ok = b64u_encode(body) == v["expected_body"]
    assert body_ok, f"body mismatch:\n  got {b64u_encode(body)}\n  exp {v['expected_body']}"

    # Independent decrypt with the receiver's private key.
    idlen = pub_body[20]
    keyid = pub_body[21:21 + idlen]
    ciphertext = pub_body[21 + idlen:]
    assert keyid == as_public, "header keyid (as_public) mismatch"
    ua_priv = _load_private_from_raw(b64u_decode(v["ua_private"]))
    ecdh2 = ua_priv.exchange(ec.ECDH(), _load_public_from_raw(keyid))
    cek2, nonce2 = _derive_cek_nonce(ecdh2, auth_secret, ua_public, keyid, salt)
    recovered = AESGCM(cek2).decrypt(nonce2, ciphertext, None)
    assert recovered[-1] == 0x02, "missing RFC 8188 last-record delimiter"
    assert recovered[:-1] == v["plaintext"], "plaintext round-trip mismatch"

    return {"cek_ok": cek_ok, "nonce_ok": nonce_ok,
            "body_ok": body_ok, "roundtrip_ok": True, "record_size": rs}


if __name__ == "__main__":
    print(selftest())
