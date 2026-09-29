
"""Client-side Ed25519 — private key never sent to ProofAgent."""
from __future__ import annotations
import base64, hashlib, json
from typing import Any

GENESIS = "sha256:" + ("0" * 64)

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
    from cryptography.hazmat.primitives import serialization
    from cryptography.exceptions import InvalidSignature
    _HAS_CRYPTO = True
except ImportError:
    _HAS_CRYPTO = False

def generate_keypair() -> tuple[str, str]:
    if not _HAS_CRYPTO:
        raise RuntimeError("Install proofagent[crypto] or cryptography for client-side keys")
    sk = Ed25519PrivateKey.generate()
    pk = sk.public_key()
    priv_raw = sk.private_bytes(encoding=serialization.Encoding.Raw, format=serialization.PrivateFormat.Raw, encryption_algorithm=serialization.NoEncryption())
    pub_raw = pk.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
    return base64.b64encode(pub_raw).decode(), base64.b64encode(priv_raw).decode()

def _canonical(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

def hash_object(obj: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical(obj)).hexdigest()

def _private_key_from_b64(private_key_b64: str):
    """Accept 32-byte seed or Go-style 64-byte PrivateKey (seed||pub)."""
    raw = base64.b64decode(private_key_b64)
    if len(raw) == 64:
        raw = raw[:32]
    if len(raw) != 32:
        raise ValueError(f"Ed25519 private key must be 32 or 64 bytes, got {len(raw)}")
    return Ed25519PrivateKey.from_private_bytes(raw)

def sign_receipt_hash(private_key_b64: str, receipt_hash: str) -> str:
    if not _HAS_CRYPTO:
        raise RuntimeError("cryptography required for local signing")
    sk = _private_key_from_b64(private_key_b64)
    return base64.b64encode(sk.sign(receipt_hash.encode("utf-8"))).decode()

def verify_receipt_hash(public_key_b64: str, receipt_hash: str, signature_b64: str) -> bool:
    if not _HAS_CRYPTO:
        return False
    try:
        pk = Ed25519PublicKey.from_public_bytes(base64.b64decode(public_key_b64))
        pk.verify(base64.b64decode(signature_b64), receipt_hash.encode("utf-8"))
        return True
    except Exception:
        return False

def build_signed_receipt(body: dict, private_key_b64: str) -> dict:
    body = {k: v for k, v in body.items() if k not in ("receipt_hash", "signature")}
    if not body.get("previous_receipt_hash"):
        body["previous_receipt_hash"] = GENESIS
    rh = hash_object(body)
    out = dict(body)
    out["receipt_hash"] = rh
    out["signature"] = sign_receipt_hash(private_key_b64, rh)
    return out
