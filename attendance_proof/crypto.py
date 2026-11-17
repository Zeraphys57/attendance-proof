"""Utilitas kriptografi bersama: encoding kanonik, tanda tangan Ed25519, hash."""
import hashlib
import json

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

PROTO = "AttendanceProof-v1"
_RAW = dict(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)


class ProtocolError(Exception):
    """Dilempar setiap kali verifikasi gagal. Pesannya menyebut mekanisme yang menolak."""


def enc(obj) -> bytes:
    """Encoding kanonik (urutan key tetap, bytes jadi hex) supaya tanda tangan deterministik."""
    def norm(v):
        if isinstance(v, bytes):
            return v.hex()
        if isinstance(v, dict):
            return {k: norm(x) for k, x in v.items()}
        if isinstance(v, (list, tuple)):
            return [norm(x) for x in v]
        return v
    return json.dumps(norm(obj), sort_keys=True, separators=(",", ":")).encode()


def h(*parts) -> bytes:
    m = hashlib.sha256()
    for p in parts:
        m.update(p if isinstance(p, bytes) else str(p).encode())
        m.update(b"|")
    return m.digest()


def new_keypair():
    sk = Ed25519PrivateKey.generate()
    return sk, sk.public_key().public_bytes(**_RAW)


def verify(pk: bytes, sig: bytes, msg: bytes, what: str):
    try:
        Ed25519PublicKey.from_public_bytes(pk).verify(sig, msg)
    except (InvalidSignature, ValueError):
        raise ProtocolError(f"tanda tangan {what} tidak valid")
