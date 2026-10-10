"""Python-referentie voor Seal_v2 (docs/HARDWARE_KEYS.md §12.5) — ALLEEN voor tests.

De server zelf verzegelt en opent nooit (P-CRYPT-09); hij controleert alleen de vorm. Deze
referentie bestaat om testvectoren te controleren en om in tests realistische kopieën te maken.
Alleen ``cryptography`` (X25519, HKDF, AESGCM).
"""

from __future__ import annotations

import base64
import json
import os
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


class UnsealFailed(Exception):
    """Equivalent van ``HwKeyError('unseal_failed')`` in de JS-module."""


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64u_dec(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _hkdf(ikm: bytes, salt: bytes, info: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=info).derive(ikm)


def _raw_pub(pk: X25519PublicKey) -> bytes:
    return pk.public_bytes(Encoding.Raw, PublicFormat.Raw)


def keypair_from_prf(prf: bytes) -> tuple[bytes, bytes]:
    """``(sk_seed, pk)``: seed = HKDF(prf, 0^32, "HorseSafe v2 X25519"); X25519 clampt zelf."""
    seed = _hkdf(prf, b"\x00" * 32, b"HorseSafe v2 X25519")
    sk = X25519PrivateKey.from_private_bytes(seed)
    return seed, _raw_pub(sk.public_key())


def build_aad(purpose: str, vault_id: str, bind: str) -> bytes:
    return b"HSv2\x00" + purpose.encode() + b"\x00" + vault_id.encode() + b"\x00" + bind.encode()


def plaintext(ph: bytes | None, kh: bytes | None) -> bytes:
    if ph is None and kh is None:
        raise ValueError("minstens één van ph/kh")

    def v(x: bytes | None) -> str:
        return "null" if x is None else f'"{b64u(x)}"'

    return f'{{"ph":{v(ph)},"kh":{v(kh)}}}'.encode()


def seal_with(
    recipient_pk: bytes,
    ph: bytes | None,
    kh: bytes | None,
    *,
    purpose: str,
    vault_id: str,
    bind: str,
    kid: str,
    ephemeral_sk: bytes,
    iv: bytes,
) -> tuple[str, dict[str, Any]]:
    """Deterministisch verzegelen (vaste e en iv) → ``(sealed, tussenwaarden)``."""
    e = X25519PrivateKey.from_private_bytes(ephemeral_sk)
    epk = _raw_pub(e.public_key())
    ss = e.exchange(X25519PublicKey.from_public_bytes(recipient_pk))
    if ss == b"\x00" * 32:
        raise ValueError("all-zero shared secret")
    k = _hkdf(ss, epk + recipient_pk, b"HorseSafe v2 seal")
    aad = build_aad(purpose, vault_id, bind)
    pt = plaintext(ph, kh)
    ct = AESGCM(k).encrypt(iv, pt, aad)
    sealed = json.dumps(
        {"v": 2, "kid": kid, "epk": b64u(epk), "iv": b64u(iv), "ct": b64u(ct)},
        separators=(",", ":"),
    )
    return sealed, {"aad": aad, "pt": pt, "k": k, "epk": epk}


def seal(recipient_pk: bytes, ph: bytes | None, kh: bytes | None, *, vault_id: str, key_id: str) -> str:
    return seal_with(
        recipient_pk, ph, kh, purpose="store", vault_id=vault_id, bind=key_id, kid=key_id,
        ephemeral_sk=os.urandom(32), iv=os.urandom(12),
    )[0]


def unseal(
    sealed: str, recipient_sk: bytes, *, purpose: str, vault_id: str, bind: str, kid: str
) -> tuple[bytes | None, bytes | None]:
    """Openen met een zelf opgebouwde AAD; nooit alleen op ``sealed.kid`` vertrouwen."""
    try:
        obj = json.loads(sealed)
        if obj.get("v") != 2 or obj.get("kid") != kid:
            raise UnsealFailed
        sk = X25519PrivateKey.from_private_bytes(recipient_sk)
        pk = _raw_pub(sk.public_key())
        epk = b64u_dec(obj["epk"])
        ss = sk.exchange(X25519PublicKey.from_public_bytes(epk))
        k = _hkdf(ss, epk + pk, b"HorseSafe v2 seal")
        pt = AESGCM(k).decrypt(b64u_dec(obj["iv"]), b64u_dec(obj["ct"]), build_aad(purpose, vault_id, bind))
        data = json.loads(pt)
    except UnsealFailed:
        raise
    except Exception as e:  # noqa: BLE001
        raise UnsealFailed from e
    ph = b64u_dec(data["ph"]) if data["ph"] is not None else None
    kh = b64u_dec(data["kh"]) if data["kh"] is not None else None
    return ph, kh
