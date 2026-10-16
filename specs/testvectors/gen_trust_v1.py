"""Genereer ``specs/testvectors/trust_v1.json`` — vertrouwde browser + ontgrendelverzoek (docs/HARDWARE_KEYS.md §14.2).

Alleen ``cryptography`` en vaste invoer (elke waarde is SHA-256 van een vast label; ECDSA deterministisch volgens
RFC 6979), dus byte voor byte reproduceerbaar. Gebruikt door pytest, ``node --test`` en de JVM-tests van de app.

Draai vanaf de repo-root:
    python specs/testvectors/gen_trust_v1.py            # schrijft trust_v1.json
    python specs/testvectors/gen_trust_v1.py --check    # faalt als trust_v1.json afwijkt

Testmateriaal: geen echte sleutels.
"""

from __future__ import annotations

import hashlib
import hmac
import importlib
import json
import sys
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

ROOT = Path(__file__).resolve().parents[2]
OUT = Path(__file__).resolve().with_name("trust_v1.json")
sys.path.insert(0, str(ROOT))
ref = importlib.import_module("backend.tests.seal_v2_ref")

VAULT_ID = "3f2a1b4c-5d6e-4f70-8a9b-0c1d2e3f4a5b"
OTHER_VAULT_ID = "00000000-0000-4000-8000-000000000000"
BROWSER_ID = "7d3c2b1a-0f9e-4d8c-b7a6-5e4d3c2b1a09"
APPROVAL_ID = "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d"
CHALLENGE_ID = "c4a11e96-0000-4abc-9def-0123456789ab"
CREATED_AT = 1792150000
N_P256 = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


def det(label: str, n: int = 32) -> bytes:
    out = b""
    i = 0
    while len(out) < n:
        out += hashlib.sha256(f"HorseSafe testvector:{label}:{i}".encode()).digest()
        i += 1
    return out[:n]


b64u = ref.b64u


def k_bind(pt_ck: bytes, vault_id: str) -> bytes:
    salt = hashlib.sha256(b"HSv2 bind salt\x00" + vault_id.encode()).digest()
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=b"HSv2 browser bind").derive(pt_ck)


def bind_t(vault_id: str, browser_id: str, pub_b: str, label: str) -> bytes:
    return "\x00".join(["HSv2 browser", vault_id, browser_id, pub_b, label]).encode("utf-8")


def login_t(challenge_id: str, challenge: bytes, browser_id: str, email_lc: str) -> bytes:
    return "\x00".join(["HSv2 blogin", challenge_id, b64u(challenge), browser_id, email_lc]).encode("utf-8")


def req_t(approval_id: str, vault_id: str, browser_id: str, epk_l: str, nonce_l: bytes, created_at: int) -> bytes:
    return "\x00".join(
        ["HSv2 approve", approval_id, vault_id, browser_id, epk_l, b64u(nonce_l), str(created_at)]
    ).encode("utf-8")


def browser_key() -> ec.EllipticCurvePrivateKey:
    d = int.from_bytes(det("trust:K_B:d"), "big") % (N_P256 - 1) + 1
    return ec.derive_private_key(d, ec.SECP256R1())


def sign_raw(key: ec.EllipticCurvePrivateKey, msg: bytes) -> bytes:
    der = key.sign(msg, ec.ECDSA(hashes.SHA256(), deterministic_signing=True))
    r, s = decode_dss_signature(der)
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def build() -> dict[str, Any]:
    kb = browser_key()
    pub_b = b64u(kb.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo))
    ph, kh = det("trust:ph"), det("trust:kh")
    label = "Chrome – laptop"

    proofs = []
    for name, p, k in [("ph+kh", ph, kh), ("alleen kh", None, kh)]:
        pt = ref.plaintext(p, k)
        kbind = k_bind(pt, VAULT_ID)
        t = bind_t(VAULT_ID, BROWSER_ID, pub_b, label)
        proofs.append({
            "name": name, "ph": b64u(p) if p else None, "kh": b64u(k), "pt_ck": pt.decode(),
            "vault_id": VAULT_ID, "browser_id": BROWSER_ID, "pub_b": pub_b, "label": label,
            "k_bind_hex": kbind.hex(), "bind_t_hex": t.hex(),
            "proof": b64u(hmac.new(kbind, t, hashlib.sha256).digest()),
        })

    challenge = det("trust:challenge")
    lt = login_t(CHALLENGE_ID, challenge, BROWSER_ID, "christian@example.com")
    login = {"challenge_id": CHALLENGE_ID, "challenge": b64u(challenge), "browser_id": BROWSER_ID,
             "email_lc": "christian@example.com", "pub_b": pub_b, "login_t_hex": lt.hex(),
             "sig": b64u(sign_raw(kb, lt))}

    e_l = det("trust:e_L")
    epk_l = b64u(ref._raw_pub(X25519PrivateKey.from_private_bytes(e_l).public_key()))
    nonce_l = det("trust:nonce_L")
    rt = req_t(APPROVAL_ID, VAULT_ID, BROWSER_ID, epk_l, nonce_l, CREATED_AT)
    bind = APPROVAL_ID + "\x00" + b64u(nonce_l)
    resp, mid = ref.seal_with(
        ref.b64u_dec(epk_l), ph, kh, purpose="relay", vault_id=VAULT_ID, bind=bind, kid=APPROVAL_ID,
        ephemeral_sk=det("trust:relay:e"), iv=det("trust:relay:iv", 12),
    )
    approval = {"approval_id": APPROVAL_ID, "vault_id": VAULT_ID, "browser_id": BROWSER_ID,
                "e_l_sk": b64u(e_l), "epk_l": epk_l, "nonce_l": b64u(nonce_l), "created_at": CREATED_AT,
                "pub_b": pub_b, "req_t_hex": rt.hex(), "sig_req": b64u(sign_raw(kb, rt)),
                "relay_bind": bind, "relay_aad_hex": mid["aad"].hex(), "ph": b64u(ph), "kh": b64u(kh),
                "resp": resp}

    return {
        "format": "HorseSafe trust_v1 testvectors",
        "version": 1,
        "spec": "docs/HARDWARE_KEYS.md §14.2",
        "browser_key": {"d_hex": format(kb.private_numbers().private_value, "064x"), "pub_b": pub_b},
        "proof_vectors": proofs,
        "login_vector": login,
        "approval_vector": approval,
        "negative": [
            {"name": "ander vault_id", "based_on": "ph+kh", "change": {"vault_id": OTHER_VAULT_ID},
             "expect": "proof wijkt af"},
            {"name": "ander label", "based_on": "ph+kh", "change": {"label": "Ander apparaat"},
             "expect": "proof wijkt af"},
            {"name": "andere pub_b", "based_on": "ph+kh", "change": {"pub_b": b64u(det("trust:other_pub", 91))},
             "expect": "proof wijkt af"},
            {"name": "kh null", "based_on": "ph+kh", "change": {"kh": None},
             "expect": "weigeren: vertrouwen vereist keyfile (kh)"},
            {"name": "andere nonce bij openen", "based_on": "approval", "change": {"nonce_l": b64u(det("trust:nonce_X"))},
             "expect": "unseal_failed"},
            {"name": "ander created_at", "based_on": "approval", "change": {"created_at": CREATED_AT + 1},
             "expect": "sig_req ongeldig"},
        ],
    }


def main() -> int:
    data = json.dumps(build(), indent=2, ensure_ascii=False) + "\n"
    if "--check" in sys.argv:
        if OUT.read_text(encoding="utf-8") != data:
            print("trust_v1.json wijkt af van de generator", file=sys.stderr)
            return 1
        print("trust_v1.json klopt")
        return 0
    OUT.write_text(data, encoding="utf-8")
    print(f"geschreven: {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
