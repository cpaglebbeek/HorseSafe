"""Genereer ``specs/testvectors/seal_v2.json`` — Seal_v2-testvectoren (docs/HARDWARE_KEYS.md §12.5).

Alleen ``cryptography`` (via de Python-referentie ``backend/tests/seal_v2_ref.py``) en vaste invoer:
elke waarde is SHA-256 van een vast label, dus het resultaat is byte voor byte reproduceerbaar.
Gebruikt door pytest (``backend/tests/test_seal_v2.py``), ``node --test``
(``frontend/tests/unit/hwkeys-crypto.test.mjs``) en later de JVM (Miller).

Draai vanaf de repo-root:
    python specs/testvectors/gen_seal_v2.py            # schrijft seal_v2.json
    python specs/testvectors/gen_seal_v2.py --check    # faalt als seal_v2.json afwijkt

Testmateriaal: geen echte sleutels, wachtwoorden of keyfiles.
"""

from __future__ import annotations

import hashlib
import importlib
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
OUT = Path(__file__).resolve().with_name("seal_v2.json")
sys.path.insert(0, str(ROOT))
ref = importlib.import_module("backend.tests.seal_v2_ref")

VAULT_ID = "3f2a1b4c-5d6e-4f70-8a9b-0c1d2e3f4a5b"
KEY_ID = "9e8d7c6b-5a49-4382-9170-6f5e4d3c2b1a"
OTHER_VAULT_ID = "00000000-0000-4000-8000-000000000000"
OTHER_KEY_ID = "11111111-1111-4111-8111-111111111111"


def det(label: str, n: int = 32) -> bytes:
    """Vaste testbytes: SHA-256("HorseSafe testvector:<label>:<i>") aaneengeregen."""
    out = b""
    i = 0
    while len(out) < n:
        out += hashlib.sha256(f"HorseSafe testvector:{label}:{i}".encode()).digest()
        i += 1
    return out[:n]


def prf_vectors() -> list[dict[str, str]]:
    out = []
    for i in range(3):
        prf = det(f"prf/{i}")
        sk, pk = ref.keypair_from_prf(prf)
        out.append({"prf": ref.b64u(prf), "sk": ref.b64u(sk), "pk": ref.b64u(pk)})
    return out


def seal_vector(name: str, ph: bytes | None, kh: bytes | None) -> dict[str, Any]:
    # De ontvanger is een PRF-afgeleid sleutelpaar, zoals in het echt (recipient_sk = seed).
    recipient_sk, recipient_pk = ref.keypair_from_prf(det(f"{name}/recipient-prf"))
    ephemeral_sk = det(f"{name}/ephemeral")
    iv = det(f"{name}/iv", 12)
    sealed, mid = ref.seal_with(
        recipient_pk,
        ph,
        kh,
        purpose="store",
        vault_id=VAULT_ID,
        bind=KEY_ID,
        kid=KEY_ID,
        ephemeral_sk=ephemeral_sk,
        iv=iv,
    )
    return {
        "name": name,
        "recipient_sk": ref.b64u(recipient_sk),
        "recipient_pk": ref.b64u(recipient_pk),
        "ephemeral_sk": ref.b64u(ephemeral_sk),
        "ephemeral_pk": ref.b64u(mid["epk"]),
        "iv": ref.b64u(iv),
        "purpose": "store",
        "vault_id": VAULT_ID,
        "bind": KEY_ID,
        "kid": KEY_ID,
        "ph": ref.b64u(ph) if ph is not None else None,
        "kh": ref.b64u(kh) if kh is not None else None,
        "aad_hex": mid["aad"].hex(),
        "pt_utf8": mid["pt"].decode(),
        "k_hex": mid["k"].hex(),
        "sealed": sealed,
    }


def flipped_ct(sealed: str, index: int = 0) -> str:
    obj = json.loads(sealed)
    ct = bytearray(ref.b64u_dec(obj["ct"]))
    ct[index] ^= 1
    obj["ct"] = ref.b64u(bytes(ct))
    return json.dumps(obj, separators=(",", ":"))


def build() -> dict[str, Any]:
    seals = [
        seal_vector("ph+kh", det("ph+kh/ph"), det("ph+kh/kh")),
        seal_vector("alleen ph", det("alleen ph/ph"), None),
        seal_vector("alleen kh", None, det("alleen kh/kh")),
    ]
    base = seals[0]
    negative = [
        {
            "name": "andere vault_id",
            "based_on": base["name"],
            "open_with": {"vault_id": OTHER_VAULT_ID},
            "expect": "unseal_failed",
        },
        {
            "name": "andere key_id",
            "based_on": base["name"],
            "open_with": {"key_id": OTHER_KEY_ID},
            "expect": "unseal_failed",
        },
        {
            "name": "andere purpose",
            "based_on": base["name"],
            "open_with": {"purpose": "relay"},
            "expect": "unseal_failed",
        },
        {
            "name": "gewijzigde ct",
            "based_on": base["name"],
            "mutate": {"ct_flip_byte": 0},
            "open_with": {"sealed": flipped_ct(base["sealed"], 0)},
            "expect": "unseal_failed",
        },
    ]
    return {
        "format": "HorseSafe Seal_v2 testvectors",
        "version": 1,
        "spec": "docs/HARDWARE_KEYS.md §12.5",
        "generator": "specs/testvectors/gen_seal_v2.py",
        "prf_vectors": prf_vectors(),
        "seal_vectors": seals,
        "negative": negative,
    }


def render() -> str:
    return json.dumps(build(), indent=2, ensure_ascii=False) + "\n"


def main(argv: list[str]) -> int:
    text = render()
    if "--check" in argv:
        if not OUT.exists() or OUT.read_text(encoding="utf-8") != text:
            print(f"{OUT} wijkt af van de generator; draai zonder --check.", file=sys.stderr)
            return 1
        print(f"{OUT} is actueel.")
        return 0
    OUT.write_text(text, encoding="utf-8")
    print(f"Geschreven: {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
