"""Genereer ``specs/testvectors/pair_v1.json`` — koppel-testvectoren (docs/HARDWARE_KEYS.md §13.1).

Alleen ``cryptography`` en vaste invoer: elke waarde is SHA-256 van een vast label, dus het resultaat is
byte voor byte reproduceerbaar. Gebruikt door pytest, ``node --test`` en de JVM-tests van de app.

Draai vanaf de repo-root:
    python specs/testvectors/gen_pair_v1.py            # schrijft pair_v1.json
    python specs/testvectors/gen_pair_v1.py --check    # faalt als pair_v1.json afwijkt

Testmateriaal: geen echte sleutels.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

OUT = Path(__file__).resolve().with_name("pair_v1.json")


def det(label: str, n: int = 32) -> bytes:
    """Vaste testbytes: SHA-256("HorseSafe testvector:<label>:<i>") aaneengeregen."""
    out = b""
    i = 0
    while len(out) < n:
        out += hashlib.sha256(f"HorseSafe testvector:{label}:{i}".encode()).digest()
        i += 1
    return out[:n]


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def hkdf(ikm: bytes, info: str) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=b"\x00" * 32, info=info.encode()).derive(ikm)


def transcript(f: dict[str, str]) -> bytes:
    parts = ["HSv2 pair", f["pairing_id"], f["pk_c"], f["k_dev_pub"], f["k_biosig_pub"],
             f["label"], f["model"], f["app_version"]]
    return "\x00".join(parts).encode("utf-8")


def sas(t: bytes) -> str:
    d = hashlib.sha256(b"HSv2 pair sas\x00" + t).digest()
    return f"{int.from_bytes(d[:4], 'big') % 1_000_000:06d}"


def vector(name: str, pairing_id: str, label: str, model: str, app_version: str) -> dict:
    s = det(f"pair:{name}:s", 16)
    k_srv = hkdf(s, "HSv2 pair srv")
    k_web = hkdf(s, "HSv2 pair web")
    fields = {
        "pairing_id": pairing_id,
        "pk_c": b64u(det(f"pair:{name}:pk_c")),
        "k_dev_pub": b64u(det(f"pair:{name}:k_dev_pub", 91)),
        "k_biosig_pub": b64u(det(f"pair:{name}:k_biosig_pub", 91)),
        "label": label,
        "model": model,
        "app_version": app_version,
    }
    t = transcript(fields)
    return {
        "name": name,
        "s": b64u(s),
        "qr": f"hs1p:{pairing_id}.{b64u(s)}",
        "k_srv": b64u(k_srv),
        "k_web": b64u(k_web),
        "att_challenge_hex": hashlib.sha256(
            b"HSv2 pair att\x00" + pairing_id.encode() + b"\x00" + k_srv).hexdigest(),
        "fields": fields,
        "transcript_hex": t.hex(),
        "mac_srv": b64u(hmac.new(k_srv, t, hashlib.sha256).digest()),
        "mac_web": b64u(hmac.new(k_web, t, hashlib.sha256).digest()),
        "sas": sas(t),
    }


def build() -> dict:
    return {
        "format": "HorseSafe pair_v1 testvectors",
        "version": 1,
        "spec": "docs/HARDWARE_KEYS.md §13.1",
        "vectors": [
            vector("basis", "5b1e2c3d-4f50-4a6b-8c7d-9e0f1a2b3c4d", "Galaxy Z Fold6", "SM-F956B", "0.3.4-Miller"),
            vector("utf8-label", "c0ffee00-1234-4abc-9def-0123456789ab", "Telefoon van Christian – é", "FP6", "0.3.4-Miller"),
        ],
        "negative": [
            {"name": "ander label", "based_on": "basis", "change": {"label": "Ander toestel"},
             "expect": "mac_srv, mac_web en sas wijken af"},
        ],
    }


def main() -> int:
    data = json.dumps(build(), indent=2, ensure_ascii=False) + "\n"
    if "--check" in sys.argv:
        if OUT.read_text(encoding="utf-8") != data:
            print("pair_v1.json wijkt af van de generator", file=sys.stderr)
            return 1
        print("pair_v1.json klopt")
        return 0
    OUT.write_text(data, encoding="utf-8")
    print(f"geschreven: {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
